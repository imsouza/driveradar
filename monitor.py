"""External release and security-feed collectors for DriveRadar.

Only facts present in a source are returned. Stability is intentionally not
inferred from the absence of reports: upstream failures and insufficient
evidence are explicit API states.
"""

from __future__ import annotations

import logging
import re
import threading
import urllib.parse
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from io import BytesIO
from typing import Any

import feedparser
import requests
from bs4 import BeautifulSoup, Tag

try:
    from pypdf import PdfReader
except ImportError:  # Local lightweight test environments may omit PDF support.
    PdfReader = None
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOGGER = logging.getLogger(__name__)

REQUEST_TIMEOUT = (5, 15)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

TECHPOWERUP_URLS = {
    "nvidia": "https://www.techpowerup.com/download/nvidia-geforce-graphics-drivers/",
    "amd": "https://www.techpowerup.com/download/amd-radeon-graphics-drivers/",
    "intel": "https://www.techpowerup.com/download/intel-arc-graphics-drivers/",
}

OFFICIAL_URLS = {
    "nvidia": "https://www.nvidia.com/en-us/drivers/",
    "amd": "https://www.amd.com/en/support/download/drivers.html",
    "intel": "https://www.intel.com/content/www/us/en/download-center/home.html",
    "windows": "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
}

NVIDIA_AJAX_URL = (
    "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/"
    "AjaxDriverService.php?func=DriverManualLookup&psid=131&pfid=1066&osID=135"
    "&languageCode=1033&beta=0&isWHQL=1&dltype=-1&dch=1&upCRD=0&qnf=0&ctk=null"
    "&sort1=1&numberOfResults=12"
)
NVIDIA_AJAX_BETA_URL = (
    "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/"
    "AjaxDriverService.php?func=DriverManualLookup&psid=131&pfid=1066&osID=135"
    "&languageCode=1033&beta=1&isWHQL=0&dltype=-1&dch=1&upCRD=0&qnf=0&ctk=null"
    "&sort1=1&numberOfResults=6"
)
AMD_DRIVER_PAGE_URL = (
    "https://www.amd.com/en/support/downloads/drivers.html/"
    "graphics/radeon-rx/radeon-rx-9000-series/amd-radeon-rx-9070-xt.html"
)
INTEL_CN_DOWNLOAD_URL = (
    "https://www.intel.cn/content/www/cn/zh/download/785597/intel-arc-graphics-windows.html"
)

VERSION_PATTERNS = {
    "nvidia": re.compile(r"NVIDIA GeForce Graphics Drivers\s+(\d{3}\.\d{2})", re.I),
    "amd": re.compile(r"AMD Radeon Graphics Drivers\s+(\d{2}\.\d{1,2}\.\d{1,2})", re.I),
    "intel": re.compile(r"Intel Graphics Drivers\s+((?:\d+\.){1,3}\d+)", re.I),
}

HEADING_VERSION_PATTERNS = {
    "nvidia": re.compile(r"(\d{3}\.\d{2})"),
    "amd": re.compile(r"(\d{2}\.\d{1,2}\.\d{1,2})"),
    "intel": re.compile(r"((?:\d+\.){1,3}\d+)"),
}

SECURITY_TERMS = (
    "nvidia",
    "amd",
    "intel",
    "windows",
    "vulnerability",
    "cve-",
    "driver",
)

_TOC_DOTS_RE = re.compile(r"\.{4,}\s*\d*\s*$")
_SKIP_SECTION_RE = re.compile(
    r"^(?:table of contents|chapter \d+\.\s*introduction|"
    r"supported nvidia|radeon product compatibility|mobility radeon|"
    r"amd processors with radeon|product support matrix|compatible operating systems|"
    r"supported apis|operating system support|packaged contents|"
    r"file information|related topics|more on intel products|notes & disclaimers|"
    r"driver package contents|how to get this update|before you install this update|"
    r"install this update|installing amd software)",
    re.I,
)
_SIGNAL_HEADING_RE = re.compile(
    r"(?:what['’]?s new|highlights|game ready|game on|new feature|new game|"
    r"fixed gaming|fixed general|fixed issues|resolved issues|changes and fixed|"
    r"known issues|open issues|important open issues|limitations|security|improvements|"
    r"announcements and messages)",
    re.I,
)
_SIGNAL_LINE_RE = re.compile(
    r"fixed|resolved|known issue|open issue|bug|crash|hang|stutter|timeout|"
    r"performance|corrupt|flicker|security|vulnerab|cve-|workaround|improv|support|"
    r"game ready|game on|dlss|fsr|rocm|new!|streamlined|inline actions",
    re.I,
)
_SKIP_BULLET_RE = re.compile(
    r"^(?:n/a|none|see\s|refer to\s|for more information|for notebook computers|"
    r"learn more in our|microsoft recommends|intel recommends|you are confirming|"
    r"surface laptop|surface pro|surface rtx|windows update|catalog|business|"
    r"server update services|how-to\s)",
    re.I,
)


def _iso_date(value: Any) -> str | None:
    """Parse common release dates into ISO YYYY-MM-DD."""
    if not value:
        return None
    raw = str(value).strip()
    cleaned = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", raw, flags=re.I)
    cleaned = re.sub(r"\s+\d{2}:\d{2}:\d{2}$", "", cleaned).strip()
    for fmt in (
        "%Y-%m-%d",
        "%B %d, %Y",
        "%b %d, %Y",
        "%a %b %d, %Y",
        "%A %b %d, %Y",
        "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(cleaned, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _date_delta_days(date_a: str | None, date_b: str | None) -> int | None:
    if not date_a or not date_b:
        return None
    try:
        return abs((date.fromisoformat(date_a) - date.fromisoformat(date_b)).days)
    except ValueError:
        return None


def _safe_text(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def _normalize_line(line: str) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", line)
    return " ".join(text.split()).strip()


def _focus_release_notes(text: str, limit: int = 18_000) -> str:
    """Strip TOC dot-leaders & hardware tables while keeping highlights, fixes & known issues."""
    raw_lines = [_normalize_line(line) for line in text.splitlines()]
    filtered: list[str] = []
    skipping_table = False

    for line in raw_lines:
        if not line:
            continue
        # Drop PDF table-of-contents lines and page footers/headers.
        if _TOC_DOTS_RE.search(line) or re.match(r"^RN-\d+-\d+\.\d+.*\|\s*\d+\s+Release\b", line):
            continue
        if line in {"rs", "Table of Contents"} or line.startswith("© Intel Corporation"):
            continue
        if _SKIP_SECTION_RE.match(line):
            skipping_table = True
            continue
        if skipping_table:
            if _SIGNAL_HEADING_RE.search(line) or re.match(r"^(?:chapter\s+\d|2\.\d|3\.\d|highlights|fixed issues|known issues)", line, re.I):
                skipping_table = False
            else:
                continue
        filtered.append(line)

    compact = "\n".join(filtered)
    if len(compact) <= limit:
        return compact

    selected: list[str] = []
    seen: set[str] = set()
    for line in filtered[:24]:
        if line not in seen:
            selected.append(line)
            seen.add(line)

    for index, line in enumerate(filtered):
        if not (_SIGNAL_HEADING_RE.search(line) or _SIGNAL_LINE_RE.search(line)):
            continue
        for nearby in filtered[max(0, index - 1) : index + 10]:
            if nearby not in seen:
                selected.append(nearby)
                seen.add(nearby)
                if sum(len(item) + 1 for item in selected) >= limit:
                    return "\n".join(selected)[:limit]

    return "\n".join(selected)[:limit]


def _clean_bullet(text: str, limit: int = 240) -> str:
    cleaned = re.sub(r"^[>\-•▪‣\*]+\s*", "", _normalize_line(text))
    cleaned = re.sub(r"\s*\[\d{5,9}\]\s*$", "", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip(" ,;:") + "…"
    return cleaned


def _add_unique_item(target: list[str], seen: set[str], raw_text: str, max_items: int = 6) -> None:
    if len(target) >= max_items:
        return
    cleaned = _clean_bullet(raw_text)
    if len(cleaned) < 14 or _SKIP_BULLET_RE.match(cleaned):
        return
    key = cleaned.casefold()
    if key in seen:
        return
    seen.add(key)
    target.append(cleaned)


def parse_release_notes_sections(
    text: str, vendor: str = "", html: str | None = None
) -> dict[str, list[str]]:
    """Deterministically extract highlights, fixed_issues, and known_issues from release notes."""
    highlights: list[str] = []
    fixed_issues: list[str] = []
    known_issues: list[str] = []
    seen: set[str] = set()

    if html and vendor in {"amd", "windows"}:
        soup = BeautifulSoup(html, "html.parser")
        for node in soup(["script", "style", "nav", "footer", "header"]):
            node.decompose()
        root = soup.find("main") or soup.find("article") or soup.body or soup
        current_bucket: str | None = None
        sub_bucket: str | None = None
        for el in root.descendants:
            if not isinstance(el, Tag):
                continue
            tag_name = el.name.lower()
            if tag_name in {"h1", "h2", "h3", "h4", "strong", "p"}:
                heading = _normalize_line(el.get_text(" ", strip=True))
                low = heading.casefold()
                if tag_name in {"h1", "h2"}:
                    sub_bucket = None
                    if _SKIP_SECTION_RE.match(heading):
                        current_bucket = "skip"
                    elif any(k in low for k in ("known issue", "open issue")):
                        current_bucket = "known"
                    elif any(k in low for k in ("fixed issue", "resolved issue", "improvements", "fixes")):
                        current_bucket = "fixed"
                    elif any(k in low for k in ("highlight", "announcement", "what's new", "new feature")):
                        current_bucket = "highlights"
                    elif any(k in low for k in ("additional information", "limitation")):
                        current_bucket = "known"
                    else:
                        current_bucket = None
                elif current_bucket in {"highlights", "fixed", "known"}:
                    if any(k in low for k in ("fixed issue", "resolved issue")):
                        sub_bucket = "fixed"
                    elif any(k in low for k in ("known issue", "open issue")):
                        sub_bucket = "known"
                    elif any(k in low for k in ("new game", "new feature", "stability", "highlight")):
                        sub_bucket = "highlights"
            elif tag_name == "li" and not el.find("li"):
                bucket = sub_bucket or current_bucket
                if bucket not in {"highlights", "fixed", "known"}:
                    continue
                item_text = _normalize_line(el.get_text(" ", strip=True))
                if item_text.casefold().startswith(("fixed issues", "new game support", "new feature support")):
                    continue
                target = (
                    highlights
                    if bucket == "highlights"
                    else fixed_issues
                    if bucket == "fixed"
                    else known_issues
                )
                _add_unique_item(target, seen, item_text)

    if highlights or fixed_issues or known_issues:
        return {
            "highlights": highlights,
            "fixed_issues": fixed_issues,
            "known_issues": known_issues,
        }

    # Text/PDF section parser (used for NVIDIA, Intel, and fallback text).
    lines = [_normalize_line(line) for line in text.splitlines() if _normalize_line(line)]
    bucket: str | None = None
    buffer = ""

    def flush_buffer() -> None:
        nonlocal buffer
        if not buffer or bucket not in {"highlights", "fixed", "known"}:
            buffer = ""
            return
        target = (
            highlights
            if bucket == "highlights"
            else fixed_issues
            if bucket == "fixed"
            else known_issues
        )
        _add_unique_item(target, seen, buffer)
        buffer = ""

    for line in lines:
        if _TOC_DOTS_RE.search(line):
            continue
        low = line.casefold()
        if _SKIP_SECTION_RE.match(line) or re.match(r"^(?:3\.3\s+issues not caused|4\.\d+\s+|driver package contents)", low):
            flush_buffer()
            bucket = None
            continue
        if re.match(r"^(?:2\.4\b|(?:\d+\.\d+(?:\.\d+)*\s+)?(?:highlights\b|what['’]?s new\b)|intel®?\s*game on\b)", low):
            flush_buffer()
            bucket = "highlights"
            continue
        if re.match(r"^(?:3\.1(?:\.\d+)*\b|fixed\s+(?:gaming\s+|general\s+)?bugs\b|fixed issues\b|resolved issues\b)", low):
            flush_buffer()
            bucket = "fixed"
            continue
        if re.match(r"^(?:3\.2(?:\.\d+)*\b|open issues\b|known issues\b|2\.10(?:\.\d+)*\b|limitations in this release\b)", low):
            flush_buffer()
            bucket = "known"
            continue
        if bucket is None:
            continue
        if re.match(r"^[>•▪‣\*]", line):
            flush_buffer()
            buffer = line
        elif line.endswith(":"):
            flush_buffer()
        elif buffer:
            if len(buffer) < 220 and not re.match(r"^(?:chapter\s+\d|\d+\.\d+)", low):
                buffer = f"{buffer} {line}"
        elif bucket == "highlights" and len(line) > 30 and not re.match(r"^(?:this section|the following|learn more|\d+\.\d+)", low):
            _add_unique_item(highlights, seen, line)

    flush_buffer()
    return {
        "highlights": highlights,
        "fixed_issues": fixed_issues,
        "known_issues": known_issues,
    }


def _extract_pdf_text(content: bytes, limit: int = 18_000) -> str:
    if PdfReader is None:
        return ""
    try:
        reader = PdfReader(BytesIO(content))
        text = "\n".join((page.extract_text() or "") for page in reader.pages[:40])
        return _focus_release_notes(text, limit)
    except Exception as exc:
        LOGGER.warning("Release-notes PDF extraction failed: %s", type(exc).__name__)
        return ""


def _extract_page_text(html: str, limit: int = 18_000) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "nav", "footer", "header"]):
        node.decompose()
    root = soup.find("main") or soup.find("article") or soup.body or soup
    return _focus_release_notes(root.get_text("\n"), limit)


def _extract_tpu_entries(soup: BeautifulSoup, vendor: str, limit: int = 10) -> list[dict[str, Any]]:
    pattern = HEADING_VERSION_PATTERNS[vendor]
    entries: list[dict[str, Any]] = []
    seen_versions: set[str] = set()
    for block in soup.find_all("div", class_="version"):
        heading = block.find("h3")
        if not heading:
            continue
        heading_text = _safe_text(heading.get_text(" ", strip=True), 160)
        match = pattern.search(heading_text)
        if not match:
            continue
        displayed = match.group(1)
        version = f"32.0.{displayed}" if vendor == "intel" and displayed.count(".") == 1 else displayed
        if version in seen_versions:
            continue
        seen_versions.add(version)
        date_node = block.find(class_="date")
        release_date = _iso_date(date_node.get_text(" ", strip=True)) if date_node else None
        size_node = block.find(class_="filesize")
        file_size = _safe_text(size_node.get_text(" ", strip=True), 40) if size_node else None
        fn_node = block.find(class_="filename")
        filename = _safe_text(fn_node.get_text(" ", strip=True), 140) if fn_node else None
        sha256 = None
        for hash_entry in block.find_all(class_="hash-entry"):
            label = _safe_text(hash_entry.find(class_="hash-name").get_text() if hash_entry.find(class_="hash-name") else "", 20)
            val = _safe_text(hash_entry.find(class_="hash-value").get_text() if hash_entry.find(class_="hash-value") else "", 80)
            if "SHA256" in label.upper() and val:
                sha256 = val
        channel = "Beta" if "beta" in heading_text.casefold() else "WHQL Optional" if "optional" in heading_text.casefold() else "WHQL"
        entries.append({
            "version": version,
            "displayed_version": displayed,
            "release_date": release_date,
            "channel": channel,
            "file_size": file_size,
            "filename": filename,
            "sha256": sha256,
            "title": heading_text,
        })
        if len(entries) >= limit:
            break
    return entries


class UpdateMonitor:
    """Collect current versions and source metadata with bounded requests."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self._injected_session = session
        self._local = threading.local()

    @property
    def session(self) -> requests.Session:
        if self._injected_session is not None:
            return self._injected_session
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = self._build_session()
            self._local.session = sess
        return sess

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD"}),
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"})
        return session

    def _probe_file_size(self, url: str | None, referer: str | None = None) -> str | None:
        if not url or not re.search(r"\.(?:exe|msi|msu|cab|zip)(?:\?|$)", url, re.I):
            return None
        head_fn = getattr(self.session, "head", None)
        if not callable(head_fn):
            return None
        headers = {"Referer": referer} if referer else None
        try:
            resp = head_fn(url, headers=headers, timeout=(3, 6), allow_redirects=True)
            if getattr(resp, "status_code", 500) >= 400:
                return None
            raw_len = (getattr(resp, "headers", None) or {}).get("Content-Length")
            size_bytes = int(raw_len) if raw_len else 0
            if size_bytes < 1_048_576:
                return None
            mb = size_bytes / (1024 * 1024)
            return f"{mb / 1024:.2f} GB" if mb >= 1024 else f"{mb:.0f} MB"
        except Exception:
            return None

    def _get_soup(self, url: str) -> BeautifulSoup:
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")

    def _fetch_nvidia_ajax(self, url: str = NVIDIA_AJAX_URL) -> list[dict[str, Any]]:
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json() if hasattr(response, "json") else {}
        except Exception as exc:
            LOGGER.warning("NVIDIA official AjaxDriverService failed: %s", exc)
            return []

        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in payload.get("IDS", []):
            info = item.get("downloadInfo") or {}
            version = _safe_text(info.get("Version") or info.get("DisplayVersion"), 40)
            if not version or version in seen:
                continue
            seen.add(version)
            raw_rn = urllib.parse.unquote(str(info.get("ReleaseNotes") or ""))
            raw_other = urllib.parse.unquote(str(info.get("OtherNotes") or ""))
            pdf_matches = re.findall(r"https?://[^\s\"'<>]+\.pdf", f"{raw_rn} {raw_other}", re.I)
            pdf_url = pdf_matches[0] if pdf_matches else (
                f"https://us.download.nvidia.com/Windows/{version}/{version}-geforce-win11-x64-release-notes.pdf"
            )
            name = _safe_text(urllib.parse.unquote(str(info.get("Name") or "GeForce Game Ready Driver")), 80)
            is_whql = str(info.get("IsWHQL") or "") == "1"
            is_beta = str(info.get("IsBeta") or "") == "1"
            is_hotfix = "hotfix" in name.casefold()
            channel = (
                f"Hotfix · {name}"
                if is_hotfix
                else "Beta / Hotfix"
                if is_beta
                else f"WHQL · {name}"
                if is_whql
                else name
            )
            details_url = _safe_text(info.get("DetailsURL"), 300) or OFFICIAL_URLS["nvidia"]
            download_url = _safe_text(info.get("DownloadURL"), 400) or details_url
            entries.append({
                "version": version,
                "release_date": _iso_date(info.get("ReleaseDateTime")),
                "channel": channel,
                "file_size": _safe_text(info.get("DownloadURLFileSize"), 40) or None,
                "source_url": details_url,
                "official_url": download_url,
                "release_notes_url": pdf_url,
                "is_hotfix_or_beta": is_beta or is_hotfix,
            })
        return entries

    def _fetch_nvidia_pdf(self, version: str, preferred_url: str | None = None) -> tuple[str, str, dict[str, list[str]]] | None:
        candidates = []
        if preferred_url:
            candidates.append(preferred_url)
        candidates.extend([
            f"https://us.download.nvidia.com/Windows/{version}/{version}-geforce-win11-x64-release-notes.pdf",
            f"https://us.download.nvidia.com/Windows/{version}/{version}-win11-win10-release-notes.pdf",
        ])
        for url in dict.fromkeys(candidates):
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                if version.encode() not in response.content and len(response.content) < 5000:
                    continue
                notes_text = _extract_pdf_text(response.content)
                structured = parse_release_notes_sections(notes_text, vendor="nvidia")
                return url, notes_text, structured
            except Exception:
                continue
        return None

    def _verify_official_release(self, vendor: str, candidate: str) -> dict[str, Any]:
        """Confirm a release against a vendor-controlled artifact or page."""
        if vendor == "nvidia":
            pdf_result = self._fetch_nvidia_pdf(candidate)
            if pdf_result is None:
                raise ValueError("nvidia official PDF did not confirm version")
            notes_url, notes_text, structured = pdf_result
            return {
                "version": candidate,
                "release_date": None,
                "url": notes_url,
                "official_url": OFFICIAL_URLS["nvidia"],
                "source_name": "NVIDIA",
                "publisher": "NVIDIA",
                "tier": "primary",
                "weight": 1.0,
                "release_notes": {"url": notes_url, "text": notes_text, "structured": structured},
            }

        if vendor == "amd":
            slug = candidate.replace(".", "-")
            url = f"https://www.amd.com/en/resources/support-articles/release-notes/RN-RAD-WIN-{slug}.html"
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            if candidate not in response.text:
                raise ValueError("amd official source did not confirm a current version")
            notes_text = _extract_page_text(response.text)
            structured = parse_release_notes_sections(notes_text, vendor="amd", html=response.text)
            return {
                "version": candidate,
                "release_date": None,
                "url": url,
                "official_url": OFFICIAL_URLS["amd"],
                "source_name": "AMD",
                "publisher": "AMD",
                "tier": "primary",
                "weight": 1.0,
                "release_notes": {"url": url, "text": notes_text, "structured": structured},
            }

        if vendor == "intel":
            url = INTEL_CN_DOWNLOAD_URL
            response = self.session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            meta_ver = soup.find("meta", attrs={"name": "DownloadVersion"})
            meta_date = soup.find("meta", attrs={"name": "LastUpdate"}) or soup.find(
                "meta", attrs={"name": "lastModifieddate"}
            )
            official_version = ""
            if meta_ver and meta_ver.get("content"):
                ver_match = re.search(r"32\.0\.101\.\d{4}", str(meta_ver.get("content")))
                if ver_match:
                    official_version = ver_match.group(0)
            if not official_version:
                versions = list(dict.fromkeys(re.findall(r"32\.0\.101\.\d{4}", response.text)))
                official_version = versions[0] if versions else ""
            if not official_version:
                raise ValueError("intel official source did not confirm a current version")

            official_date = _iso_date(meta_date.get("content")) if meta_date and meta_date.get("content") else None
            channel = "WHQL" if "whql" in str(meta_ver.get("content") if meta_ver else "").lower() else None
            short_version = official_version.removeprefix("32.0.")
            notes_match = re.search(
                rf'https://downloadmirror\.intel\.com/\d+/ReleaseNotes_{re.escape(short_version)}_[^"\s<>]+\.pdf',
                response.text,
                re.I,
            )
            notes_url = notes_match.group(0) if notes_match else url
            notes_text = ""
            structured: dict[str, list[str]] = {"highlights": [], "fixed_issues": [], "known_issues": []}
            if notes_match:
                try:
                    notes_response = self.session.get(notes_url, timeout=REQUEST_TIMEOUT)
                    notes_response.raise_for_status()
                    notes_text = _extract_pdf_text(notes_response.content)
                    structured = parse_release_notes_sections(notes_text, vendor="intel")
                except Exception as exc:
                    LOGGER.warning("Intel release notes PDF fetch failed: %s", type(exc).__name__)
            return {
                "version": official_version,
                "release_date": official_date,
                "channel": channel,
                "url": url,
                "official_url": OFFICIAL_URLS["intel"],
                "source_name": "Intel",
                "publisher": "Intel",
                "tier": "primary",
                "weight": 1.0,
                "release_notes": {"url": notes_url, "text": notes_text, "structured": structured},
            }

        raise ValueError(f"Unsupported vendor: {vendor}")

    def _get_nvidia_release(self) -> dict[str, Any]:
        ajax_entries = self._fetch_nvidia_ajax(NVIDIA_AJAX_URL)
        beta_entries = self._fetch_nvidia_ajax(NVIDIA_AJAX_BETA_URL) if self._injected_session is None else []
        tpu_url = TECHPOWERUP_URLS["nvidia"]
        tpu_entries: list[dict[str, Any]] = []
        tpu_version: str | None = None
        tpu_date: str | None = None
        tpu_err: Exception | None = None
        try:
            soup = self._get_soup(tpu_url)
            title = _safe_text(soup.title.get_text(" ", strip=True) if soup.title else "")
            match = VERSION_PATTERNS["nvidia"].search(title)
            if match:
                tpu_version = match.group(1)
            tpu_entries = _extract_tpu_entries(soup, "nvidia", limit=10)
            if tpu_entries:
                tpu_version = tpu_version or tpu_entries[0]["version"]
                tpu_date = tpu_entries[0]["release_date"]
        except Exception as exc:
            tpu_err = exc

        if ajax_entries:
            primary_entry = ajax_entries[0]
            version = primary_entry["version"]
            release_date = primary_entry["release_date"]
            newer_hotfix = None
            cur_parts = tuple(int(p) for p in re.findall(r"\d+", version))
            for b_entry in beta_entries:
                b_parts = tuple(int(p) for p in re.findall(r"\d+", b_entry["version"]))
                if b_parts > cur_parts:
                    newer_hotfix = b_entry
                    break
            pdf_result = self._fetch_nvidia_pdf(version, primary_entry.get("release_notes_url"))
            if pdf_result:
                notes_url, notes_text, structured = pdf_result
            else:
                notes_url = primary_entry.get("release_notes_url") or primary_entry["source_url"]
                notes_text = ""
                structured = {"highlights": [], "fixed_issues": [], "known_issues": []}

            tpu_top = next((e for e in tpu_entries if e["version"] == version), tpu_entries[0] if tpu_entries else {})
            evidence = [
                {
                    "version": version,
                    "url": primary_entry["source_url"],
                    "source_name": "NVIDIA",
                    "publisher": "NVIDIA",
                    "tier": "primary",
                    "weight": 1.0,
                    "title": f"NVIDIA {primary_entry['channel']} {version}",
                    "published_at": release_date,
                }
            ]
            if newer_hotfix:
                evidence.append({
                    "version": newer_hotfix["version"],
                    "url": newer_hotfix["source_url"],
                    "source_name": "NVIDIA Hotfix",
                    "publisher": "NVIDIA Hotfix",
                    "tier": "primary",
                    "weight": 0.9,
                    "title": f"NVIDIA {newer_hotfix['channel']} {newer_hotfix['version']}",
                    "published_at": newer_hotfix.get("release_date"),
                    "conflict_type": "newer_reported",
                })
            if tpu_version:
                evidence.append({
                    "version": tpu_version,
                    "url": tpu_url,
                    "source_name": "TechPowerUp",
                    "publisher": "TechPowerUp",
                    "tier": "specialist",
                    "weight": 0.8,
                    "title": tpu_top.get("title") or f"TechPowerUp NVIDIA {tpu_version}",
                    "published_at": tpu_date,
                })

            resolved_size = (
                primary_entry["file_size"]
                or tpu_top.get("file_size")
                or self._probe_file_size(primary_entry["official_url"], OFFICIAL_URLS["nvidia"])
            )
            combined_recent = ([newer_hotfix] if newer_hotfix else []) + ajax_entries[:10]
            return {
                "version": version,
                "release_date": release_date,
                "channel": primary_entry["channel"],
                "file_size": resolved_size,
                "sha256": tpu_top.get("sha256"),
                "hotfix_available": newer_hotfix,
                "date_delta_days": _date_delta_days(release_date, tpu_date) if tpu_version == version else None,
                "source_url": primary_entry["source_url"],
                "source_name": "NVIDIA",
                "official_url": primary_entry["official_url"],
                "release_notes_url": notes_url,
                "verified": True,
                "primary_verified": True,
                "evidence": evidence,
                "release_notes": {"url": notes_url, "text": notes_text, "structured": structured},
                "recent_releases": combined_recent[:10],
                "error": None,
            }

        if not tpu_version:
            raise ValueError(f"NVIDIA sources unavailable ({tpu_err})")
        return self._finish_tpu_driver("nvidia", tpu_url, tpu_version, tpu_date, tpu_entries)

    def _try_tpu_entries(self, vendor: str) -> tuple[str | None, str | None, list[dict[str, Any]]]:
        tpu_url = TECHPOWERUP_URLS[vendor]
        try:
            soup = self._get_soup(tpu_url)
            title = _safe_text(soup.title.get_text(" ", strip=True) if soup.title else "")
            match = VERSION_PATTERNS[vendor].search(title)
            tpu_ver = match.group(1) if match else None
            if tpu_ver and vendor == "intel" and tpu_ver.count(".") == 1:
                tpu_ver = f"32.0.{tpu_ver}"
            entries = _extract_tpu_entries(soup, vendor, limit=10)
            if not tpu_ver and entries:
                tpu_ver = entries[0]["version"]
            tpu_date = entries[0]["release_date"] if entries else None
            return tpu_ver, tpu_date, entries
        except Exception as exc:
            LOGGER.info("Optional TechPowerUp check skipped for %s: %s", vendor, exc)
            return None, None, []

    def _get_amd_release(self) -> dict[str, Any]:
        tpu_url = TECHPOWERUP_URLS["amd"]
        try:
            page_resp = self.session.get(AMD_DRIVER_PAGE_URL, timeout=REQUEST_TIMEOUT)
            page_resp.raise_for_status()
            html = page_resp.text
            rev_match = re.search(
                r"Adrenalin\s+(\d{2}\.\d{1,2}\.\d{1,2})\s+([^<\n]{0,40})",
                html,
                re.I,
            )
            if not rev_match:
                raise ValueError("AMD official version not found on driver page")
            version = rev_match.group(1)
            raw_chan = _safe_text(rev_match.group(2), 40)
            channel = (
                "WHQL Optional"
                if "optional" in raw_chan.casefold()
                else "Beta"
                if "beta" in raw_chan.casefold()
                else "WHQL"
            )
            section_html = html[rev_match.start() : rev_match.start() + 1200]
            date_match = re.search(
                r"Release Date\s*(?:<[^>]+>\s*)*(20\d{2}-\d{2}-\d{2})", section_html, re.I
            ) or re.search(r"Release Date\s*(?:<[^>]+>\s*)*(20\d{2}-\d{2}-\d{2})", html, re.I)
            release_date = date_match.group(1) if date_match else None
            size_match = re.search(
                r"File Size\s*(?:<[^>]+>\s*)*(\d+(?:\.\d+)?\s*(?:GB|MB))", section_html, re.I
            )
            file_size = size_match.group(1) if size_match else None
            exe_match = re.search(
                r"https://drivers\.amd\.com/drivers/whql-amd-software-adrenalin-edition-[^\s\"'<>]+\.exe",
                html,
                re.I,
            )
            download_url = exe_match.group(0) if exe_match else OFFICIAL_URLS["amd"]

            official_evidence = self._verify_official_release("amd", version)
            release_notes = official_evidence.pop("release_notes", None)
            notes_url = (release_notes or {}).get("url") or official_evidence["url"]
            official_evidence["title"] = f"AMD Software: Adrenalin Edition {version} ({channel})"
            official_evidence["published_at"] = release_date

            evidence: list[dict[str, Any]] = [official_evidence]
            tpu_ver, tpu_date, tpu_entries = self._try_tpu_entries("amd")
            tpu_top = next((e for e in tpu_entries if e["version"] == version), tpu_entries[0] if tpu_entries else {})
            if tpu_ver:
                evidence.append({
                    "version": tpu_ver,
                    "url": tpu_url,
                    "source_name": "TechPowerUp",
                    "publisher": "TechPowerUp",
                    "tier": "specialist",
                    "weight": 0.8,
                    "title": tpu_top.get("title") or f"TechPowerUp AMD {tpu_ver}",
                    "published_at": tpu_date,
                })

            recent_releases = [
                {
                    "version": entry["version"],
                    "release_date": entry["release_date"],
                    "channel": entry.get("channel"),
                    "file_size": entry.get("file_size"),
                    "sha256": entry.get("sha256"),
                    "release_notes_url": (
                        f"https://www.amd.com/en/resources/support-articles/release-notes/"
                        f"RN-RAD-WIN-{entry['version'].replace('.', '-')}.html"
                    ),
                }
                for entry in tpu_entries[:10]
            ] or [
                {
                    "version": version,
                    "release_date": release_date,
                    "channel": channel,
                    "file_size": file_size,
                    "official_url": download_url,
                    "release_notes_url": notes_url,
                }
            ]

            return {
                "version": version,
                "release_date": release_date,
                "channel": channel,
                "file_size": file_size or tpu_top.get("file_size"),
                "sha256": tpu_top.get("sha256"),
                "date_delta_days": _date_delta_days(release_date, tpu_date) if tpu_ver == version else None,
                "source_url": notes_url,
                "source_name": "AMD",
                "official_url": download_url,
                "release_notes_url": notes_url,
                "verified": True,
                "primary_verified": True,
                "evidence": evidence,
                "release_notes": release_notes,
                "recent_releases": recent_releases,
                "error": None,
            }
        except Exception as exc:
            LOGGER.info("AMD official driver-page fallback to TPU: %s", exc)
            return self._get_tpu_driver("amd")

    def _get_intel_release(self) -> dict[str, Any]:
        tpu_url = TECHPOWERUP_URLS["intel"]
        try:
            response = self.session.get(
                INTEL_CN_DOWNLOAD_URL, headers={"User-Agent": "Mozilla/5.0"}, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            meta_ver = soup.find("meta", attrs={"name": "DownloadVersion"})
            if not meta_ver or not meta_ver.get("content"):
                raise ValueError("Intel official DownloadVersion meta tag absent")

            ver_match = re.search(r"32\.0\.101\.\d{4}", str(meta_ver.get("content")))
            if not ver_match:
                raise ValueError("Intel official version missing in meta tag")
            version = ver_match.group(0)
            channel = "WHQL" if "whql" in str(meta_ver.get("content")).lower() else "Beta / Non-WHQL"
            meta_date = soup.find("meta", attrs={"name": "LastUpdate"}) or soup.find(
                "meta", attrs={"name": "lastModifieddate"}
            )
            release_date = _iso_date(meta_date.get("content")) if meta_date and meta_date.get("content") else None

            short_version = version.removeprefix("32.0.")
            notes_match = re.search(
                rf'https://downloadmirror\.intel\.com/\d+/ReleaseNotes_{re.escape(short_version)}_[^"\s<>]+\.pdf',
                response.text,
                re.I,
            )
            notes_url = notes_match.group(0) if notes_match else INTEL_CN_DOWNLOAD_URL
            notes_text = ""
            structured: dict[str, list[str]] = {"highlights": [], "fixed_issues": [], "known_issues": []}
            if notes_match:
                try:
                    notes_response = self.session.get(notes_url, timeout=REQUEST_TIMEOUT)
                    notes_response.raise_for_status()
                    notes_text = _extract_pdf_text(notes_response.content)
                    structured = parse_release_notes_sections(notes_text, vendor="intel")
                except Exception as exc:
                    LOGGER.warning("Intel release notes PDF fetch failed: %s", type(exc).__name__)

            recent_releases: list[dict[str, Any]] = []
            for opt in soup.find_all("option"):
                opt_val = str(opt.get("value") or "")
                if "download/785597" not in opt_val:
                    continue
                opt_text = _safe_text(opt.get_text(" ", strip=True), 80)
                opt_ver_m = re.search(r"32\.0\.101\.\d{4}", opt_text)
                if not opt_ver_m:
                    continue
                opt_ver = opt_ver_m.group(0)
                opt_chan = "WHQL" if "whql" in opt_text.lower() else "Non-WHQL"
                opt_url = opt_val if opt_val.startswith("http") else f"https://www.intel.cn{opt_val}"
                recent_releases.append({
                    "version": opt_ver,
                    "channel": opt_chan,
                    "official_url": opt_url,
                })

            evidence: list[dict[str, Any]] = [
                {
                    "version": version,
                    "url": INTEL_CN_DOWNLOAD_URL,
                    "source_name": "Intel",
                    "publisher": "Intel",
                    "tier": "primary",
                    "weight": 1.0,
                    "title": f"Intel Graphics Driver {version} ({channel})",
                    "published_at": release_date,
                }
            ]
            tpu_ver, tpu_date, tpu_entries = self._try_tpu_entries("intel")
            tpu_top = next((e for e in tpu_entries if e["version"] == version), tpu_entries[0] if tpu_entries else {})
            if tpu_ver:
                evidence.append({
                    "version": tpu_ver,
                    "url": tpu_url,
                    "source_name": "TechPowerUp",
                    "publisher": "TechPowerUp",
                    "tier": "specialist",
                    "weight": 0.8,
                    "title": tpu_top.get("title") or f"TechPowerUp Intel {tpu_ver}",
                    "published_at": tpu_date,
                })

            exe_match = re.search(
                r'https://downloadmirror\.intel\.com/\d+/[^\s"\'<>]+\.exe',
                response.text,
                re.I,
            )
            exe_url = exe_match.group(0) if exe_match else None
            html_size_match = re.search(
                r"(?:Size|大小)\s*[:：]?\s*(?:<[^>]+>\s*)*(\d+(?:\.\d+)?\s*(?:MB|GB))",
                response.text,
                re.I,
            )
            intel_file_size = (
                tpu_top.get("file_size")
                or (html_size_match.group(1) if html_size_match else None)
                or self._probe_file_size(exe_url, INTEL_CN_DOWNLOAD_URL)
            )
            sha_match = re.search(r"SHA256\s*[:：]?\s*([A-Fa-f0-9]{64})", response.text)
            intel_sha256 = tpu_top.get("sha256") or (sha_match.group(1).lower() if sha_match else None)

            return {
                "version": version,
                "release_date": release_date,
                "channel": channel,
                "file_size": intel_file_size,
                "sha256": intel_sha256,
                "date_delta_days": _date_delta_days(release_date, tpu_date) if tpu_ver == version else None,
                "source_url": INTEL_CN_DOWNLOAD_URL,
                "source_name": "Intel",
                "official_url": exe_url or INTEL_CN_DOWNLOAD_URL,
                "release_notes_url": notes_url,
                "verified": True,
                "primary_verified": True,
                "evidence": evidence,
                "release_notes": {"url": notes_url, "text": notes_text, "structured": structured},
                "recent_releases": recent_releases[:12],
                "error": None,
            }
        except Exception as exc:
            LOGGER.info("Intel official page fallback to TPU: %s", exc)
            return self._get_tpu_driver("intel")

    def _finish_tpu_driver(
        self,
        vendor: str,
        tpu_url: str,
        tpu_version: str,
        tpu_date: str | None,
        tpu_entries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        top_tpu = tpu_entries[0] if tpu_entries else {}
        version = tpu_version
        release_date = tpu_date
        channel = top_tpu.get("channel")
        file_size = top_tpu.get("file_size")
        sha256 = top_tpu.get("sha256")

        evidence: list[dict[str, Any]] = [
            {
                "version": tpu_version,
                "url": tpu_url,
                "source_name": "TechPowerUp",
                "publisher": "TechPowerUp",
                "tier": "specialist",
                "weight": 0.8,
                "title": top_tpu.get("title") or f"TechPowerUp {vendor.upper()} {tpu_version}",
                "published_at": tpu_date,
            }
        ]
        release_notes = None
        release_notes_url = None
        source_url = tpu_url
        source_name = "TechPowerUp"
        official_url = OFFICIAL_URLS[vendor]
        primary_verified = False
        date_delta_days = None

        try:
            official_evidence = self._verify_official_release(vendor, tpu_version)
            release_notes = official_evidence.pop("release_notes", None)
            official_date = official_evidence.pop("release_date", None)
            official_channel = official_evidence.pop("channel", None)
            if official_evidence["version"] != tpu_version:
                # Never pair an official version with a mismatched TPU date.
                version = official_evidence["version"]
                release_date = official_date
                file_size = None
                sha256 = None
            else:
                date_delta_days = _date_delta_days(official_date, tpu_date)
                release_date = official_date or tpu_date
            if official_channel:
                channel = official_channel
            release_notes_url = (release_notes or {}).get("url") or official_evidence["url"]
            source_url = official_evidence["url"]
            source_name = official_evidence["source_name"]
            official_url = official_evidence.pop("official_url", OFFICIAL_URLS[vendor])
            evidence.append(official_evidence)
            primary_verified = True
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("%s official verification failed: %s", vendor, exc)

        recent_releases = []
        for entry in tpu_entries[:10]:
            rn_url = None
            if vendor == "amd":
                rn_url = f"https://www.amd.com/en/resources/support-articles/release-notes/RN-RAD-WIN-{entry['version'].replace('.', '-')}.html"
            recent_releases.append({
                "version": entry["version"],
                "release_date": entry["release_date"],
                "channel": entry.get("channel"),
                "file_size": entry.get("file_size"),
                "sha256": entry.get("sha256"),
                "release_notes_url": rn_url,
            })

        return {
            "version": version,
            "release_date": release_date,
            "channel": channel,
            "file_size": file_size,
            "sha256": sha256,
            "date_delta_days": date_delta_days,
            "source_url": source_url,
            "source_name": source_name,
            "official_url": official_url,
            "release_notes_url": release_notes_url,
            "verified": True,
            "primary_verified": primary_verified,
            "evidence": evidence,
            "release_notes": release_notes,
            "recent_releases": recent_releases,
            "error": None,
        }

    def get_driver_release(self, vendor: str) -> dict[str, Any]:
        """Return the current release verified against official manufacturer artifacts."""
        if vendor not in TECHPOWERUP_URLS:
            raise ValueError(f"Unsupported vendor: {vendor}")
        if vendor == "nvidia":
            return self._get_nvidia_release()
        if vendor == "amd":
            return self._get_amd_release()
        if vendor == "intel":
            return self._get_intel_release()
        return self._get_tpu_driver(vendor)

    def _get_tpu_driver(self, vendor: str) -> dict[str, Any]:
        source_url = TECHPOWERUP_URLS[vendor]
        soup = self._get_soup(source_url)
        title = _safe_text(soup.title.get_text(" ", strip=True) if soup.title else "")
        match = VERSION_PATTERNS[vendor].search(title)
        if not match:
            raise ValueError(f"Version not found in {vendor} source title")

        displayed_version = match.group(1)
        version = (
            f"32.0.{displayed_version}"
            if vendor == "intel" and displayed_version.count(".") == 1
            else displayed_version
        )
        tpu_entries = _extract_tpu_entries(soup, vendor, limit=10)
        release_date = None
        release_node = next(
            (
                heading.find_parent("div", class_="version")
                for heading in soup.find_all("h3")
                if displayed_version in heading.get_text(" ", strip=True)
            ),
            None,
        )
        if release_node:
            date_node = release_node.find(class_="date")
            if date_node:
                release_date = _iso_date(date_node.get_text(" ", strip=True))
        if not release_date and tpu_entries:
            release_date = tpu_entries[0].get("release_date")

        return self._finish_tpu_driver(vendor, source_url, version, release_date, tpu_entries)

    @staticmethod
    def _format_windows_channel(update_type: str | None, win_ver: str | None) -> str:
        ut = str(update_type or "").strip()
        suffix = f" · Win11 {win_ver}" if win_ver else ""
        if ut.upper().endswith("D") or ut.upper().endswith("C") or "preview" in ut.casefold():
            return f"Preview opcional (D){suffix}"
        if ut.upper().endswith("B"):
            return f"Patch Tuesday (B){suffix}"
        if "oob" in ut.casefold() or "out-of-band" in ut.casefold():
            return f"Out-of-Band{suffix}"
        return f"{ut or 'General Availability'}{suffix}"

    def get_windows_release(self) -> dict[str, Any]:
        """Read the current General Availability Channel Windows 11 release and history."""
        source_url = OFFICIAL_URLS["windows"]
        soup = self._get_soup(source_url)

        branch_by_build: dict[str, str] = {}
        recent_releases: list[dict[str, Any]] = []
        sibling_versions: list[str] = []
        seen_kbs: set[str] = set()
        current: dict[str, Any] | None = None

        for row in soup.find_all("tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.find_all(["th", "td"])]
            row_text = " | ".join(cells)
            if "General Availability Channel" not in row_text:
                continue
            kb_match = re.search(r"\b(KB\d{7})\b", row_text)
            date_match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", row_text)
            if not kb_match or not date_match:
                continue
            kb = kb_match.group(1)
            rel_date = date_match.group(1)
            build_match = re.search(r"\b(2[4-9]\d{3}\.\d+)\b", row_text)
            os_build = build_match.group(1) if build_match else None
            win_ver_match = re.match(r"^(2[3-9]H[12])\b", cells[0] if cells else "")
            win_ver = win_ver_match.group(1) if win_ver_match else None
            if win_ver and os_build:
                branch_by_build[os_build.split(".")[0]] = win_ver
            if not win_ver and os_build:
                win_ver = branch_by_build.get(os_build.split(".")[0])
            update_type = next((c for c in cells if re.match(r"^20\d{2}-\d{2}\s+[A-Z0-9]+", c)), None)
            channel = self._format_windows_channel(update_type, win_ver)
            link_node = row.find("a", string=re.compile(kb, re.I))
            kb_url = link_node.get("href", source_url) if link_node else f"https://support.microsoft.com/help/{kb.removeprefix('KB')}"

            if current is None:
                current = {
                    "version": kb,
                    "release_date": rel_date,
                    "os_build": os_build,
                    "windows_version": win_ver,
                    "channel": channel,
                    "official_url": kb_url,
                }
            elif win_ver and kb != current["version"] and kb not in sibling_versions:
                # Track other active GA servicing branches (e.g. 26H1 KB5132265) so they are not flagged as newer conflicts.
                sibling_versions.append(kb)
            if kb not in seen_kbs:
                seen_kbs.add(kb)
                recent_releases.append({
                    "version": kb,
                    "release_date": rel_date,
                    "os_build": os_build,
                    "channel": channel,
                    "official_url": kb_url,
                    "release_notes_url": kb_url,
                })
                if len(recent_releases) >= 15:
                    break

        if current is None:
            raise ValueError("Current Windows GA update row not found")

        notes_url = current["official_url"]
        notes_text = ""
        structured: dict[str, list[str]] = {"highlights": [], "fixed_issues": [], "known_issues": []}
        try:
            notes_response = self.session.get(notes_url, timeout=REQUEST_TIMEOUT)
            notes_response.raise_for_status()
            notes_text = _extract_page_text(notes_response.text)
            structured = parse_release_notes_sections(notes_text, vendor="windows", html=notes_response.text)
        except Exception as exc:
            LOGGER.warning("Windows release notes fetch failed: %s", type(exc).__name__)

        return {
            "version": current["version"],
            "release_date": current["release_date"],
            "channel": current["channel"],
            "os_build": current["os_build"],
            "windows_version": current["windows_version"],
            "sibling_versions": sibling_versions,
            "file_size": None,
            "sha256": None,
            "date_delta_days": None,
            "source_url": source_url,
            "source_name": "Microsoft Release Health",
            "official_url": notes_url,
            "release_notes_url": notes_url,
            "verified": True,
            "primary_verified": True,
            "evidence": [
                {
                    "version": current["version"],
                    "url": source_url,
                    "source_name": "Microsoft Release Health",
                    "publisher": "Microsoft",
                    "tier": "primary",
                    "weight": 1.0,
                    "title": f"Microsoft Windows 11 {current['version']} ({current['channel']})",
                    "published_at": current["release_date"],
                }
            ],
            "release_notes": {"url": notes_url, "text": notes_text, "structured": structured},
            "recent_releases": recent_releases,
            "error": None,
        }

    def fetch_historical_release_notes(
        self, vendor: str, version: str, release_notes_url: str | None = None
    ) -> dict[str, Any] | None:
        """Fetch official release notes and metadata for a past driver/OS version."""
        try:
            if vendor == "nvidia":
                ajax_entries = self._fetch_nvidia_ajax()
                match = next((e for e in ajax_entries if e["version"] == version), None)
                preferred = release_notes_url or (match.get("release_notes_url") if match else None)
                pdf_res = self._fetch_nvidia_pdf(version, preferred)
                if not pdf_res:
                    return None
                url, text, structured = pdf_res
                return {
                    "url": url,
                    "text": text,
                    "structured": structured,
                    "channel": match.get("channel") if match else "WHQL",
                    "file_size": match.get("file_size") if match else None,
                    "official_url": match.get("official_url") if match else None,
                }

            if vendor == "amd":
                slug = version.replace(".", "-")
                url = release_notes_url or f"https://www.amd.com/en/resources/support-articles/release-notes/RN-RAD-WIN-{slug}.html"
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                text = _extract_page_text(response.text)
                structured = parse_release_notes_sections(text, vendor="amd", html=response.text)
                return {"url": url, "text": text, "structured": structured}

            if vendor == "intel":
                short_version = version.removeprefix("32.0.")
                if release_notes_url and release_notes_url.lower().endswith(".pdf"):
                    resp = self.session.get(release_notes_url, timeout=REQUEST_TIMEOUT)
                    resp.raise_for_status()
                    text = _extract_pdf_text(resp.content)
                    return {
                        "url": release_notes_url,
                        "text": text,
                        "structured": parse_release_notes_sections(text, vendor="intel"),
                    }
                # Discover exact page from Intel CN dropdown options.
                main_resp = self.session.get(
                    INTEL_CN_DOWNLOAD_URL, headers={"User-Agent": "Mozilla/5.0"}, timeout=REQUEST_TIMEOUT
                )
                main_resp.raise_for_status()
                soup = BeautifulSoup(main_resp.text, "html.parser")
                target_url = INTEL_CN_DOWNLOAD_URL
                for opt in soup.find_all("option"):
                    if version in opt.get_text(" ", strip=True) and opt.get("value"):
                        val = str(opt["value"])
                        target_url = val if val.startswith("http") else f"https://www.intel.cn{val}"
                        break
                page_resp = (
                    main_resp
                    if target_url == INTEL_CN_DOWNLOAD_URL
                    else self.session.get(target_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=REQUEST_TIMEOUT)
                )
                page_resp.raise_for_status()
                pdf_match = re.search(
                    rf'https://downloadmirror\.intel\.com/\d+/ReleaseNotes_{re.escape(short_version)}_[^"\s<>]+\.pdf',
                    page_resp.text,
                    re.I,
                )
                if not pdf_match:
                    return None
                pdf_url = pdf_match.group(0)
                pdf_resp = self.session.get(pdf_url, timeout=REQUEST_TIMEOUT)
                pdf_resp.raise_for_status()
                text = _extract_pdf_text(pdf_resp.content)
                return {
                    "url": pdf_url,
                    "text": text,
                    "structured": parse_release_notes_sections(text, vendor="intel"),
                    "official_url": target_url,
                }

            if vendor == "windows":
                kb_num = version.upper().removeprefix("KB")
                url = release_notes_url or f"https://support.microsoft.com/help/{kb_num}"
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                text = _extract_page_text(response.text)
                structured = parse_release_notes_sections(text, vendor="windows", html=response.text)
                return {"url": url, "text": text, "structured": structured, "official_url": url}
        except Exception as exc:
            LOGGER.warning("Historical release notes fetch failed (%s %s): %s", vendor, version, exc)
        return None

    def get_release(self, vendor: str) -> dict[str, Any]:
        try:
            return self.get_windows_release() if vendor == "windows" else self.get_driver_release(vendor)
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("%s release fetch failed: %s", vendor, exc)
            return {
                "version": None,
                "release_date": None,
                "channel": None,
                "os_build": None,
                "file_size": None,
                "sha256": None,
                "date_delta_days": None,
                "source_url": OFFICIAL_URLS.get(vendor, ""),
                "source_name": "Fonte indisponível",
                "official_url": OFFICIAL_URLS.get(vendor, ""),
                "release_notes_url": None,
                "verified": False,
                "primary_verified": False,
                "evidence": [],
                "release_notes": None,
                "recent_releases": [],
                "error": _safe_text(exc, 160),
            }

    def get_cybersecurity_alerts(self) -> list[dict[str, Any]]:
        """Return relevant recent feed entries; never claim exhaustive coverage."""
        feed_url = "https://www.bleepingcomputer.com/feed/"
        try:
            response = self.session.get(feed_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
        except requests.RequestException as exc:
            LOGGER.warning("Security feed fetch failed: %s", exc)
            return []

        alerts = []
        for entry in feed.entries[:20]:
            title = _safe_text(entry.get("title"))
            if not any(term in title.lower() for term in SECURITY_TERMS):
                continue
            published = None
            raw_published = entry.get("published") or entry.get("updated")
            if raw_published:
                try:
                    published = parsedate_to_datetime(raw_published).astimezone(timezone.utc).isoformat()
                except (TypeError, ValueError, OverflowError):
                    pass
            alerts.append(
                {
                    "title": title,
                    "link": _safe_text(entry.get("link"), 500),
                    "source": "BleepingComputer",
                    "published_at": published,
                }
            )
            if len(alerts) == 5:
                break
        return alerts

    # Compatibility helpers used by maintenance scripts.
    def get_latest_nvidia_driver(self, analyze: bool = False):
        release = self.get_release("nvidia")
        return release["version"], release["official_url"]

    def get_latest_amd_driver(self, analyze: bool = False):
        release = self.get_release("amd")
        return release["version"], release["official_url"]

    def get_latest_intel_driver(self, analyze: bool = False):
        release = self.get_release("intel")
        return release["version"], release["official_url"]

    def get_latest_windows_update(self):
        release = self.get_release("windows")
        return release["version"], release["official_url"], release["release_date"]

    def get_community_feedback(self, subject: str, version: str | None, **_: Any):
        """Compatibility response without fabricated community sentiment."""
        return {
            "version": version,
            "status": "Sem dados suficientes",
            "sentiment": "Indeterminado",
            "pros": [],
            "cons": [],
            "source": "Nenhuma amostra comunitária verificável",
            "evidence_level": "none",
        }


if __name__ == "__main__":
    monitor = UpdateMonitor()
    for name in ("nvidia", "amd", "intel", "windows"):
        print(name, monitor.get_release(name))
