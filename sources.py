"""Trusted-source registry and cross-source audit engine."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import requests
from bs4 import BeautifulSoup

LOGGER = logging.getLogger(__name__)
MAX_SOURCE_BYTES = 1_500_000
SOURCE_TIMEOUT = (4, 10)
MAX_SOURCE_SECONDS = 25
MAX_AUDIT_SECONDS = 90
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

ECOSYSTEM_TARGETS = (
    "nvidia",
    "geforce",
    "amd",
    "radeon",
    "adrenalin",
    "intel arc",
    "intel graphics",
    "windows 11",
    "windows 10",
    "windows update",
    "patch tuesday",
    "gpu driver",
    "graphics driver",
    "directx",
    "vulkan",
)
SECURITY_SIGNAL_RE = re.compile(
    r"(?:\bcve-\d|\bvulnerab|\bflaw\b|\bzero-day\b|\b0-day\b|\bexploit|"
    r"\bsecurity\b|\badvisory\b|\bbug\b|\bcrash|\bbsod\b|\bhotfix\b|"
    r"\bregression\b|\bout-of-band\b|\bcritical\b|\brce\b|\bremote code execution\b|"
    r"\bprivilege\b|\bbypass|\bwear(?:ing)? out\b|\bthrash|\bcorrupt|"
    r"\bknown issue|\bemergency\b|\bpatch tuesday\b)",
    re.I,
)
SEVERITY_CRITICAL_RE = re.compile(
    r"\b(?:zero-day|0-day|actively exploited|emergency|out-of-band|rce|"
    r"remote code execution|killing your ssd|thrash ssds?|wearing out)\b",
    re.I,
)
SEVERITY_HIGH_RE = re.compile(
    r"(?:\bcve-\d|\bvulnerab|\bprivilege|\badvisory|\bsecurity flaw|"
    r"\barbitrary code|\bbypass(?:es|ing)?\b|\bflaw\b|\bbitlocker\b)",
    re.I,
)
SEVERITY_MEDIUM_RE = re.compile(
    r"\b(?:bsod|crash|bug|regression|hotfix|known issue|broken)\b",
    re.I,
)
NON_TECHNICAL_GOSSIP_RE = re.compile(
    r"\b(?:ceo|scandal|stock|stocks|shares|earnings|valuation|market cap|"
    r"antitrust|lawsuit|black friday|cyber monday|deals?|savings|discount|"
    r"geforce now|for just \$|xbox speed)\b",
    re.I,
)
WINDOWS_NON_CONFLICT_BRANCH_RE = re.compile(
    r"\b(?:26H1|25H2|24H2|23H2|22H2|Windows 10|Windows Server|LTSC|Insider|Dev Channel|Canary|Beta Channel|Release Preview)\b",
    re.I,
)

VENDOR_CONTEXT = {
    "nvidia": ("nvidia", "geforce", "rtx", "gtx", "game ready", "studio driver", "dlss"),
    "amd": ("amd", "radeon", "adrenalin", "fsr", "rx"),
    "intel": ("intel", "arc", "core ultra", "xe graphics", "iris xe"),
    "windows": ("windows 11", "windows 10", "windows update", "windows hello", "bitlocker", "patch tuesday", "microsoft", "kb5"),
}
VENDOR_CONTEXT_REGEX = {
    vendor: re.compile(
        r"(?:" + "|".join(rf"\b{re.escape(term)}\b" if len(term) <= 4 else rf"\b{re.escape(term)}" for term in terms) + r")",
        re.I,
    )
    for vendor, terms in VENDOR_CONTEXT.items()
}
DRIVER_UPDATE_CONTEXT = (
    "driver",
    "whql",
    "hotfix",
    "geforce",
    "adrenalin",
    "radeon",
    "arc",
    "patch",
    "update",
    "release",
    "build",
    "kb5",
)
CONFLICT_VERSION_PATTERNS = {
    "nvidia": re.compile(r"\b([56]\d{2}\.\d{2})\b"),
    "amd": re.compile(r"\b(2[4-9]\.(?:[1-9]|1[0-2])\.\d{1,2})\b"),
    "intel": re.compile(r"\b((?:32\.0\.)?101\.\d{4})\b"),
    "windows": re.compile(r"\b(KB5\d{6})\b", re.I),
}

SECURITY_TERMS = (
    "gpu",
    "graphics driver",
    "nvidia",
    "geforce",
    "amd",
    "radeon",
    "intel arc",
    "windows 11",
    "windows update",
    "cve-",
)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    publisher: str
    url: str
    tier: str
    weight: float
    kind: str = "feed"


# Sources are independent publishers where possible. Community networks and social
# profiles are deliberately excluded from the deterministic confidence score.
SOURCES = (
    Source("cisa-kev", "CISA Known Exploited Vulnerabilities", "CISA", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "authority", 1.0, "cisa"),
    Source("cisa-advisories", "CISA Cybersecurity Advisories", "CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "authority", 1.0),
    Source("nvd", "National Vulnerability Database", "NIST", "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=graphics%20driver&resultsPerPage=100", "authority", 1.0, "json"),
    Source("cert-cc", "CERT/CC Vulnerability Notes", "CERT/CC", "https://kb.cert.org/vuls/atomfeed/", "authority", 0.95),
    Source("msrc", "Microsoft Security Response Center", "Microsoft", "https://msrc.microsoft.com/blog/feed", "primary", 1.0),
    Source("msrc-cvrf", "Microsoft Security Update Guide", "Microsoft", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "primary", 1.0, "msrc-json"),
    Source("microsoft-security-blog", "Microsoft Security Blog", "Microsoft", "https://www.microsoft.com/en-us/security/blog/feed/", "primary", 0.95),
    Source("windows-release-health", "Windows Release Health", "Microsoft", "https://learn.microsoft.com/en-us/windows/release-health/", "primary", 1.0, "page"),
    Source("nvidia-blog", "NVIDIA Technical Blog", "NVIDIA", "https://blogs.nvidia.com/feed/", "primary", 0.95),
    Source("nvidia-security", "NVIDIA Security Bulletins", "NVIDIA", "https://www.nvidia.com/en-us/security/", "primary", 1.0, "page"),
    Source("amd-security", "AMD Product Security", "AMD", "https://www.amd.com/en/resources/product-security.html", "primary", 1.0, "page"),
    Source("google-security", "Google Security Blog", "Google", "https://security.googleblog.com/feeds/posts/default", "research", 0.9),
    Source("bleepingcomputer", "BleepingComputer", "BleepingComputer", "https://www.bleepingcomputer.com/feed/", "established", 0.8),
    Source("securityweek", "SecurityWeek", "SecurityWeek", "https://www.securityweek.com/feed/", "established", 0.8),
    Source("hacker-news", "The Hacker News", "The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "established", 0.78),
    Source("dark-reading", "Dark Reading", "Dark Reading", "https://www.darkreading.com/rss.xml", "established", 0.8),
    Source("krebs", "Krebs on Security", "Krebs on Security", "https://krebsonsecurity.com/feed/", "established", 0.85),
    Source("sans-isc", "SANS Internet Storm Center", "SANS", "https://isc.sans.edu/rssfeed.xml", "research", 0.88),
    Source("cisco-talos", "Cisco Talos", "Cisco Talos", "https://blog.talosintelligence.com/rss/", "research", 0.88),
    Source("unit42", "Palo Alto Unit 42", "Palo Alto Networks", "https://unit42.paloaltonetworks.com/feed/", "research", 0.88),
    Source("rapid7", "Rapid7 Research", "Rapid7", "https://www.rapid7.com/blog/rss/", "research", 0.85),
    Source("tenable", "Tenable Research", "Tenable", "https://www.tenable.com/blog", "research", 0.85, "page"),
    Source("welivesecurity", "ESET WeLiveSecurity", "ESET", "https://www.welivesecurity.com/en/rss/feed/", "research", 0.82),
    Source("malwarebytes", "Malwarebytes Labs", "Malwarebytes", "https://www.malwarebytes.com/blog/feed/index.xml", "research", 0.82),
    Source("trendmicro", "Trend Micro Research", "Trend Micro", "https://www.trendmicro.com/en_us/research.html", "research", 0.82, "page"),
    Source("sentinelone", "SentinelLabs", "SentinelOne", "https://www.sentinelone.com/labs/feed/", "research", 0.82),
    Source("fortinet", "Fortinet Threat Research", "Fortinet", "https://www.fortinet.com/blog/threat-research", "research", 0.8, "page"),
    Source("checkpoint", "Check Point Research", "Check Point", "https://research.checkpoint.com/feed/", "research", 0.82),
    Source("securelist", "Securelist", "Kaspersky", "https://securelist.com/feed/", "research", 0.82),
    Source("bitdefender", "Bitdefender Labs", "Bitdefender", "https://www.bitdefender.com/en-us/blog/labs/", "research", 0.8, "page"),
    Source("elastic", "Elastic Security Labs", "Elastic", "https://www.elastic.co/security-labs/rss/feed.xml", "research", 0.82),
    Source("techpowerup", "TechPowerUp News", "TechPowerUp", "https://www.techpowerup.com/rss/news", "specialist", 0.8),
    Source("tomshardware", "Tom's Hardware", "Tom's Hardware", "https://www.tomshardware.com/feeds/all", "established", 0.78),
    Source("windowscentral", "Windows Central", "Windows Central", "https://www.windowscentral.com/feeds.xml", "specialist", 0.76),
    Source("windowslatest", "Windows Latest", "Windows Latest", "https://www.windowslatest.com/feed/", "specialist", 0.78),
    Source("pureinfotech", "Pureinfotech", "Pureinfotech", "https://pureinfotech.com/feed/", "specialist", 0.76),
    Source("askwoody", "AskWoody", "AskWoody", "https://www.askwoody.com/feed/", "specialist", 0.76),
    Source("winaero", "Winaero", "Winaero", "https://winaero.com/feed/", "specialist", 0.74),
    Source("neowin", "Neowin", "Neowin", "https://www.neowin.net/news/rss/", "specialist", 0.74),
    Source("pcgamer", "PC Gamer Hardware", "PC Gamer", "https://www.pcgamer.com/rss/", "established", 0.72),
    Source("dsogaming", "DSOGaming", "DSOGaming", "https://www.dsogaming.com/feed/", "specialist", 0.74),
    Source("overclock3d", "Overclock3D", "Overclock3D", "https://overclock3d.net/feed/", "specialist", 0.74),
    Source("ars-security", "Ars Technica Technology Lab", "Ars Technica", "https://feeds.arstechnica.com/arstechnica/technology-lab", "established", 0.82),
    Source("theregister", "The Register Security", "The Register", "https://www.theregister.com/security/headlines.atom", "established", 0.8),
    Source("adrenaline", "Adrenaline", "Adrenaline", "https://www.adrenaline.com.br/feed/", "established", 0.8),
    Source("phoronix", "Phoronix", "Phoronix", "https://www.phoronix.com/rss.php", "specialist", 0.8),
    Source("computerbase", "ComputerBase", "ComputerBase", "https://www.computerbase.de/rss/news.xml", "established", 0.8),
    Source("techspot", "TechSpot", "TechSpot", "https://www.techspot.com/backend.xml", "established", 0.8),
    Source("servethehome", "ServeTheHome", "ServeTheHome", "https://www.servethehome.com/feed/", "specialist", 0.78),
    Source("hothardware", "HotHardware", "HotHardware", "https://hothardware.com/rss/news.aspx", "specialist", 0.76),
    Source("tweaktown", "TweakTown", "TweakTown", "https://www.tweaktown.com/rss/news.xml", "specialist", 0.74),
    Source("club386", "Club386", "Club386", "https://www.club386.com/feed/", "specialist", 0.74),
    Source("heise-security", "heise Security", "Heise", "https://www.heise.de/security/rss/news-atom.xml", "established", 0.82),
    Source("ghacks", "gHacks Technology News", "gHacks", "https://www.ghacks.net/feed/", "specialist", 0.72),
    Source("borncity", "Born's Tech and Windows World", "BornCity", "https://borncity.com/win/feed/", "specialist", 0.72),
    Source("notebookcheck", "NotebookCheck", "NotebookCheck", "https://www.notebookcheck.net/News.152.100.html", "specialist", 0.76),
    Source("techradar", "TechRadar", "TechRadar", "https://www.techradar.com/rss", "established", 0.74),
    # Official social profiles broaden early-signal coverage, never affect score.
    Source("x-nvidia", "NVIDIA GeForce on X", "NVIDIA", "https://x.com/NVIDIAGeForce", "social", 0.35, "page"),
    Source("x-amd", "AMD Radeon on X", "AMD", "https://x.com/AMDRadeon", "social", 0.35, "page"),
    Source("x-intel", "Intel Gaming on X", "Intel", "https://x.com/IntelGaming", "social", 0.35, "page"),
    Source("x-windows", "Windows Update on X", "Microsoft", "https://x.com/WindowsUpdate", "social", 0.35, "page"),
)


def parse_version_tuple(vendor: str | None, version: str | None) -> tuple[int, ...]:
    """Convert a driver or KB version string into a sortable numeric tuple."""
    raw = str(version or "").strip()
    if not raw:
        return (0,)
    if vendor == "windows" or raw.upper().startswith("KB"):
        digits = re.sub(r"\D", "", raw)
        return (int(digits),) if digits else (0,)
    if vendor == "intel" and raw.startswith("101."):
        raw = f"32.0.{raw}"
    parts = re.findall(r"\d+", raw)
    return tuple(int(p) for p in parts) if parts else (0,)


def _parse_datetime(raw: Any) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    try:
        dt = parsedate_to_datetime(text)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        d = date.fromisoformat(text[:10])
        return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    except ValueError:
        return None


def _iso_timestamp(raw: Any) -> str | None:
    dt = _parse_datetime(raw)
    return dt.isoformat() if dt else None


def _infer_vendor(version: str) -> str | None:
    if re.fullmatch(r"KB\d{6,8}", version, re.I):
        return "windows"
    if re.fullmatch(r"(?:32\.0\.)?101\.\d{4}", version):
        return "intel"
    if re.fullmatch(r"\d{2}\.\d{1,2}\.\d{1,2}", version):
        return "amd"
    if re.fullmatch(r"\d{3}\.\d{2}", version):
        return "nvidia"
    return None


def _version_aliases(version: str, vendor: str | None = None) -> list[str]:
    aliases = [version]
    if (vendor == "intel" or version.startswith("32.0.")) and version.startswith("32.0."):
        aliases.append(version.removeprefix("32.0."))
    return aliases


def _version_in_text(version: str, text: str, vendor: str | None = None) -> bool:
    """Require strict numeric/token boundaries and vendor context so substrings never collide."""
    if not version or not text:
        return False
    resolved_vendor = vendor or _infer_vendor(version)
    if resolved_vendor and resolved_vendor in VENDOR_CONTEXT_REGEX:
        if not VENDOR_CONTEXT_REGEX[resolved_vendor].search(text):
            return False
    for alias in _version_aliases(version, resolved_vendor):
        pattern = rf"(?<![0-9A-Za-z.]){re.escape(alias)}(?![0-9A-Za-z.])"
        if re.search(pattern, text, re.I):
            return True
    return False


def _match_vendors(text: str) -> list[str]:
    return [
        vendor
        for vendor, pattern in VENDOR_CONTEXT_REGEX.items()
        if pattern.search(text)
    ]


def _classify_alert_severity(text: str, source: Source) -> str:
    if source.id == "cisa-kev" or SEVERITY_CRITICAL_RE.search(text):
        return "critical"
    if SEVERITY_HIGH_RE.search(text):
        return "high"
    if SEVERITY_MEDIUM_RE.search(text):
        return "medium"
    return "info"


class SourceHub:
    def __init__(self, refresh_ttl: int = 21_600) -> None:
        self.refresh_ttl = refresh_ttl
        self._cache: dict[str, Any] | None = None
        self._cache_time = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _fetch(source: Source, targets: dict[str, str]) -> dict[str, Any]:
        started = time.monotonic()
        response = None
        try:
            response = requests.get(
                source.url,
                headers={"User-Agent": USER_AGENT},
                timeout=SOURCE_TIMEOUT,
                stream=True,
            )
            response.raise_for_status()
            chunks = []
            total = 0
            for chunk in response.iter_content(65_536):
                if time.monotonic() - started > MAX_SOURCE_SECONDS:
                    raise requests.Timeout("source exceeded total time limit")
                if not chunk:
                    continue
                remaining = MAX_SOURCE_BYTES - total
                chunks.append(chunk[:remaining])
                total += len(chunks[-1])
                if total >= MAX_SOURCE_BYTES:
                    break
            body = b"".join(chunks)
            documents = SourceHub._extract_documents(source, body)
            alerts = SourceHub._extract_alerts(source, body)
            matched_versions: dict[str, dict[str, Any]] = {}
            for vendor, version in targets.items():
                if not version:
                    continue
                for doc in documents:
                    haystack = f"{doc.get('title', '')} {doc.get('summary', '')}"
                    if _version_in_text(version, haystack, vendor):
                        matched_versions[version] = {
                            "url": doc.get("url") or source.url,
                            "title": doc.get("title") or source.name,
                            "published_at": doc.get("published_at"),
                        }
                        break

            return {
                "source": source,
                "status": "reachable",
                "http_status": response.status_code,
                "latency_ms": round((time.monotonic() - started) * 1000),
                "matched_versions": matched_versions,
                "alerts": alerts,
                "documents": documents,
                "error": None,
            }
        except requests.RequestException as exc:
            return {
                "source": source,
                "status": "unavailable",
                "http_status": getattr(exc.response, "status_code", None),
                "latency_ms": round((time.monotonic() - started) * 1000),
                "matched_versions": {},
                "alerts": [],
                "documents": [],
                "error": str(exc)[:180],
            }
        finally:
            if response is not None:
                response.close()

    @staticmethod
    def _is_relevant_alert(title: str, summary: str) -> bool:
        title_low = title.casefold()
        combined = f"{title} {summary}"
        combined_low = combined.casefold()
        if NON_TECHNICAL_GOSSIP_RE.search(title_low) and not re.search(
            r"(?:\bcve-\d|\bvulnerab|\bflaw\b|\bhotfix\b|\bbug\b)", title_low
        ):
            return False
        has_target = bool(_match_vendors(combined)) or any(
            t in combined_low for t in ("gpu driver", "graphics driver", "directx", "vulkan")
        )
        has_signal = bool(SECURITY_SIGNAL_RE.search(combined))
        return has_target and has_signal

    @staticmethod
    def _extract_alerts(source: Source, body: bytes) -> list[dict[str, Any]]:
        if source.kind in {"page", "json", "msrc-json"}:
            return []
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=60 if source.kind == "cisa" else 45)

        if source.kind == "cisa":
            try:
                data = json.loads(body)
                alerts = []
                for item in data.get("vulnerabilities", []):
                    title = SourceHub._clean_document_text(item.get("vulnerabilityName"), 220)
                    summary = SourceHub._clean_document_text(item.get("shortDescription"), 240)
                    vendor_proj = f"{item.get('vendorProject', '')} {item.get('product', '')}"
                    combined = f"{vendor_proj} {title} {summary}"
                    if not SourceHub._is_relevant_alert(combined, summary):
                        continue
                    pub_dt = _parse_datetime(item.get("dateAdded"))
                    if pub_dt and pub_dt < cutoff_dt:
                        continue
                    vendors = _match_vendors(combined)
                    alerts.append({
                        "title": title,
                        "summary": summary,
                        "link": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}",
                        "source": source.name,
                        "published_at": pub_dt.isoformat() if pub_dt else item.get("dateAdded"),
                        "vendors": vendors,
                        "severity": "critical",
                    })
                return alerts[:5]
            except (json.JSONDecodeError, TypeError):
                return []

        feed = feedparser.parse(body)
        alerts = []
        for entry in feed.entries[:25]:
            title = SourceHub._clean_document_text(entry.get("title"), 240)
            summary = SourceHub._clean_document_text(entry.get("summary"), 320)
            if not SourceHub._is_relevant_alert(title, summary):
                continue
            raw_pub = entry.get("published") or entry.get("updated")
            pub_dt = _parse_datetime(raw_pub)
            if pub_dt and pub_dt < cutoff_dt:
                continue
            combined = f"{title} {summary}"
            alerts.append({
                "title": title,
                "summary": summary[:220],
                "link": str(entry.get("link", ""))[:500],
                "source": source.name,
                "published_at": pub_dt.isoformat() if pub_dt else raw_pub,
                "vendors": _match_vendors(combined),
                "severity": _classify_alert_severity(combined, source),
            })
            if len(alerts) == 4:
                break
        return alerts

    @staticmethod
    def _clean_document_text(value: Any, limit: int = 700) -> str:
        text = BeautifulSoup(str(value or ""), "html.parser").get_text(" ")
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
        return " ".join(text.split())[:limit]

    @staticmethod
    def _extract_documents(source: Source, body: bytes) -> list[dict[str, Any]]:
        """Extract bounded evidence text. It remains untrusted until agent sanitization."""
        if source.kind == "page":
            soup = BeautifulSoup(body, "html.parser")
            title = SourceHub._clean_document_text(soup.title.get_text(" ") if soup.title else "")
            description = soup.find("meta", attrs={"name": "description"})
            summary = SourceHub._clean_document_text(description.get("content") if description else "")
            return [{"title": title, "summary": summary, "url": source.url}] if title else []
        if source.kind == "cisa":
            try:
                data = json.loads(body)
                return [
                    {
                        "title": SourceHub._clean_document_text(
                            f"{item.get('vendorProject', '')} {item.get('product', '')} - {item.get('vulnerabilityName', '')}"
                        ),
                        "summary": SourceHub._clean_document_text(item.get("shortDescription")),
                        "url": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}",
                        "published_at": _iso_timestamp(item.get("dateAdded")) or item.get("dateAdded"),
                    }
                    for item in data.get("vulnerabilities", [])[:100]
                ]
            except (json.JSONDecodeError, TypeError):
                return []
        if source.kind == "msrc-json":
            try:
                data = json.loads(body)
                return [
                    {
                        "title": SourceHub._clean_document_text(item.get("DocumentTitle")),
                        "summary": SourceHub._clean_document_text(f"Microsoft Security Update {item.get('ID', '')} ({item.get('Severity', '')})"),
                        "url": str(item.get("CvrfUrl") or source.url)[:500],
                        "published_at": _iso_timestamp(item.get("CurrentReleaseDate")),
                    }
                    for item in (data.get("value") or [])[:20]
                    if isinstance(item, dict) and item.get("DocumentTitle")
                ]
            except (json.JSONDecodeError, TypeError):
                return []
        if source.kind == "json":
            try:
                data = json.loads(body)
                documents = []
                for item in data.get("vulnerabilities", [])[:100]:
                    cve = item.get("cve", {})
                    descriptions = cve.get("descriptions", [])
                    summary = next((x.get("value") for x in descriptions if x.get("lang") == "en"), "")
                    cve_id = cve.get("id", "")
                    documents.append(
                        {
                            "title": cve_id,
                            "summary": SourceHub._clean_document_text(summary),
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "published_at": _iso_timestamp(cve.get("published")) or cve.get("published"),
                        }
                    )
                return documents
            except (json.JSONDecodeError, TypeError):
                return []

        feed = feedparser.parse(body)
        return [
            {
                "title": SourceHub._clean_document_text(entry.get("title")),
                "summary": SourceHub._clean_document_text(entry.get("summary")),
                "url": str(entry.get("link", ""))[:500],
                "published_at": _iso_timestamp(entry.get("published") or entry.get("updated"))
                or entry.get("published")
                or entry.get("updated"),
            }
            for entry in feed.entries[:25]
            if entry.get("title")
        ]

    @staticmethod
    def _detect_external_conflicts(
        results: list[dict[str, Any]],
        targets: dict[str, str],
        ignored_siblings: dict[str, set[str]] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Flag trusted sources reporting a strictly newer driver/KB version in recent headlines."""
        conflicts: dict[str, list[dict[str, Any]]] = {v: [] for v in targets.values() if v}
        ignored_siblings = ignored_siblings or {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=14)
        for result in results:
            source = result["source"]
            if source.tier in {"community", "social"} or result["status"] != "reachable":
                continue
            for doc in result["documents"]:
                title = str(doc.get("title") or "")
                title_low = title.casefold()
                if not any(ctx in title_low for ctx in DRIVER_UPDATE_CONTEXT):
                    continue
                pub_dt = _parse_datetime(doc.get("published_at"))
                if pub_dt and pub_dt < cutoff:
                    continue
                for vendor, current_ver in targets.items():
                    if not current_ver:
                        continue
                    if not VENDOR_CONTEXT_REGEX[vendor].search(title):
                        continue
                    if vendor == "windows" and WINDOWS_NON_CONFLICT_BRANCH_RE.search(title):
                        continue
                    current_tuple = parse_version_tuple(vendor, current_ver)
                    siblings = ignored_siblings.get(vendor, set())
                    for match in CONFLICT_VERSION_PATTERNS[vendor].finditer(title):
                        candidate = match.group(1).upper() if vendor == "windows" else match.group(1)
                        if vendor == "intel" and not candidate.startswith("32.0."):
                            candidate = f"32.0.{candidate}"
                        if candidate == current_ver or candidate in siblings:
                            continue
                        if parse_version_tuple(vendor, candidate) > current_tuple:
                            conflicts.setdefault(current_ver, []).append({
                                "source_name": source.name,
                                "publisher": source.publisher,
                                "url": doc.get("url") or source.url,
                                "title": title[:200],
                                "published_at": doc.get("published_at"),
                                "tier": source.tier,
                                "weight": source.weight,
                                "version": candidate,
                                "conflict_type": "newer_reported",
                            })
                            break
        return conflicts

    def audit(
        self,
        targets_or_versions: dict[str, str] | list[str],
        ignored_siblings: dict[str, list[str] | set[str]] | None = None,
    ) -> dict[str, Any]:
        if isinstance(targets_or_versions, dict):
            targets = {k: str(v) for k, v in targets_or_versions.items() if v}
        else:
            targets = {}
            for v in targets_or_versions:
                if not v:
                    continue
                inferred = _infer_vendor(str(v)) or f"item-{len(targets)}"
                targets[inferred] = str(v)

        sibling_sets = {k: set(v) for k, v in (ignored_siblings or {}).items()}
        versions = list(dict.fromkeys(targets.values()))
        cache_key = (tuple(sorted(targets.items())), tuple((k, tuple(sorted(v))) for k, v in sorted(sibling_sets.items())))
        now = time.monotonic()
        with self._lock:
            if (
                self._cache
                and self._cache.get("cache_key") == cache_key
                and now - self._cache_time < self.refresh_ttl
            ):
                cached = dict(self._cache)
                cached["cache_age_seconds"] = int(now - self._cache_time)
                return cached

            results = []
            executor = ThreadPoolExecutor(max_workers=40, thread_name_prefix="source-audit")
            jobs = {executor.submit(self._fetch, source, targets): source for source in SOURCES}
            completed, pending = wait(jobs, timeout=MAX_AUDIT_SECONDS)
            for future in completed:
                results.append(future.result())
            for future in pending:
                source = jobs[future]
                future.cancel()
                results.append({
                    "source": source,
                    "status": "unavailable",
                    "http_status": None,
                    "latency_ms": MAX_AUDIT_SECONDS * 1000,
                    "matched_versions": {},
                    "alerts": [],
                    "documents": [],
                    "error": "source audit deadline exceeded",
                })
            executor.shutdown(wait=False, cancel_futures=True)
            order = {source.id: index for index, source in enumerate(SOURCES)}
            results.sort(key=lambda result: order[result["source"].id])

            corroboration: dict[str, list[dict[str, Any]]] = {version: [] for version in versions}
            external_conflicts = self._detect_external_conflicts(results, targets, ignored_siblings=sibling_sets)
            for version, conflict_items in external_conflicts.items():
                corroboration.setdefault(version, []).extend(conflict_items)

            alerts: list[dict[str, Any]] = []
            seen_alerts: set[str] = set()
            public_results = []
            knowledge_documents = []
            for result in results:
                source = result["source"]
                matched_map = result["matched_versions"]
                for version in versions:
                    if version in matched_map:
                        hit = matched_map[version]
                        corroboration[version].append(
                            {
                                "source_name": source.name,
                                "publisher": source.publisher,
                                "url": hit.get("url") or source.url,
                                "title": hit.get("title") or source.name,
                                "published_at": hit.get("published_at"),
                                "tier": source.tier,
                                "weight": source.weight,
                                "version": version,
                            }
                        )
                for alert in result["alerts"]:
                    key = str(alert.get("title", "")).casefold()
                    if key and key not in seen_alerts:
                        seen_alerts.add(key)
                        alerts.append(alert)
                for document in result["documents"]:
                    knowledge_documents.append(
                        {
                            **document,
                            "source_id": source.id,
                            "source_name": source.name,
                            "publisher": source.publisher,
                            "tier": source.tier,
                            "weight": source.weight,
                        }
                    )
                public_results.append(
                    {
                        **asdict(source),
                        "status": result["status"],
                        "http_status": result["http_status"],
                        "latency_ms": result["latency_ms"],
                        "matched_versions": [
                            version for version in versions if version in matched_map
                        ],
                        "error": result["error"],
                    }
                )

            severity_rank = {"critical": 4, "high": 3, "medium": 2, "info": 1}
            alerts.sort(
                key=lambda item: (
                    (_parse_datetime(item.get("published_at")) or datetime.min.replace(tzinfo=timezone.utc)).timestamp(),
                    severity_rank.get(item.get("severity", "info"), 1),
                ),
                reverse=True,
            )

            reachable = sum(result["status"] == "reachable" for result in results)
            audited_at = int(time.time())
            audit = {
                "cache_key": cache_key,
                "audited_at": audited_at,
                "configured_sources": len(SOURCES),
                "reachable_sources": reachable,
                "independent_publishers": len({
                    result["source"].publisher
                    for result in results
                    if result["status"] == "reachable"
                }),
                "corroboration": corroboration,
                "alerts": alerts[:16],
                "knowledge_documents": knowledge_documents,
                "sources": public_results,
                "cache_age_seconds": 0,
            }
            self._cache = audit
            self._cache_time = now
            return dict(audit)
