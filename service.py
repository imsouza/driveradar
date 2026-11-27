"""Shared DriveRadar data service, cache, snapshot and durable v4 state."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Windows test runners do not provide POSIX fcntl.
    fcntl = None  # type: ignore[assignment]

from advisor import (
    SUPPORTED_LANGS,
    TRANSLATION_TARGET_LANGS,
    AIAdvisorPool,
    compute_release_maturity,
    evaluate_risk_policy,
)
from monitor import OFFICIAL_URLS, UpdateMonitor
from radar_core.application.vote_service import CommunityValidationService
from radar_core.infrastructure.crypto_tokens import HmacTokenSigner
from radar_core.infrastructure.rate_limiter import SlidingWindowRateLimiter
from radar_core.infrastructure.sqlite_vote_repo import SqliteVoteRepository
from sources import (
    CONFLICT_VERSION_PATTERNS,
    DRIVER_UPDATE_CONTEXT,
    IRRELEVANT_ALERT_RE,
    NON_TECHNICAL_GOSSIP_RE,
    SECURITY_SIGNAL_RE,
    SOURCES,
    SourceHub,
    _match_vendors,
    _parse_datetime,
    _version_in_text,
    parse_version_tuple,
)

LOGGER = logging.getLogger(__name__)
VENDORS = ("nvidia", "amd", "intel", "windows")
STATE_SCHEMA_VERSION = 4
HISTORY_LIMIT = 24


def build_verification(
    release: dict[str, Any], corroboration: list[dict[str, Any]], stale: bool = False
) -> dict[str, Any]:
    """Score independent agreement with a transparent point breakdown."""
    version = release.get("version")
    evidence = [
        item
        for item in [*release.get("evidence", []), *corroboration]
        if item.get("tier") not in {"community", "social"}
    ]
    agreements_by_pub: dict[str, dict[str, Any]] = {}
    conflicts_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for item in evidence:
        publisher = str(item.get("publisher") or item.get("source_name") or "").strip()
        if not publisher:
            continue
        item_ver = item.get("version")
        if item_ver == version and version:
            current = agreements_by_pub.get(publisher)
            if current is None or float(item.get("weight", 0)) > float(current.get("weight", 0)):
                agreements_by_pub[publisher] = item
        elif item_ver not in (None, version):
            key = (publisher, str(item_ver))
            current = conflicts_by_key.get(key)
            if current is None or float(item.get("weight", 0)) > float(current.get("weight", 0)):
                conflicts_by_key[key] = item

    # If the same publisher disagreed directly (non-newer_reported) with higher weight, drop its agreement.
    for (publisher, _), conflict_item in conflicts_by_key.items():
        if conflict_item.get("conflict_type") != "newer_reported" and publisher in agreements_by_pub:
            if float(conflict_item.get("weight", 0)) >= float(agreements_by_pub[publisher].get("weight", 0)):
                agreements_by_pub.pop(publisher, None)

    agreements = list(agreements_by_pub.values())
    conflicts = list(conflicts_by_key.values())
    has_primary = any(item.get("tier") in {"primary", "authority"} for item in agreements)

    breakdown: list[dict[str, Any]] = []
    if has_primary:
        base_score = 72
        breakdown.append({"code": "primary_confirmed", "label": "Confirmação em fonte primária / fabricante", "delta": 72, "kind": "positive"})
    elif agreements:
        base_score = 42
        breakdown.append({"code": "secondary_only", "label": "Apenas fontes secundárias (sem confirmação primária)", "delta": 42, "kind": "neutral"})
    else:
        base_score = 0
        breakdown.append({"code": "no_confirmation", "label": "Nenhuma confirmação disponível", "delta": 0, "kind": "negative"})

    corrob_points = min(24, max(0, len(agreements) - 1) * 8)
    if corrob_points > 0:
        extra_pubs = max(0, len(agreements) - 1)
        breakdown.append({
            "code": "independent_publishers",
            "count": extra_pubs,
            "label": f"+{extra_pubs} publisher{'es' if extra_pubs > 1 else ''} independente{'s' if extra_pubs > 1 else ''} concordante{'s' if extra_pubs > 1 else ''}",
            "delta": corrob_points,
            "kind": "positive",
        })

    conflict_penalty = min(50, len(conflicts) * 20)
    if conflict_penalty > 0:
        breakdown.append({
            "code": "version_conflicts",
            "count": len(conflicts),
            "label": f"{len(conflicts)} conflito{'s' if len(conflicts) > 1 else ''} de versão detectado{'s' if len(conflicts) > 1 else ''}",
            "delta": -conflict_penalty,
            "kind": "negative",
        })

    stale_penalty = 20 if stale else 0
    if stale_penalty:
        breakdown.append({
            "code": "stale_data",
            "label": "Usando último registro válido persistido (stale)",
            "delta": -stale_penalty,
            "kind": "negative",
        })

    score = max(0, min(98, base_score + corrob_points - conflict_penalty - stale_penalty))
    label = "confirmada" if score >= 88 else "alta" if score >= 72 else "moderada" if score >= 50 else "baixa"
    crossover_status = (
        "stale"
        if stale
        else "conflict"
        if conflicts
        else "confirmed"
        if has_primary
        else "unconfirmed"
        if agreements
        else "unavailable"
    )

    return {
        "score": score,
        "label": label,
        "crossover_status": crossover_status,
        "independent_publishers": len(agreements),
        "primary_confirmed": has_primary,
        "agreements": agreements,
        "conflicts": conflicts,
        "breakdown": breakdown,
        "date_delta_days": release.get("date_delta_days"),
        "method": (
            "72 pontos por confirmação primária; +8 por publisher independente (máx. 24); "
            "-20 por conflito e -20 se o dado estiver desatualizado. Limite: 98."
        ),
    }


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "last_successful_sync": 0,
        "releases": {},
        "history": {vendor: [] for vendor in VENDORS},
    }


def _compact_verification_snapshot(verification: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(verification, dict) or not verification:
        return None
    return {
        "score": verification.get("score"),
        "label": verification.get("label"),
        "crossover_status": verification.get("crossover_status"),
        "primary_confirmed": bool(verification.get("primary_confirmed")),
        "independent_publishers": int(verification.get("independent_publishers") or 0),
        "conflict_count": len(verification.get("conflicts") or []),
        "publishers": [
            item.get("publisher") or item.get("source_name")
            for item in (verification.get("agreements") or [])
            if item.get("publisher") or item.get("source_name")
        ][:10],
        "agreements": [
            {
                "publisher": item.get("publisher") or item.get("source_name"),
                "url": item.get("url"),
                "title": item.get("title"),
                "tier": item.get("tier"),
                "published_at": item.get("published_at"),
            }
            for item in (verification.get("agreements") or [])[:10]
        ],
        "conflicts": [
            {
                "publisher": item.get("publisher") or item.get("source_name"),
                "version": item.get("version"),
                "url": item.get("url"),
                "title": item.get("title"),
                "conflict_type": item.get("conflict_type"),
            }
            for item in (verification.get("conflicts") or [])[:6]
        ],
        "breakdown": verification.get("breakdown") or [],
    }


def _clean_history_entry(entry: dict[str, Any], vendor: str = "") -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    version = str(entry.get("version") or "").strip()
    if not version or version == "0.0" or entry.get("primary_verified") is not True:
        return None
    release_notes_url = entry.get("release_notes_url")
    if not release_notes_url:
        if vendor == "amd":
            release_notes_url = f"https://www.amd.com/en/resources/support-articles/release-notes/RN-RAD-WIN-{version.replace('.', '-')}.html"
        elif vendor == "windows" and version.upper().startswith("KB"):
            release_notes_url = entry.get("official_url") or f"https://support.microsoft.com/help/{version.upper().removeprefix('KB')}"

    return {
        "version": version,
        "date": entry.get("release_date") or entry.get("date"),
        "channel": entry.get("channel"),
        "os_build": entry.get("os_build"),
        "file_size": entry.get("file_size"),
        "sha256": entry.get("sha256"),
        "source_name": entry.get("source_name"),
        "source_url": entry.get("source_url"),
        "official_url": entry.get("official_url"),
        "release_notes_url": release_notes_url,
        "verified_at": entry.get("verified_at"),
        "first_seen_at": entry.get("first_seen_at") or entry.get("verified_at"),
        "primary_verified": True,
        "verification": entry.get("verification"),
        "release_summary": entry.get("release_summary"),
        "verdict_history": list(entry.get("verdict_history") or [])[-8:],
    }


_ACTION_SEVERITY_RANK = {"install": 0, "observe": 1, "wait": 2, "do_not_install": 4}
_RISK_SEVERITY_RANK = {"low": 0, "moderate": 1, "high": 2, "critical": 4}


def _append_verdict_transition(
    existing: list[dict[str, Any]] | None,
    action: str | None,
    risk_level: str | None,
    risk_score: int | None,
    at: int | None = None,
) -> list[dict[str, Any]]:
    history = [dict(x) for x in (existing or []) if isinstance(x, dict)]
    clean_action = str(action or "wait").strip().lower()
    clean_risk = str(risk_level or "moderate").strip().lower()
    ts = int(at or time.time())
    if not history:
        history.append({
            "action": clean_action,
            "risk_level": clean_risk,
            "risk_score": risk_score,
            "at": ts,
        })
        return history[-8:]
    last = history[-1]
    if last.get("action") != clean_action or last.get("risk_level") != clean_risk:
        history.append({
            "action": clean_action,
            "risk_level": clean_risk,
            "risk_score": risk_score,
            "prev_action": last.get("action"),
            "prev_risk_level": last.get("risk_level"),
            "at": ts,
        })
    return history[-8:]


def _latest_verdict_change(verdict_history: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not isinstance(verdict_history, list) or len(verdict_history) < 2:
        return None
    prev = verdict_history[-2]
    curr = verdict_history[-1]
    prev_rank = max(
        _ACTION_SEVERITY_RANK.get(str(prev.get("action") or ""), 0),
        _RISK_SEVERITY_RANK.get(str(prev.get("risk_level") or ""), 0),
    )
    curr_rank = max(
        _ACTION_SEVERITY_RANK.get(str(curr.get("action") or ""), 0),
        _RISK_SEVERITY_RANK.get(str(curr.get("risk_level") or ""), 0),
    )
    return {
        "from_action": prev.get("action"),
        "to_action": curr.get("action"),
        "from_risk": prev.get("risk_level"),
        "to_risk": curr.get("risk_level"),
        "changed_at": curr.get("at"),
        "escalated": curr_rank > prev_rank,
    }


def _sort_history(vendor: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries,
        key=lambda item: (
            str(item.get("date") or ""),
            parse_version_tuple(vendor, item.get("version")),
            int(item.get("verified_at") or 0),
        ),
        reverse=True,
    )[:HISTORY_LIMIT]


def _summary_from_assessment(assessment: dict[str, Any], enriched_at: int | None = None) -> dict[str, Any] | None:
    if not isinstance(assessment, dict) or assessment.get("status") != "ready":
        return None
    rec = assessment.get("recommendation") or {}
    risk = assessment.get("risk_assessment") or {}
    raw_translations = assessment.get("translations") or {}
    translations: dict[str, dict[str, Any]] = {}
    for lang in TRANSLATION_TARGET_LANGS:
        tblock = raw_translations.get(lang)
        if isinstance(tblock, dict) and tblock.get("headline") and tblock.get("summary"):
            translations[lang] = {
                "headline": tblock.get("headline") or "",
                "summary": tblock.get("summary") or "",
                "recommendation_reason": tblock.get("reason") or "",
                "critical_reasons": list(tblock.get("critical_reasons") or []),
                "highlights": list(tblock.get("highlights") or []),
                "fixed_issues": list(tblock.get("positive_signals") or []),
                "known_issues": list(tblock.get("risk_signals") or []),
                "watch_items": list(tblock.get("watch_items") or []),
            }
    return {
        "headline": assessment.get("headline"),
        "summary": assessment.get("summary"),
        "risk_level": risk.get("level") or ("critical" if rec.get("action") == "do_not_install" else "moderate"),
        "risk_score": risk.get("score") if risk.get("score") is not None else (90 if rec.get("action") == "do_not_install" else 38),
        "risk_categories": list(risk.get("categories") or []),
        "critical_reasons": list(risk.get("critical_reasons") or []),
        "recommendation_action": rec.get("action") or "wait",
        "recommendation_reason": rec.get("reason") or "",
        "highlights": [item.get("text") for item in (assessment.get("highlights") or []) if item.get("text")],
        "fixed_issues": [item.get("text") for item in (assessment.get("positive_signals") or []) if item.get("text")],
        "known_issues": [item.get("text") for item in (assessment.get("risk_signals") or []) if item.get("text")],
        "watch_items": [item.get("text") for item in (assessment.get("watch_items") or []) if item.get("text")],
        "translations": translations,
        "citations": assessment.get("citations") or [],
        "enriched_at": enriched_at or int(time.time()),
    }


def _project_summary_lang(summary: dict[str, Any] | None, lang: str) -> dict[str, Any] | None:
    if not isinstance(summary, dict) or lang not in TRANSLATION_TARGET_LANGS:
        return summary
    tblock = (summary.get("translations") or {}).get(lang)
    if not isinstance(tblock, dict):
        return summary
    projected = copy.deepcopy(summary)
    for field in ("headline", "summary", "recommendation_reason"):
        if tblock.get(field):
            projected[field] = tblock[field]
    for list_field in ("critical_reasons", "highlights", "fixed_issues", "known_issues", "watch_items"):
        if isinstance(tblock.get(list_field), list) and (tblock.get(list_field) or not projected.get(list_field)):
            projected[list_field] = list(tblock[list_field])
    return projected


def localize_history_entry(entry: dict[str, Any] | None, lang: str | None) -> dict[str, Any] | None:
    """Project a single history entry's release_summary to the requested language."""
    if not isinstance(entry, dict) or lang not in TRANSLATION_TARGET_LANGS:
        return entry
    projected = copy.deepcopy(entry)
    if isinstance(projected.get("release_summary"), dict):
        projected["release_summary"] = _project_summary_lang(projected["release_summary"], lang)
    return projected


def localize_payload(payload: dict[str, Any], lang: str | None) -> dict[str, Any]:
    """Project cached advisor & history text to the requested supported language when available."""
    if not isinstance(payload, dict) or lang not in TRANSLATION_TARGET_LANGS:
        return payload
    localized = copy.deepcopy(payload)
    assessments = (localized.get("advisor") or {}).get("assessments") or {}
    for assessment in assessments.values():
        if not isinstance(assessment, dict):
            continue
        tblock = (assessment.get("translations") or {}).get(lang)
        if not isinstance(tblock, dict):
            continue
        if tblock.get("headline"):
            assessment["headline"] = tblock["headline"]
        if tblock.get("summary"):
            assessment["summary"] = tblock["summary"]
        rec = assessment.get("recommendation")
        if isinstance(rec, dict):
            if tblock.get("target_audience"):
                rec["target_audience"] = tblock["target_audience"]
            if tblock.get("reason"):
                rec["reason"] = tblock["reason"]
        risk = assessment.get("risk_assessment")
        if isinstance(risk, dict) and isinstance(tblock.get("critical_reasons"), list) and tblock.get("critical_reasons"):
            risk["critical_reasons"] = list(tblock["critical_reasons"])
        for group in ("highlights", "positive_signals", "risk_signals", "watch_items"):
            translated_items = tblock.get(group)
            canonical_items = assessment.get(group)
            if isinstance(translated_items, list) and isinstance(canonical_items, list):
                for idx, txt in enumerate(translated_items[:len(canonical_items)]):
                    if txt and isinstance(canonical_items[idx], dict):
                        canonical_items[idx]["text"] = txt

    for entries in (localized.get("history") or {}).values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("release_summary"), dict):
                entry["release_summary"] = _project_summary_lang(entry["release_summary"], lang)
    return localized


def migrate_state(raw: Any) -> dict[str, Any]:
    """Migrate v3/v4 ledgers losslessly while discarding unverified pre-v3 legacies."""
    if not isinstance(raw, dict):
        return _empty_state()

    if raw.get("schema_version") in {3, STATE_SCHEMA_VERSION}:
        state = _empty_state()
        state["last_successful_sync"] = raw.get("last_successful_sync") or 0
        state["history"] = {
            vendor: _sort_history(
                vendor,
                [
                    cleaned
                    for item in raw.get("history", {}).get(vendor, [])[:HISTORY_LIMIT]
                    if (cleaned := _clean_history_entry(item, vendor=vendor))
                ],
            )
            for vendor in VENDORS
        }
        state["releases"] = {
            vendor: item
            for vendor, item in raw.get("releases", {}).items()
            if vendor in VENDORS and isinstance(item, dict) and item.get("primary_verified") is True
        }
        state["schema_version"] = STATE_SCHEMA_VERSION
        return state
    return _empty_state()


_WIN_STATE_LOCK = threading.RLock()


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    @contextlib.contextmanager
    def _locked(self, exclusive: bool):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fcntl is None:
            with _WIN_STATE_LOCK:
                yield
            return
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            return migrate_state(json.loads(self.path.read_text(encoding="utf-8")))
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            LOGGER.warning("State read failed, using empty state: %s", exc)
            return _empty_state()

    def read(self) -> dict[str, Any]:
        with self._locked(exclusive=False):
            return self._read_unlocked()

    def update(
        self,
        releases: dict[str, dict[str, Any]],
        collected_at: int,
        verifications: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        verifications = verifications or {}
        with self._locked(exclusive=True):
            state = self._read_unlocked()
            successful = False
            for vendor in VENDORS:
                release = releases[vendor]
                if not release.get("primary_verified") or not release.get("version"):
                    continue
                successful = True
                existing_by_ver = {
                    item["version"]: item for item in state["history"].get(vendor, []) if item.get("version")
                }
                prev = existing_by_ver.get(release["version"], {})
                ver_snapshot = _compact_verification_snapshot(verifications.get(vendor)) or prev.get("verification")
                persisted = _clean_history_entry(
                    {
                        "version": release["version"],
                        "date": release.get("release_date") or prev.get("date"),
                        "channel": release.get("channel") or prev.get("channel"),
                        "os_build": release.get("os_build") or prev.get("os_build"),
                        "file_size": release.get("file_size") or prev.get("file_size"),
                        "sha256": release.get("sha256") or prev.get("sha256"),
                        "source_name": release.get("source_name"),
                        "source_url": release.get("source_url"),
                        "official_url": release.get("official_url"),
                        "release_notes_url": release.get("release_notes_url")
                        or (release.get("release_notes") or {}).get("url")
                        or prev.get("release_notes_url"),
                        "verified_at": collected_at,
                        "first_seen_at": prev.get("first_seen_at") or collected_at,
                        "primary_verified": True,
                        "verification": ver_snapshot,
                        "release_summary": prev.get("release_summary"),
                        "verdict_history": prev.get("verdict_history") or [],
                    },
                    vendor=vendor,
                )
                if persisted:
                    state["releases"][vendor] = persisted
                    existing_by_ver[persisted["version"]] = persisted

                # Enrich matching historical entries with newly discovered official metadata.
                for recent in release.get("recent_releases") or []:
                    r_ver = str(recent.get("version") or "").strip()
                    if not r_ver:
                        continue
                    if r_ver in existing_by_ver:
                        item = existing_by_ver[r_ver]
                        for field in ("channel", "os_build", "file_size", "sha256", "release_notes_url"):
                            if recent.get(field) and not item.get(field):
                                item[field] = recent[field]
                        if recent.get("release_date") and not item.get("date"):
                            item["date"] = recent["release_date"]
                        if recent.get("official_url") and (
                            not item.get("official_url") or item.get("official_url") == OFFICIAL_URLS.get(vendor)
                        ):
                            item["official_url"] = recent["official_url"]

                state["history"][vendor] = _sort_history(vendor, list(existing_by_ver.values()))

            if successful:
                state["last_successful_sync"] = collected_at
            state["schema_version"] = STATE_SCHEMA_VERSION
            self._atomic_write(state)
            return state

    def save_history_summary(
        self,
        vendor: str,
        version: str,
        release_summary: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        metadata = metadata or {}
        with self._locked(exclusive=True):
            state = self._read_unlocked()
            history = state["history"].get(vendor, [])
            updated = False
            for item in history:
                if item.get("version") == version:
                    item["release_summary"] = release_summary
                    item["verdict_history"] = _append_verdict_transition(
                        item.get("verdict_history"),
                        release_summary.get("recommendation_action"),
                        release_summary.get("risk_level"),
                        release_summary.get("risk_score"),
                        release_summary.get("enriched_at"),
                    )
                    for key in ("release_notes_url", "channel", "file_size", "official_url"):
                        if metadata.get(key) and not item.get(key):
                            item[key] = metadata[key]
                    updated = True
                    break
            if updated:
                if state["releases"].get(vendor, {}).get("version") == version:
                    state["releases"][vendor]["release_summary"] = release_summary
                    matched_hist = next((h for h in history if h.get("version") == version), None)
                    if matched_hist:
                        state["releases"][vendor]["verdict_history"] = matched_hist.get("verdict_history") or []
                self._atomic_write(state)
            return state

    def _atomic_write(self, state: dict[str, Any]) -> None:
        descriptor, temp_path = tempfile.mkstemp(
            dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as temp_file:
                json.dump(state, temp_file, ensure_ascii=False, separators=(",", ":"))
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class DriveRadarService:
    def __init__(
        self,
        state_path: str | Path = "cache/bot_state.json",
        cache_ttl: int | None = None,
        monitor: UpdateMonitor | None = None,
        source_hub: SourceHub | None = None,
        vote_service: CommunityValidationService | None = None,
        use_shared_snapshot: bool = False,
    ) -> None:
        self.store = StateStore(state_path)
        self.snapshot_path = self.store.path.with_name("snapshot.json")
        self.use_shared_snapshot = use_shared_snapshot
        self.cache_ttl = cache_ttl or int(os.getenv("CACHE_TTL_SECONDS", "3600"))
        self.monitor = monitor or UpdateMonitor()
        self.source_hub = source_hub or SourceHub()
        self.advisor = AIAdvisorPool(self.store.path.with_name("advisor_state.json"))
        self.votes = vote_service or CommunityValidationService(
            SqliteVoteRepository(self.store.path.with_name("community_votes.db")),
            HmacTokenSigner(),
            SlidingWindowRateLimiter(),
        )
        self._analysis_evidence: dict[str, list[dict[str, Any]]] = {}
        self._cache: dict[str, Any] | None = None
        self._cache_time = 0.0
        self._state_mtime = self._read_state_mtime()
        self._refresh_lock = asyncio.Lock()
        self._advisor_lock = asyncio.Lock()
        self._history_locks: dict[tuple[str, str], asyncio.Lock] = {}
        warm_snapshot = self._load_shared_snapshot()
        if warm_snapshot:
            self._cache = warm_snapshot
            snap_ts = (warm_snapshot.get("collection") or {}).get("collected_at") or warm_snapshot.get("last_updated") or 0
            snap_age = max(0, int(time.time()) - int(snap_ts))
            if use_shared_snapshot or snap_age < self.cache_ttl:
                self._cache_time = time.monotonic() - min(snap_age, self.cache_ttl)
        if self._cache is None:
            self._cache = self._bootstrap_cache()
            if self._cache:
                self._cache_time = time.monotonic()

    def _read_state_mtime(self) -> float:
        try:
            return self.store.path.stat().st_mtime
        except OSError:
            return 0.0

    def _load_shared_snapshot(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("schema_version") == STATE_SCHEMA_VERSION:
                return payload
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _write_shared_snapshot(self, data: dict[str, Any]) -> None:
        try:
            self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temp_path = tempfile.mkstemp(
                dir=self.snapshot_path.parent, prefix=".snapshot-", suffix=".tmp"
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as temp_file:
                    json.dump(data, temp_file, ensure_ascii=False, separators=(",", ":"))
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                os.replace(temp_path, self.snapshot_path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
        except OSError as exc:
            LOGGER.warning("Snapshot write failed: %s", exc)

    def _bootstrap_cache(self) -> dict[str, Any] | None:
        """Serve the last verified ledger while the first live audit warms up."""
        state = self.store.read()
        if not state.get("releases"):
            return None
        drivers: dict[str, dict[str, Any]] = {}
        for vendor in VENDORS:
            persisted = state["releases"].get(vendor, {})
            version = persisted.get("version")
            evidence = []
            if version:
                evidence.append(
                    {
                        "version": version,
                        "publisher": persisted.get("source_name") or vendor.upper(),
                        "source_name": persisted.get("source_name") or vendor.upper(),
                        "url": persisted.get("source_url"),
                        "tier": "primary",
                        "weight": 1.0,
                    }
                )
            first_seen_at = persisted.get("first_seen_at") or persisted.get("verified_at")
            v_hist = list(persisted.get("verdict_history") or [])
            item = {
                "version": version,
                "release_date": persisted.get("date"),
                "first_seen_at": first_seen_at,
                "channel": persisted.get("channel"),
                "os_build": persisted.get("os_build"),
                "file_size": persisted.get("file_size"),
                "sha256": persisted.get("sha256"),
                "official_url": persisted.get("official_url") or OFFICIAL_URLS[vendor],
                "source_url": persisted.get("source_url"),
                "source_name": persisted.get("source_name"),
                "release_notes_url": persisted.get("release_notes_url"),
                "source_status": "stale",
                "maturity": compute_release_maturity(
                    persisted.get("date"), first_seen_at, channel=persisted.get("channel")
                ),
                "verdict_history": v_hist,
                "verdict_change": _latest_verdict_change(v_hist),
                "structured_notes": {"highlights": [], "fixed_issues": [], "known_issues": []},
                "verification": build_verification(
                    {"version": version, "evidence": evidence}, [], stale=True
                ),
                "feedback": {
                    "version": version,
                    "status": "Aguardando auditoria ao vivo",
                    "sentiment": "Indeterminado",
                    "pros": [],
                    "cons": [],
                    "source": "Último registro primário persistido",
                    "evidence_level": "stale",
                },
            }
            item["reference_link" if vendor == "windows" else "download_link"] = item["official_url"]
            drivers[vendor] = item
        configured = len(SOURCES)
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "status": "warming",
            "last_updated": state.get("last_successful_sync"),
            "collection": {
                "collected_at": None,
                "interval_seconds": self.cache_ttl,
                "failed_sources": [],
                "stability_analysis": "warming",
                "configured_sources": configured,
                "reachable_sources": 0,
                "independent_publishers": 0,
                "disclaimer": "Auditoria ao vivo em andamento; exibindo o último registro primário.",
            },
            "drivers": drivers,
            "history": state["history"],
            "security_alerts": [],
            "advisor": self.advisor.public_state(drivers),
            "source_audit": {
                "audited_at": None,
                "configured_sources": configured,
                "reachable_sources": 0,
                "independent_publishers": 0,
                "sources": [],
            },
        }

    def _collect(self) -> dict[str, Any]:
        collected_at = int(time.time())
        releases: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="driveradar") as executor:
            jobs = {executor.submit(self.monitor.get_release, vendor): vendor for vendor in VENDORS}
            for future in as_completed(jobs):
                vendor = jobs[future]
                try:
                    releases[vendor] = future.result()
                except Exception as exc:
                    LOGGER.exception("Unexpected %s collector error", vendor)
                    releases[vendor] = {
                        "version": None,
                        "release_date": None,
                        "source_url": OFFICIAL_URLS[vendor],
                        "source_name": "Fonte indisponível",
                        "official_url": OFFICIAL_URLS[vendor],
                        "verified": False,
                        "error": str(exc)[:160],
                    }

        vendor_targets = {
            vendor: release["version"]
            for vendor, release in releases.items()
            if release.get("version")
        }
        ignored_siblings = {
            vendor: release.get("sibling_versions") or []
            for vendor, release in releases.items()
            if release.get("sibling_versions")
        }
        source_audit = self.source_hub.audit(vendor_targets, ignored_siblings=ignored_siblings)

        pre_state = self.store.read()
        drivers: dict[str, dict[str, Any]] = {}
        verifications: dict[str, dict[str, Any]] = {}
        failed_sources: list[str] = []

        for vendor in VENDORS:
            live = releases[vendor]
            persisted = pre_state["releases"].get(vendor, {})
            if live.get("verified"):
                effective = live
                stale = False
            else:
                effective = {
                    "version": persisted.get("version"),
                    "release_date": persisted.get("date"),
                    "channel": persisted.get("channel"),
                    "os_build": persisted.get("os_build"),
                    "file_size": persisted.get("file_size"),
                    "sha256": persisted.get("sha256"),
                    "source_url": persisted.get("source_url") or live.get("source_url"),
                    "source_name": persisted.get("source_name") or live.get("source_name"),
                    "official_url": persisted.get("official_url") or live.get("official_url"),
                    "release_notes_url": persisted.get("release_notes_url"),
                }
                stale = bool(persisted)
                failed_sources.append(vendor)

            verification_release = {**live, "version": effective.get("version")}
            verification = build_verification(
                verification_release,
                source_audit["corroboration"].get(effective.get("version"), []),
                stale=stale,
            )
            verifications[vendor] = verification
            release_notes = live.get("release_notes") or {}
            structured_notes = release_notes.get("structured") or {
                "highlights": [],
                "fixed_issues": [],
                "known_issues": [],
            }

            effective_ver = effective.get("version")
            existing_hist_entry = next(
                (h for h in pre_state.get("history", {}).get(vendor, []) if h.get("version") == effective_ver),
                persisted if persisted.get("version") == effective_ver else {},
            )
            first_seen_at = (
                existing_hist_entry.get("first_seen_at")
                or existing_hist_entry.get("verified_at")
                or (collected_at if effective_ver else None)
            )
            v_hist = list(existing_hist_entry.get("verdict_history") or [])
            rel_date = effective.get("release_date") or effective.get("date")
            eff_channel = effective.get("channel")
            drivers[vendor] = {
                "version": effective_ver,
                "release_date": rel_date,
                "first_seen_at": first_seen_at,
                "channel": eff_channel,
                "os_build": effective.get("os_build"),
                "file_size": effective.get("file_size"),
                "sha256": effective.get("sha256"),
                "hotfix_available": live.get("hotfix_available"),
                "official_url": effective.get("official_url") or OFFICIAL_URLS[vendor],
                "source_url": effective.get("source_url"),
                "source_name": effective.get("source_name"),
                "release_notes_url": effective.get("release_notes_url") or release_notes.get("url"),
                "source_status": (
                    "stale"
                    if stale
                    else "verified"
                    if live.get("primary_verified")
                    else "unconfirmed"
                    if live.get("verified")
                    else "unavailable"
                ),
                "maturity": compute_release_maturity(
                    rel_date, first_seen_at, now_ts=collected_at, channel=eff_channel
                ),
                "verdict_history": v_hist,
                "verdict_change": _latest_verdict_change(v_hist),
                "structured_notes": structured_notes,
                "verification": verification,
                "feedback": {
                    "version": effective_ver,
                    "status": "Sem dados suficientes",
                    "sentiment": "Indeterminado",
                    "pros": [],
                    "cons": [],
                    "source": "Nenhuma amostra comunitária verificável",
                    "evidence_level": "none",
                },
            }
            if vendor == "windows":
                drivers[vendor]["reference_link"] = drivers[vendor]["official_url"]
            else:
                drivers[vendor]["download_link"] = drivers[vendor]["official_url"]

        state = self.store.update(releases, collected_at, verifications=verifications)

        analysis_evidence: dict[str, list[dict[str, Any]]] = {vendor: [] for vendor in VENDORS}
        min_dt = datetime.min.replace(tzinfo=timezone.utc)
        sorted_documents = sorted(
            source_audit.get("knowledge_documents", []),
            key=lambda doc: (
                (_parse_datetime(doc.get("published_at")) or min_dt).timestamp(),
                float(doc.get("weight") or 0.0),
            ),
            reverse=True,
        )
        now_dt = datetime.fromtimestamp(collected_at, tz=timezone.utc)
        for vendor in VENDORS:
            version = str(drivers[vendor].get("version") or "").strip()
            release_notes = releases[vendor].get("release_notes") or {}
            notes_text = str(release_notes.get("text") or "").strip()
            if version and notes_text:
                primary = next(
                    (item for item in releases[vendor].get("evidence", []) if item.get("tier") == "primary"),
                    {},
                )
                analysis_evidence[vendor].append({
                    "title": f"Notas oficiais da versão {version}",
                    "summary": notes_text[:18_000],
                    "url": release_notes.get("url") or primary.get("url"),
                    "publisher": primary.get("publisher") or primary.get("source_name") or vendor.upper(),
                    "tier": "primary",
                    "published_at": drivers[vendor].get("release_date"),
                })
            hotfix_avail = releases[vendor].get("hotfix_available")
            if isinstance(hotfix_avail, dict) and hotfix_avail.get("version"):
                analysis_evidence[vendor].append({
                    "title": f"Hotfix oficial mais recente disponível: {hotfix_avail.get('channel')} {hotfix_avail['version']}",
                    "summary": f"O fabricante disponibilizou a versão {hotfix_avail['version']} ({hotfix_avail.get('channel')}) posterior ao WHQL atual {version}.",
                    "url": hotfix_avail.get("source_url") or OFFICIAL_URLS[vendor],
                    "publisher": vendor.upper(),
                    "tier": "primary",
                    "published_at": hotfix_avail.get("release_date"),
                })
            if not version:
                continue
            version_aliases = [version]
            if version.startswith("32.0."):
                version_aliases.append(version.removeprefix("32.0."))
            for conf in verifications[vendor].get("conflicts", []):
                if conf.get("version"):
                    version_aliases.append(str(conf["version"]))
            seen_urls = {item.get("url") for item in analysis_evidence[vendor]}

            # Pass 1: Explicit version mentions with vendor context (most recent first).
            for document in sorted_documents:
                haystack = f"{document.get('title', '')} {document.get('summary', '')}"
                if not any(_version_in_text(alias, haystack, vendor) for alias in version_aliases):
                    continue
                url = document.get("url")
                if not url or url in seen_urls:
                    continue
                analysis_evidence[vendor].append({
                    "title": document.get("title"),
                    "summary": str(document.get("summary") or "")[:1_500],
                    "url": url,
                    "publisher": document.get("publisher") or document.get("source_name"),
                    "tier": document.get("tier"),
                    "published_at": document.get("published_at"),
                })
                seen_urls.add(url)
                if len(analysis_evidence[vendor]) >= 10:
                    break

            # Pass 2: Recent versionless regression/defect reports strictly within the release window.
            rel_dt = _parse_datetime(drivers[vendor].get("release_date"))
            window_floor = max(
                now_dt - timedelta(days=10),
                (rel_dt - timedelta(days=1)) if rel_dt else (now_dt - timedelta(days=7)),
            )
            if len(analysis_evidence[vendor]) < 10:
                for document in sorted_documents:
                    url = document.get("url")
                    if not url or url in seen_urls or document.get("tier") in {"community", "social"}:
                        continue
                    pub_dt = _parse_datetime(document.get("published_at"))
                    if not pub_dt or pub_dt < window_floor:
                        continue
                    title = str(document.get("title") or "")
                    summary = str(document.get("summary") or "")
                    combined = f"{title} {summary}"
                    combined_low = combined.casefold()
                    if NON_TECHNICAL_GOSSIP_RE.search(title.casefold()) or IRRELEVANT_ALERT_RE.search(combined_low):
                        continue
                    if vendor not in _match_vendors(title):
                        continue
                    if not any(ctx in combined_low for ctx in DRIVER_UPDATE_CONTEXT):
                        continue
                    if not SECURITY_SIGNAL_RE.search(combined):
                        continue
                    mentioned_vers = {
                        m.group(1).upper() if vendor == "windows" else m.group(1)
                        for m in CONFLICT_VERSION_PATTERNS[vendor].finditer(combined)
                    }
                    # Skip articles explicitly about a different (e.g. older) version.
                    if mentioned_vers and not any(
                        mv in {a.upper() if vendor == "windows" else a for a in version_aliases}
                        for mv in mentioned_vers
                    ):
                        continue
                    analysis_evidence[vendor].append({
                        "title": title,
                        "summary": summary[:1_500],
                        "url": url,
                        "publisher": document.get("publisher") or document.get("source_name"),
                        "tier": document.get("tier"),
                        "published_at": document.get("published_at"),
                    })
                    seen_urls.add(url)
                    if len(analysis_evidence[vendor]) >= 10:
                        break
        self._analysis_evidence = analysis_evidence

        payload = {
            "schema_version": STATE_SCHEMA_VERSION,
            "status": "success" if not failed_sources else "partial",
            "last_updated": state.get("last_successful_sync") or collected_at,
            "collection": {
                "collected_at": collected_at,
                "interval_seconds": self.cache_ttl,
                "failed_sources": failed_sources,
                "stability_analysis": "unavailable",
                "configured_sources": source_audit["configured_sources"],
                "reachable_sources": source_audit["reachable_sources"],
                "independent_publishers": source_audit["independent_publishers"],
                "disclaimer": "Versões e datas são verificadas nas fontes indicadas. Estabilidade não é inferida sem amostra verificável.",
            },
            "drivers": drivers,
            "history": state["history"],
            "security_alerts": source_audit["alerts"],
            "advisor": self.advisor.public_state(drivers),
            "source_audit": {
                "audited_at": source_audit["audited_at"],
                "configured_sources": source_audit["configured_sources"],
                "reachable_sources": source_audit["reachable_sources"],
                "independent_publishers": source_audit["independent_publishers"],
                "sources": source_audit["sources"],
            },
        }
        self._write_shared_snapshot(payload)
        return payload

    async def get_data(self, force: bool = False) -> dict[str, Any]:
        if not force and self.use_shared_snapshot:
            shared = await asyncio.to_thread(self._load_shared_snapshot)
            if shared:
                collected_at = (shared.get("collection") or {}).get("collected_at") or shared.get("last_updated") or 0
                age = max(0, int(time.time()) - int(collected_at))
                self._cache = shared
                self._cache_time = time.monotonic() - min(age, self.cache_ttl)
                response = await asyncio.to_thread(self.votes.enrich_payload_with_community, shared)
                response["cache_age_seconds"] = age
                return response

        now = time.monotonic()
        if not force and self._cache and now - self._cache_time < self.cache_ttl:
            disk_mtime = self._read_state_mtime()
            if disk_mtime > self._state_mtime:
                self._cache["history"] = (await asyncio.to_thread(self.store.read))["history"]
                self._cache["advisor"] = self.advisor.public_state(self._cache.get("drivers", {}))
                self._state_mtime = disk_mtime
            response = await asyncio.to_thread(self.votes.enrich_payload_with_community, self._cache)
            response["cache_age_seconds"] = int(now - self._cache_time)
            return response

        async with self._refresh_lock:
            now = time.monotonic()
            if not force and self._cache and now - self._cache_time < self.cache_ttl:
                response = await asyncio.to_thread(self.votes.enrich_payload_with_community, self._cache)
                response["cache_age_seconds"] = int(now - self._cache_time)
                return response
            try:
                fresh = await asyncio.to_thread(self._collect)
                self._cache = fresh
                self._cache_time = time.monotonic()
                self._state_mtime = self._read_state_mtime()
            except Exception:
                LOGGER.exception("Full data refresh failed")
                if not self._cache:
                    raise

            response = await asyncio.to_thread(self.votes.enrich_payload_with_community, self._cache)
            response["cache_age_seconds"] = int(time.monotonic() - self._cache_time)
            return response

    async def refresh_advisor(self) -> None:
        if not self.advisor.enabled or not self._cache:
            return
        async with self._advisor_lock:
            snapshot = copy.deepcopy(self._cache)
            versions = {vendor: item.get("version") for vendor, item in snapshot.get("drivers", {}).items()}
            try:
                state = await asyncio.to_thread(
                    self.advisor.analyze,
                    snapshot.get("drivers", {}),
                    snapshot.get("security_alerts", []),
                    copy.deepcopy(self._analysis_evidence),
                )
                if state.get("status") == "ready":
                    LOGGER.info("Advisor analysis ready via %s/%s", state.get("provider"), state.get("model"))
                else:
                    LOGGER.warning("Advisor analysis unavailable after provider pool (%s)", state.get("status"))
            except Exception:
                LOGGER.exception("Advisor pool refresh failed")
                return

            # Persist ready assessments directly into the corresponding history versions (using live maturity-adjusted action).
            live_public = self.advisor.public_state(snapshot.get("drivers", {}))
            assessments = live_public.get("assessments") or state.get("assessments") or {}
            updated_state = None
            for vendor, assessment in assessments.items():
                summary = _summary_from_assessment(assessment, state.get("last_analysis_at"))
                ver = assessment.get("version")
                if summary and ver:
                    updated_state = await asyncio.to_thread(
                        self.store.save_history_summary, vendor, ver, summary
                    )

            async with self._refresh_lock:
                current = {vendor: item.get("version") for vendor, item in self._cache.get("drivers", {}).items()}
                if current == versions:
                    self._cache["advisor"] = self.advisor.public_state(self._cache["drivers"])
                    if updated_state:
                        self._cache["history"] = updated_state["history"]
                        for vendor in VENDORS:
                            cur_ver = self._cache["drivers"].get(vendor, {}).get("version")
                            hist_item = next(
                                (h for h in updated_state["history"].get(vendor, []) if h.get("version") == cur_ver),
                                None,
                            )
                            if hist_item:
                                vh = list(hist_item.get("verdict_history") or [])
                                self._cache["drivers"][vendor]["verdict_history"] = vh
                                self._cache["drivers"][vendor]["verdict_change"] = _latest_verdict_change(vh)
                    self._write_shared_snapshot(self._cache)

    async def enrich_history_entry(self, vendor: str, version: str, lang: str = "pt-BR") -> dict[str, Any] | None:
        if vendor not in VENDORS:
            return None
        clean_lang = lang if lang in SUPPORTED_LANGS else "pt-BR"
        lock = self._history_locks.setdefault((vendor, version), asyncio.Lock())
        async with lock:
            state = await asyncio.to_thread(self.store.read)
            entry = next(
                (item for item in state.get("history", {}).get(vendor, []) if item.get("version") == version),
                None,
            )
            if not entry:
                return None

            existing_summary = entry.get("release_summary") or {}
            has_content = bool(
                existing_summary.get("enriched_at")
                and (
                    existing_summary.get("summary")
                    or existing_summary.get("highlights")
                    or existing_summary.get("fixed_issues")
                )
            )
            if has_content:
                existing_translations = existing_summary.get("translations") if isinstance(existing_summary.get("translations"), dict) else {}
                missing_langs = [code for code in TRANSLATION_TARGET_LANGS if code not in existing_translations]
                needs_risk = not existing_summary.get("risk_level")
                needs_translation = clean_lang in missing_langs

                if not needs_risk and not needs_translation:
                    return entry

                updated_summary = copy.deepcopy(existing_summary)
                if needs_risk:
                    policy = evaluate_risk_policy(updated_summary, driver_info={"channel": entry.get("channel")})
                    risk = policy["risk_assessment"]
                    updated_summary["risk_level"] = risk["level"]
                    updated_summary["risk_score"] = risk["score"]
                    updated_summary["risk_categories"] = risk["categories"]
                    updated_summary["critical_reasons"] = risk["critical_reasons"]
                    updated_summary["recommendation_action"] = policy["action"]
                if missing_langs and self.advisor.enabled:
                    translated = await asyncio.to_thread(
                        self.advisor.translate_history_summary, updated_summary, tuple(TRANSLATION_TARGET_LANGS)
                    )
                    if translated:
                        updated_summary["translations"] = {**existing_translations, **translated}

                new_state = await asyncio.to_thread(
                    self.store.save_history_summary, vendor, version, updated_summary
                )
                async with self._refresh_lock:
                    if self._cache:
                        self._cache["history"] = new_state["history"]
                        self._write_shared_snapshot(self._cache)
                return next(
                    (i for i in new_state["history"][vendor] if i["version"] == version), entry
                )

            # Check if live advisor already holds a ready assessment for this exact version.
            if self._cache:
                adv = (self._cache.get("advisor") or {}).get("assessments", {}).get(vendor)
                if adv and adv.get("version") == version and adv.get("status") == "ready":
                    summary = _summary_from_assessment(adv, self._cache["advisor"].get("last_analysis_at"))
                    if summary:
                        new_state = await asyncio.to_thread(
                            self.store.save_history_summary, vendor, version, summary
                        )
                        async with self._refresh_lock:
                            if self._cache:
                                self._cache["history"] = new_state["history"]
                                self._write_shared_snapshot(self._cache)
                        return next(
                            (i for i in new_state["history"][vendor] if i["version"] == version), entry
                        )

            fetched = await asyncio.to_thread(
                self.monitor.fetch_historical_release_notes,
                vendor,
                version,
                entry.get("release_notes_url"),
            )
            if not fetched:
                return entry

            summary = await asyncio.to_thread(
                self.advisor.summarize_history_release,
                vendor,
                version,
                entry.get("date"),
                fetched.get("channel") or entry.get("channel"),
                fetched.get("url") or entry.get("release_notes_url"),
                fetched.get("text", ""),
                fetched.get("structured"),
            )
            metadata = {
                "release_notes_url": fetched.get("url"),
                "channel": fetched.get("channel"),
                "file_size": fetched.get("file_size"),
                "official_url": fetched.get("official_url"),
            }
            if not summary:
                return entry

            new_state = await asyncio.to_thread(
                self.store.save_history_summary, vendor, version, summary, metadata
            )
            async with self._refresh_lock:
                if self._cache:
                    self._cache["history"] = new_state["history"]
                    self._write_shared_snapshot(self._cache)
            return next((i for i in new_state["history"][vendor] if i["version"] == version), entry)

    async def enrich_history_batch(self, limit: int = 6) -> int:
        state = await asyncio.to_thread(self.store.read)
        candidates: list[tuple[int, str, str, str]] = []
        for vendor in VENDORS:
            for idx, item in enumerate(state.get("history", {}).get(vendor, [])):
                rs = item.get("release_summary") or {}
                trs = rs.get("translations") if isinstance(rs.get("translations"), dict) else {}
                missing_lang = next((code for code in TRANSLATION_TARGET_LANGS if code not in trs), None)
                if not rs.get("enriched_at") or not rs.get("risk_level") or missing_lang:
                    candidates.append((idx, vendor, item["version"], missing_lang or "en"))
        candidates.sort(key=lambda row: row[0])
        enriched = 0
        for _, vendor, version, req_lang in candidates[:limit]:
            try:
                res = await self.enrich_history_entry(vendor, version, lang=req_lang)
                if res and (res.get("release_summary") or {}).get("enriched_at"):
                    enriched += 1
            except Exception as exc:
                LOGGER.warning("Background history enrich failed (%s %s): %s", vendor, version, exc)
        return enriched

    async def background_loop(self) -> None:
        next_collection = 0.0
        while True:
            try:
                now = time.monotonic()
                if now >= next_collection:
                    await self.get_data(force=True)
                    next_collection = time.monotonic() + self.cache_ttl
                await self.refresh_advisor()
                await self.enrich_history_batch(limit=4)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("Background refresh failed")
            advisor_status = (self._cache or {}).get("advisor", {}).get("status")
            retry_seconds = self.cache_ttl if advisor_status in {"ready", "stale"} else min(self.cache_ttl, 300)
            await asyncio.sleep(retry_seconds)
