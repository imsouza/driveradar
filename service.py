"""Shared DriveRadar data service, cache, snapshot and durable v4 state."""

from __future__ import annotations

import asyncio
import copy
import fcntl
import json
import logging
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from advisor import AIAdvisorPool
from monitor import OFFICIAL_URLS, UpdateMonitor
from sources import SOURCES, SourceHub, parse_version_tuple

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
        breakdown.append({"label": "Confirmação em fonte primária / fabricante", "delta": 72, "kind": "positive"})
    elif agreements:
        base_score = 42
        breakdown.append({"label": "Apenas fontes secundárias (sem confirmação primária)", "delta": 42, "kind": "neutral"})
    else:
        base_score = 0
        breakdown.append({"label": "Nenhuma confirmação disponível", "delta": 0, "kind": "negative"})

    corrob_points = min(24, max(0, len(agreements) - 1) * 8)
    if corrob_points > 0:
        extra_pubs = max(0, len(agreements) - 1)
        breakdown.append({
            "label": f"+{extra_pubs} publisher{'es' if extra_pubs > 1 else ''} independente{'s' if extra_pubs > 1 else ''} concordante{'s' if extra_pubs > 1 else ''}",
            "delta": corrob_points,
            "kind": "positive",
        })

    conflict_penalty = min(50, len(conflicts) * 20)
    if conflict_penalty > 0:
        breakdown.append({
            "label": f"{len(conflicts)} conflito{'s' if len(conflicts) > 1 else ''} de versão detectado{'s' if len(conflicts) > 1 else ''}",
            "delta": -conflict_penalty,
            "kind": "negative",
        })

    stale_penalty = 20 if stale else 0
    if stale_penalty:
        breakdown.append({
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
    return {
        "headline": assessment.get("headline"),
        "summary": assessment.get("summary"),
        "recommendation_action": rec.get("action") or "wait",
        "recommendation_reason": rec.get("reason") or "",
        "highlights": [item.get("text") for item in (assessment.get("highlights") or []) if item.get("text")],
        "fixed_issues": [item.get("text") for item in (assessment.get("positive_signals") or []) if item.get("text")],
        "known_issues": [item.get("text") for item in (assessment.get("risk_signals") or []) if item.get("text")],
        "watch_items": [item.get("text") for item in (assessment.get("watch_items") or []) if item.get("text")],
        "citations": assessment.get("citations") or [],
        "enriched_at": enriched_at or int(time.time()),
    }


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


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            return migrate_state(json.loads(self.path.read_text(encoding="utf-8")))
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            LOGGER.warning("State read failed, using empty state: %s", exc)
            return _empty_state()

    def read(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_SH)
            try:
                return self._read_unlocked()
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def update(
        self,
        releases: dict[str, dict[str, Any]],
        collected_at: int,
        verifications: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        verifications = verifications or {}
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
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
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def save_history_summary(
        self,
        vendor: str,
        version: str,
        release_summary: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        metadata = metadata or {}
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                state = self._read_unlocked()
                history = state["history"].get(vendor, [])
                updated = False
                for item in history:
                    if item.get("version") == version:
                        item["release_summary"] = release_summary
                        for key in ("release_notes_url", "channel", "file_size", "official_url"):
                            if metadata.get(key) and not item.get(key):
                                item[key] = metadata[key]
                        updated = True
                        break
                if updated:
                    if state["releases"].get(vendor, {}).get("version") == version:
                        state["releases"][vendor]["release_summary"] = release_summary
                    self._atomic_write(state)
                return state
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

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
        use_shared_snapshot: bool = False,
    ) -> None:
        self.store = StateStore(state_path)
        self.snapshot_path = self.store.path.with_name("snapshot.json")
        self.use_shared_snapshot = use_shared_snapshot
        self.cache_ttl = cache_ttl or int(os.getenv("CACHE_TTL_SECONDS", "3600"))
        self.monitor = monitor or UpdateMonitor()
        self.source_hub = source_hub or SourceHub()
        self.advisor = AIAdvisorPool(self.store.path.with_name("advisor_state.json"))
        self._analysis_evidence: dict[str, list[dict[str, Any]]] = {}
        self._cache: dict[str, Any] | None = None
        self._cache_time = 0.0
        self._state_mtime = self._read_state_mtime()
        self._refresh_lock = asyncio.Lock()
        self._advisor_lock = asyncio.Lock()
        self._history_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._cache = self._load_shared_snapshot() if use_shared_snapshot else None
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
            item = {
                "version": version,
                "release_date": persisted.get("date"),
                "channel": persisted.get("channel"),
                "os_build": persisted.get("os_build"),
                "file_size": persisted.get("file_size"),
                "sha256": persisted.get("sha256"),
                "official_url": persisted.get("official_url") or OFFICIAL_URLS[vendor],
                "source_url": persisted.get("source_url"),
                "source_name": persisted.get("source_name"),
                "release_notes_url": persisted.get("release_notes_url"),
                "source_status": "stale",
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

            drivers[vendor] = {
                "version": effective.get("version"),
                "release_date": effective.get("release_date") or effective.get("date"),
                "channel": effective.get("channel"),
                "os_build": effective.get("os_build"),
                "file_size": effective.get("file_size"),
                "sha256": effective.get("sha256"),
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
                "structured_notes": structured_notes,
                "verification": verification,
                "feedback": {
                    "version": effective.get("version"),
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
        documents = source_audit.get("knowledge_documents", [])
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
            if not version:
                continue
            version_terms = {version.casefold()}
            if version.startswith("32.0."):
                version_terms.add(version.removeprefix("32.0.").casefold())
            # Also include conflicting newer versions mentioned for this vendor so the advisor sees them.
            for conf in verifications[vendor].get("conflicts", []):
                if conf.get("version"):
                    version_terms.add(str(conf["version"]).casefold())
            seen_urls = {item.get("url") for item in analysis_evidence[vendor]}
            for document in documents:
                haystack = f"{document.get('title', '')} {document.get('summary', '')}".casefold()
                if not any(term in haystack for term in version_terms):
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
            shared = self._load_shared_snapshot()
            if shared:
                collected_at = (shared.get("collection") or {}).get("collected_at") or shared.get("last_updated") or 0
                age = max(0, int(time.time()) - int(collected_at))
                if age < self.cache_ttl:
                    self._cache = shared
                    self._cache_time = time.monotonic() - age
                    response = copy.deepcopy(shared)
                    response["cache_age_seconds"] = age
                    return response

        now = time.monotonic()
        if not force and self._cache and now - self._cache_time < self.cache_ttl:
            disk_mtime = self._read_state_mtime()
            if disk_mtime > self._state_mtime:
                self._cache["history"] = (await asyncio.to_thread(self.store.read))["history"]
                self._cache["advisor"] = self.advisor.public_state(self._cache.get("drivers", {}))
                self._state_mtime = disk_mtime
            response = copy.deepcopy(self._cache)
            response["cache_age_seconds"] = int(now - self._cache_time)
            return response

        async with self._refresh_lock:
            now = time.monotonic()
            if not force and self._cache and now - self._cache_time < self.cache_ttl:
                response = copy.deepcopy(self._cache)
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

            response = copy.deepcopy(self._cache)
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

            # Persist ready assessments directly into the corresponding history versions.
            assessments = state.get("assessments") or {}
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
                    self._write_shared_snapshot(self._cache)

    async def enrich_history_entry(self, vendor: str, version: str) -> dict[str, Any] | None:
        if vendor not in VENDORS:
            return None
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
            if existing_summary.get("enriched_at") and (
                existing_summary.get("summary") or existing_summary.get("highlights") or existing_summary.get("fixed_issues")
            ):
                return entry

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
        candidates: list[tuple[int, str, str]] = []
        for vendor in VENDORS:
            for idx, item in enumerate(state.get("history", {}).get(vendor, [])):
                rs = item.get("release_summary") or {}
                if not rs.get("enriched_at"):
                    candidates.append((idx, vendor, item["version"]))
        candidates.sort(key=lambda row: row[0])
        enriched = 0
        for _, vendor, version in candidates[:limit]:
            try:
                res = await self.enrich_history_entry(vendor, version)
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
