"""Community Validation Use-Case Service (Dual-Track / Zero-Override architecture)."""

from __future__ import annotations

import copy
from typing import Any

from radar_core.domain.models import (
    DomainValidationError,
    RateLimitExceededError,
    SecurityViolationError,
    VoteCommand,
)
from radar_core.domain.policies import AlertTargetIdBuilder, CommunityQuorumPolicy
from radar_core.domain.ports import RateLimiterPort, TokenSignerPort, VoteRepositoryPort


class CommunityValidationService:
    """Application service coordinating anti-abuse checks, vote persistence, and snapshot enrichment."""

    def __init__(
        self,
        repository: VoteRepositoryPort,
        signer: TokenSignerPort,
        rate_limiter: RateLimiterPort,
        *,
        max_voters_per_subnet: int = 2,
        min_token_age_seconds: float = 1.0,
        max_token_age_seconds: float = 3600.0,
    ) -> None:
        self._repo = repository
        self._signer = signer
        self._limiter = rate_limiter
        self._max_voters_per_subnet = max_voters_per_subnet
        self._min_token_age_seconds = min_token_age_seconds
        self._max_token_age_seconds = max_token_age_seconds

    def resolve_identity(
        self,
        *,
        cookie_value: str | None,
        desktop_proof: str | None,
        client_ip: str,
    ) -> tuple[str, str, str | None]:
        """Return (voter_hash, subnet_hash, new_cookie_to_set_or_None)."""
        subnet_hash = self._signer.hash_subnet(client_ip)
        desktop_id = self._signer.derive_desktop_voter_id(desktop_proof)
        if desktop_id:
            return self._signer.hash_voter(desktop_id), subnet_hash, None

        existing_id = self._signer.verify_voter_cookie(cookie_value)
        if existing_id:
            return self._signer.hash_voter(existing_id), subnet_hash, None

        raw_id, signed_cookie = self._signer.mint_voter_cookie()
        return self._signer.hash_voter(raw_id), subnet_hash, signed_cookie

    @staticmethod
    def collect_allowed_targets(snapshot_payload: dict[str, Any] | None) -> dict[str, dict[str, str]]:
        """Extract all active votable targets from the current verified snapshot."""
        allowed: dict[str, dict[str, str]] = {}
        if not isinstance(snapshot_payload, dict):
            return allowed
        for vendor, drv in (snapshot_payload.get("drivers") or {}).items():
            ver = str((drv or {}).get("version") or "").strip()
            if ver:
                target_id = f"{vendor}:{ver}"
                allowed[f"driver:{target_id}"] = {"target_type": "driver", "target_id": target_id}
        for alert in snapshot_payload.get("security_alerts") or []:
            if not isinstance(alert, dict):
                continue
            aid = AlertTargetIdBuilder.build(alert)
            allowed[f"alert:{aid}"] = {"target_type": "alert", "target_id": aid}
        return allowed

    def open_session(
        self,
        *,
        voter_hash: str,
        subnet_hash: str,
        snapshot_payload: dict[str, Any] | None,
        now_ts: float | None = None,
    ) -> dict[str, Any]:
        allowed = self.collect_allowed_targets(snapshot_payload)
        keys = list(allowed.keys())
        tallies = self._repo.get_tallies_bulk(keys)
        my_votes = self._repo.get_voter_votes(voter_hash, keys)
        token = self._signer.issue_challenge(voter_hash, subnet_hash, now_ts=now_ts)
        return {
            "vote_token": token,
            "tallies": {k: v.to_dict() for k, v in tallies.items()},
            "my_votes": my_votes,
        }

    def cast_vote(
        self,
        *,
        voter_hash: str,
        subnet_hash: str,
        vote_token: str,
        target_type: str,
        target_id: str,
        vote: str,
        reason_tag: str | None,
        snapshot_payload: dict[str, Any] | None,
        now_ts: float | None = None,
    ) -> dict[str, Any]:
        voter_limit = self._limiter.check(f"vote:voter:{voter_hash}", limit=12, window_seconds=60)
        if not voter_limit.allowed:
            raise RateLimitExceededError("Too many vote actions; slow down.", voter_limit.retry_after_seconds)

        subnet_limit = self._limiter.check(f"vote:subnet:{subnet_hash}", limit=24, window_seconds=60)
        if not subnet_limit.allowed:
            raise RateLimitExceededError("Subnet vote rate exceeded.", subnet_limit.retry_after_seconds)

        if not self._signer.verify_challenge(
            str(vote_token or ""),
            voter_hash=voter_hash,
            subnet_hash=subnet_hash,
            min_age_seconds=self._min_token_age_seconds,
            max_age_seconds=self._max_token_age_seconds,
            now_ts=now_ts,
        ):
            raise SecurityViolationError("Invalid, expired, or premature vote challenge token.")

        command = VoteCommand.create(
            target_type=target_type,
            target_id=target_id,
            vote=vote,
            reason_tag=reason_tag,
            voter_hash=voter_hash,
            subnet_hash=subnet_hash,
            now_ts=int(now_ts) if now_ts is not None else None,
        )

        allowed = self.collect_allowed_targets(snapshot_payload)
        if command.target_key not in allowed:
            raise DomainValidationError("Target version or alert is not active.")

        already_voted = self._repo.has_voter_voted(command.target_key, voter_hash)
        if not already_voted:
            distinct_in_subnet = self._repo.count_distinct_voters_in_subnet(command.target_key, subnet_hash)
            if distinct_in_subnet >= self._max_voters_per_subnet:
                raise RateLimitExceededError(
                    "Maximum independent votes per network reached for this item.", 120
                )

        self._repo.upsert_vote(command)
        tally = self._repo.get_tally(command.target_key)
        return {
            "status": "recorded",
            "target_key": command.target_key,
            "my_vote": {"vote": command.vote.value, "tag": command.reason_tag.value},
            "tally": tally.to_dict(),
        }

    def enrich_payload_with_community(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Attach Dual-Track community tallies without mutating Crossover or Risk scores."""
        if not isinstance(payload, dict):
            return payload
        out = copy.deepcopy(payload)
        target_keys: list[str] = []

        drivers = out.get("drivers") or {}
        for vendor, drv in drivers.items():
            if isinstance(drv, dict) and drv.get("version"):
                key = f"driver:{vendor}:{drv['version']}"
                drv["vote_target_id"] = f"{vendor}:{drv['version']}"
                target_keys.append(key)

        alerts = out.get("security_alerts") or []
        for alert in alerts:
            if isinstance(alert, dict):
                aid = AlertTargetIdBuilder.build(alert)
                alert["id"] = aid
                target_keys.append(f"alert:{aid}")

        tallies = self._repo.get_tallies_bulk(target_keys)

        for vendor, drv in drivers.items():
            if isinstance(drv, dict) and drv.get("version"):
                key = f"driver:{vendor}:{drv['version']}"
                tally = tallies.get(key) or CommunityQuorumPolicy.build_tally(key, 0, 0, 0, {})
                drv["community"] = tally.to_dict()

        for alert in alerts:
            if isinstance(alert, dict) and alert.get("id"):
                key = f"alert:{alert['id']}"
                tally = tallies.get(key) or CommunityQuorumPolicy.build_tally(key, 0, 0, 0, {})
                alert["community"] = tally.to_dict()

        return out
