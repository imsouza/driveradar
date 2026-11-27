"""Immutable Domain Value Objects, Entities, Commands, and Exceptions."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DomainValidationError(ValueError):
    """Raised when untrusted input violates strict domain invariants."""


class SecurityViolationError(PermissionError):
    """Raised when an anti-abuse, CSRF, SSRF, or token invariant fails."""


class RateLimitExceededError(RuntimeError):
    """Raised when a client or subnet exceeds its allowed interaction budget."""

    def __init__(self, message: str, retry_after_seconds: int = 30) -> None:
        super().__init__(message)
        self.retry_after_seconds = max(1, int(retry_after_seconds))


class VoteTargetType(str, Enum):
    DRIVER = "driver"
    ALERT = "alert"


class VoteDirection(str, Enum):
    UP = "up"
    DOWN = "down"


class VoteReasonTag(str, Enum):
    MAKES_SENSE = "makes_sense"
    STABLE = "stable"
    USEFUL_ALERT = "useful_alert"
    FALSE_POSITIVE = "false_positive"
    WORKS_FINE = "works_fine"
    BLACK_SCREEN = "black_screen"
    CRASH_BSOD = "crash_bsod"
    FPS_DROP = "fps_drop"
    INSTALL_FAIL = "install_fail"
    AUDIO_DISPLAY = "audio_display"
    OUTDATED = "outdated"


ALLOWED_REASON_TAGS: dict[tuple[VoteTargetType, VoteDirection], frozenset[VoteReasonTag]] = {
    (VoteTargetType.DRIVER, VoteDirection.UP): frozenset({
        VoteReasonTag.MAKES_SENSE,
        VoteReasonTag.STABLE,
    }),
    (VoteTargetType.DRIVER, VoteDirection.DOWN): frozenset({
        VoteReasonTag.FALSE_POSITIVE,
        VoteReasonTag.WORKS_FINE,
        VoteReasonTag.BLACK_SCREEN,
        VoteReasonTag.CRASH_BSOD,
        VoteReasonTag.FPS_DROP,
        VoteReasonTag.INSTALL_FAIL,
        VoteReasonTag.AUDIO_DISPLAY,
        VoteReasonTag.OUTDATED,
    }),
    (VoteTargetType.ALERT, VoteDirection.UP): frozenset({VoteReasonTag.USEFUL_ALERT}),
    (VoteTargetType.ALERT, VoteDirection.DOWN): frozenset({
        VoteReasonTag.FALSE_POSITIVE,
        VoteReasonTag.OUTDATED,
    }),
}

DEFAULT_REASON_TAG: dict[tuple[VoteTargetType, VoteDirection], VoteReasonTag] = {
    (VoteTargetType.DRIVER, VoteDirection.UP): VoteReasonTag.MAKES_SENSE,
    (VoteTargetType.DRIVER, VoteDirection.DOWN): VoteReasonTag.FALSE_POSITIVE,
    (VoteTargetType.ALERT, VoteDirection.UP): VoteReasonTag.USEFUL_ALERT,
    (VoteTargetType.ALERT, VoteDirection.DOWN): VoteReasonTag.FALSE_POSITIVE,
}

_SAFE_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9:._-]{2,64}$")


@dataclass(frozen=True)
class VoteCommand:
    target_type: VoteTargetType
    target_id: str
    vote: VoteDirection
    reason_tag: VoteReasonTag
    voter_hash: str
    subnet_hash: str
    created_at: int

    @property
    def target_key(self) -> str:
        return f"{self.target_type.value}:{self.target_id}"

    @classmethod
    def create(
        cls,
        *,
        target_type: str,
        target_id: str,
        vote: str,
        reason_tag: str | None,
        voter_hash: str,
        subnet_hash: str,
        now_ts: int | None = None,
    ) -> VoteCommand:
        try:
            t_type = VoteTargetType(str(target_type or "").strip().lower())
        except ValueError as exc:
            raise DomainValidationError("invalid target_type") from exc

        try:
            direction = VoteDirection(str(vote or "").strip().lower())
        except ValueError as exc:
            raise DomainValidationError("invalid vote direction") from exc

        clean_id = str(target_id or "").strip()
        if not _SAFE_TARGET_ID_RE.fullmatch(clean_id) or ".." in clean_id:
            raise DomainValidationError("invalid target_id")

        allowed_tags = ALLOWED_REASON_TAGS[(t_type, direction)]
        if reason_tag:
            try:
                parsed_tag = VoteReasonTag(str(reason_tag).strip().lower())
            except ValueError as exc:
                raise DomainValidationError("invalid reason_tag") from exc
            if parsed_tag not in allowed_tags:
                raise DomainValidationError("reason_tag incompatible with target/vote")
        else:
            parsed_tag = DEFAULT_REASON_TAG[(t_type, direction)]

        if not voter_hash or not subnet_hash:
            raise SecurityViolationError("missing cryptographic voter identity")

        return cls(
            target_type=t_type,
            target_id=clean_id,
            vote=direction,
            reason_tag=parsed_tag,
            voter_hash=voter_hash,
            subnet_hash=subnet_hash,
            created_at=int(now_ts if now_ts is not None else time.time()),
        )


@dataclass(frozen=True)
class CommunityTally:
    target_key: str
    up_count: int
    down_count: int
    unique_subnets: int
    reason_counts: dict[str, int]
    wilson_positive: float
    wilson_negative: float
    quorum_met: bool
    community_signal: str

    @property
    def total(self) -> int:
        return self.up_count + self.down_count

    @property
    def approval_pct(self) -> int | None:
        if self.total == 0:
            return None
        return round((self.up_count / self.total) * 100)

    def to_dict(self) -> dict[str, Any]:
        top_issue = None
        issue_entries = [
            (tag, cnt)
            for tag, cnt in self.reason_counts.items()
            if tag not in {
                VoteReasonTag.MAKES_SENSE.value,
                VoteReasonTag.STABLE.value,
                VoteReasonTag.USEFUL_ALERT.value,
            } and cnt > 0
        ]
        if issue_entries:
            issue_entries.sort(key=lambda pair: pair[1], reverse=True)
            top_issue = issue_entries[0][0]
        return {
            "target_key": self.target_key,
            "up": self.up_count,
            "down": self.down_count,
            "total": self.total,
            "approval_pct": self.approval_pct,
            "unique_subnets": self.unique_subnets,
            "reasons": dict(self.reason_counts),
            "top_issue": top_issue,
            "wilson_positive": round(self.wilson_positive, 3),
            "wilson_negative": round(self.wilson_negative, 3),
            "quorum_met": self.quorum_met,
            "signal": self.community_signal,
        }


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    remaining: int
