"""Pure Domain Specifications & Security/Statistical Strategies."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import socket
import urllib.parse
from typing import Any

from .models import CommunityTally, SecurityViolationError, VoteTargetType


class WilsonScoreCalculator:
    """Strategy for lower-bound binomial proportion confidence intervals."""

    @staticmethod
    def lower_bound(successes: int, total: int, z: float = 1.96) -> float:
        if total <= 0 or successes <= 0:
            return 0.0
        phat = successes / total
        z2 = z * z
        denom = 1.0 + z2 / total
        center = phat + z2 / (2.0 * total)
        radicand = (phat * (1.0 - phat) + z2 / (4.0 * total)) / total
        return max(0.0, min(1.0, (center - z * math.sqrt(max(0.0, radicand))) / denom))


class CommunityQuorumPolicy:
    """Specification converting raw community counts into a bounded Dual-Track signal."""

    MIN_QUORUM_TOTAL = 5
    DRIVER_WARN_DOWNS = 5
    DRIVER_WARN_SUBNETS = 4
    ALERT_FP_DOWNS = 4
    ALERT_FP_SUBNETS = 3

    @classmethod
    def build_tally(
        cls,
        target_key: str,
        up_count: int,
        down_count: int,
        unique_subnets: int,
        reason_counts: dict[str, int],
    ) -> CommunityTally:
        total = up_count + down_count
        w_pos = WilsonScoreCalculator.lower_bound(up_count, total)
        w_neg = WilsonScoreCalculator.lower_bound(down_count, total)
        quorum_met = total >= cls.MIN_QUORUM_TOTAL and unique_subnets >= min(3, cls.MIN_QUORUM_TOTAL)
        is_alert = target_key.startswith(f"{VoteTargetType.ALERT.value}:")

        if is_alert:
            if down_count >= cls.ALERT_FP_DOWNS and unique_subnets >= cls.ALERT_FP_SUBNETS and w_neg >= 0.45:
                signal = "likely_false_positive"
            elif quorum_met and w_pos >= 0.55:
                signal = "positive"
            elif quorum_met:
                signal = "mixed"
            else:
                signal = "insufficient"
        else:
            if down_count >= cls.DRIVER_WARN_DOWNS and unique_subnets >= cls.DRIVER_WARN_SUBNETS and w_neg >= 0.42:
                signal = "warning"
            elif quorum_met and w_pos >= 0.62:
                signal = "positive"
            elif quorum_met:
                signal = "mixed"
            else:
                signal = "insufficient"

        return CommunityTally(
            target_key=target_key,
            up_count=up_count,
            down_count=down_count,
            unique_subnets=unique_subnets,
            reason_counts=dict(reason_counts),
            wilson_positive=w_pos,
            wilson_negative=w_neg,
            quorum_met=quorum_met,
            community_signal=signal,
        )


class AlertTargetIdBuilder:
    """Deterministic URL-safe identifier for RSS security alerts."""

    @staticmethod
    def build(alert: dict[str, Any]) -> str:
        existing = str(alert.get("id") or "").strip()
        if existing.startswith("al_") and len(existing) == 19:
            return existing
        seed = f"{alert.get('source', '')}|{alert.get('link', '')}|{alert.get('title', '')}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return f"al_{digest}"


class SafeExternalUrlPolicy:
    """SSRF & Phishing URL Specification blocking private/reserved/metadata addresses."""

    _FORBIDDEN_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".arpa")

    @staticmethod
    def is_disallowed_ip(ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )

    @classmethod
    def validate_url(cls, raw_url: str, *, require_https: bool = False) -> str:
        clean = str(raw_url or "").strip()
        if not clean or len(clean) > 1024 or any(ord(ch) < 33 or ord(ch) == 127 for ch in clean):
            raise SecurityViolationError("malformed or oversized URL")
        parsed = urllib.parse.urlsplit(clean)
        allowed_schemes = {"https"} if require_https else {"https", "http"}
        if parsed.scheme.lower() not in allowed_schemes:
            raise SecurityViolationError(f"disallowed URL scheme: {parsed.scheme}")
        if parsed.username or parsed.password:
            raise SecurityViolationError("embedded URL credentials are forbidden")
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host or host == "localhost" or any(host.endswith(sfx) for sfx in cls._FORBIDDEN_SUFFIXES):
            raise SecurityViolationError("private or local hostname is forbidden")
        try:
            ipaddress.ip_address(host)
            if cls.is_disallowed_ip(host):
                raise SecurityViolationError("private or loopback IP is forbidden")
        except ValueError:
            pass
        return urllib.parse.urlunsplit(parsed)

    @classmethod
    def verify_public_destination(cls, raw_url: str) -> str:
        validated = cls.validate_url(raw_url, require_https=False)
        host = (urllib.parse.urlsplit(validated).hostname or "").lower().rstrip(".")
        # Offline synthetic test domains (.test per RFC 2606) bypass live DNS lookup.
        if host.endswith(".test") or host == "testserver":
            return validated
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return validated
        for info in infos:
            sockaddr = info[4]
            if sockaddr and cls.is_disallowed_ip(str(sockaddr[0])):
                raise SecurityViolationError(f"DNS resolved {host} to non-public IP")
        return validated


class PromptInjectionSanitizer:
    """Sanitize untrusted web/RSS excerpts before passing them to LLM prompts."""

    _INVISIBLE_UNICODE_RE = re.compile(
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\x00-\x1f\x7f]+"
    )
    _INJECTION_PATTERNS = (
        re.compile(r"\bignore\s+(?:all\s+|any\s+|previous\s+|prior\s+|above\s+)+instructions?\b", re.I),
        re.compile(r"\bdisregard\s+(?:all\s+|previous\s+|system\s+)+(?:instructions?|prompts?|rules?)\b", re.I),
        re.compile(r"\b(?:system\s*prompt|developer\s*message|new\s+instructions?)\s*:", re.I),
        re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>)", re.I),
    )

    @classmethod
    def clean(cls, value: Any, limit: int) -> str:
        text = cls._INVISIBLE_UNICODE_RE.sub(" ", str(value or ""))
        for pattern in cls._INJECTION_PATTERNS:
            text = pattern.sub("[filtered]", text)
        return re.sub(r"\s+", " ", text).strip()[:limit]
