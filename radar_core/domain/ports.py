"""Abstract Ports (Dependency Inversion interfaces) for the Domain & Application layers."""

from __future__ import annotations

from typing import Any, Protocol

from .models import CommunityTally, RateLimitDecision, VoteCommand


class VoteRepositoryPort(Protocol):
    def upsert_vote(self, command: VoteCommand) -> None: ...

    def has_voter_voted(self, target_key: str, voter_hash: str) -> bool: ...

    def count_distinct_voters_in_subnet(self, target_key: str, subnet_hash: str) -> int: ...

    def get_tally(self, target_key: str) -> CommunityTally: ...

    def get_tallies_bulk(self, target_keys: list[str]) -> dict[str, CommunityTally]: ...

    def get_voter_votes(self, voter_hash: str, target_keys: list[str]) -> dict[str, dict[str, str]]: ...


class TokenSignerPort(Protocol):
    def mint_voter_cookie(self) -> tuple[str, str]: ...

    def verify_voter_cookie(self, cookie_value: str | None) -> str | None: ...

    def derive_desktop_voter_id(self, client_proof: str | None) -> str | None: ...

    def hash_voter(self, raw_voter_id: str) -> str: ...

    def hash_subnet(self, client_ip: str) -> str: ...

    def issue_challenge(self, voter_hash: str, subnet_hash: str, now_ts: float | None = None) -> str: ...

    def verify_challenge(
        self,
        token: str,
        *,
        voter_hash: str,
        subnet_hash: str,
        min_age_seconds: float,
        max_age_seconds: float,
        now_ts: float | None = None,
    ) -> bool: ...


class RateLimiterPort(Protocol):
    def check(self, bucket_key: str, limit: int, window_seconds: int) -> RateLimitDecision: ...
