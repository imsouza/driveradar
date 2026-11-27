"""HMAC-SHA256 Cryptographic Token Signer & Privacy-Preserving Subnet Hasher."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time
from pathlib import Path

_DESKTOP_PROOF_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_RAW_VOTER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


def _load_or_generate_secret(env_name: str, default_file: str) -> bytes:
    env_val = os.getenv(env_name, "").strip()
    if len(env_val) >= 32:
        return env_val.encode("utf-8")
    path = Path(os.getenv(f"{env_name}_FILE", default_file))
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if len(raw) >= 32 and not raw.startswith("#"):
            return raw.encode("utf-8")
    except OSError:
        pass
    return secrets.token_bytes(32)


class HmacTokenSigner:
    """Signs anonymous voter cookies and time-gated anti-script tokens with zero PII storage."""

    def __init__(self, secret_key: bytes | str | None = None) -> None:
        if isinstance(secret_key, str):
            self._secret = secret_key.encode("utf-8")
        elif isinstance(secret_key, bytes):
            self._secret = secret_key
        else:
            self._secret = _load_or_generate_secret("VOTE_HMAC_SECRET", "/run/secrets/vote_hmac_secret")

    def _mac(self, domain: str, message: str) -> str:
        return hmac.new(self._secret, f"{domain}:{message}".encode("utf-8"), hashlib.sha256).hexdigest()

    def mint_voter_cookie(self) -> tuple[str, str]:
        raw_id = secrets.token_urlsafe(24)
        sig = self._mac("voter-cookie", raw_id)[:32]
        return raw_id, f"{raw_id}.{sig}"

    def verify_voter_cookie(self, cookie_value: str | None) -> str | None:
        if not cookie_value or "." not in cookie_value or len(cookie_value) > 128:
            return None
        raw_id, sig = cookie_value.split(".", 1)
        if not _RAW_VOTER_ID_RE.fullmatch(raw_id):
            return None
        expected = self._mac("voter-cookie", raw_id)[:32]
        return raw_id if hmac.compare_digest(sig, expected) else None

    def derive_desktop_voter_id(self, client_proof: str | None) -> str | None:
        clean = str(client_proof or "").strip()
        if not _DESKTOP_PROOF_RE.fullmatch(clean):
            return None
        return f"desktop:{self._mac('desktop-proof', clean)[:32]}"

    def hash_voter(self, raw_voter_id: str) -> str:
        return self._mac("voter-id", raw_voter_id)[:32]

    @staticmethod
    def extract_subnet_prefix(client_ip: str) -> str:
        raw = str(client_ip or "").strip()
        try:
            addr = ipaddress.ip_address(raw)
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.IPv4Network(f"{addr}/24", strict=False)
                return str(net.network_address)
            net6 = ipaddress.IPv6Network(f"{addr}/64", strict=False)
            return str(net6.network_address)
        except ValueError:
            return "0.0.0.0"

    def hash_subnet(self, client_ip: str) -> str:
        month_bucket = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        prefix = self.extract_subnet_prefix(client_ip)
        return self._mac(f"subnet-{month_bucket}", prefix)[:24]

    def issue_challenge(self, voter_hash: str, subnet_hash: str, now_ts: float | None = None) -> str:
        issued_ms = int((now_ts if now_ts is not None else time.time()) * 1000)
        nonce = secrets.token_hex(6)
        payload = f"{issued_ms}.{nonce}"
        sig = self._mac("vote-challenge", f"{payload}:{voter_hash}:{subnet_hash}")[:32]
        return f"{payload}.{sig}"

    def verify_challenge(
        self,
        token: str,
        *,
        voter_hash: str,
        subnet_hash: str,
        min_age_seconds: float,
        max_age_seconds: float,
        now_ts: float | None = None,
    ) -> bool:
        parts = str(token or "").split(".")
        if len(parts) != 3 or len(token) > 120:
            return False
        ts_str, nonce, sig = parts
        if not ts_str.isdigit() or not re.fullmatch(r"[0-9a-f]{12}", nonce):
            return False
        payload = f"{ts_str}.{nonce}"
        expected = self._mac("vote-challenge", f"{payload}:{voter_hash}:{subnet_hash}")[:32]
        if not hmac.compare_digest(sig, expected):
            return False
        now_ms = int((now_ts if now_ts is not None else time.time()) * 1000)
        age_sec = (now_ms - int(ts_str)) / 1000.0
        return min_age_seconds <= age_sec <= max_age_seconds
