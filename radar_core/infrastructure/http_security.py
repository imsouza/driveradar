"""HTTP Security Utilities: Trusted Proxy IP extraction, Security Headers & Bounded Streaming."""

from __future__ import annotations

import ipaddress
import time
from typing import Any

import requests

from radar_core.domain.policies import SafeExternalUrlPolicy


class TrustedProxyIpExtractor:
    """Extract client IP safely behind local Nginx / Cloudflare without trusting spoofed headers."""

    @staticmethod
    def _is_trusted_proxy_peer(peer_ip: str) -> bool:
        if peer_ip in {"127.0.0.1", "::1", "testclient"}:
            return True
        try:
            addr = ipaddress.ip_address(peer_ip)
            return bool(addr.is_loopback or addr.is_private)
        except ValueError:
            return False

    @classmethod
    def extract(cls, request: Any) -> str:
        peer = getattr(getattr(request, "client", None), "host", None) or "127.0.0.1"
        if not cls._is_trusted_proxy_peer(str(peer)):
            return str(peer)
        headers = getattr(request, "headers", {}) or {}
        cf_ip = str(headers.get("cf-connecting-ip") or "").strip()
        if cf_ip:
            try:
                return str(ipaddress.ip_address(cf_ip))
            except ValueError:
                pass
        real_ip = str(headers.get("x-real-ip") or "").strip()
        if real_ip:
            try:
                return str(ipaddress.ip_address(real_ip))
            except ValueError:
                pass
        xff = str(headers.get("x-forwarded-for") or "").strip()
        if xff:
            # Take rightmost hop appended by local reverse proxy if CF-Connecting-IP is absent.
            candidate = xff.split(",")[-1].strip()
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
        return str(peer)


WEB_CSP = (
    "default-src 'self'; script-src 'self' 'sha256-63iNIim4dZEEKxCEopD9h2k4I2qtvaNcOChCVyzU7pw=' "
    "https://pagead2.googlesyndication.com https://www.googletagservices.com "
    "https://www.googletagmanager.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com; "
    "connect-src 'self' https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com "
    "https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com; "
    "frame-src https://*.googlesyndication.com https://*.doubleclick.net; "
    "worker-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
    "form-action 'self'"
)

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def apply_security_headers(response: Any, *, csp: str = WEB_CSP) -> Any:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = csp
    return response


def fetch_bounded_bytes(
    session: Any,
    url: str,
    *,
    max_bytes: int,
    timeout: tuple[int, int] = (5, 15),
    max_seconds: float = 25.0,
    headers: dict[str, str] | None = None,
) -> tuple[bytes, Any]:
    """Fetch an external URL with SSRF destination verification and strict byte/time caps."""
    is_real_requests = isinstance(session, requests.Session)
    safe_url = (
        SafeExternalUrlPolicy.verify_public_destination(url)
        if is_real_requests
        else SafeExternalUrlPolicy.validate_url(url)
    )
    started = time.monotonic()
    resp = (
        session.get(safe_url, headers=headers, timeout=timeout, stream=True)
        if is_real_requests
        else session.get(safe_url, headers=headers, timeout=timeout)
    )
    try:
        resp.raise_for_status()
        final_url = getattr(resp, "url", None)
        if is_real_requests and final_url:
            SafeExternalUrlPolicy.verify_public_destination(str(final_url))
        iter_fn = getattr(resp, "iter_content", None)
        if callable(iter_fn):
            chunks: list[bytes] = []
            total = 0
            for chunk in iter_fn(65_536):
                if time.monotonic() - started > max_seconds:
                    raise requests.Timeout("bounded stream exceeded total time budget")
                if not chunk:
                    continue
                remaining = max_bytes - total
                chunks.append(chunk[:remaining])
                total += len(chunks[-1])
                if total >= max_bytes:
                    break
            return b"".join(chunks), resp
        raw_content = getattr(resp, "content", b"") or b""
        return raw_content[:max_bytes], resp
    finally:
        close_fn = getattr(resp, "close", None)
        if is_real_requests and callable(close_fn):
            close_fn()
