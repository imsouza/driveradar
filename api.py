"""Authenticated DriveRadar API for internal/mobile clients."""

from __future__ import annotations

import hmac
import os
import re

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from radar_core.infrastructure.http_security import (
    API_CSP,
    TrustedProxyIpExtractor,
    apply_security_headers,
)
from radar_core.infrastructure.rate_limiter import SlidingWindowRateLimiter
from service import SUPPORTED_LANGS, VENDORS, DriveRadarService, localize_history_entry, localize_payload

app = FastAPI(title="DriveRadar API", version="3.1.0", docs_url=None, redoc_url=None)
service = DriveRadarService(use_shared_snapshot=True)
auth_limiter = SlidingWindowRateLimiter()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_STRICT_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")

allowed_origins = [
    origin.strip()
    for origin in os.getenv("API_ALLOWED_ORIGINS", "https://optlabs.com.br").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["X-API-Key"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    return apply_security_headers(response, csp=API_CSP)


def require_api_key(request: Request, provided: str | None = Security(api_key_header)) -> str:
    configured = os.getenv("API_SECRET_KEY", "")
    if not configured:
        raise HTTPException(status_code=503, detail="API access is not configured")
    client_ip = TrustedProxyIpExtractor.extract(request)
    if not provided or not hmac.compare_digest(provided, configured):
        decision = auth_limiter.check(f"bad-apikey:{client_ip}", limit=10, window_seconds=60)
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many failed authentication attempts",
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )
        raise HTTPException(status_code=403, detail="Invalid API key")
    return provided


@app.get("/health")
async def health():
    return {"status": "ok", "service": "driveradar-api"}


@app.get("/api/data")
async def get_data(lang: str | None = None, _: str = Depends(require_api_key)):
    payload = await service.get_data()
    return localize_payload(payload, lang)


@app.get("/api/history/{vendor}/{version:path}")
async def get_history_entry(vendor: str, version: str, lang: str = "pt-BR", _: str = Depends(require_api_key)):
    clean_vendor = vendor.strip().lower()
    if clean_vendor not in VENDORS:
        raise HTTPException(status_code=404, detail="Vendor not found")
    clean_version = version.strip()
    if not _STRICT_VERSION_RE.fullmatch(clean_version) or ".." in clean_version:
        raise HTTPException(status_code=400, detail="Invalid version format")
    clean_lang = lang.strip() if lang and lang.strip() in SUPPORTED_LANGS else "pt-BR"
    entry = await service.enrich_history_entry(clean_vendor, clean_version, lang=clean_lang)
    if not entry:
        raise HTTPException(status_code=404, detail="History version not found")
    return localize_history_entry(entry, clean_lang)
