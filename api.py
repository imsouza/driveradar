"""Authenticated DriveRadar API for internal/mobile clients."""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from service import VENDORS, DriveRadarService

app = FastAPI(title="DriveRadar API", version="3.0.0", docs_url=None, redoc_url=None)
service = DriveRadarService(use_shared_snapshot=True)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

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


def require_api_key(provided: str | None = Security(api_key_header)) -> str:
    configured = os.getenv("API_SECRET_KEY", "")
    if not configured:
        raise HTTPException(status_code=503, detail="API access is not configured")
    if not provided or not hmac.compare_digest(provided, configured):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return provided


@app.get("/health")
async def health():
    return {"status": "ok", "service": "driveradar-api"}


@app.get("/api/data")
async def get_data(_: str = Depends(require_api_key)):
    return await service.get_data()


@app.get("/api/history/{vendor}/{version:path}")
async def get_history_entry(vendor: str, version: str, _: str = Depends(require_api_key)):
    clean_vendor = vendor.strip().lower()
    if clean_vendor not in VENDORS:
        raise HTTPException(status_code=404, detail="Vendor not found")
    entry = await service.enrich_history_entry(clean_vendor, version.strip())
    if not entry:
        raise HTTPException(status_code=404, detail="History version not found")
    return entry
