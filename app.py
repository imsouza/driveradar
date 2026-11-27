"""Public DriveRadar web application."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.parse
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from radar_core.domain.models import (
    DomainValidationError,
    RateLimitExceededError,
    SecurityViolationError,
)
from radar_core.infrastructure.http_security import (
    WEB_CSP,
    TrustedProxyIpExtractor,
    apply_security_headers,
)
from radar_core.infrastructure.rate_limiter import SlidingWindowRateLimiter
from service import SUPPORTED_LANGS, VENDORS, DriveRadarService, localize_history_entry, localize_payload

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
service = DriveRadarService()
http_limiter = SlidingWindowRateLimiter()
ADSENSE_PUBLISHER_ID = "pub-7513394193260475"
RELEASES_DIR = Path(os.getenv("RELEASES_DIR", "releases"))
VOTER_COOKIE_NAME = "dr_vid"
MAX_VOTE_BODY_BYTES = 512
_UPDATE_FILE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_STRICT_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_UPDATE_ALLOWED_EXTS = {".yml", ".yaml", ".exe", ".blockmap", ".zip", ".sha256"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    updater = asyncio.create_task(service.background_loop(), name="driveradar-updater")
    try:
        yield
    finally:
        updater.cancel()
        with suppress(asyncio.CancelledError):
            await updater


app = FastAPI(title="DriveRadar", docs_url=None, redoc_url=None, lifespan=lifespan)
web = FastAPI(title="DriveRadar Web", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    return apply_security_headers(response, csp=WEB_CSP)


def _enforce_same_origin_csrf(request: Request, *, has_desktop_proof: bool) -> None:
    if request.headers.get("x-requested-with") != "DriveRadar":
        raise SecurityViolationError("Missing anti-CSRF header")
    if has_desktop_proof:
        return
    sec_site = str(request.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_site and sec_site not in {"same-origin", "none"}:
        raise SecurityViolationError("Cross-site vote request blocked")
    origin = str(request.headers.get("origin") or "").strip()
    if origin:
        parsed_origin = urllib.parse.urlsplit(origin)
        req_host = str(request.headers.get("host") or "").split(":")[0].lower()
        if parsed_origin.hostname and req_host and parsed_origin.hostname.lower() != req_host:
            raise SecurityViolationError("Origin mismatch")


def _set_voter_cookie(response: Response, signed_cookie: str, request: Request) -> None:
    is_https = (
        request.url.scheme == "https"
        or str(request.headers.get("x-forwarded-proto") or "").lower() == "https"
    )
    response.set_cookie(
        key=VOTER_COOKIE_NAME,
        value=signed_cookie,
        max_age=365 * 86400,
        path="/driveradar",
        secure=is_https,
        httponly=True,
        samesite="strict",
    )


@web.get("/api/data")
async def get_data(response: Response, lang: str | None = None):
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
    payload = await service.get_data()
    return localize_payload(payload, lang)


@web.get("/api/votes")
async def get_votes_session(request: Request, response: Response):
    response.headers["Cache-Control"] = "private, no-store"
    client_ip = TrustedProxyIpExtractor.extract(request)
    decision = http_limiter.check(f"votes-session:{client_ip}", limit=60, window_seconds=60)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    voter_hash, subnet_hash, new_cookie = service.votes.resolve_identity(
        cookie_value=request.cookies.get(VOTER_COOKIE_NAME),
        desktop_proof=request.headers.get("x-driveradar-client-proof"),
        client_ip=client_ip,
    )
    if new_cookie:
        _set_voter_cookie(response, new_cookie, request)
    snapshot = service._cache or await service.get_data()
    return await asyncio.to_thread(
        service.votes.open_session,
        voter_hash=voter_hash,
        subnet_hash=subnet_hash,
        snapshot_payload=snapshot,
    )


@web.post("/api/vote")
async def submit_vote(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    desktop_proof = request.headers.get("x-driveradar-client-proof")
    try:
        _enforce_same_origin_csrf(request, has_desktop_proof=bool(desktop_proof))
        raw_body = await request.body()
        if len(raw_body) > MAX_VOTE_BODY_BYTES:
            raise DomainValidationError("Payload exceeds 512-byte limit")
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainValidationError("Invalid JSON payload") from exc
        if not isinstance(body, dict):
            raise DomainValidationError("Payload must be an object")

        client_ip = TrustedProxyIpExtractor.extract(request)
        voter_hash, subnet_hash, new_cookie = service.votes.resolve_identity(
            cookie_value=request.cookies.get(VOTER_COOKIE_NAME),
            desktop_proof=desktop_proof,
            client_ip=client_ip,
        )
        if new_cookie:
            _set_voter_cookie(response, new_cookie, request)

        snapshot = service._cache or await service.get_data()
        return await asyncio.to_thread(
            service.votes.cast_vote,
            voter_hash=voter_hash,
            subnet_hash=subnet_hash,
            vote_token=str(body.get("vote_token") or ""),
            target_type=str(body.get("target_type") or ""),
            target_id=str(body.get("target_id") or ""),
            vote=str(body.get("vote") or ""),
            reason_tag=body.get("reason_tag"),
            snapshot_payload=snapshot,
        )
    except DomainValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SecurityViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


@web.get("/api/history/{vendor}/{version:path}")
async def get_history_entry(vendor: str, version: str, request: Request, response: Response, lang: str = "pt-BR"):
    clean_vendor = vendor.strip().lower()
    if clean_vendor not in VENDORS:
        raise HTTPException(status_code=404, detail="Vendor not found")
    clean_version = version.strip()
    if not _STRICT_VERSION_RE.fullmatch(clean_version) or ".." in clean_version:
        raise HTTPException(status_code=400, detail="Invalid version format")
    client_ip = TrustedProxyIpExtractor.extract(request)
    decision = http_limiter.check(f"history:{client_ip}", limit=40, window_seconds=60)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    clean_lang = lang.strip() if lang and lang.strip() in SUPPORTED_LANGS else "pt-BR"
    entry = await service.enrich_history_entry(clean_vendor, clean_version, lang=clean_lang)
    if not entry:
        raise HTTPException(status_code=404, detail="History version not found")
    response.headers["Cache-Control"] = "public, max-age=300"
    return localize_history_entry(entry, clean_lang)


@web.get("/health")
async def health():
    cache = service._cache or {}
    drivers = cache.get("drivers") or {}
    return JSONResponse({
        "status": "ok",
        "service": "driveradar",
        "last_updated": cache.get("last_updated"),
        "advisor_status": (cache.get("advisor") or {}).get("status"),
        "verified_drivers": sum(1 for d in drivers.values() if (d.get("verification") or {}).get("primary_confirmed")),
    })


@web.get("/robots.txt", include_in_schema=False)
async def robots():
    return FileResponse("static/robots.txt", media_type="text/plain")


@web.get("/sitemap.xml", include_in_schema=False)
async def sitemap():
    return FileResponse("static/sitemap.xml", media_type="application/xml")


@web.get("/privacidade", include_in_schema=False)
async def privacy():
    return FileResponse("static/privacidade.html")


@web.get("/termos", include_in_schema=False)
async def terms():
    return FileResponse("static/termos.html")


@web.get("/ads.txt", include_in_schema=False)
async def ads_txt():
    return Response(
        f"google.com, {ADSENSE_PUBLISHER_ID}, DIRECT, f08c47fec0942fa0\n",
        media_type="text/plain",
    )


@web.get("/service-worker.js", include_in_schema=False)
async def service_worker():
    return FileResponse(
        "static/service-worker.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/driveradar/", "Cache-Control": "no-cache"},
    )


def _resolve_latest_installer(releases_dir: Path | None = None) -> str | None:
    base = releases_dir or RELEASES_DIR
    manifest = base / "latest.yml"
    try:
        content = manifest.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in content.splitlines():
        match = re.match(r"^\s*path:\s*['\"]?([A-Za-z0-9._-]+\.exe)['\"]?\s*$", line)
        if match:
            candidate = match.group(1)
            if (base / candidate).is_file():
                return candidate
    return None


@web.api_route("/updates/DriveRadar-Setup.exe", methods=["GET", "HEAD"], include_in_schema=False)
async def latest_windows_installer():
    filename = _resolve_latest_installer()
    if not filename:
        raise HTTPException(status_code=404, detail="Windows installer not published yet")
    return RedirectResponse(url=f"/driveradar/updates/{filename}", status_code=302)


@web.api_route("/updates/{filename}", methods=["GET", "HEAD"], include_in_schema=False)
async def update_artifact(filename: str):
    if not _UPDATE_FILE_RE.fullmatch(filename):
        raise HTTPException(status_code=404, detail="Not found")
    suffix = Path(filename).suffix.lower()
    if suffix not in _UPDATE_ALLOWED_EXTS:
        raise HTTPException(status_code=404, detail="Not found")
    base = RELEASES_DIR.resolve()
    target = (base / filename).resolve()
    if target.parent != base or not target.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    cache_control = "no-cache" if suffix in {".yml", ".yaml"} else "public, max-age=86400"
    media_type = "text/yaml; charset=utf-8" if suffix in {".yml", ".yaml"} else "application/octet-stream"
    return FileResponse(target, media_type=media_type, headers={"Cache-Control": cache_control})


web.mount("/static", StaticFiles(directory="static"), name="static")


@web.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root():
    return FileResponse("static/index.html")


app.mount("/driveradar", web)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8512, proxy_headers=True, forwarded_allow_ips="127.0.0.1")
