"""Public DriveRadar web application."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from service import SUPPORTED_LANGS, VENDORS, DriveRadarService, localize_history_entry, localize_payload

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
service = DriveRadarService()
ADSENSE_PUBLISHER_ID = "pub-7513394193260475"
RELEASES_DIR = Path(os.getenv("RELEASES_DIR", "releases"))
_UPDATE_FILE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
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
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'sha256-63iNIim4dZEEKxCEopD9h2k4I2qtvaNcOChCVyzU7pw=' "
        "https://pagead2.googlesyndication.com https://www.googletagservices.com "
        "https://www.googletagmanager.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com; "
        "connect-src 'self' https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com "
        "https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com; "
        "frame-src https://*.googlesyndication.com https://*.doubleclick.net; "
        "worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@web.get("/api/data")
async def get_data(response: Response, lang: str | None = None):
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
    payload = await service.get_data()
    return localize_payload(payload, lang)


@web.get("/api/history/{vendor}/{version:path}")
async def get_history_entry(vendor: str, version: str, response: Response, lang: str = "pt-BR"):
    clean_vendor = vendor.strip().lower()
    if clean_vendor not in VENDORS:
        raise HTTPException(status_code=404, detail="Vendor not found")
    clean_lang = lang.strip() if lang and lang.strip() in SUPPORTED_LANGS else "pt-BR"
    entry = await service.enrich_history_entry(clean_vendor, version.strip(), lang=clean_lang)
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
