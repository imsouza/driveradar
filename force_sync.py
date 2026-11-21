"""Run one explicit source audit, Gemini advisor refresh, and history enrichment."""

import argparse
import asyncio
import json
import os
from pathlib import Path

from service import DriveRadarService


async def main() -> None:
    parser = argparse.ArgumentParser(description="Force a full DriveRadar sync")
    parser.add_argument("--enrich-history", type=int, default=12, help="Max historical releases to enrich")
    args = parser.parse_args()

    if not os.getenv("GEMINI_API_KEY") and not Path(os.getenv("GEMINI_API_KEY_FILE", "/run/secrets/gemini_api_key")).exists():
        local_secret = Path(".secrets/gemini_api_key")
        if local_secret.exists():
            os.environ["GEMINI_API_KEY_FILE"] = str(local_secret)

    service = DriveRadarService()
    await service.get_data(force=True)
    await service.refresh_advisor()
    enriched = await service.enrich_history_batch(limit=max(0, args.enrich_history))
    data = await service.get_data()
    advisor = data.get("advisor", {})
    assessments = advisor.get("assessments", {})
    summary = {
        "status": data["status"],
        "last_updated": data["last_updated"],
        "versions": {vendor: item["version"] for vendor, item in data["drivers"].items()},
        "scores": {vendor: item["verification"]["score"] for vendor, item in data["drivers"].items()},
        "primary": {vendor: item["verification"]["primary_confirmed"] for vendor, item in data["drivers"].items()},
        "sources": {
            "reachable": data["collection"]["reachable_sources"],
            "configured": data["collection"]["configured_sources"],
        },
        "advisor": {
            "status": advisor.get("status"),
            "assessments": len(assessments),
            "vendors": {
                vendor: {
                    "risk_level": (item.get("risk_assessment") or {}).get("level"),
                    "risk_score": (item.get("risk_assessment") or {}).get("score"),
                    "action": (item.get("recommendation") or {}).get("action"),
                    "translated_langs": sorted((item.get("translations") or {}).keys()),
                }
                for vendor, item in assessments.items()
            },
        },
        "history_enriched": enriched,
    }
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
