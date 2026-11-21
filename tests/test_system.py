import json
import tempfile
import unittest
from pathlib import Path

from advisor import AIAdvisorPool, GEMINI_API_BASE, NIM_MODEL
from monitor import USER_AGENT, UpdateMonitor, parse_release_notes_sections
from service import HISTORY_LIMIT, DriveRadarService, StateStore, build_verification, migrate_state
from sources import SOURCES, Source, SourceHub, _version_in_text


class FakeResponse:
    def __init__(self, text="", content=None, status_code=200, url="https://example.test"):
        self.text = text
        self.content = content if content is not None else text.encode()
        self.status_code = status_code
        self.url = url
        self.encoding = "utf-8"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)

    def json(self):
        return json.loads(self.text)


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **_):
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        raise AssertionError(f"Unexpected URL: {url}")


class MonitorTests(unittest.TestCase):
    def test_driver_catalog_uses_windows_user_agent(self):
        self.assertIn("Windows NT 10.0", USER_AGENT)

    def test_intel_normalizes_version_and_uses_release_date(self):
        tpu = """
        <html><head><title>Latest Intel Graphics Drivers 101.8974 WHQL Download</title></head>
        <body><div class='version'><h3>Intel Graphics Drivers 101.8974 WHQL</h3>
        <span class='date'>August 17th, 2026</span></div></body></html>
        """
        official = "Current package version 32.0.101.8974; previous 32.0.101.8864"
        monitor = UpdateMonitor(FakeSession({"techpowerup": FakeResponse(tpu), "intel.cn": FakeResponse(official)}))
        release = monitor.get_driver_release("intel")
        self.assertEqual(release["version"], "32.0.101.8974")
        self.assertEqual(release["release_date"], "2026-08-17")
        self.assertTrue(release["primary_verified"])

    def test_intel_mismatched_official_version_uses_official_date_not_tpu_date(self):
        tpu = """
        <html><head><title>Latest Intel Graphics Drivers 101.9180 WHQL Download</title></head>
        <body><div class='version'><h3>Intel Graphics Drivers 101.9180 WHQL</h3>
        <span class='date'>November 20th, 2026</span></div></body></html>
        """
        official = """
        <html><head>
        <meta name="DownloadVersion" content="32.0.101.9175 WHQL Certified"/>
        <meta name="LastUpdate" content="11/04/2026 00:00:00"/>
        </head><body></body></html>
        """
        monitor = UpdateMonitor(FakeSession({"techpowerup": FakeResponse(tpu), "intel.cn": FakeResponse(official)}))
        release = monitor.get_driver_release("intel")
        self.assertEqual(release["version"], "32.0.101.9175")
        self.assertEqual(release["release_date"], "2026-11-04")
        self.assertTrue(release["primary_verified"])

    def test_nvidia_ajax_primary_extracts_version_date_and_pdf_url(self):
        ajax_payload = json.dumps({
            "Success": "1",
            "IDS": [{
                "downloadInfo": {
                    "Version": "621.24",
                    "ReleaseDateTime": "Thu Nov 12, 2026",
                    "Name": "GeForce%20Game%20Ready%20Driver",
                    "IsWHQL": "1",
                    "IsBeta": "0",
                    "DownloadURL": "https://us.download.nvidia.com/Windows/621.24/621.24-desktop.exe",
                    "DetailsURL": "https://www.nvidia.com/en-us/drivers/details/285321/",
                    "DownloadURLFileSize": "990.1 MB",
                    "ReleaseNotes": '<a href="https://us.download.nvidia.com/Windows/621.24/621.24-geforce-win11-x64-release-notes.pdf">PDF</a>',
                    "OtherNotes": "",
                }
            }]
        })
        tpu = """
        <html><head><title>Latest NVIDIA GeForce Graphics Drivers 621.24 WHQL Download</title></head>
        <body><div class='version'><h3>NVIDIA GeForce Graphics Drivers 621.24 WHQL</h3>
        <span class='date'>November 12th, 2026</span></div></body></html>
        """
        monitor = UpdateMonitor(FakeSession({
            "AjaxDriverService": FakeResponse(ajax_payload),
            "release-notes.pdf": FakeResponse("621.24 Release Notes", content=b"%PDF-1.4 621.24"),
            "techpowerup": FakeResponse(tpu),
        }))
        release = monitor.get_driver_release("nvidia")
        self.assertEqual(release["version"], "621.24")
        self.assertEqual(release["release_date"], "2026-11-12")
        self.assertTrue(release["primary_verified"])
        self.assertEqual(release["source_name"], "NVIDIA")
        self.assertIn("release-notes.pdf", release["release_notes_url"])

    def test_windows_date_comes_from_ga_row_not_collection_day(self):
        html = """
        <table><tr><td>General Availability Channel</td><td>2026-08 B</td>
        <td>2026-08-11</td><td>26200.9168</td>
        <td><a href='https://support.microsoft.com/help/5121003'>KB5121003</a></td></tr></table>
        """
        monitor = UpdateMonitor(FakeSession({
            "release-health": FakeResponse(html),
            "support.microsoft": FakeResponse("<main><h2>Highlights</h2><ul><li>Security fixes for core kernel components.</li></ul></main>"),
        }))
        release = monitor.get_windows_release()
        self.assertEqual(release["version"], "KB5121003")
        self.assertEqual(release["release_date"], "2026-08-11")
        self.assertEqual(release["os_build"], "26200.9168")

    def test_release_notes_section_parser_strips_toc_and_extracts_fixes(self):
        sample = """
        2.1 Version 621.24 WHQL Highlights ........................................ 7
        3.1 Fixed Issues .......................................................... 14
        2.4 What's New in Version 621.24 WHQL
        Game Ready for Dawn of War IV with DLSS 5 support.
        3.1.2 Fixed General Bugs
        > Chaos Vantage: NVIDIA OptiX Denoiser may fail at high resolutions. [6953474]
        3.2 Open Issues in Version 621.24 WHQL
        > Windows Photos: Minor flicker on multi-monitor setups. [123456]
        """
        sections = parse_release_notes_sections(sample, vendor="nvidia")
        self.assertTrue(any("Dawn of War IV" in item for item in sections["highlights"]))
        self.assertTrue(any("Chaos Vantage" in item for item in sections["fixed_issues"]))
        self.assertTrue(any("Windows Photos" in item for item in sections["known_issues"]))


class CrossoverAndSourceTests(unittest.TestCase):
    def test_version_boundary_prevents_cisa_substring_false_positive(self):
        cisa_doc = "CISA Catalog of Known Exploited Vulnerabilities catalogVersion 2026.11.20"
        self.assertFalse(_version_in_text("26.11.2", cisa_doc, "amd"))
        self.assertFalse(_version_in_text("621.24", "Some random build 621.24 without GPU context", "nvidia"))
        self.assertTrue(_version_in_text("26.11.2", "AMD Radeon Adrenalin 26.11.2 WHQL released today", "amd"))
        self.assertTrue(_version_in_text("32.0.101.9175", "Intel Arc Graphics 101.9175 WHQL driver update", "intel"))
        # Word-boundary vendor context must not falsely match "arc" inside "Search".
        from sources import _match_vendors
        self.assertEqual(_match_vendors("Windows 11 KB5132057 out with native Search"), ["windows"])

    def test_external_conflict_flags_only_strictly_newer_headline(self):
        results = [
            {
                "source": Source("tpu-news", "TechPowerUp News", "TechPowerUp", "https://tpu.test/rss", "specialist", 0.8),
                "status": "reachable",
                "documents": [
                    {
                        "title": "NVIDIA's SSD Write Bug Gets Patched in GeForce Hotfix 621.35 Driver",
                        "summary": "Hotfix 621.35 fixes bug from 621.24",
                        "url": "https://tpu.test/news/hotfix-621-35",
                        "published_at": "2026-11-20T12:00:00+00:00",
                    },
                    {
                        "title": "Older NVIDIA GeForce 621.14 driver review",
                        "summary": "Review of older release",
                        "url": "https://tpu.test/news/old-621-14",
                        "published_at": "2026-11-18T12:00:00+00:00",
                    },
                    {
                        "title": "KB5132265 (Build 28000.3620) for Windows 11 26H1 drops",
                        "summary": "26H1 sibling update",
                        "url": "https://tpu.test/news/win11-26h1",
                        "published_at": "2026-11-20T12:00:00+00:00",
                    },
                ],
            }
        ]
        conflicts = SourceHub._detect_external_conflicts(
            results, {"nvidia": "621.24", "windows": "KB5132057"}, ignored_siblings={"windows": {"KB5132265"}}
        )
        self.assertEqual(len(conflicts["621.24"]), 1)
        self.assertEqual(conflicts["621.24"][0]["version"], "621.35")
        self.assertEqual(conflicts["621.24"][0]["url"], "https://tpu.test/news/hotfix-621-35")
        self.assertEqual(conflicts["KB5132057"], [])

    def test_relevant_alert_filtering_drops_unrelated_cves_and_gossip(self):
        from sources import _classify_alert_severity, _match_vendors
        self.assertFalse(SourceHub._is_relevant_alert("Memory corruption vulnerabilities in PHP CVE-2026-1111", "PHP patch"))
        self.assertFalse(SourceHub._is_relevant_alert("WhatsApp Fixes Flaw Uncovered While Disrupting Scam", "Android patch"))
        self.assertFalse(SourceHub._is_relevant_alert("Nvidia CEO Scandal Rocks AI Industry", "Stock news"))
        self.assertFalse(SourceHub._is_relevant_alert("Season's Streamings and Savings: Black Friday Deals Come to GeForce NOW", "GeForce NOW Black Friday"))
        self.assertFalse(SourceHub._is_relevant_alert("Microsoft Unlocks Up To 16% More Xbox Speed With Open-Source AMD Code", "DirectX open-source performance boost"))
        self.assertTrue(SourceHub._is_relevant_alert("NVIDIA GeForce Hotfix 621.35 fixes Windows 11 SSD bug", "Driver update"))
        self.assertTrue(SourceHub._is_relevant_alert("Windows 11 KB5132057 patch fixes elevation of privilege CVE-2026-9999", "Microsoft update"))
        bitlocker = "FastUnlock zero-day bypasses BitLocker on fully patched Windows 11"
        self.assertTrue(SourceHub._is_relevant_alert(bitlocker, "Security flaw"))
        self.assertEqual(_match_vendors(bitlocker), ["windows"])
        src = Source("neowin", "Neowin", "Neowin", "https://neowin.test", "specialist", 0.74)
        self.assertEqual(_classify_alert_severity(bitlocker, src), "critical")

    def test_amd_official_driver_page_extracts_date_and_full_package_size(self):
        amd_page = """
        <div><strong>File Size</strong><p>46 MB</p></div>
        <div><a href="https://drivers.amd.com/drivers/installer/26.20/whql/amd-software-adrenalin-edition-26.11.2-minimalsetup-261118_web.exe">Auto-Detect</a></div>
        <div>Revision Number</div><div>Adrenalin 26.11.2 WHQL (Recommended)</div>
        <div><strong>File Size</strong><p>887 MB</p></div>
        <div><strong>Release Date</strong>\n<p>\n2026-11-18\n</p></div>
        <a href="https://drivers.amd.com/drivers/whql-amd-software-adrenalin-edition-26.11.2-win11-b.exe">Download</a>
        """
        amd_rn = "<main><h2>Highlights</h2><ul><li>Stability and ROCm 10.2 support for 26.11.2.</li></ul></main>"
        monitor = UpdateMonitor(FakeSession({
            "amd-radeon-rx-9070-xt.html": FakeResponse(amd_page),
            "RN-RAD-WIN-26-11-2.html": FakeResponse(amd_rn),
            "techpowerup": FakeResponse("", status_code=403),
        }))
        release = monitor.get_driver_release("amd")
        self.assertEqual(release["version"], "26.11.2")
        self.assertEqual(release["release_date"], "2026-11-18")
        self.assertEqual(release["file_size"], "887 MB")
        self.assertTrue(release["primary_verified"])


class StateAndScoringTests(unittest.TestCase):
    def test_legacy_generated_claims_are_not_migrated(self):
        legacy = {"last_nv": "610.88", "hist_nv": [{"version": "610.88", "sentiment": "Estável"}]}
        self.assertEqual(migrate_state(legacy)["history"]["nvidia"], [])

    def test_v3_state_migrates_losslessly_to_v4(self):
        v3 = {
            "schema_version": 3,
            "last_successful_sync": 123,
            "releases": {"amd": {"version": "26.11.2", "date": "2026-11-19", "primary_verified": True}},
            "history": {"amd": [{"version": "26.11.2", "date": "2026-11-19", "primary_verified": True, "verified_at": 123}]},
        }
        migrated = migrate_state(v3)
        self.assertEqual(migrated["schema_version"], 4)
        self.assertEqual(len(migrated["history"]["amd"]), 1)
        self.assertEqual(migrated["history"]["amd"][0]["release_notes_url"], "https://www.amd.com/en/resources/support-articles/release-notes/RN-RAD-WIN-26-11-2.html")

    def test_publishers_are_deduplicated_and_conflicts_penalize(self):
        release = {"version": "610.88", "evidence": [
            {"publisher": "NVIDIA", "version": "610.88", "tier": "primary", "weight": 1.0},
            {"publisher": "NVIDIA", "version": "610.88", "tier": "primary", "weight": 1.0},
            {"publisher": "TechPowerUp", "version": "610.88", "tier": "specialist", "weight": 0.8},
            {"publisher": "Example", "version": "610.77", "tier": "established", "weight": 0.7},
        ]}
        result = build_verification(release, [])
        self.assertEqual(result["independent_publishers"], 2)
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertEqual(result["score"], 60)
        self.assertTrue(len(result["breakdown"]) >= 2)

    def test_history_keeps_configured_limit_and_full_details(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.json")
            for index in range(HISTORY_LIMIT + 4):
                releases = {
                    vendor: {
                        "version": f"v-{vendor}-{index}", "release_date": "2026-08-20",
                        "verified": True, "primary_verified": True, "source_name": "Official",
                        "source_url": "https://example.test/source", "official_url": "https://example.test/download",
                    }
                    for vendor in ("nvidia", "amd", "intel", "windows")
                }
                state = store.update(releases, 100 + index)
            self.assertEqual(len(state["history"]["nvidia"]), HISTORY_LIMIT)
            self.assertEqual(state["history"]["nvidia"][0]["verified_at"], 100 + HISTORY_LIMIT + 3)
            self.assertEqual(state["history"]["nvidia"][0]["source_url"], "https://example.test/source")

    def test_service_bootstraps_from_last_verified_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            path.write_text(json.dumps({
                "schema_version": 3,
                "last_successful_sync": 123,
                "releases": {"nvidia": {
                    "version": "610.88", "date": "2026-07-28", "source_name": "NVIDIA",
                    "source_url": "https://nvidia.com/release", "official_url": "https://nvidia.com/download",
                    "primary_verified": True,
                }},
                "history": {vendor: [] for vendor in ("nvidia", "amd", "intel", "windows")},
            }), encoding="utf-8")
            service = DriveRadarService(state_path=path)
            self.assertEqual(service._cache["status"], "warming")
            self.assertIn("advisor", service._cache)


class AdvisorPoolTests(unittest.TestCase):
    def test_pool_fails_over_to_nim_and_validates_all_assessments(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = AIAdvisorPool(Path(directory) / "advisor.json")
            pool.gemini_key = None
            pool.zen_key = "zen-test"
            pool.nim_key = "nim-test"
            pool.zen_models = ("free-test",)
            drivers = {
                vendor: {
                    "version": f"v-{vendor}",
                    "release_date": "2026-09-04",
                    "source_status": "verified",
                    "verification": {
                        "score": 80, "primary_confirmed": True,
                        "independent_publishers": 2, "conflicts": [],
                        "agreements": [{
                            "publisher": f"Official {vendor}", "source_name": f"Official {vendor}",
                            "version": f"v-{vendor}", "tier": "primary", "url": "https://example.test/source",
                        }],
                    },
                }
                for vendor in ("nvidia", "amd", "intel", "windows")
            }
            calls = []

            def fake_call(_, __, model, ___):
                calls.append(model)
                if model == "free-test":
                    raise ValueError("temporary failure")
                return {"insights": {vendor: {
                    "headline": "Leitura validada", "summary": "Resumo baseado nas fontes.",
                    "summary_evidence_ids": [f"{vendor}-technical-1"],
                    "recommendation": {"action": "install", "confidence": "alta", "target_audience": "Todos", "reason": "Correção oficial disponível.", "evidence_ids": [f"{vendor}-technical-1"]},
                    "highlights": [{"text": "Novo recurso", "evidence_ids": [f"{vendor}-technical-1"]}],
                    "positive_signals": [{"text": "Correção documentada", "evidence_ids": [f"{vendor}-technical-1"]}],
                    "risk_signals": [{"text": "Sem fonte", "evidence_ids": ["unknown"]}],
                    "watch_items": [],
                } for vendor in ("nvidia", "amd", "intel", "windows")}}

            pool._call = fake_call
            technical = {vendor: [{
                "title": "Notas oficiais", "summary": "Correção documentada.",
                "url": f"https://example.test/{vendor}-notes", "publisher": f"Official {vendor}",
                "tier": "primary", "published_at": "2026-09-04",
            }] for vendor in ("nvidia", "amd", "intel", "windows")}
            state = pool.analyze(drivers, [], technical)
            self.assertEqual(calls, ["free-test", NIM_MODEL])
            self.assertEqual(state["provider"], "NVIDIA NIM fallback")
            self.assertEqual(set(state["assessments"]), {"nvidia", "amd", "intel", "windows"})
            public = pool.public_state(drivers)
            self.assertEqual(public["status"], "ready")
            self.assertNotIn("provider", public)
            self.assertNotIn("model", public)
            self.assertEqual(public["assessments"]["nvidia"]["positive_signals"][0]["citations"][0]["publisher"], "Official nvidia")
            self.assertEqual(public["assessments"]["nvidia"]["recommendation"]["action"], "install")
            self.assertEqual(public["assessments"]["nvidia"]["risk_signals"], [])

    def test_gemini_is_primary_provider_when_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = AIAdvisorPool(Path(directory) / "advisor.json")
            pool.gemini_key = "gem-test-key"
            pool.gemini_models = ("gemini-3.5-flash-lite",)
            pool.zen_key = "zen-test"
            drivers = {
                vendor: {
                    "version": f"v-{vendor}", "release_date": "2026-11-19", "source_status": "verified",
                    "verification": {"score": 88, "primary_confirmed": True, "independent_publishers": 3, "conflicts": [], "agreements": []},
                }
                for vendor in ("nvidia", "amd", "intel", "windows")
            }
            seen_endpoints = []

            def fake_call(endpoint, key, model, _prompt):
                seen_endpoints.append((endpoint, key, model))
                return {"insights": {vendor: {
                    "headline": "Leitura Gemini", "summary": "Resumo Gemini.",
                    "summary_evidence_ids": [f"{vendor}-technical-1"],
                    "recommendation": {"action": "install", "reason": "Estável conforme notas.", "evidence_ids": [f"{vendor}-technical-1"]},
                    "highlights": [], "positive_signals": [], "risk_signals": [], "watch_items": [],
                } for vendor in ("nvidia", "amd", "intel", "windows")}}

            pool._call = fake_call
            technical = {vendor: [{
                "title": "Notas", "summary": "Dados oficiais.", "url": f"https://example.test/{vendor}",
                "publisher": vendor.upper(), "tier": "primary", "published_at": "2026-11-19",
            }] for vendor in ("nvidia", "amd", "intel", "windows")}
            state = pool.analyze(drivers, [], technical)
            self.assertEqual(state["provider"], "Google Gemini")
            self.assertEqual(seen_endpoints[0], (GEMINI_API_BASE, "gem-test-key", "gemini-3.5-flash-lite"))


class RegistryAndFrontendTests(unittest.TestCase):
    def test_registry_has_dozen_scale_independent_trusted_publishers(self):
        self.assertGreaterEqual(len(SOURCES), 55)
        self.assertGreaterEqual(len({source.publisher for source in SOURCES}), 40)

    def test_frontend_security_history_notifications_and_ads(self):
        root = Path(__file__).parents[1]
        script = (root / "static/js/app.js").read_text()
        page = (root / "static/index.html").read_text()
        css = (root / "static/css/style.css").read_text()
        server = (root / "app.py").read_text()
        worker = (root / "static/service-worker.js").read_text()
        analytics = (root / "static/js/analytics.js").read_text()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", server)
        self.assertIn("history-dialog", page)
        self.assertIn("overflow-y: scroll", css)
        self.assertIn("Notification.requestPermission", script)
        self.assertIn("ALERT_PREFS_KEY", script)
        self.assertIn("vulnerabilities", script)
        self.assertIn("alert-category-all", page)
        self.assertIn("RESULTADO DO CROSSOVER", script)
        self.assertIn("O QUE AS FONTES DIZEM", script)
        self.assertIn("RECOMENDAÇÃO", script)
        self.assertIn("FONTES CRUZADAS", script)
        self.assertIn("do_not_install", script)
        self.assertNotIn("advisor.provider", script)
        self.assertIn("notificationclick", worker)
        self.assertIn("ca-pub-7513394193260475", page)
        self.assertIn("G-36YL9QLC5K", page)
        self.assertIn("G-36YL9QLC5K", analytics)
        web_i18n = (root / "static/js/i18n.js").read_text()
        desktop_i18n = (root / "desktop/src/i18n.js").read_text()
        for code in ("pt-BR", "en", "es", "fr"):
            self.assertIn(code, web_i18n)
            self.assertIn(code, desktop_i18n)
        self.assertNotIn("innerHTML", web_i18n)
        self.assertNotIn("innerHTML", desktop_i18n)

    def test_updates_endpoint_validation_and_latest_manifest_resolution(self):
        import asyncio
        from fastapi import HTTPException
        import app as web_app

        with tempfile.TemporaryDirectory() as tmp:
            rel_dir = Path(tmp)
            (rel_dir / "latest.yml").write_text("version: 1.0.0\npath: DriveRadar-Setup-1.0.0.exe\n", encoding="utf-8")
            (rel_dir / "DriveRadar-Setup-1.0.0.exe").write_bytes(b"MZ")
            self.assertEqual(web_app._resolve_latest_installer(rel_dir), "DriveRadar-Setup-1.0.0.exe")

            original_dir = web_app.RELEASES_DIR
            web_app.RELEASES_DIR = rel_dir
            try:
                resp = asyncio.run(web_app.latest_windows_installer())
                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp.headers["location"], "/driveradar/updates/DriveRadar-Setup-1.0.0.exe")
                with self.assertRaises(HTTPException):
                    asyncio.run(web_app.update_artifact("../etc/passwd"))
                with self.assertRaises(HTTPException):
                    asyncio.run(web_app.update_artifact("secret.txt"))
                yml_resp = asyncio.run(web_app.update_artifact("latest.yml"))
                self.assertEqual(yml_resp.headers["cache-control"], "no-cache")
            finally:
                web_app.RELEASES_DIR = original_dir


if __name__ == "__main__":
    unittest.main()
