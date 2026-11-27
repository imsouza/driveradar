import json
import tempfile
import unittest
from pathlib import Path

from advisor import AIAdvisorPool, GEMINI_API_BASE, NIM_MODEL, evaluate_risk_policy
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
        # Real-world production false positives (must all be rejected):
        self.assertFalse(SourceHub._is_relevant_alert(
            "Hackers Compromise 24 Check Point Management Servers in Suspected AI-Driven Attack Campaign",
            "Cyber threat intel researchers warn of critical security exploit.",
        ))
        self.assertEqual(_match_vendors("Cyber threat intel researchers warn of critical security exploit"), [])
        self.assertFalse(SourceHub._is_relevant_alert(
            "Microsoft pushes emergency hotpatch to fix Windows Server crashes",
            "Emergency update resolves Windows Server 2025 restarts.",
        ))
        self.assertFalse(SourceHub._is_relevant_alert(
            "Phishing scam uses fake webinars and $500 incentives to steal Google accounts",
            "Attackers impersonate Nvidia and Zoom webinars in security scam.",
        ))
        self.assertFalse(SourceHub._is_relevant_alert(
            "Kioxia and Nvidia demo 144 SSDs that expand GPU memory past 1 petabyte in a GB200 NVL72 rack",
            "Datacenter rack architecture critical milestone.",
        ))
        self.assertFalse(SourceHub._is_relevant_alert(
            "“We are crossing a threshold”: Microsoft’s AI boss warns after an unreleased AI produced a proof for a 150-year-old math problem",
            "Emergency safety discussion around AI lab models.",
        ))
        self.assertFalse(SourceHub._is_relevant_alert(
            "Microsoft named a Leader in the 2026 Gartner Magic Quadrant for Email Security",
            "Enterprise security report recognition.",
        ))
        self.assertFalse(SourceHub._is_relevant_alert(
            "Microsoft's Final Outage Report Blames a July Bug and Confirms Some Emails Never Arrived",
            "Exchange Online bug caused delayed emails.",
        ))
        # Genuine driver & OS security/regression alerts (must be kept and accurately rated):
        self.assertTrue(SourceHub._is_relevant_alert("NVIDIA GeForce Hotfix 621.35 fixes Windows 11 SSD bug", "Driver update"))
        self.assertTrue(SourceHub._is_relevant_alert("Windows 11 KB5132057 patch fixes elevation of privilege CVE-2026-9999", "Microsoft update"))
        tpu_black_screen = "NVIDIA GeForce 621.40 Stops the SSD Writes, but Now Users Report Black Screens"
        self.assertTrue(SourceHub._is_relevant_alert(tpu_black_screen, "Users report loss of signal after updating."))
        src = Source("neowin", "Neowin", "Neowin", "https://neowin.test", "specialist", 0.74)
        self.assertEqual(_classify_alert_severity(tpu_black_screen, src), "high")
        de_treiber = "GeForce-Treiber 621.40: Nach dem Hotfix macht auch der neue Treiber Probleme"
        self.assertTrue(SourceHub._is_relevant_alert(de_treiber, "Schwarzer Bildschirm nach GeForce-Treiber Update."))
        self.assertEqual(_classify_alert_severity(f"{de_treiber} Schwarzer Bildschirm", src), "high")
        bitlocker = "FastUnlock zero-day bypasses BitLocker on fully patched Windows 11"
        self.assertTrue(SourceHub._is_relevant_alert(bitlocker, "Security flaw"))
        self.assertEqual(_match_vendors(bitlocker), ["windows"])
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

            def fake_call(_, __, model, prompt):
                if "EVIDENCIAS_NAO_CONFIAVEIS" in prompt:
                    calls.append(model)
                    if model == "free-test":
                        raise ValueError("temporary failure")
                    return {"insights": {vendor: {
                        "headline": "Leitura validada", "summary": "Resumo baseado nas fontes.",
                        "summary_evidence_ids": [f"{vendor}-technical-1"],
                        "risk_assessment": {"level": "low", "score": 15, "categories": [], "critical_reasons": []},
                        "recommendation": {"action": "install", "confidence": "alta", "target_audience": "Todos", "reason": "Correção oficial disponível.", "evidence_ids": [f"{vendor}-technical-1"]},
                        "highlights": [{"text": "Novo recurso", "evidence_ids": [f"{vendor}-technical-1"]}],
                        "positive_signals": [{"text": "Correção documentada", "evidence_ids": [f"{vendor}-technical-1"]}],
                        "risk_signals": [{"text": "Sem fonte", "evidence_ids": ["unknown"]}],
                        "watch_items": [],
                    } for vendor in ("nvidia", "amd", "intel", "windows")}}
                return {"translations": {
                    lang: {
                        vendor: {
                            "headline": f"[{lang}] Headline {vendor}",
                            "summary": f"[{lang}] Summary {vendor}.",
                            "target_audience": f"[{lang}] All",
                            "reason": f"[{lang}] Official fix.",
                            "critical_reasons": [],
                            "highlights": [f"[{lang}] New feature"],
                            "positive_signals": [f"[{lang}] Documented fix"],
                            "risk_signals": [],
                            "watch_items": [],
                        }
                        for vendor in ("nvidia", "amd", "intel", "windows")
                    }
                    for lang in ("en", "es", "fr")
                }}

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
            self.assertEqual(public["assessments"]["nvidia"]["risk_assessment"]["level"], "low")
            self.assertEqual(set(public["assessments"]["nvidia"]["translations"]), {"en", "es", "fr"})

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

            def fake_call(endpoint, key, model, prompt):
                if "EVIDENCIAS_NAO_CONFIAVEIS" in prompt:
                    seen_endpoints.append((endpoint, key, model))
                    return {"insights": {vendor: {
                        "headline": "Leitura Gemini", "summary": "Resumo Gemini.",
                        "summary_evidence_ids": [f"{vendor}-technical-1"],
                        "risk_assessment": {"level": "low", "score": 12, "categories": [], "critical_reasons": []},
                        "recommendation": {"action": "install", "reason": "Estável conforme notas.", "evidence_ids": [f"{vendor}-technical-1"]},
                        "highlights": [], "positive_signals": [], "risk_signals": [], "watch_items": [],
                    } for vendor in ("nvidia", "amd", "intel", "windows")}}
                return {"translations": {
                    lang: {
                        vendor: {
                            "headline": f"[{lang}] Gemini",
                            "summary": f"[{lang}] Gemini summary.",
                            "target_audience": f"[{lang}] All",
                            "reason": f"[{lang}] Stable per notes.",
                            "critical_reasons": [],
                            "highlights": [], "positive_signals": [], "risk_signals": [], "watch_items": [],
                        }
                        for vendor in ("nvidia", "amd", "intel", "windows")
                    }
                    for lang in ("en", "es", "fr")
                }}

            pool._call = fake_call
            technical = {vendor: [{
                "title": "Notas", "summary": "Dados oficiais.", "url": f"https://example.test/{vendor}",
                "publisher": vendor.upper(), "tier": "primary", "published_at": "2026-11-19",
            }] for vendor in ("nvidia", "amd", "intel", "windows")}
            state = pool.analyze(drivers, [], technical)
            self.assertEqual(state["provider"], "Google Gemini")
            self.assertEqual(seen_endpoints[0], (GEMINI_API_BASE, "gem-test-key", "gemini-3.5-flash-lite"))

    def test_risk_policy_escalates_critical_defects_and_forbids_wait(self):
        ssd_wear = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "moderate", "score": 45, "categories": ["regression"], "critical_reasons": []},
                "recommendation": {"action": "wait", "reason": "Relatos de desgaste excessivo do SSD devido a gravações contínuas."},
                "risk_signals": [{"text": "O Display Container pode realizar gravações excessivas (3GB a 30GB por hora) no SSD em alguns PCs."}],
            },
            cited_records=[{"tier": "alert", "kind": "technical", "title": "Nvidia driver bug could be silently killing your SSD"}],
        )
        self.assertEqual(ssd_wear["risk_assessment"]["level"], "critical")
        self.assertGreaterEqual(ssd_wear["risk_assessment"]["score"], 85)
        self.assertEqual(ssd_wear["action"], "do_not_install")
        self.assertIn("hardware_damage", ssd_wear["risk_assessment"]["categories"])
        self.assertTrue(ssd_wear["risk_assessment"]["critical_reasons"])

        for sample_text, expected_cat in (
            ("Critical bug causes NTFS corruption and data loss on Windows 11", "data_loss"),
            ("Users hit boot loop and widespread BSOD after installing update", "system_crash"),
            ("Update recalled and pulled by Microsoft after failures", "recalled"),
        ):
            res = evaluate_risk_policy({
                "recommendation": {"action": "wait", "reason": "Wait for fix."},
                "risk_signals": [{"text": sample_text}],
            })
            self.assertEqual(res["risk_assessment"]["level"], "critical")
            self.assertEqual(res["action"], "do_not_install")
            self.assertIn(expected_cat, res["risk_assessment"]["categories"])

    def test_risk_policy_anti_false_positive_for_security_fixes_and_minor_issues(self):
        fixed_sec = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "low", "score": 15, "categories": [], "critical_reasons": []},
                "recommendation": {"action": "install", "reason": "Correção oficial para vulnerabilidade CVE-2026-9999 sem regressões graves."},
                "positive_signals": [{"text": "Fixes critical zero-day privilege escalation CVE-2026-9999."}],
                "risk_signals": [{"text": "Minor stutter in one legacy game when V-Sync is toggled."}],
            },
            cited_records=[{"tier": "alert", "kind": "security", "title": "Patch fixes zero-day BitLocker bypass CVE-2026-9999"}],
        )
        self.assertEqual(fixed_sec["risk_assessment"]["level"], "low")
        self.assertEqual(fixed_sec["action"], "install")
        self.assertEqual(fixed_sec["risk_assessment"]["critical_reasons"], [])

        minor_wait = evaluate_risk_policy({
            "risk_assessment": {"level": "moderate", "score": 38, "categories": ["regression"], "critical_reasons": []},
            "recommendation": {"action": "wait", "reason": "Intermittent timeout in Cyberpunk 2077 on RX 9000."},
            "risk_signals": [{"text": "Intermittent driver timeout in Cyberpunk 2077 with ray tracing enabled."}],
        })
        self.assertEqual(minor_wait["risk_assessment"]["level"], "moderate")
        self.assertEqual(minor_wait["action"], "wait")

    def test_enrich_history_entry_translates_existing_ptbr_summary_on_demand(self):
        import asyncio
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "bot_state.json"
            store = StateStore(state_path)
            store.update({
                "nvidia": {
                    "version": "621.24", "release_date": "2026-11-12", "verified": True, "primary_verified": True,
                    "source_name": "NVIDIA", "source_url": "https://nvidia.com/621.24", "official_url": "https://nvidia.com/621.24",
                },
                **{v: {"verified": False} for v in ("amd", "intel", "windows")},
            }, collected_at=1000)
            store.save_history_summary("nvidia", "621.24", {
                "headline": "Problema grave de desgaste no SSD",
                "summary": "Gravações contínuas no SSD justificam não instalar.",
                "recommendation_action": "wait",
                "recommendation_reason": "Risco de desgaste excessivo do SSD.",
                "highlights": ["Suporte DLSS"],
                "fixed_issues": [],
                "known_issues": ["Gravações excessivas (3GB a 30GB/h) no SSD"],
                "watch_items": [],
                "citations": [],
                "enriched_at": 1000,
            })

            service = DriveRadarService(state_path=state_path)
            service.advisor.gemini_key = "gem-test-key"

            def fake_call(_, __, ___, ____):
                return {"translations": {
                    lang: {
                        "headline": f"[{lang}] Severe SSD wear bug",
                        "summary": f"[{lang}] Continuous SSD writes justify avoiding this release.",
                        "recommendation_reason": f"[{lang}] Excessive SSD wear risk.",
                        "critical_reasons": [f"[{lang}] Excessive SSD writes (3GB to 30GB/h)"],
                        "highlights": [f"[{lang}] DLSS support"],
                        "fixed_issues": [],
                        "known_issues": [f"[{lang}] Excessive SSD writes (3GB to 30GB/h)"],
                        "watch_items": [],
                    }
                    for lang in ("en", "es", "fr")
                }}

            service.advisor._call = fake_call
            entry = asyncio.run(service.enrich_history_entry("nvidia", "621.24", lang="en"))
            rs = entry["release_summary"]
            self.assertEqual(rs["risk_level"], "critical")
            self.assertEqual(rs["recommendation_action"], "do_not_install")
            self.assertEqual(set(rs["translations"]), {"en", "es", "fr"})
            self.assertEqual(rs["translations"]["en"]["headline"], "[en] Severe SSD wear bug")


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
        desktop_renderer = (root / "desktop/src/renderer/renderer.js").read_text()
        desktop_css = (root / "desktop/src/renderer/styles.css").read_text()
        desktop_main = (root / "desktop/src/main.js").read_text()
        self.assertNotIn("innerHTML", desktop_renderer)
        self.assertIn("theme-select", page)
        for theme_name in ("midnight", "nord", "forest", "sand"):
            self.assertIn(theme_name, css)
            self.assertIn(theme_name, desktop_css)
            self.assertIn(theme_name, desktop_main)
        for marker in ("risk-critical", "critical-badge", "localizeAssessment", "localizeSummary"):
            self.assertIn(marker, script + css)
            self.assertIn(marker, desktop_renderer + desktop_css)

        desktop_html = (root / "desktop/src/renderer/index.html").read_text()
        desktop_main_src = (root / "desktop/src/main.js").read_text()
        self.assertIn("tab-about", desktop_html)
        self.assertIn("Confidence ≠ stability", desktop_i18n)
        self.assertIn("renderAbout", desktop_renderer)
        for obs_marker in ("drivers-observation-tip", "fresh-callout"):
            self.assertIn(obs_marker, page + script)
            self.assertIn(obs_marker, desktop_html + desktop_renderer)
        self.assertIn("drivers.waitTipBody", web_i18n)
        self.assertIn("drivers.waitTipBody", desktop_i18n)
        self.assertIn("notif.recFreshTip", desktop_i18n)
        self.assertIn("notif.recFreshTip", desktop_main_src)

        legal_js = (root / "static/js/legal.js").read_text()
        self.assertNotIn("innerHTML", legal_js)
        for legal_name in ("privacidade.html", "termos.html"):
            legal_html = (root / "static" / legal_name).read_text()
            self.assertIn("i18n.js", legal_html)
            self.assertIn("legal.js", legal_html)
            self.assertIn("lang-select", legal_html)
            self.assertIn("theme-select", legal_html)
            self.assertIn("data-i18n", legal_html)
            self.assertNotIn("fonts.googleapis.com", legal_html)
            self.assertNotIn("innerHTML", legal_html)

        readme = (root / "README.md").read_text()
        workflow = (root / ".github/workflows/release-desktop.yml").read_text()
        self.assertIn("Cross-verified", readme)
        self.assertIn("Risk Evaluation", readme)
        self.assertIn("DriveRadar Desktop for Windows", workflow)
        self.assertNotIn("para Windows", workflow)

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


class SoakMaturityAndSeniorQATests(unittest.TestCase):
    def test_monitor_uses_thread_local_http_sessions(self):
        import concurrent.futures
        import threading
        monitor = UpdateMonitor()
        barrier = threading.Barrier(2)

        def grab(_):
            sess = monitor.session
            barrier.wait(timeout=5)
            return sess

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            s1, s2 = list(pool.map(grab, range(2)))
        self.assertIsNot(s1, s2)
        self.assertIsNot(s1, monitor.session)

    def test_clause_guardrail_catches_regression_after_mitigated_clause(self):
        # Clause 1 says SSD bug was fixed ("corrigido"), Clause 2 reports black screens!
        corroborated = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "moderate", "score": 40, "categories": ["regression"], "critical_reasons": []},
                "recommendation": {
                    "action": "wait",
                    "reason": "Embora o bug de gravação no SSD tenha sido corrigido, há relatos de telas pretas e perda de sinal de vídeo.",
                },
                "risk_signals": [{"text": "Embora o bug de gravação no SSD tenha sido corrigido, há relatos de telas pretas."}],
            },
            cited_records=[
                {"publisher": "TechPowerUp", "tier": "specialist", "kind": "technical", "title": "NVIDIA 621.40 Stops the SSD Writes, but Now Users Report Black Screens"},
                {"publisher": "ComputerBase", "tier": "established", "kind": "technical", "title": "GeForce 621.40: Nach dem Hotfix schwarzer Bildschirm"},
            ],
        )
        self.assertEqual(corroborated["risk_assessment"]["level"], "critical")
        self.assertEqual(corroborated["action"], "do_not_install")
        self.assertIn("system_crash", corroborated["risk_assessment"]["categories"])
        # Mitigated SSD clause must NOT trigger hardware_damage!
        self.assertNotIn("hardware_damage", corroborated["risk_assessment"]["categories"])

    def test_corroboration_holds_single_secondary_rumor_at_high_wait(self):
        single_rumor = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "critical", "score": 88, "categories": ["system_crash"], "critical_reasons": ["Relato isolado de tela preta"]},
                "recommendation": {"action": "do_not_install", "reason": "Um blog reportou telas pretas."},
                "risk_signals": [{"text": "Users report black screens after updating."}],
            },
            cited_records=[
                {"publisher": "SingleBlog", "tier": "specialist", "kind": "technical", "title": "Users report black screens on new GPU driver"},
            ],
        )
        self.assertEqual(single_rumor["risk_assessment"]["level"], "high")
        self.assertEqual(single_rumor["action"], "wait")
        self.assertLess(single_rumor["risk_assessment"]["score"], 80)

    def test_soak_engine_quarantines_fresh_release_and_graduates_after_96h(self):
        from advisor import compute_release_maturity
        now_ts = 1_795_788_000.0  # 2026-11-27 14:00 UTC
        first_seen = int(now_ts - 18 * 3600)  # 18h old (Day 1 of 4)
        mat = compute_release_maturity("2026-11-27", first_seen, now_ts=now_ts, channel="WHQL")
        self.assertTrue(mat["in_quarantine"])
        self.assertEqual(mat["soak_day"], 1)
        self.assertEqual(mat["state"], "observing")

        # Clean fresh GPU driver must receive 'observe', NEVER premature green 'install'
        fresh_gpu = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "low", "score": 12, "categories": [], "critical_reasons": []},
                "recommendation": {"action": "install", "reason": "Notas oficiais limpas."},
                "positive_signals": [{"text": "Suporte Game Ready otimizado."}],
            },
            driver_info={"release_date": "2026-11-27", "first_seen_at": first_seen, "channel": "WHQL"},
            now_ts=now_ts,
        )
        self.assertEqual(fresh_gpu["action"], "observe")
        self.assertEqual(fresh_gpu["post_soak_action"], "install")
        self.assertEqual(fresh_gpu["risk_assessment"]["level"], "low")

        # Urgent Patch Tuesday (B) security fix with zero regressions bypasses quarantine
        urgent_patch = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "low", "score": 10, "categories": [], "critical_reasons": []},
                "recommendation": {"action": "install", "reason": "Corrige CVE-2026-7777 ativamente explorada."},
                "positive_signals": [{"text": "Patches actively exploited CVE-2026-7777."}],
            },
            driver_info={"release_date": "2026-11-27", "first_seen_at": first_seen, "channel": "Patch Tuesday (B)"},
            now_ts=now_ts,
        )
        self.assertEqual(urgent_patch["action"], "install")
        self.assertTrue(urgent_patch["maturity"]["security_bypass"])

        # Severe defect at Hour 2 jumps straight to do_not_install (never delayed by soak)
        hour2_critical = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "low", "score": 15, "categories": [], "critical_reasons": []},
                "recommendation": {"action": "install", "reason": "Novo lançamento."},
                "risk_signals": [{"text": "Driver causes severe SSD excessive writes (30GB/h) wearing out NVMe drives."}],
            },
            driver_info={"release_date": "2026-11-27", "first_seen_at": int(now_ts - 2 * 3600), "channel": "WHQL"},
            now_ts=now_ts,
        )
        self.assertEqual(hour2_critical["action"], "do_not_install")
        self.assertEqual(hour2_critical["risk_assessment"]["level"], "critical")

        # Dynamic graduation across 96h in public_state without re-calling LLM
        with tempfile.TemporaryDirectory() as tmp:
            pool = AIAdvisorPool(Path(tmp) / "advisor.json")
            pool.state = {
                "schema_version": 5,
                "status": "ready",
                "last_analysis_at": int(now_ts),
                "assessments": {
                    v: {
                        "status": "ready",
                        "version": f"v-{v}",
                        "risk_assessment": {"level": "low", "score": 15, "categories": [], "critical_reasons": []},
                        "recommendation": {"action": "observe", "post_soak_action": "install", "reason": "Limpo."},
                        "maturity": mat,
                    }
                    for v in ("nvidia", "amd", "intel", "windows")
                },
            }
            pool._write_state(pool.state)
            drivers_at_100h = {
                v: {"version": f"v-{v}", "release_date": "2026-11-27", "first_seen_at": first_seen, "channel": "WHQL"}
                for v in ("nvidia", "amd", "intel", "windows")
            }
            graduated = pool.public_state(drivers_at_100h, now_ts=now_ts + 100 * 3600)
            self.assertEqual(graduated["assessments"]["nvidia"]["recommendation"]["action"], "install")
            self.assertFalse(graduated["assessments"]["nvidia"]["maturity"]["in_quarantine"])

    def test_advisor_accepts_root_vendor_keys_without_insights_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = AIAdvisorPool(Path(tmp) / "advisor.json")
            drivers = {v: {"version": f"1.{i}", "release_date": "2026-10-01"} for i, v in enumerate(("nvidia", "amd", "intel", "windows"))}
            registry = {
                f"{v}-technical-1": {"id": f"{v}-technical-1", "vendor": v, "kind": "technical", "publisher": v.upper(), "tier": "primary", "url": f"https://{v}.test", "title": "Notes"}
                for v in ("nvidia", "amd", "intel", "windows")
            }
            raw_without_wrapper = {
                v: {
                    "headline": "Notas",
                    "summary": "Resumo.",
                    "summary_evidence_ids": [f"{v}-technical-1"],
                    "risk_assessment": {"level": "low", "score": 10, "categories": [], "critical_reasons": []},
                    "recommendation": {"action": "install", "reason": "OK", "evidence_ids": [f"{v}-technical-1"]},
                }
                for v in ("nvidia", "amd", "intel", "windows")
            }
            validated = pool._validate(raw_without_wrapper, drivers, registry)
            self.assertEqual(set(validated), {"nvidia", "amd", "intel", "windows"})
            self.assertEqual(validated["nvidia"]["recommendation"]["action"], "install")

    def test_verdict_history_records_post_release_escalation_and_shared_snapshot_never_scrapes(self):
        import asyncio
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "bot_state.json"
            store = StateStore(state_path)
            store.update({
                "nvidia": {
                    "version": "621.40", "release_date": "2026-11-24", "verified": True, "primary_verified": True,
                    "source_name": "NVIDIA", "source_url": "https://nvidia.com/621.40", "official_url": "https://nvidia.com/621.40",
                },
                **{v: {"verified": False} for v in ("amd", "intel", "windows")},
            }, collected_at=1000)
            store.save_history_summary("nvidia", "621.40", {
                "headline": "Lançamento inicial", "summary": "Sem relatos.", "risk_level": "low", "risk_score": 15,
                "recommendation_action": "observe", "recommendation_reason": "Em observação.", "enriched_at": 1100,
            })
            updated = store.save_history_summary("nvidia", "621.40", {
                "headline": "Telas pretas reportadas", "summary": "Falha grave.", "risk_level": "critical", "risk_score": 90,
                "recommendation_action": "do_not_install", "recommendation_reason": "Telas pretas.", "enriched_at": 2200,
            })
            vh = updated["history"]["nvidia"][0]["verdict_history"]
            self.assertEqual(len(vh), 2)
            self.assertEqual(vh[0]["action"], "observe")
            self.assertEqual(vh[1]["action"], "do_not_install")
            from service import _latest_verdict_change
            change = _latest_verdict_change(vh)
            self.assertTrue(change["escalated"])
            self.assertEqual(change["from_action"], "observe")
            self.assertEqual(change["to_action"], "do_not_install")

            # Shared snapshot mode (driveradar_api) must serve expired snapshot without triggering live scrape
            snap_path = Path(tmp) / "snapshot.json"
            snap_path.write_text(json.dumps({
                "schema_version": 4,
                "status": "success",
                "last_updated": 500,
                "collection": {"collected_at": 500},
                "drivers": {},
                "history": {},
                "security_alerts": [],
                "advisor": {"status": "ready", "assessments": {}},
            }), encoding="utf-8")

            class ExplodingMonitor:
                def get_release(self, _vendor):
                    raise AssertionError("Shared snapshot API must not trigger live scrape!")

            shared_svc = DriveRadarService(state_path=state_path, cache_ttl=60, monitor=ExplodingMonitor(), use_shared_snapshot=True)
            data = asyncio.run(shared_svc.get_data())
            self.assertEqual(data["status"], "success")
            self.assertGreater(data["cache_age_seconds"], 60)

    def test_i18n_four_language_key_parity_web_and_desktop(self):
        import subprocess
        root = Path(__file__).parents[1]
        node_check = r"""
        const fs = require('fs');
        const vm = require('vm');
        const desktop = require('./desktop/src/i18n.js');
        const webSrc = fs.readFileSync('./static/js/i18n.js', 'utf8');
        const m = webSrc.match(/const DICT = (\{[\s\S]*?\n  \});/);
        if (!m) throw new Error('Web DICT not found');
        const webDict = vm.runInNewContext('(' + m[1] + ')');
        const deskSrc = fs.readFileSync('./desktop/src/i18n.js', 'utf8');
        const m2 = deskSrc.match(/const DICT = (\{[\s\S]*?\n  \});/);
        if (!m2) throw new Error('Desktop DICT not found');
        const deskDict = vm.runInNewContext('(' + m2[1] + ')');
        for (const [name, dict] of [['web', webDict], ['desktop', deskDict]]) {
          const base = Object.keys(dict['pt-BR']).sort();
          for (const lang of ['en', 'es', 'fr']) {
            const cur = Object.keys(dict[lang]).sort();
            const missing = base.filter(k => !cur.includes(k));
            const extra = cur.filter(k => !base.includes(k));
            if (missing.length || extra.length) {
              throw new Error(`${name} ${lang} mismatch: missing=${missing} extra=${extra}`);
            }
            for (const k of cur) {
              if (!String(dict[lang][k]).trim()) throw new Error(`${name} ${lang}.${k} empty`);
            }
          }
        }
        console.log('PARITY_OK', Object.keys(webDict['pt-BR']).length, Object.keys(deskDict['pt-BR']).length);
        """
        proc = subprocess.run(["node", "-e", node_check], cwd=root, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertIn("PARITY_OK", proc.stdout)

    def test_fastapi_endpoints_localization_and_csp_headers(self):
        from fastapi.testclient import TestClient
        import app as web_app
        from service import localize_history_entry

        sample_entry = {
            "version": "621.40",
            "release_summary": {
                "headline": "Título PT",
                "summary": "Resumo PT",
                "recommendation_reason": "Motivo PT",
                "translations": {
                    "fr": {"headline": "Titre FR", "summary": "Résumé FR", "recommendation_reason": "Raison FR"}
                },
            },
        }
        projected = localize_history_entry(sample_entry, "fr")
        self.assertEqual(projected["release_summary"]["headline"], "Titre FR")
        self.assertEqual(sample_entry["release_summary"]["headline"], "Título PT")

        client = TestClient(web_app.app, raise_server_exceptions=True)
        for route in ("/driveradar/", "/driveradar/privacidade", "/driveradar/termos", "/driveradar/health", "/driveradar/service-worker.js"):
            resp = client.get(route)
            self.assertEqual(resp.status_code, 200, msg=route)
            self.assertIn("Content-Security-Policy", resp.headers)
            self.assertEqual(resp.headers["X-Frame-Options"], "DENY")

    def test_sourcehub_304_not_modified_reuses_http_cache(self):
        from unittest.mock import patch
        hub = SourceHub(refresh_ttl=0)
        src = Source("tpu-test", "TechPowerUp News", "TechPowerUp", "https://tpu.test/rss", "specialist", 0.8)
        rss_bytes = (
            b"<rss><channel><item><title>NVIDIA GeForce 621.40 WHQL driver released</title>"
            b"<description>Official release</description><link>https://tpu.test/1</link></item></channel></rss>"
        )

        class StreamResp:
            def __init__(self, code, body=b"", headers=None):
                self.status_code = code
                self._body = body
                self.headers = headers or {}

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise RuntimeError(self.status_code)

            def iter_content(self, _chunk):
                yield self._body

            def close(self):
                pass

        seen_headers = []

        def fake_get(_url, headers=None, **_kwargs):
            seen_headers.append(dict(headers or {}))
            if len(seen_headers) == 1:
                return StreamResp(200, rss_bytes, {"ETag": '"v1-tag"'})
            return StreamResp(304, b"", {"ETag": '"v1-tag"'})

        with patch("sources.requests.get", side_effect=fake_get):
            first = hub._fetch(src, {"nvidia": "621.40"})
            second = hub._fetch(src, {"nvidia": "621.40"})
        self.assertEqual(first["status"], "reachable")
        self.assertIn("621.40", first["matched_versions"])
        self.assertEqual(seen_headers[1].get("If-None-Match"), '"v1-tag"')
        self.assertEqual(second["http_status"], 304)
        self.assertIn("621.40", second["matched_versions"])

    def test_monitor_probe_file_size_head_content_length_fallback(self):
        class HeadSession(FakeSession):
            def head(self, url, **_kwargs):
                resp = FakeResponse("", status_code=200, url=url)
                resp.headers = {"Content-Length": str(850 * 1024 * 1024)}
                return resp

        monitor = UpdateMonitor(HeadSession({}))
        self.assertEqual(monitor._probe_file_size("https://downloadmirror.intel.com/12345/gfx_win_101.9175.exe"), "850 MB")
        self.assertIsNone(monitor._probe_file_size("https://www.intel.com/content/www/us/en/download.html"))

    def test_nvidia_hotfix_pending_escalates_risk_category(self):
        res = evaluate_risk_policy(
            {
                "risk_assessment": {"level": "moderate", "score": 45, "categories": [], "critical_reasons": []},
                "recommendation": {"action": "wait", "reason": "Hotfix disponível."},
            },
            driver_info={"channel": "WHQL", "hotfix_available": {"version": "621.45", "channel": "Hotfix"}},
        )
        self.assertIn("hotfix_pending", res["risk_assessment"]["categories"])

    def test_versionless_regression_pass2_avoids_older_version_contamination(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "bot_state.json"

            class StubMonitor:
                def get_release(self, vendor):
                    ver = {"nvidia": "621.40", "amd": "26.11.2", "intel": "32.0.101.9175", "windows": "KB5132057"}[vendor]
                    return {
                        "version": ver,
                        "release_date": "2026-11-24",
                        "channel": "WHQL",
                        "source_url": f"https://{vendor}.test",
                        "source_name": vendor.upper(),
                        "official_url": f"https://{vendor}.test/dl",
                        "release_notes_url": f"https://{vendor}.test/rn",
                        "verified": True,
                        "primary_verified": True,
                        "evidence": [{"version": ver, "publisher": vendor.upper(), "tier": "primary", "weight": 1.0, "url": f"https://{vendor}.test"}],
                        "release_notes": {"url": f"https://{vendor}.test/rn", "text": "Official notes", "structured": {}},
                        "recent_releases": [],
                    }

            class StubHub:
                def audit(self, _targets, ignored_siblings=None):
                    return {
                        "audited_at": 1_795_788_000,
                        "configured_sources": 61,
                        "reachable_sources": 60,
                        "independent_publishers": 45,
                        "corroboration": {},
                        "alerts": [],
                        "sources": [],
                        "knowledge_documents": [
                            {
                                "title": "Latest NVIDIA GeForce Game Ready driver causes black screens on RTX GPUs",
                                "summary": "Users report signal loss after updating.",
                                "url": "https://tpu.test/versionless-black-screen",
                                "publisher": "TechPowerUp",
                                "tier": "specialist",
                                "weight": 0.8,
                                "published_at": "2026-11-26T20:00:00+00:00",
                            },
                            {
                                "title": "Old NVIDIA GeForce 621.14 driver had minor crash bug",
                                "summary": "Older driver issue.",
                                "url": "https://tpu.test/old-621-14-bug",
                                "publisher": "TechPowerUp",
                                "tier": "specialist",
                                "weight": 0.8,
                                "published_at": "2026-11-26T18:00:00+00:00",
                            },
                        ],
                    }

            svc = DriveRadarService(state_path=state_path, monitor=StubMonitor(), source_hub=StubHub())
            svc._collect()
            nv_urls = [doc["url"] for doc in svc._analysis_evidence["nvidia"]]
            self.assertIn("https://tpu.test/versionless-black-screen", nv_urls)
            self.assertNotIn("https://tpu.test/old-621-14-bug", nv_urls)

    def test_desktop_v140_parity_escalation_and_api_guard_markers(self):
        root = Path(__file__).parents[1]
        pkg = json.loads((root / "desktop/package.json").read_text())
        self.assertEqual(pkg["version"], "1.4.0")
        main_js = (root / "desktop/src/main.js").read_text()
        preload_js = (root / "desktop/src/preload.js").read_text()
        renderer_js = (root / "desktop/src/renderer/renderer.js").read_text()
        web_js = (root / "static/js/app.js").read_text()
        for marker in ("settings:validateApi", "notifyEscalation", "notif.escalationTitle", "tray.tagObserve"):
            self.assertIn(marker, main_js)
        self.assertIn("validateApiEndpoint", preload_js)
        for marker in ("verdict-change-banner", "soak-meter", "copy-hash-btn", "applyValidatedApiUrl", "signal-mini-grid"):
            self.assertIn(marker, renderer_js)
        for marker in ("SEEN_VERDICTS_KEY", "verdict-change-banner", "soak-meter", "notif.escalationTitle"):
            self.assertIn(marker, web_js)
        self.assertNotIn("publisher(s) ·", web_js)


if __name__ == "__main__":
    unittest.main()
