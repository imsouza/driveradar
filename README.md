# DriveRadar

Cross-verified release tracker for **NVIDIA GeForce**, **AMD Radeon**, **Intel Arc**, and **Windows 11** updates with deterministic risk scoring, AI technical interpretation, Web dashboard, and Windows Desktop notifications.

## Data Verification & Crossover Score

- **Primary source verification**: Candidate versions are discovered on official vendor feeds or APIs and cross-checked against independent technical publishers.
- **Publisher deduplication**: Multiple URLs belonging to the same organization count once.
- **Boundary-safe matching**: Corroboration requires strict version boundaries and vendor context, preserving exact source URLs.
- **External conflict detection**: Flags trustworthy reports of newer hotfixes or uncatalogued releases not yet promoted in official catalogs.
- **Honest availability**: Community telemetry is never fabricated; collection failures expose `stale` or `unavailable` states while preserving the last verified record.

### Deterministic Confidence Formula (0–98)

- **+72 pts**: Official vendor or authority confirmation
- **+8 pts** per agreeing independent publisher (up to **+24 pts**)
- **-20 pts** per conflicting version report (up to `-50`)
- **-20 pts** if only persisted `stale` data is available
- Capped at **98** (confidence scores confirm version and release date accuracy — never hardware-specific stability)

## Precision 4-Tier Risk Evaluation Engine

Each verified release runs through both AI evidence synthesis and deterministic policy guardrails (`advisor.py`) so critical defects are never masked as neutral advice:

| Risk Level | Score | Enforced Recommendation | Triggers |
| :--- | :--- | :--- | :--- |
| **Critical** | `80–100` | **`do_not_install`** (Red alert badge) | Hardware damage (e.g., excessive SSD writes / overheating / bricking), filesystem or data corruption, boot loops / widespread BSOD, official vendor recall, or active unmitigated critical flaw |
| **High** | `55–79` | `wait` | Widespread functional regressions or newer official hotfix pending |
| **Moderate** | `25–54` | `wait` / `install` | Localized known issues (1–2 specific games/apps) or optional/Preview builds without critical risk |
| **Low** | `0–24` | `install` | Clean WHQL/GA release, including security patches that **fix** CVEs without introducing regressions (anti-false-positive rule) |

## AI Provider Pool & Failover

Textual assessments and historical release summaries use a JSON-validated failover pool grounded strictly in collected evidence IDs:

1. **Google Gemini API** (`GEMINI_API_KEY_FILE`, default `/run/secrets/gemini_api_key`)
2. **OpenCode Zen** free models (optional fallback)
3. **NVIDIA NIM** (optional fallback)
4. Last valid persisted analysis if all upstream providers are temporarily unavailable

## Multilingual & Theme Support

- **4 Languages (`pt-BR`, `en`, `es`, `fr`)**: Complete translation across the Web dashboard, Desktop app, Windows notifications, system tray menus, Privacy & Terms pages, Crossover score breakdown, and AI assessments + on-demand historical summaries.
- **6 Curated Themes + OS Sync**: `System`, `Graphite (Dark)`, `Light`, `Midnight OLED`, `Nordic`, `Emerald`, and `Sand`.

## History & Browser Alerts

- Preserves up to **24 primarily verified versions** per vendor in a scrollable list (`overflow-y: scroll`).
- Each version exposes channel/OS build, release date, Crossover breakdown, structured release notes, risk classification, and 4-language AI summaries (enriched automatically in the background and on demand).
- Browser **Alert settings** request notification permission for new releases and relevant security alerts.

## Windows Desktop App (`desktop/`)

Minimalist Electron client for Windows 10/11 located in `desktop/`:

- **System Tray Background Mode**: Minimize or close to the tray (`--hidden`), optional Windows sign-in autostart, and visual unread alert indicator.
- **Native Windows Notifications**: Per-vendor toggles, Beta/Preview filter, external hotfix conflict alerts, security severity threshold, quiet hours, and **automatic app update notifications** (`available` and `downloaded` ready-to-install prompts).
- **Auto-Updates**: Powered by `electron-updater` using the `generic` HTTPS provider pointing to `https://optlabs.com.br/driveradar/updates/` (serving `./releases:/app/releases:ro`).
- **CI Releases**: [.github/workflows/release-desktop.yml](.github/workflows/release-desktop.yml) compiles `DriveRadar-Setup-*.exe` (NSIS installer), `.blockmap`, `latest.yml`, and `DriveRadar-Portable-*.exe` on `windows-latest` whenever a `v*` tag is pushed.

## Sources & Advertising

- `sources.py` monitors **55+ independent security authorities, research teams, vendor feeds, and hardware publications**.
- Google AdSense Auto Ads (`ca-pub-7513394193260475`) and `/ads.txt` are served under a strict Content Security Policy with zero `innerHTML` usage.

## Running with Docker

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8512/driveradar/health
```

Optional environment variables:

- `CACHE_TTL_SECONDS`: Collection interval in seconds (default `3600`).
- `API_SECRET_KEY`: Enables internal API endpoints on port `8513` (returns `503` if unset).
- `API_ALLOWED_ORIGINS`: Allowed CORS origins for the internal API.
- `APP_UID` / `APP_GID`: Non-privileged container user IDs.
- `GEMINI_API_KEY_FILE`: Path to Gemini secret file (default `/run/secrets/gemini_api_key`).
- `GEMINI_MODELS`: Comma-separated ordered list of Gemini model IDs.
- `OPENCODE_ZEN_MODELS` / `OPENCODE_ZEN_API_KEY_FILE`: Optional OpenCode Zen fallback settings.
- `NVIDIA_API_KEY_FILE`: Optional NVIDIA NIM fallback secret path.

## Testing

```bash
.venv/bin/python -m unittest discover -s tests -v
node --check static/js/i18n.js && node --check static/js/app.js && node --check static/js/legal.js
(cd desktop && npm run check)
docker compose config -q
```
