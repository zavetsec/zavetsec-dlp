# Changelog

All notable changes to ZavetSec DLP are documented in this file.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`

---

## [Unreleased]

### Added
- **Multi-monitor screenshots** — each screen captured independently in the same capture cycle;
  files named `HHmmss_trigger_m1.jpg`, `_m2.jpg`; per-monitor blank screen detection
- **Email alerts (SMTP)** — configurable via Management tab or `appsettings.json`; rate-limited
  (1 per host+module per 5 min); supports TLS port 587 and SSL port 465; background send
- **Certificate fingerprint pinning** — set `"serverFingerprint"` in agent `config.json`
  (SHA-256 printed at server startup); agents reject connections to unrecognised certificates
- **Live feed toggle** — ⬤ Live button in dashboard header; switches auto-refresh from 30s to 5s
- **Per-agent API keys** — agents auto-enroll on first heartbeat and receive a unique key stored
  in `config.json`; Management → Agent Keys shows all enrolled keys with revocation button;
  revoked agents re-enroll automatically with global key; header: `X-Agent-Key`
- **Watchdog timer** — checks every 60 seconds that LogShipper and ScreenshotShipper are running;
  re-registers the ONLOGON scheduled task if it was deleted (basic tamper resistance)
- **Email section in Management tab** — SMTP form with dark-theme inputs matching rest of UI;
  Refresh / Save / Send Test buttons; settings saved directly to `appsettings.json`
- **Database migration v8** — `agent_status` column in `hosts` table for three-color status indicator
- **Database migration v9** — `agent_keys` table for per-agent authentication

### Planned
- Per-agent authentication (unique key per agent)
- Certificate fingerprint pinning
- Multi-monitor screenshot support
- PostgreSQL backend
- WebSocket live event feed
- SIEM integration (Syslog/CEF)

---

## [1.0.1] — 2026-05-22

### Fixed
- **`/api/auth/change-password` returned 500 with empty body** — the entire `/api/auth/*` path was
  marked public in middleware, so `ctx.Items["session"]` was null; fix: only `/api/auth/login` and
  `/api/auth/me` are public now
- **Agent shows Offline after Stop command** — `StopInternal()` was stopping `CommandPoller`,
  so the agent could not receive the subsequent `start` command; fix: CommandPoller now keeps
  running when monitoring is stopped, only monitors are paused
- **Screenshots not uploading** — `ScreenshotShipper.Init()` was missing from `DlpService`
  and `ScreenshotMonitor` was not calling `ScreenshotShipper.Enqueue()` after capture
- **Agent shows Offline / "Invalid Date"** after adding `agent_id` column — column indices in
  `GetAgentStatuses` were off by 2 after adding `agent_id` and `first_seen` to SELECT query
- **`SCREENSHOT_ERROR: Win32Exception: Invalid Handle`** from SYSTEM session — ONSTART scheduled
  task runs as SYSTEM in Session 0 with no desktop access; fix: `ScreenshotMonitor.Capture()`
  now skips capture when `SessionId == 0`
- **Brute force protection not working** — `login_attempts.ip` column was missing `UNIQUE`
  constraint, so `ON CONFLICT(ip)` never triggered; fix: migration v4 recreates table with
  correct constraint
- **Ingest error: `ON CONFLICT clause does not match any PRIMARY KEY`** — after migration v6
  changed `hosts` PRIMARY KEY to `(agent_id, host)`, `InsertBatch` still used
  `ON CONFLICT(host)`; fix: changed to simple `UPDATE hosts SET last_seen WHERE host`
- **`CryptographicException: Wrong password`** on first run from release — documented in
  Troubleshooting with cause list and fix steps; `appsettings.example.json` updated with warning
- **`[FromQuery]` attribute not found** in `/api/audit` endpoint — not available in Minimal API
  without MVC; fix: read query parameters manually from `ctx.Request.Query`
- **Build fails with `cannot access ZavetSecDlpAgent.exe`** — documented in README; agent must
  be stopped before rebuild

### Added
- **Unique Agent ID** — each agent generates a persistent 16-char hex UUID on first run,
  saved to `config.json` as `shipper.agentId`; sent as `X-Agent-Id` header in all API calls;
  prevents conflicts when multiple machines share the same hostname
- **Agent lifecycle events** — `AGENT_ONLINE` on first heartbeat from a new agent,
  `AGENT_REMOVED` when removed from dashboard, `AGENT_UNINSTALLED` when uninstall command
  is confirmed by the agent; all appear in the Events tab with `user=system`
- **Admin Audit Log tab** (admin only) — chronological log of all admin actions: LOGIN,
  LOGOUT, PASSWORD_CHANGE, USER_CREATE, USER_DELETE, SCREENSHOT_DELETE, DATA_DELETE,
  SEND_COMMAND_UNINSTALL, SEND_COMMAND_STOP; color-coded, searchable, paginated
- **`GET /api/audit`** endpoint — returns last 500 audit entries (admin only)
- **Session 0 detection in ScreenshotMonitor** — silently skips screenshot capture when
  running as SYSTEM (SessionId == 0); logged as `SCREENSHOT_SKIP` to local log only
- **HTTP disable recommendation** — documented in README HTTPS section and `appsettings.example.json`
  with comments; production deployments should remove the `Http` Kestrel endpoint
- **`SECURITY.md`** — vulnerability reporting policy, security design boundaries,
  detection evasion disclaimer, known limitations
- **Production hardening table** in README — reverse proxy, VPN, firewall, key rotation, backup
- **Compliance considerations** in README — GDPR, employee notification, retention, access control
- **`AgentStatus` model** extended with `AgentId` and `FirstSeen` fields
- **Database migration v5** — `audit_log` table with immutable admin action records
- **Database migration v6** — `hosts` table rebuilt with `agent_id` and `first_seen` columns,
  composite PRIMARY KEY `(agent_id, host)`; existing rows migrated with generated pseudo-IDs

### Changed
- **`StopInternal()`** no longer stops `CommandPoller` — poller keeps running to receive
  commands while monitoring is paused
- **`InitCommandPoller()`** extracted as separate method, called once at startup;
  `StartInternal()` no longer creates a new poller on each invocation
- **`isPublic` middleware** — narrowed from `path.StartsWith("/api/auth/")` to only
  `/api/auth/login` and `/api/auth/me`; `change-password` and `logout` now require session
- **`install.ps1`** — ONLOGON task no longer uses `/ru SYSTEM` (required for screenshot
  desktop access); ONSTART task still uses SYSTEM for boot persistence
- **Dashboard** — "Users" tab renamed to "Management"; language switcher added (EN/RU);
  Uninstall button added for both Online and Offline agents
- **CSV export** — UTF-8 BOM added to `QueryCsv()` output for correct Excel display
- **`appsettings.example.json`** — added `_COMMENT_` keys explaining HTTP disable and
  certificate password timing

---

## [1.0.0] — 2026-05-19

### First stable production release

---

### Agent

**Core monitors:**
- `KeyloggerMonitor` — WH_KEYBOARD_LL hook, keyboard layout support, dead keys, special keys
- `ClipboardMonitor` — polling-based clipboard monitoring with configurable sensitive word alerts
- `ScreenshotMonitor` — interval + window-change capture, blank screen detection, JPEG quality control
- `NetworkMonitor` — TCP connection monitoring on configurable alert ports, DNS cache tracking
- `UsbMonitor` — WMI-based USB device detection
- `FileActivityMonitor` — FileSystemWatcher on removable drives
- `ProcessMonitor` — process launch tracking with whitelist and suspicious process alerts

**Data pipeline:**
- `LogShipper` — batched event delivery, in-memory queue, persistent disk buffer up to 50 MB,
  exponential backoff (30s → 30 min)
- `ScreenshotShipper` — async screenshot upload, automatic local deletion after upload
- `CommandPoller` — remote command polling, heartbeat updates `last_seen` on every poll

**Security:**
- `Logger` — AES-256-CBC encrypted local logs, key protected by Windows DPAPI (machine scope)
- Lazy `HttpClient` initialization (safe static field order)
- `allowInvalidCertificate` option for self-signed HTTPS

**Configuration (`config.json`):**
- Auto-generated on first run with sensible defaults
- `AppContext.BaseDirectory` used (fixes IL3000 warning in single-file apps)

---

### Server

**API:** events, screenshots, commands, agents, stats, CSV export, auth, users, health, Telegram

**Security:**
- Brute force protection: 5 failed attempts → 15-minute IP lockout
- Rate limiting: 1,000 req/min/IP on agent endpoints (HTTP 429 + Retry-After)
- Session invalidation on password change
- PBKDF2-SHA256, 100,000 iterations, 16-byte salt
- 32-byte random session tokens, 24h TTL with sliding expiry
- Role-based access: `admin` / `viewer`
- Forced password change on first login

**HTTPS:**
- Self-signed certificate auto-generated (RSA 2048, SHA-256, 10 years)
- SAN: localhost, hostname, 127.0.0.1

**Database:** SQLite, WAL mode, migration system (schema_version table), schema v4 on release

**Telegram:** per-module filters, rate limit 30s/host+module, test endpoint

---

### Dashboard

5 tabs: Events, Screenshots, Keylogger, Agents, Management (admin)
Auto-refresh 30s, EN/RU i18n, localStorage language preference

---

### Deployment

- `install.ps1` — single-machine install with Defender exclusion, config generation, scheduled tasks
- `deploy.ps1` — WinRM parallel deployment, ping check, PSCredential, CSV report

---

## Known Limitations (v1.0.0)

- Primary display only (no multi-monitor)
- No code signing — AV exclusion required
- SQLite not recommended above ~50 GB
- Shared API key for all agents
- No certificate pinning
