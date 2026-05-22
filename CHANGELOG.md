# Changelog

All notable changes to ZavetSec DLP are documented in this file.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`

---

## [1.0.0] — 2026-05-20

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
- `LogShipper` — batched event delivery, in-memory queue, **persistent disk buffer up to 50 MB** when server is unreachable, exponential backoff (30s → 30 min)
- `ScreenshotShipper` — async screenshot upload, **automatic local file deletion** after successful upload
- `CommandPoller` — remote command polling, **heartbeat** updates `last_seen` on every poll

**Security:**
- `Logger` — AES-256-CBC encrypted local logs, key protected by Windows DPAPI (machine scope)
- All `HttpClient` instances use **lazy initialization** (safe static field order)
- `AllowInvalidCertificate` option for self-signed HTTPS certificates

**Configuration (`config.json`):**
- Auto-generated on first run with sensible defaults
- `shipper.enabled = true` by default
- `shipper.deleteLocalScreenshotsAfterUpload = true` by default
- `shipper.allowInvalidCertificate = true` by default
- `AppContext.BaseDirectory` used (fixes IL3000 warning in single-file apps)

---

### Server

**API:**
- Agent endpoints: `POST /api/ingest`, `POST /api/screenshots/upload`, `GET /api/commands/{host}`, `POST /api/commands/result`
- Dashboard endpoints: events, screenshots, keylogger, agents, stats, CSV export
- Auth endpoints: login, logout, me, change-password
- User management: create, list, delete (admin only)
- Data management: delete by host, delete all (admin only)
- `GET /health` — health check endpoint (status, DB connectivity, uptime)
- `GET /api/telegram/test` — send test Telegram message
- `GET /api/telegram/config` — current alert filter configuration

**Security:**
- **Brute force protection**: 5 failed attempts → 15-minute IP lockout, auto-cleanup every 5 minutes
- **Brute force protection**: 5 failed attempts → 15-minute IP lockout, auto-cleanup every 5 minutes
- **Rate limiting**: 1000 requests/minute per IP on agent endpoints (HTTP 429 + `Retry-After` header)
- **Session invalidation**: all user sessions invalidated on password change
- PBKDF2-SHA256 password hashing, 100,000 iterations, 16-byte salt
- 32-byte cryptographically random session tokens, 24-hour TTL with sliding expiry
- Role-based access: `admin` (full) / `viewer` (read-only)

**Password policy:**
- Minimum 12 characters
- Must contain: uppercase, lowercase, digits, special characters
- Enforced on server and client side
- First login forces password change (cannot be bypassed)

**HTTPS:**
- Self-signed certificate auto-generated on first run (RSA 2048, SHA-256, 10 years)
- SAN includes: localhost, machine hostname, 127.0.0.1
- HTTP :5000 + HTTPS :5001 simultaneous
- Warning logged if default certificate password is used

**Database:**
- SQLite with WAL mode
- **Migration system** (`schema_version` table) — safe upgrades from any previous version
- Schema v3: events, hosts, screenshots, commands, users, sessions, login_attempts
- Automatic cleanup of expired sessions and old brute-force records

**Telegram:**
- Configurable per-module alert filters (`AlertModules` array)
- `SendAllAlerts: true` to bypass filter
- Rate limit: 1 notification per 30 seconds per host+module pair
- Test endpoint in dashboard

---

### Dashboard (index.html, vanilla JS)

**Audit Log tab (admin only):**
- Chronological log of all admin actions: LOGIN, LOGOUT, PASSWORD_CHANGE, USER_CREATE, USER_DELETE, SCREENSHOT_DELETE, DATA_DELETE, COMMAND
- Color-coded by action type, full-text search, pagination

**Events tab:**
- Filter by module, host, date range, full-text search
- Auto-apply on dropdown change (no "Apply" button needed)
- Enter key in search field = instant filter
- **CSV export** with real-time progress indicator (shows KB loaded)
- Up to 100,000 rows per export

**Screenshots tab:**
- Grid view with process name and window title
- Case-insensitive search (Cyrillic supported via SQLite `LOWER()`)
- Click → full-size modal with metadata
- Delete button in modal (admin only)
- **Multi-select mode**: checkboxes, select-all, bulk delete

**Keylogger tab:**
- Sessions grouped by window
- Full-text search with match highlighting
- Special key display: `[BS]` `[TAB]` `[CTRL+C]` `[WIN]`

**Agents tab:**
- **Pagination: 20 agents per page**
- Online/Offline status (heartbeat < 2 minutes)
- Per-host data management buttons (screenshots, events) for all agents
- Broadcast commands to all agents
- Server data management panel (admin only)
- DB and screenshot disk usage display (admin only)

**Users tab (admin only):**
- Create / delete users
- Password status column (OK / Must Change)
- Change own password
- Telegram status and filter display
- Send test notification button

**Auth:**
- Session restored from `localStorage` on page reload
- Forced password change modal on first login (cannot be dismissed)
- 15-minute countdown timer on brute-force lockout
- Friendly error messages: 404, 429 (with retry countdown), 500

---

### Deployment

**`install.ps1`:**
- Auto-detects `publish\` source directory
- Stops old agent process if running
- Adds Windows Defender exclusion
- Creates complete `config.json` with all parameters
- Registers two Scheduled Tasks (ONLOGON + ONSTART, SYSTEM, HIGHEST)
- Verifies agent started successfully

**`deploy.ps1`:**
- Parallel deployment via WinRM (configurable `ConcurrentJobs`, default 10)
- Ping check before attempt
- Optional `PSCredential` parameter
- Exports CSV deployment report with per-machine status
- Supports AD computer lists

---

## Known Limitations

- Agent monitors primary display only (multi-monitor: only screen 0)
- No code signing certificate — Windows Defender behavioral detection requires exclusion
- SQLite is not recommended above ~50 GB database size
- Self-signed HTTPS certificate shows browser warning (expected behavior)
