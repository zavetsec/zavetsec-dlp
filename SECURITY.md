# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security issue in ZavetSec DLP, please use one of the following:

- **GitHub Security Advisory:** [Report a vulnerability](../../security/advisories/new) (preferred)
- **Email:** create a GitHub Security Advisory and we will respond within 72 hours

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 72 hours and provide a timeline for resolution.

## Security Design

ZavetSec DLP is a **monitoring tool**, not a remote access framework:

- No remote shell or arbitrary code execution
- No privilege escalation beyond scheduled task permissions
- No lateral movement — communicates only with the configured server URL
- No cloud telemetry or license server
- Local logs are AES-256-CBC encrypted with DPAPI-protected keys
- All agent→server communication requires a pre-shared API key

## Intended Deployment

This software is designed for **authorized corporate endpoint monitoring** with employee
knowledge and consent as required by applicable law. It is not designed or intended for:

- Covert surveillance without legal authorization
- Bypassing OS security or EDR tools
- Any malicious or unauthorized use

**ZavetSec DLP is not designed to evade antivirus, EDR, or forensic tools.**
Antivirus exclusions are required precisely because the software uses legitimate
monitoring APIs (keyboard hooks, screen capture) that behavioral engines flag.

## Known Security Limitations

- All agents share one API key — compromise of one agent config requires key rotation on all agents
- `allowInvalidCertificate: true` by default — vulnerable to MITM on untrusted networks
- No certificate pinning (planned for v1.1)
- No per-agent authentication (planned for v1.1)

See [Roadmap](README.md#roadmap) for planned security improvements.
