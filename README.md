# MacSecurityGuard

A free, visual security monitoring tool for macOS — built for developers who use AI coding agents and want to know exactly what's running on their machine.

## Why This Exists

I activated 12 Claude Code agents instead of 6. An hour later, my 24GB Mac was at the limit.

I closed terminals, checked Activity Monitor... between 6 and 9 processes consuming 3GB of RAM. I'd had security on my mind for months, especially after a conversation with my colleague Luis about physical passkeys and their relevance.

And then I started to really worry.

Even though I understand 95% of what Claude Code does, I never know exactly which library was installed, which dependency was added, which port was opened. If there's a vulnerability, I find out too late.

I looked for solutions. There are open source tools that solve this — [LuLu](https://github.com/objective-see/LuLu), [BlockBlock](https://github.com/objective-see/BlockBlock), [KnockKnock](https://github.com/objective-see/KnockKnock) — but they all require the terminal. I wanted something visual, a couple of clicks. Review and done.

So I built it.

**MacSecurityGuard is a minimum security and audit layer for Mac, designed for those who use Claude Code and don't want too many red flags they don't know about.**

## Features

### Security Status Dashboard
One-click scan of your Mac's security posture: SIP, Gatekeeper, XProtect, Firewall, Stealth Mode, FileVault, Remote Login (SSH), plus detection of third-party tools like LuLu, BlockBlock, and KnockKnock.

### Process Scanner
Scans all running non-Apple processes, verifies their code signatures, and flags unsigned or suspicious binaries. Shows CPU/memory usage and parent app detection.

### Persistence Scanner
Audits LaunchAgents, LaunchDaemons, cron jobs, and login items. Verifies the binary behind each persistence entry and flags orphaned, unsigned, or tampered items.

### App Signature Verification
Scans every `.app` in `/Applications`, verifies code signatures, and shows the signing authority. Flags tampered or unsigned applications.

### Chrome Extension Analyzer
Scans Chrome profiles for extensions, analyzes their permissions (host access, native messaging, debugger, proxy), and assigns a risk level. Detects sideloaded extensions.

### Network Monitor
Real-time network connection capture with process identification, code signature verification, IP geolocation, and reverse DNS. See exactly which process is connecting where.

### Connection History
SQLite-backed history of all network connections with top IPs, apps, and countries. Filter by time range. Automatic 90-day data retention with secure deletion.

## Installation

### Requirements

- macOS 15 (Sequoia) or later
- Xcode 16+ or Swift 6.0+ toolchain

### Build from Source

```bash
git clone https://github.com/manuloop/MacSecurityGuard.git
cd MacSecurityGuard
swift build
```

### Run

```bash
swift run MacSecurityGuard
```

Or open the project in Xcode and run from there.

## Security Architecture

MacSecurityGuard is built with a zero-dependency, defense-in-depth security posture:

- **Zero external dependencies** — only Apple system frameworks (Foundation, SwiftUI, SQLite3, os.log)
- **No shell injection** — all system commands use absolute paths with separated arguments via `Process`, never string interpolation
- **SPKI certificate pinning** — SHA256 public key pinning (RFC 7469) for all external network calls
- **SQL injection prevention** — all database queries use parameterized prepared statements
- **Hardened database** — exclusive locking, secure deletion (zero-fill), owner-only directory permissions
- **Structured audit logging** — every shell command, network call, and security event is logged via os.log
- **Command timeouts** — all subprocess executions have enforced timeouts with SIGTERM/SIGINT cleanup
- **Minimal entitlements** — Hardened Runtime with only `automation.apple-events`
- **No telemetry, no analytics, no cloud sync**

For full details, see [SECURITY.md](SECURITY.md).

## Tests

94 automated tests covering all security-critical logic:

```bash
swift test
```

Test coverage includes: shell command injection prevention, SQL injection prevention, certificate pinning, code signature classification, network address parsing, Chrome extension risk assessment, persistence model validation, input sanitization, and format utilities.

## Privacy

- All data stays on your machine
- The only external network call is to `ip-api.com` for IP geolocation (with certificate pinning)
- No accounts, no sign-ups, no tracking
- Connection history stored locally in `~/Library/Application Support/MacSecurityGuard/`

## License

[GNU Affero General Public License v3](LICENSE) (AGPL-3.0)

You are free to use, modify, and distribute this software under the terms of the AGPL v3. If you modify it and provide it as a service, you must make your source code available.

## Contributing

If you're a security expert and want to review, audit, or contribute improvements — PRs are welcome.

If you discover a security vulnerability, please report it responsibly (see [SECURITY.md](SECURITY.md#reporting-security-vulnerabilities)).

## Author

**Manu López**

---

*What tools do you use to monitor what's happening on your machine when working with AI agents?*
