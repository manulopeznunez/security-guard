# Security Policy — MacSecurityGuard

## System Binary Dependencies

MacSecurityGuard invokes the following macOS system binaries. All paths are absolute to prevent PATH injection.

| Binary | Path | Purpose | Timeout |
|--------|------|---------|---------|
| codesign | `/usr/bin/codesign` | Code signature verification | 10s |
| ps | `/bin/ps` | Process information | 10s |
| lsof | `/usr/sbin/lsof` | Network connection listing | 10s |
| nettop | `/usr/bin/nettop` | Byte transfer counters | 10s |
| host | `/usr/bin/host` | Reverse DNS lookups | 30s |
| plutil | `/usr/bin/plutil` | Plist file parsing | 10s |
| pgrep | `/usr/bin/pgrep` | Process detection | 10s |
| csrutil | `/usr/bin/csrutil` | SIP status | 10s |
| spctl | `/usr/sbin/spctl` | Gatekeeper status | 10s |
| socketfilterfw | `/usr/libexec/ApplicationFirewall/socketfilterfw` | Firewall status | 10s |
| fdesetup | `/usr/sbin/fdesetup` | FileVault status | 10s |
| systemsetup | `/usr/sbin/systemsetup` | SSH status | 10s |
| crontab | `/usr/bin/crontab` | Cron job listing | 10s |
| osascript | `/usr/bin/osascript` | Login items via AppleScript | 10s |
| open | `/usr/bin/open` | Open URLs/apps | 10s |
| env | `/usr/bin/env` | Find brew for tool installation | 120s |

## External Network Endpoints

| Endpoint | Protocol | Purpose | Rate Limit |
|----------|----------|---------|------------|
| `ip-api.com/batch` | HTTPS POST | IP geolocation | 40 req/min (free tier: 45) |

No other external network calls are made. All geolocation requests use URLSession with SPKI certificate pinning (SHA256 hash of the server's public key, RFC 7469 compatible). Pin mismatches are logged as critical security events.

## Entitlements

This app uses **Hardened Runtime** (not App Sandbox) because it must invoke system tools for security monitoring.

| Entitlement | Reason |
|-------------|--------|
| `automation.apple-events` | Querying login items via System Events, admin privilege escalation for uninstall |

## Local Data Storage

| Location | Content | Permissions |
|----------|---------|-------------|
| `~/Library/Application Support/MacSecurityGuard/history.db` | SQLite WAL — network connection snapshots (IP, port, process, geo, bytes) | 0700 (owner only) |
| `UserDefaults` | User approval preferences for flagged items | Standard app defaults |

Data retention: connection history is retained for up to 90 days and automatically purged.

## Database At-Rest Protection

The connection history database is protected through defense-in-depth:

1. **FileVault** — macOS full-disk encryption (AES-XTS-128) protects all data at rest. The Security Status dashboard warns when FileVault is disabled.
2. **Directory permissions** — The database directory is restricted to `0700` (owner only). Permissions are verified and restored on every launch.
3. **Exclusive locking** — `PRAGMA locking_mode=EXCLUSIVE` prevents other processes from reading the database while the app is running.
4. **Secure deletion** — `PRAGMA secure_delete=ON` zero-fills deleted rows to prevent recovery of purged data.

SQLCipher (database-level encryption) was deliberately not adopted because:
- The stored data (network metadata: IPs, ports, process names) is not high-value secrets
- FileVault already provides at-rest encryption at the OS level
- Adding a third-party dependency increases supply chain attack surface
- This is consistent with the project's zero-dependency security posture

## Third-Party Dependencies

**None.** MacSecurityGuard has zero external Swift package dependencies. It uses only Apple system frameworks (Foundation, SwiftUI, SQLite3, os.log).

## Reporting Security Vulnerabilities

If you discover a security vulnerability in MacSecurityGuard, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainers with details of the vulnerability
3. Include steps to reproduce and potential impact
4. Allow reasonable time for a fix before public disclosure

## License

MacSecurityGuard is licensed under the [GNU Affero General Public License v3](LICENSE) (AGPL-3.0).
