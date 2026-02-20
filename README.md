# MacSecurityGuard

**Know what's happening on your Mac when AI builds your code.**

A free, open source security app for macOS. One window. No terminal needed.

---

## The Problem

You use Claude Code. You trust it. But you also know it installs packages, opens connections, runs processes — and you don't always see what's going on under the hood.

Activity Monitor doesn't tell you enough. The terminal tools out there are great, but they're not for everyone.

You just want to open something, click a button, and see: **is my Mac okay?**

## What You Get

**A visual dashboard that answers the questions you've been ignoring:**

- **Is my Mac's security on?** — One-click check of your firewall, disk encryption, system protections, and more.
- **What's running right now?** — See every non-Apple process on your machine, and whether it's signed or suspicious.
- **Is anything connecting out?** — Live view of every network connection, where it goes, and which app opened it.
- **Did something install itself?** — Scan for programs that auto-start when your Mac boots, and spot anything you didn't put there.
- **Are my apps legit?** — Verify that every app in your Applications folder has a valid signature.
- **What about my Chrome extensions?** — See which ones have risky permissions and which were sideloaded.
- **What happened while I was away?** — Connection history with filters by time, app, and country.

## Who Is This For

- PMs and builders using Claude Code daily
- Anyone running AI agents on their Mac who wants peace of mind
- People who care about security but don't want to live in the terminal
- Teams that want a quick way to audit a machine before a demo, a release, or just a Monday

## Getting Started

You need a Mac running macOS 15 (Sequoia) or later, and Xcode installed.

```bash
git clone https://github.com/manulopeznunez/security-guard.git
cd security-guard
swift build
swift run MacSecurityGuard
```

That's it. No accounts. No sign-ups. No configuration.

## Privacy First

- Everything stays on your machine. No cloud. No telemetry. No tracking.
- The only external call is for IP geolocation (pinned and secured).
- No accounts, no sign-ups, no analytics. Ever.

## Open Source — And Open to You

This is [AGPL-3.0](LICENSE) licensed. The code is yours to read, run, audit, and improve.

You don't need to be a security expert to contribute. Found a confusing label? A missing edge case? A better way to explain something? Open a PR. That counts.

If you *are* a security expert, even better — audits and reviews are very welcome.

If you find a vulnerability, please report it responsibly (see [SECURITY.md](SECURITY.md#reporting-security-vulnerabilities)).

## Built Seriously

This isn't a toy. Under the hood: zero external dependencies, no shell injection vectors, certificate pinning on all network calls, parameterized database queries, hardened runtime, and 94 automated tests covering every security-critical path. Full details in [SECURITY.md](SECURITY.md).

## Author

**Manu López**

---

*You let AI write your code. Do you know what else it's doing on your machine?*
