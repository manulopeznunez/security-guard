import Foundation
import os.log

@Observable
@MainActor
final class SecurityStatusViewModel {
    var items: [SecurityItem] = []
    var isLoading = false
    var actionInProgress: String? = nil
    var installError: String? = nil

    /// Resolve the full path to the Homebrew binary.
    /// GUI apps don't inherit the shell PATH, so /usr/bin/env won't find brew.
    nonisolated static func brewPath() -> String? {
        let candidates = [
            "/opt/homebrew/bin/brew",   // Apple Silicon
            "/usr/local/bin/brew",      // Intel
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    var groupedItems: [(category: SecurityCategory, items: [SecurityItem])] {
        SecurityCategory.allCases.compactMap { cat in
            let matching = items.filter { $0.category == cat }
            return matching.isEmpty ? nil : (category: cat, items: matching)
        }
    }

    var enabledCount: Int { items.filter { $0.status == .enabled }.count }

    var scoreProgress: Double {
        guard !items.isEmpty else { return 0 }
        return Double(enabledCount) / Double(items.count)
    }

    func refresh() async {
        isLoading = true
        let results = await Self.checkAll()
        items = results
        isLoading = false

        // Keep the displayed score in sync with the current result
        let score = items.isEmpty ? 0.0 : Double(enabledCount) / Double(items.count)
        BackgroundMonitor.shared.lastScore = score
    }

    func performAction(_ action: SecurityAction) async {
        switch action {
        case .none:
            break
        case .installBrew(let formula):
            AuditLogger.security.info("User requested install of \(formula, privacy: .public)")
            installError = nil
            guard let brew = Self.brewPath() else {
                installError = "Homebrew not found. Install it first from https://brew.sh"
                AuditLogger.security.error("Homebrew not found at any known path")
                return
            }
            actionInProgress = "Installing \(formula)..."
            let result = await Task.detached {
                ShellExecutor.run(brew, arguments: ["install", "--cask", formula], timeout: .install)
            }.value
            actionInProgress = nil
            if result.exitCode != 0 {
                let msg = result.error.isEmpty ? result.output : result.error
                installError = "Failed to install \(formula): \(msg)"
                AuditLogger.security.error("brew install \(formula, privacy: .public) failed: \(msg, privacy: .public)")
            }
            await refresh()
        case .openSystemSettings(let path):
            _ = await Task.detached {
                ShellExecutor.run("/usr/bin/open", arguments: [path])
            }.value
        case .openURL(let url):
            _ = await Task.detached {
                ShellExecutor.run("/usr/bin/open", arguments: [url])
            }.value
        }
    }

    nonisolated static func checkAll() async -> [SecurityItem] {
        AuditLogger.security.info("Starting security status check")
        var results: [SecurityItem] = []

        // SIP
        let sip = ShellExecutor.run("/usr/bin/csrutil", arguments: ["status"])
        let sipEnabled = sip.output.contains("enabled")
        results.append(SecurityItem(
            name: "System Integrity Protection (SIP)",
            explanation: "Protects critical system files from being modified, even by admin users. Prevents malware from altering macOS core components.",
            howToUse: "SIP is managed by macOS automatically. You don't need to do anything. If it's disabled, reboot into Recovery Mode (hold Cmd+R on Intel or Power button on Apple Silicon), open Terminal from the menu, and type 'csrutil enable'.",
            description: sipEnabled
                ? "Enabled — your system files are protected"
                : "Disabled — reboot to Recovery Mode to re-enable",
            status: sipEnabled ? .enabled : .disabled,
            action: sipEnabled ? .none : .openURL(url: "https://support.apple.com/en-us/102149"),
            category: .builtIn
        ))

        // Gatekeeper
        let gk = ShellExecutor.run("/usr/sbin/spctl", arguments: ["--status"])
        let gkText = gk.output + " " + gk.error
        let gkEnabled = gkText.contains("assessments enabled")
        results.append(SecurityItem(
            name: "Gatekeeper",
            explanation: "Blocks apps that aren't signed by identified developers or from the App Store. First line of defense against downloading malware.",
            howToUse: "Gatekeeper is managed by macOS. Go to System Settings > Privacy & Security > under 'Allow applications downloaded from' select 'App Store and identified developers'. Never set it to 'Anywhere'.",
            description: gkEnabled
                ? "Enabled — only signed apps can run"
                : "Disabled — unsigned apps can run freely, which is risky",
            status: gkEnabled ? .enabled : .disabled,
            action: gkEnabled ? .none : .openSystemSettings(path: "x-apple.systempreferences:com.apple.preference.security"),
            category: .builtIn
        ))

        // XProtect
        let xp = ShellExecutor.shell("pgrep -f XProtect")
        results.append(SecurityItem(
            name: "XProtect",
            explanation: "Apple's built-in antivirus. Automatically scans downloaded files and blocks known malware signatures. Updates silently in the background.",
            howToUse: "XProtect runs automatically in the background. No configuration needed. It updates silently through macOS system updates. Just keep your Mac updated to ensure you have the latest malware definitions.",
            description: xp.exitCode == 0
                ? "Running — Apple's built-in malware scanner is active"
                : "Not detected — it should start automatically. Try restarting your Mac.",
            status: xp.exitCode == 0 ? .enabled : .disabled,
            action: .none,
            category: .builtIn
        ))

        // Firewall
        let fw = ShellExecutor.run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            arguments: ["--getglobalstate"]
        )
        let fwEnabled = fw.output.contains("enabled") || fw.output.contains("State = 1")
        results.append(SecurityItem(
            name: "macOS Firewall",
            explanation: "Blocks unauthorized INCOMING connections to your Mac. Important when connected to public Wi-Fi (cafes, airports, hotels).",
            howToUse: "Go to System Settings > Network > Firewall > turn it ON. This only blocks incoming connections. For outgoing protection, install LuLu (see below).",
            description: fwEnabled
                ? "Enabled — incoming connections are filtered"
                : "Disabled — your Mac accepts all incoming connections",
            status: fwEnabled ? .enabled : .disabled,
            action: fwEnabled ? .none : .openSystemSettings(path: "x-apple.systempreferences:com.apple.preference.security?Firewall"),
            category: .builtIn
        ))

        // LuLu
        let luluInstalled = FileManager.default.fileExists(atPath: "/Applications/LuLu.app")
        let lulu = ShellExecutor.run("/usr/bin/pgrep", arguments: ["-x", "LuLu"])
        let luluRunning = lulu.exitCode == 0
        results.append(SecurityItem(
            name: "LuLu Firewall",
            explanation: "Free, open-source OUTGOING firewall by Objective-See (Patrick Wardle, ex-NSA). Unlike the macOS firewall (incoming only), LuLu monitors every app that tries to connect to the internet and lets you allow or block it.",
            howToUse: luluInstalled
                ? """
                LuLu lives in your menu bar (top-right of screen, small firewall icon). \
                When an app tries to connect to the internet for the first time, a popup appears asking to Allow or Block. \
                Check 'Remember' to save the rule. First 15 minutes will have many popups — this is normal. \
                To review rules: click LuLu icon in menu bar > 'Rules'. \
                To temporarily disable: click LuLu icon > toggle off.
                """
                : "Press 'Install' to download via Homebrew. After installation, open LuLu from /Applications. It will ask to restart your Mac. After restart, it runs automatically from the menu bar.",
            description: luluRunning
                ? "Running — outgoing connections are monitored 24/7"
                : (luluInstalled
                    ? "Installed but not running — open it to start monitoring"
                    : "Not installed — highly recommended"),
            status: luluRunning ? .enabled : .disabled,
            action: luluRunning ? .none : (luluInstalled
                ? .openURL(url: "/Applications/LuLu.app")
                : .installBrew(formula: "lulu")),
            category: .recommended
        ))

        // BlockBlock — check both /Applications and /Library/Objective-See
        let bbHelperPath = "/Applications/BlockBlock Helper.app"
        let bbObjSeePath = "/Library/Objective-See/BlockBlock"
        let bbInstalled = FileManager.default.fileExists(atPath: bbHelperPath)
            || FileManager.default.fileExists(atPath: bbObjSeePath)
        let bb = ShellExecutor.run("/usr/bin/pgrep", arguments: ["-f", "BlockBlock"])
        let bbRunning = bb.exitCode == 0
        results.append(SecurityItem(
            name: "BlockBlock",
            explanation: "Free, open-source persistence monitor by Objective-See. Alerts you in real-time whenever ANY program tries to install itself to run automatically (LaunchAgents, Login Items, cron jobs).",
            howToUse: bbInstalled
                ? """
                BlockBlock runs silently in the background (icon in menu bar, top-right). \
                You won't see anything until a program tries to persist — then a popup appears asking to Allow or Block. \
                This is normal when installing new software (e.g., Docker, Zoom). \
                If a popup appears and you didn't install anything, that's suspicious — press Block. \
                To review alerts: click BlockBlock icon in menu bar > 'Rules'.
                """
                : "Download from https://objective-see.org/products/blockblock.html and run the installer. Grant it permissions when macOS asks (Accessibility and Full Disk Access). Then it runs silently in the menu bar.",
            description: bbRunning
                ? "Running — persistence attempts are monitored in real-time"
                : (bbInstalled
                    ? "Installed but not running — open BlockBlock Helper.app"
                    : "Not installed — recommended"),
            status: bbRunning ? .enabled : .disabled,
            action: bbRunning ? .none : (bbInstalled
                ? .openURL(url: bbHelperPath)
                : .openURL(url: "https://objective-see.org/products/blockblock.html")),
            category: .recommended
        ))

        // KnockKnock
        let kkInstalled = FileManager.default.fileExists(atPath: "/Applications/KnockKnock.app")
        results.append(SecurityItem(
            name: "KnockKnock",
            explanation: "Free, open-source persistence scanner by Objective-See. Does a deep scan of everything that persists on your Mac and checks it against VirusTotal. Unlike BlockBlock (always running), KnockKnock is a manual scanner you run when you want.",
            howToUse: kkInstalled
                ? """
                Open KnockKnock from /Applications (or Spotlight: Cmd+Space, type 'KnockKnock'). \
                Click 'Start Scan'. It scans all persistence locations on your Mac. \
                Results are color-coded: items flagged by VirusTotal appear in red. \
                Green = known/signed. Gray = unsigned but not flagged. \
                Run it once a month as a health check, or whenever something feels off. \
                Tip: click 'Show all items' to see Apple items too.
                """
                : "Press 'Install' to download via Homebrew. After installation, open KnockKnock from /Applications. It doesn't run in the background — just open it when you want to scan.",
            description: kkInstalled
                ? "Installed — open it to do a full persistence scan"
                : "Not installed — useful for monthly security audits",
            status: kkInstalled ? .enabled : .disabled,
            action: kkInstalled
                ? .openURL(url: "/Applications/KnockKnock.app")
                : .installBrew(formula: "knockknock"),
            category: .recommended
        ))

        // MARK: - Blind Spots

        // FileVault (disk encryption)
        let fv = ShellExecutor.run("/usr/bin/fdesetup", arguments: ["status"])
        let fvEnabled = fv.output.contains("FileVault is On")
        results.append(SecurityItem(
            name: "FileVault (Disk Encryption)",
            explanation: "Encrypts your entire disk. If someone steals your Mac, they can't read your data without your password. Without FileVault, someone could remove the SSD and read everything.",
            howToUse: "Go to System Settings > Privacy & Security > FileVault > Turn On. You'll need your password to enable it. Encryption happens in the background and takes a few hours on first enable.",
            description: fvEnabled
                ? "Enabled — your disk is fully encrypted"
                : "Disabled — your data is NOT encrypted. Anyone with physical access can read your files.",
            status: fvEnabled ? .enabled : .disabled,
            action: fvEnabled ? .none : .openSystemSettings(path: "x-apple.systempreferences:com.apple.preference.security?FileVault"),
            category: .blindSpots
        ))

        // Firewall Stealth Mode
        let stealth = ShellExecutor.run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            arguments: ["--getstealthmode"]
        )
        let stealthEnabled = stealth.output.contains("enabled") || stealth.output.contains("is on")
        results.append(SecurityItem(
            name: "Firewall Stealth Mode",
            explanation: "Makes your Mac invisible on the network. Doesn't respond to ping or port scans. Important on public WiFi — prevents attackers from discovering your machine.",
            howToUse: "Open Terminal and run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on. Or go to System Settings > Network > Firewall > Options > Enable Stealth Mode.",
            description: stealthEnabled
                ? "Enabled — your Mac is invisible to network scans"
                : "Disabled — your Mac responds to pings and port scans",
            status: stealthEnabled ? .enabled : .disabled,
            action: stealthEnabled ? .none : .openSystemSettings(path: "x-apple.systempreferences:com.apple.preference.security?Firewall"),
            category: .blindSpots
        ))

        // MARK: - Scanner results (read from cache — no scanning here)

        appendCachedCard(&results,
            category: .process,
            name: "Unsigned Processes",
            explanation: "Processes running without a valid code signature could be modified binaries or unknown software.",
            howToUse: "Go to the 'Processes' tab and scan. Unsigned processes show an Approve button. Review the path and name, then approve if you recognize it."
        )

        appendCachedCard(&results,
            category: .persistence,
            name: "Unsigned Persistence Items",
            explanation: "Launch agents, daemons, or login items without valid signatures could be malware that survives reboots.",
            howToUse: "Go to the 'Persistence' tab and scan. Flagged items show an Approve button. Review the label and executable path, then approve if you recognize it."
        )

        appendCachedCard(&results,
            category: .appSignature,
            name: "Invalid App Signatures",
            explanation: "Apps in /Applications with broken or missing code signatures may have been tampered with or are unsigned builds.",
            howToUse: "Go to the 'App Signatures' tab and scan. Invalid apps show an Approve button. Review the app name and authority, then approve if you trust it."
        )

        appendCachedCard(&results,
            category: .chromeExtension,
            name: "Chrome Extensions Audit",
            explanation: "Browser extensions are the #1 blind spot. A malicious extension runs INSIDE Chrome with Chrome's signature — invisible to process scanners.",
            howToUse: "Go to the 'Extensions' tab to review each HIGH risk extension. Press 'Approve' once you verify it's legitimate."
        )

        // Remote Login (SSH) — check if sshd is listening on port 22
        let ssh = ShellExecutor.shell("lsof -i :22 -n -P 2>/dev/null | grep LISTEN")
        let sshEnabled = !ssh.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        results.append(SecurityItem(
            name: "Remote Login (SSH)",
            explanation: "SSH allows remote terminal access to your Mac. If enabled, anyone who knows your password (or has your SSH key) can connect from anywhere. Should be OFF unless you specifically need it.",
            howToUse: "Go to System Settings > General > Sharing > Remote Login — turn it OFF. If you need SSH occasionally, only enable it when needed and disable it after.",
            description: sshEnabled
                ? "Enabled — your Mac accepts SSH connections from the network"
                : "Disabled — no remote terminal access",
            status: sshEnabled ? .disabled : .enabled,
            action: sshEnabled ? .openSystemSettings(path: "x-apple.systempreferences:com.apple.preferences.sharing") : .none,
            category: .blindSpots
        ))

        return results
    }

    // MARK: - Cached scanner cards

    nonisolated private static func appendCachedCard(
        _ results: inout [SecurityItem],
        category: ApprovalManager.Category,
        name: String,
        explanation: String,
        howToUse: String
    ) {
        guard ApprovalManager.hasBeenScanned(category) else {
            // Never scanned — show "not scanned yet" card
            results.append(SecurityItem(
                name: name,
                explanation: explanation,
                howToUse: howToUse,
                description: "Not scanned yet — run a scan from the corresponding tab",
                status: .disabled,
                action: .none,
                category: .blindSpots
            ))
            return
        }

        let flagged = ApprovalManager.flaggedIDs(for: category)
        let pending = ApprovalManager.pendingCount(for: category)

        if flagged.isEmpty {
            // Scanned and nothing flagged — all clean
            results.append(SecurityItem(
                name: name,
                explanation: explanation,
                howToUse: howToUse,
                description: "Last scan: all clear",
                status: .enabled,
                action: .none,
                category: .blindSpots
            ))
        } else if pending > 0 {
            results.append(SecurityItem(
                name: name,
                explanation: explanation,
                howToUse: howToUse,
                description: "\(pending) item\(pending == 1 ? "" : "s") pending review",
                status: .disabled,
                action: .none,
                category: .blindSpots
            ))
        } else {
            results.append(SecurityItem(
                name: name,
                explanation: explanation,
                howToUse: howToUse,
                description: "\(flagged.count) item\(flagged.count == 1 ? "" : "s") reviewed and approved",
                status: .enabled,
                action: .none,
                category: .blindSpots
            ))
        }
    }

    // MARK: - Scan All

    func scanAll() async {
        isLoading = true
        actionInProgress = "Scanning processes..."

        // Run all scanners and cache results
        let processResults = await ProcessScannerViewModel.performScan(onProgress: { _ in })
        let flaggedProcesses = processResults.filter { $0.signatureValid == false }.map(\.path)
        ApprovalManager.saveFlagged(.process, ids: flaggedProcesses)

        actionInProgress = "Scanning persistence..."
        let persistenceResults = await PersistenceScannerViewModel.performScan()
        let flaggedPersistence = persistenceResults.filter(\.needsReview).map(\.executablePath)
        ApprovalManager.saveFlagged(.persistence, ids: flaggedPersistence)

        actionInProgress = "Scanning app signatures..."
        let appResults = await AppSignatureViewModel.performScan(onProgress: { _ in })
        let flaggedApps = appResults.filter { !$0.isValid }.map(\.appPath)
        ApprovalManager.saveFlagged(.appSignature, ids: flaggedApps)

        actionInProgress = "Scanning Chrome extensions..."
        let extResults = ChromeExtensionViewModel.performScan()
        let flaggedExts = extResults.filter { $0.risk == .high }.map(\.extensionId)
        ApprovalManager.saveFlagged(.chromeExtension, ids: flaggedExts)

        actionInProgress = nil
        await refresh()
    }
}
