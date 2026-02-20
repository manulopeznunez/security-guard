import AppKit
import Foundation

@Observable
@MainActor
final class HomebrewScannerViewModel {
    var packages: [HomebrewPackage] = []
    var isScanning = false
    var progress = ""
    var brewInstalled = true

    func scan() async {
        isScanning = true
        progress = "Checking Homebrew installation..."
        let results = await Self.performScan { [weak self] msg in
            Task { @MainActor in self?.progress = msg }
        }
        packages = results.packages
        brewInstalled = results.brewFound
        progress = results.brewFound
            ? "Done. Found \(results.packages.count) packages."
            : "Homebrew not installed."
        isScanning = false

        let flagged = results.packages.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.homebrew, flaggedIDs: flagged)

        Self.saveCachedResult(results)
        ScanDateTracker.record(.homebrew)
        let flaggedCount = flagged.count
        DatabaseManager.shared.insertScanHistory(
            scanner: "homebrew", total: results.packages.count, flagged: flaggedCount,
            summary: "\(results.packages.count) packages, \(flaggedCount) need review"
        )
    }

    func loadCached() {
        if let cached = Self.loadCachedResult() {
            packages = cached.packages
            brewInstalled = cached.brewFound
        }
    }

    // MARK: - JSON Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("homebrew-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: ScanResult) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> ScanResult? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode(ScanResult.self, from: data)
    }

    // MARK: - Static scan result

    struct ScanResult: Sendable, Codable {
        let brewFound: Bool
        let packages: [HomebrewPackage]
    }

    // MARK: - Static scan

    nonisolated static func performScan(
        onProgress: @Sendable @escaping (String) -> Void = { _ in }
    ) async -> ScanResult {
        guard let brew = SecurityStatusViewModel.brewPath() else {
            return ScanResult(brewFound: false, packages: [])
        }

        // List installed formulae
        onProgress("Listing installed packages...")
        let listResult = await Task.detached {
            ShellExecutor.run(brew, arguments: ["list", "--versions"], timeout: .local)
        }.value

        guard listResult.exitCode == 0 else {
            return ScanResult(brewFound: true, packages: [])
        }

        let installedFormulae = parseInstalledList(listResult.output)

        // List installed casks
        let caskListResult = await Task.detached {
            ShellExecutor.run(brew, arguments: ["list", "--cask", "--versions"], timeout: .local)
        }.value
        let installedCasks = parseInstalledList(
            caskListResult.exitCode == 0 ? caskListResult.output : ""
        )

        // Get leaf packages (top-level installs, not dependencies)
        let leavesResult = await Task.detached {
            ShellExecutor.run(brew, arguments: ["leaves"], timeout: .local)
        }.value
        let leaves = parseLeaves(leavesResult.exitCode == 0 ? leavesResult.output : "")

        // Check outdated (network call)
        onProgress("Checking for outdated packages (this may take a moment)...")
        let outdatedResult = await Task.detached {
            ShellExecutor.run(brew, arguments: ["outdated", "--json=v2"], timeout: .scan)
        }.value

        let outdatedInfo: OutdatedInfo
        if outdatedResult.exitCode == 0 && !outdatedResult.output.isEmpty {
            outdatedInfo = parseOutdatedJSON(outdatedResult.output)
        } else {
            outdatedInfo = OutdatedInfo(formulae: [:], casks: [:])
        }

        // Build package list
        onProgress("Assessing package health...")
        var packages: [HomebrewPackage] = []

        for (name, version) in installedFormulae {
            let outdated = outdatedInfo.formulae[name]
            let (risk, reason) = assessRisk(
                name: name,
                installedVersion: version,
                latestVersion: outdated?.currentVersion,
                pinned: outdated?.pinned ?? false,
                type: .formula
            )
            packages.append(HomebrewPackage(
                name: name,
                type: .formula,
                installedVersion: version,
                currentVersion: outdated?.currentVersion,
                pinned: outdated?.pinned ?? false,
                isLeaf: leaves.contains(name),
                risk: risk,
                riskReason: reason
            ))
        }

        for (name, version) in installedCasks {
            let outdated = outdatedInfo.casks[name]
            let (risk, reason) = assessRisk(
                name: name,
                installedVersion: version,
                latestVersion: outdated?.currentVersion,
                pinned: false,
                type: .cask
            )
            packages.append(HomebrewPackage(
                name: name,
                type: .cask,
                installedVersion: version,
                currentVersion: outdated?.currentVersion,
                pinned: false,
                isLeaf: true, // casks are always top-level
                risk: risk,
                riskReason: reason
            ))
        }

        return ScanResult(
            brewFound: true,
            packages: packages.sorted { $0.risk > $1.risk }
        )
    }

    // MARK: - Bulk Update Analysis

    struct BulkAnalysisEntry: Identifiable, Sendable {
        let id = UUID()
        let name: String
        let installedVersion: String
        let latestVersion: String
        let dependents: [String]
        let dependentsAlsoUpdating: [String]
        let dependentsAtRisk: [String]
        let isSecurityCritical: Bool
        let isMajorVersionBump: Bool
        let isLeaf: Bool
        let recommendation: String
        let ifUpdate: String
        let ifIgnore: String
        let ifApprove: String
        let ifQuarantine: String
        let ifDelete: String
        let vulnerabilities: [CVERecord]
        let projectWarning: String?
    }

    struct BulkAnalysisResult: Sendable {
        let safeUpdates: [BulkAnalysisEntry]
        let cautionUpdates: [BulkAnalysisEntry]
        let securityCritical: [BulkAnalysisEntry]
    }

    func analyzeBulkUpdate() async -> BulkAnalysisResult {
        let outdated = packages.filter(\.isOutdated)
        let outdatedNames = Set(outdated.map(\.name))

        // Batch CVE lookup for all outdated packages
        progress = "Checking for known vulnerabilities..."
        let cveInput = outdated.map { (name: $0.name, version: $0.installedVersion) }
        let allCVEs = await CVEService.shared.lookup(packages: cveInput)

        var safe: [BulkAnalysisEntry] = []
        var caution: [BulkAnalysisEntry] = []
        var critical: [BulkAnalysisEntry] = []

        for (index, pkg) in outdated.enumerated() {
            progress = "Analyzing \(index + 1)/\(outdated.count): \(pkg.name)..."
            let dependents = await Self.checkDependents(for: pkg.name)

            let alsoUpdating = dependents.filter { outdatedNames.contains($0) }
            let atRisk = dependents.filter { !outdatedNames.contains($0) }

            let isCritical = Self.securityCritical.contains(pkg.name)
            let latest = pkg.currentVersion ?? pkg.installedVersion
            let versionDistance = Self.estimateVersionDistance(
                installed: pkg.installedVersion,
                latest: latest
            )
            let majorBump = versionDistance >= 1

            // CVE data and project warning
            let vulns = allCVEs[pkg.name] ?? []
            let projectWarning = Self.projectDependencyWarning(
                for: pkg.name, version: pkg.installedVersion, latest: latest
            )
            let hasHighSeverityCVE = vulns.contains { $0.severity >= .high }

            // CVE summary for recommendation text
            let cveSuffix: String
            if !vulns.isEmpty {
                let critCount = vulns.filter { $0.severity == .critical }.count
                let highCount = vulns.filter { $0.severity == .high }.count
                if critCount > 0 {
                    cveSuffix = " — \(vulns.count) CVE\(vulns.count == 1 ? "" : "s"), \(critCount) CRITICAL"
                } else if highCount > 0 {
                    cveSuffix = " — \(vulns.count) CVE\(vulns.count == 1 ? "" : "s"), \(highCount) HIGH"
                } else {
                    cveSuffix = " — \(vulns.count) CVE\(vulns.count == 1 ? "" : "s")"
                }
            } else {
                cveSuffix = ""
            }

            // Generate recommendation and consequences
            let recommendation: String
            let ifUpdate: String
            let ifIgnore: String
            let ifApprove: String
            let ifQuarantine: String
            let ifDelete: String

            // --- Recommendation ---
            if (isCritical || hasHighSeverityCVE) && atRisk.isEmpty {
                recommendation = "Update now — \(hasHighSeverityCVE ? "has known vulnerabilities" : "security-critical package"), no dependents at risk\(cveSuffix)"
            } else if isCritical || hasHighSeverityCVE {
                recommendation = "Update with caution — \(hasHighSeverityCVE ? "has known vulnerabilities" : "security-critical"), but \(atRisk.count) dependent\(atRisk.count == 1 ? "" : "s") may be affected\(cveSuffix)"
            } else if atRisk.isEmpty && !majorBump {
                recommendation = "Safe to update — minor change, nothing depends on it\(cveSuffix)"
            } else if atRisk.isEmpty && majorBump {
                recommendation = "Update recommended — major version bump but no dependents at risk\(cveSuffix)"
            } else if majorBump {
                recommendation = "Review carefully — major version bump may break \(atRisk.joined(separator: ", "))\(cveSuffix)"
            } else {
                recommendation = "Update recommended — low risk, but check \(atRisk.joined(separator: ", ")) after\(cveSuffix)"
            }

            // --- If Update ---
            if atRisk.isEmpty {
                ifUpdate = "\(pkg.name) updates from \(pkg.installedVersion) to \(latest). No other packages affected.\(vulns.isEmpty ? "" : " This fixes \(vulns.count) known vulnerabilit\(vulns.count == 1 ? "y" : "ies").")"
            } else {
                let riskList = atRisk.joined(separator: ", ")
                ifUpdate = "\(pkg.name) updates to \(latest). Could affect: \(riskList). Homebrew handles most compatibility, but \(majorBump ? "major version bumps can introduce breaking changes" : "minor issues are rare").\(vulns.isEmpty ? "" : " Fixes \(vulns.count) known vulnerabilit\(vulns.count == 1 ? "y" : "ies").")"
            }

            // --- If Ignore (don't update) ---
            if !vulns.isEmpty {
                let cveList = vulns.prefix(3).map(\.displayID).joined(separator: ", ")
                let moreText = vulns.count > 3 ? " and \(vulns.count - 3) more" : ""
                ifIgnore = "WARNING: \(vulns.count) known vulnerabilit\(vulns.count == 1 ? "y affects" : "ies affect") this version (\(cveList)\(moreText)). Any tool using \(pkg.name) \(pkg.installedVersion) is exposed."
            } else if isCritical {
                ifIgnore = "\(pkg.name) \(pkg.installedVersion) may have known security vulnerabilities. Any tool using it (including scripts, git hooks, CI) runs with the old version. \(versionDistance >= 2 ? "You are \(versionDistance) major versions behind." : "")"
            } else if versionDistance >= 3 {
                ifIgnore = "\(pkg.name) is \(versionDistance) major versions behind. You miss bug fixes, performance improvements, and may hit compatibility issues with newer tools."
            } else {
                ifIgnore = "Low risk. \(pkg.name) \(pkg.installedVersion) continues working as-is. You miss bug fixes from \(latest) but nothing critical."
            }

            // --- If Approve (accept the outdated state) ---
            if !vulns.isEmpty {
                ifApprove = "You accept the risk of running a version with \(vulns.count) known vulnerabilit\(vulns.count == 1 ? "y" : "ies"). The warning disappears from the dashboard, but the exposure remains. Not recommended."
            } else if isCritical {
                ifApprove = "You accept the risk of running an outdated security-critical package. The warning disappears from the dashboard, but the vulnerability remains. Not recommended."
            } else {
                ifApprove = "The warning disappears from the dashboard. \(pkg.name) stays at \(pkg.installedVersion). You can revoke later if you change your mind."
            }

            // --- If Quarantine ---
            ifQuarantine = "Marks \(pkg.name) as dangerous. If it reappears at this version after a reinstall or downgrade, you'll get a macOS notification. Use this if you suspect the package is compromised."

            // --- If Delete ---
            if !dependents.isEmpty {
                let depList = dependents.joined(separator: ", ")
                ifDelete = "Cannot safely delete. \(dependents.count) package\(dependents.count == 1 ? "" : "s") depend on it: \(depList). Uninstall those first."
            } else if pkg.isLeaf {
                ifDelete = "Safe to remove. You installed this directly and nothing depends on it. Run 'brew uninstall \(pkg.name)' or use the trash button."
            } else {
                ifDelete = "This is a dependency. Nothing currently uses it, so it's safe to remove. It was likely left behind after uninstalling another package."
            }

            let entry = BulkAnalysisEntry(
                name: pkg.name,
                installedVersion: pkg.installedVersion,
                latestVersion: latest,
                dependents: dependents,
                dependentsAlsoUpdating: alsoUpdating,
                dependentsAtRisk: atRisk,
                isSecurityCritical: isCritical,
                isMajorVersionBump: majorBump,
                isLeaf: pkg.isLeaf,
                recommendation: recommendation,
                ifUpdate: ifUpdate,
                ifIgnore: ifIgnore,
                ifApprove: ifApprove,
                ifQuarantine: ifQuarantine,
                ifDelete: ifDelete,
                vulnerabilities: vulns,
                projectWarning: projectWarning
            )

            if isCritical || hasHighSeverityCVE {
                critical.append(entry)
            } else if atRisk.isEmpty {
                safe.append(entry)
            } else {
                caution.append(entry)
            }
        }

        return BulkAnalysisResult(
            safeUpdates: safe,
            cautionUpdates: caution,
            securityCritical: critical
        )
    }

    // MARK: - Project Dependency Warnings

    /// Returns a warning if the package is a language runtime that projects may depend on.
    nonisolated static func projectDependencyWarning(
        for name: String, version: String, latest: String
    ) -> String? {
        let runtimeWarnings: [String: (files: String, tool: String)] = [
            "python": (".python-version, pyproject.toml, Pipfile", "pyenv"),
            "python@3.12": (".python-version, pyproject.toml, Pipfile", "pyenv"),
            "python@3.13": (".python-version, pyproject.toml, Pipfile", "pyenv"),
            "python@3.14": (".python-version, pyproject.toml, Pipfile", "pyenv"),
            "node": (".nvmrc, .node-version, package.json engines", "nvm/fnm"),
            "go": ("go.mod (go directive)", "goenv"),
            "ruby": (".ruby-version, Gemfile", "rbenv/rvm"),
        ]

        guard let info = runtimeWarnings[name] else { return nil }

        return "This is a language runtime. Projects on your machine may pin \(version) via \(info.files). Updating to \(latest) could break those projects. Consider using \(info.tool) to manage multiple versions."
    }

    // MARK: - Update All

    func updateAll() async {
        guard let brew = SecurityStatusViewModel.brewPath() else { return }
        isScanning = true
        progress = "Updating all packages (this may take a while)..."
        let result = await Task.detached {
            ShellExecutor.run(brew, arguments: ["upgrade"], timeout: .none)
        }.value
        isScanning = false

        if result.exitCode != 0 && !result.timedOut {
            let alert = NSAlert()
            alert.messageText = "Update finished with errors"
            alert.informativeText = result.error.isEmpty ? result.output : result.error
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }

        await scan()
    }

    // MARK: - Dependency Checks (on demand)

    /// Returns packages that depend on the given package.
    nonisolated static func checkDependents(for name: String) async -> [String] {
        guard let brew = SecurityStatusViewModel.brewPath() else { return [] }
        let result = await Task.detached {
            ShellExecutor.run(brew, arguments: ["uses", "--installed", name], timeout: .local)
        }.value
        guard result.exitCode == 0 else { return [] }
        return parseSimpleList(result.output)
    }

    /// Returns packages that the given package depends on.
    nonisolated static func checkDependencies(for name: String) async -> [String] {
        guard let brew = SecurityStatusViewModel.brewPath() else { return [] }
        let result = await Task.detached {
            ShellExecutor.run(brew, arguments: ["deps", name], timeout: .local)
        }.value
        guard result.exitCode == 0 else { return [] }
        return parseSimpleList(result.output)
    }

    // MARK: - Uninstall

    func uninstallPackage(_ pkg: HomebrewPackage) async {
        guard let brew = SecurityStatusViewModel.brewPath() else { return }

        // Check dependents first
        let dependents = await Self.checkDependents(for: pkg.name)

        if !dependents.isEmpty {
            let list = dependents.joined(separator: ", ")
            let alert = NSAlert()
            alert.messageText = "Cannot uninstall \(pkg.name)"
            alert.informativeText = "These packages depend on it and would break:\n\n\(list)\n\nUninstall those packages first, or use 'brew uninstall --ignore-dependencies' manually if you know what you're doing."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
            return
        }

        let alert = NSAlert()
        alert.messageText = "Uninstall \(pkg.name)?"
        alert.informativeText = "This will run 'brew uninstall \(pkg.name)'. The package and its files will be removed."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Uninstall")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else { return }

        let args: [String]
        if pkg.type == .cask {
            args = ["uninstall", "--cask", pkg.name]
        } else {
            args = ["uninstall", pkg.name]
        }

        isScanning = true
        progress = "Uninstalling \(pkg.name)..."
        let result = await Task.detached {
            ShellExecutor.run(brew, arguments: args, timeout: .install)
        }.value
        isScanning = false

        if result.exitCode != 0 {
            let alert = NSAlert()
            alert.messageText = "Failed to uninstall \(pkg.name)"
            alert.informativeText = result.error.isEmpty ? result.output : result.error
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }

        await scan()
    }

    // MARK: - Update with Impact Check

    func updatePackageWithImpactCheck(_ pkg: HomebrewPackage) async {
        guard let brew = SecurityStatusViewModel.brewPath() else { return }

        let dependents = await Self.checkDependents(for: pkg.name)

        if !dependents.isEmpty {
            let list = dependents.joined(separator: ", ")
            let alert = NSAlert()
            alert.messageText = "Update \(pkg.name)?"
            alert.informativeText = "These \(dependents.count) package\(dependents.count == 1 ? "" : "s") depend on \(pkg.name) and could be affected:\n\n\(list)\n\nHomebrew will try to keep them compatible, but breaking changes are possible."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Update Anyway")
            alert.addButton(withTitle: "Cancel")

            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }

        let args: [String]
        if pkg.type == .cask {
            args = ["upgrade", "--cask", pkg.name]
        } else {
            args = ["upgrade", pkg.name]
        }

        isScanning = true
        progress = "Updating \(pkg.name)..."
        let result = await Task.detached {
            ShellExecutor.run(brew, arguments: args, timeout: .none)
        }.value
        isScanning = false

        if result.exitCode != 0 && !result.timedOut {
            let alert = NSAlert()
            alert.messageText = "Failed to update \(pkg.name)"
            alert.informativeText = result.error.isEmpty ? result.output : result.error
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }

        await scan()
    }

    // MARK: - Parsing

    nonisolated static func parseInstalledList(_ output: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 2 else { continue }
            result[parts[0]] = parts.last!
        }
        return result
    }

    nonisolated static func parseLeaves(_ output: String) -> Set<String> {
        Set(
            output.components(separatedBy: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        )
    }

    nonisolated static func parseSimpleList(_ output: String) -> [String] {
        output.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    struct OutdatedEntry: Sendable {
        let currentVersion: String
        let pinned: Bool
    }

    struct OutdatedInfo: Sendable {
        let formulae: [String: OutdatedEntry]
        let casks: [String: OutdatedEntry]
    }

    nonisolated static func parseOutdatedJSON(_ jsonString: String) -> OutdatedInfo {
        guard let data = jsonString.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return OutdatedInfo(formulae: [:], casks: [:])
        }

        var formulae: [String: OutdatedEntry] = [:]
        if let formulaeArray = root["formulae"] as? [[String: Any]] {
            for item in formulaeArray {
                guard let name = item["name"] as? String,
                      let currentVersion = item["current_version"] as? String else { continue }
                let pinned = item["pinned"] as? Bool ?? false
                formulae[name] = OutdatedEntry(currentVersion: currentVersion, pinned: pinned)
            }
        }

        var casks: [String: OutdatedEntry] = [:]
        if let casksArray = root["casks"] as? [[String: Any]] {
            for item in casksArray {
                guard let name = item["name"] as? String,
                      let currentVersion = item["current_version"] as? String else { continue }
                casks[name] = OutdatedEntry(currentVersion: currentVersion, pinned: false)
            }
        }

        return OutdatedInfo(formulae: formulae, casks: casks)
    }

    // MARK: - Risk Assessment

    nonisolated private static let securityCritical: Set<String> = [
        "openssl", "openssl@3", "openssl@1.1",
        "gnutls", "libressl",
        "curl", "wget",
        "git", "git-lfs",
        "openssh", "ssh-copy-id",
        "gnupg", "gpg",
        "python", "python@3.12", "python@3.13", "python@3.14",
        "node", "go", "ruby",
        "nginx", "httpd", "postgresql", "mysql", "redis",
    ]

    nonisolated static func assessRisk(
        name: String,
        installedVersion: String,
        latestVersion: String?,
        pinned: Bool,
        type: HomebrewPackageType
    ) -> (ProcessRisk, String) {
        guard let latest = latestVersion else {
            return (.safe, "Up to date")
        }

        if securityCritical.contains(name) {
            if pinned {
                return (.warning, "Security-critical package pinned at \(installedVersion) (latest: \(latest))")
            }
            return (.suspicious, "Security-critical package outdated: \(installedVersion) \u{2192} \(latest)")
        }

        if pinned {
            return (.warning, "Pinned at \(installedVersion) (latest: \(latest))")
        }

        let distance = estimateVersionDistance(installed: installedVersion, latest: latest)

        if distance >= 3 {
            return (.suspicious, "Significantly outdated: \(installedVersion) \u{2192} \(latest) (\(distance) major versions behind)")
        }

        return (.warning, "Update available: \(installedVersion) \u{2192} \(latest)")
    }

    nonisolated static func estimateVersionDistance(installed: String, latest: String) -> Int {
        let installedMajor = extractMajorVersion(installed)
        let latestMajor = extractMajorVersion(latest)

        guard let iMajor = installedMajor, let lMajor = latestMajor else {
            return installed == latest ? 0 : 1
        }

        return max(0, lMajor - iMajor)
    }

    nonisolated private static func extractMajorVersion(_ version: String) -> Int? {
        let clean = version.split(separator: ",").first.map(String.init) ?? version
        let parts = clean.split(separator: ".").map(String.init)
        guard let first = parts.first else { return nil }
        return Int(first)
    }
}
