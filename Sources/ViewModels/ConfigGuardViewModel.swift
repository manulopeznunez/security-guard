import CryptoKit
import Foundation

@Observable
@MainActor
final class ConfigGuardViewModel {
    var entries: [ConfigGuardEntry] = []
    var isScanning = false
    var progress = ""
    var hasBaseline: Bool { !Self.loadBaselines().isEmpty }

    nonisolated static let baselineKey = "ConfigGuardBaselines"

    nonisolated static let monitoredFiles: [String] = [
        // Shell configuration
        "~/.zshrc",
        "~/.bashrc",
        "~/.bash_profile",
        "~/.zprofile",
        "~/.profile",

        // Git
        "~/.gitconfig",

        // SSH keys & config
        "~/.ssh/config",
        "~/.ssh/authorized_keys",
        "~/.ssh/known_hosts",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.ssh/id_ecdsa",

        // Cloud & DevOps credentials
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.config/gh/hosts.yml",

        // Package managers & registries
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.config/pip/pip.conf",
        "~/.gemrc",
        "~/.cargo/config.toml",
        "~/.m2/settings.xml",

        // System & misc
        "/etc/hosts",
        "~/.curlrc",
        "~/.gnupg/gpg.conf",
    ]

    // MARK: - Scan

    func scan() async {
        isScanning = true
        progress = "Checking configuration files..."
        let result = await Self.performScan()
        entries = result
        isScanning = false
        progress = ""

        let flagged = result.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.configGuard, flaggedIDs: flagged)
    }

    // MARK: - Approve change (save new baseline for one file)

    func approveChange(for entry: ConfigGuardEntry) {
        guard let hash = entry.currentHash else { return }
        var baselines = Self.loadBaselines()
        baselines[entry.filePath] = hash
        Self.saveBaselines(baselines)
        ApprovalManager.approve(.configGuard, id: entry.approvalID)
    }

    // MARK: - Set Baseline (snapshot all current hashes)

    func setBaseline() async {
        isScanning = true
        progress = "Setting baseline..."
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var baselines: [String: String] = [:]

        for relativePath in Self.monitoredFiles {
            let absolutePath = relativePath.replacingOccurrences(of: "~", with: home)
            if let data = FileManager.default.contents(atPath: absolutePath) {
                let digest = SHA256.hash(data: data)
                baselines[relativePath] = digest.map { String(format: "%02x", $0) }.joined()
            }
        }

        Self.saveBaselines(baselines)
        await scan()
    }

    // MARK: - Static Scan

    nonisolated static func performScan() async -> [ConfigGuardEntry] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let baselines = loadBaselines()
        let hasBaseline = !baselines.isEmpty

        var entries: [ConfigGuardEntry] = []

        for relativePath in monitoredFiles {
            let absolutePath = relativePath.replacingOccurrences(of: "~", with: home)
            let exists = FileManager.default.fileExists(atPath: absolutePath)

            let currentHash: String?
            let permissions: String

            if exists {
                if let data = FileManager.default.contents(atPath: absolutePath) {
                    let digest = SHA256.hash(data: data)
                    currentHash = digest.map { String(format: "%02x", $0) }.joined()
                } else {
                    currentHash = nil
                }

                let permResult = await Task.detached {
                    ShellExecutor.run("/usr/bin/stat", arguments: ["-f", "%Lp", absolutePath])
                }.value
                permissions = permResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                currentHash = nil
                permissions = ""
            }

            let baselineHash = baselines[relativePath]

            let changeType: ConfigChangeType
            let risk: AccessRisk
            let reason: String

            if !hasBaseline {
                changeType = .unchanged
                risk = .safe
                reason = exists ? "No baseline yet — click 'Set Baseline' to start tracking" : "File does not exist"
            } else if !exists && baselineHash != nil {
                changeType = .deleted
                risk = .suspicious
                reason = "File was present in baseline but has been deleted"
            } else if exists && baselineHash == nil {
                changeType = .newFile
                risk = .warning
                reason = "File not in baseline — created since last scan"
            } else if exists && currentHash != baselineHash {
                changeType = .modified
                risk = .suspicious
                reason = "File content changed since baseline"
            } else if exists && isInsecurePermissions(relativePath, permissions: permissions) {
                changeType = .insecurePermissions
                risk = .warning
                reason = "File has insecure permissions (\(permissions))"
            } else {
                changeType = .unchanged
                risk = .safe
                reason = exists ? "Unchanged since baseline" : "File does not exist"
            }

            entries.append(ConfigGuardEntry(
                filePath: relativePath,
                absolutePath: absolutePath,
                exists: exists,
                currentHash: currentHash,
                baselineHash: baselineHash,
                permissions: permissions,
                changeType: changeType,
                risk: risk,
                riskReason: reason
            ))
        }

        return entries.sorted { $0.risk > $1.risk }
    }

    // MARK: - Baseline Storage

    nonisolated static func loadBaselines() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: baselineKey) as? [String: String] ?? [:]
    }

    nonisolated private static func saveBaselines(_ baselines: [String: String]) {
        UserDefaults.standard.set(baselines, forKey: baselineKey)
    }

    // MARK: - Permission Checks

    nonisolated static func isInsecurePermissions(_ path: String, permissions: String) -> Bool {
        // Files that MUST be 600 or 400 (private keys, credentials)
        let strictFiles: Set<String> = [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/id_ecdsa",
            "~/.aws/credentials",
            "~/.kube/config",
            "~/.docker/config.json",
            "~/.config/gh/hosts.yml",
            "~/.pypirc",
            "~/.netrc",
            "~/.m2/settings.xml",
            "~/.gnupg/gpg.conf",
        ]
        if strictFiles.contains(path) {
            return permissions != "600" && permissions != "400"
        }

        // Files that should be 600, 644, or 400
        let sensitiveFiles: Set<String> = [
            "~/.ssh/config",
            "~/.ssh/authorized_keys",
            "~/.ssh/known_hosts",
            "~/.aws/config",
            "~/.npmrc",
            "~/.gemrc",
            "~/.cargo/config.toml",
            "~/.curlrc",
        ]
        if sensitiveFiles.contains(path) {
            return permissions != "600" && permissions != "644" && permissions != "400"
        }

        return false
    }
}
