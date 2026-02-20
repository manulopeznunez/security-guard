import Foundation

@Observable
@MainActor
final class PersistenceScannerViewModel {
    var items: [PersistenceEntry] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Scanning persistence locations..."
        let results = await Self.performScan()
        items = results
        progress = "Done. Found \(results.count) items."
        isScanning = false

        // Cache flagged items for Security Status
        let flagged = results.filter(\.needsReview).map(\.executablePath)
        ApprovalManager.recordScanResults(.persistence, flaggedIDs: flagged)

        Self.saveCachedResult(results)
        ScanDateTracker.record(.persistence)
        DatabaseManager.shared.insertScanHistory(
            scanner: "persistence", total: results.count, flagged: flagged.count,
            summary: "\(results.count) items, \(flagged.count) need review"
        )
    }

    func loadCached() {
        if let cached = Self.loadCachedResult() { items = cached }
    }

    // MARK: - JSON Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("persistence-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: [PersistenceEntry]) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> [PersistenceEntry]? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode([PersistenceEntry].self, from: data)
    }

    nonisolated static func performScan() async -> [PersistenceEntry] {
        let home = NSHomeDirectory()
        let directories: [(String, String)] = [
            ("~/Library/LaunchAgents", "\(home)/Library/LaunchAgents"),
            ("/Library/LaunchAgents", "/Library/LaunchAgents"),
            ("/Library/LaunchDaemons", "/Library/LaunchDaemons"),
        ]

        var results: [PersistenceEntry] = []

        for (sourceName, dirPath) in directories {
            let contents = (try? FileManager.default.contentsOfDirectory(atPath: dirPath)) ?? []
            let files = contents.filter { $0.hasSuffix(".plist") }.map { "\(dirPath)/\($0)" }
            guard !files.isEmpty else { continue }

            for file in files {
                let parsed = ShellExecutor.run("/usr/bin/plutil", arguments: ["-p", file])
                let plistContent = parsed.output

                // Skip empty plists
                guard plistContent.contains("=>") else {
                    let filename = URL(fileURLWithPath: file).deletingPathExtension().lastPathComponent
                    results.append(PersistenceEntry(
                        source: sourceName,
                        label: filename,
                        executablePath: "Empty plist",
                        isApple: filename.hasPrefix("com.apple."),
                        parentAppName: nil,
                        parentAppPath: nil,
                        signatureStatus: .unchecked,
                        signatureAuthority: "",
                        risk: .safe
                    ))
                    continue
                }

                let label = extractValue(from: plistContent, key: "Label")
                    ?? URL(fileURLWithPath: file).deletingPathExtension().lastPathComponent

                // Extract executable: prefer "Program" key, then ProgramArguments[0]
                let program = extractProgramPath(from: plistContent)

                let isApple = label.hasPrefix("com.apple.")

                // Determine signature status
                let signatureStatus: SignatureStatus
                let risk: ProcessRisk
                let signatureAuthority: String

                if isApple {
                    signatureStatus = .apple
                    risk = .safe
                    signatureAuthority = "Apple"
                } else if program == nil || program == "Unknown" {
                    signatureStatus = .unchecked
                    risk = .safe
                    signatureAuthority = ""
                } else {
                    let result = verifyBinary(at: program!)
                    signatureStatus = result.0
                    risk = result.1
                    signatureAuthority = result.2
                }

                let appPath = program.flatMap { findParentApp($0) }
                let appName = appPath.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent }

                results.append(PersistenceEntry(
                    source: sourceName,
                    label: label,
                    executablePath: program ?? "Unknown",
                    isApple: isApple,
                    parentAppName: appName,
                    parentAppPath: appPath,
                    signatureStatus: signatureStatus,
                    signatureAuthority: signatureAuthority,
                    risk: risk
                ))
            }
        }

        // Cron jobs
        let cron = ShellExecutor.shell("crontab -l 2>/dev/null")
        if cron.exitCode == 0 && !cron.output.isEmpty {
            for line in cron.output.components(separatedBy: "\n")
            where !line.hasPrefix("#") && !line.isEmpty {
                results.append(PersistenceEntry(
                    source: "crontab",
                    label: "Cron Job",
                    executablePath: line,
                    isApple: false,
                    parentAppName: nil,
                    parentAppPath: nil,
                    signatureStatus: .unchecked,
                    signatureAuthority: "",
                    risk: .warning
                ))
            }
        }

        // Login Items
        let loginItems = ShellExecutor.shell(
            "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null"
        )
        if loginItems.exitCode == 0 && !loginItems.output.isEmpty {
            let items = loginItems.output.components(separatedBy: ", ")
            for item in items where !item.isEmpty {
                results.append(PersistenceEntry(
                    source: "Login Items",
                    label: item.trimmingCharacters(in: .whitespaces),
                    executablePath: "Login Item",
                    isApple: false,
                    parentAppName: nil,
                    parentAppPath: nil,
                    signatureStatus: .unchecked,
                    signatureAuthority: "",
                    risk: .safe
                ))
            }
        }

        return results.sorted { $0.risk > $1.risk }
    }

    // MARK: - Binary Verification

    /// Known safe path prefixes for Homebrew-installed software.
    /// These binaries are compiled from source and never code-signed — this is expected.
    nonisolated private static let homebrewPrefixes = [
        "/usr/local/opt/",
        "/usr/local/Cellar/",
        "/usr/local/bin/",
        "/opt/homebrew/opt/",
        "/opt/homebrew/Cellar/",
        "/opt/homebrew/bin/",
    ]

    /// Verifies a binary with multiple checks to avoid false positives.
    /// Returns (signatureStatus, risk, authority).
    nonisolated private static func verifyBinary(at path: String) -> (SignatureStatus, ProcessRisk, String) {
        // 1. Check if the file exists at all — orphaned plists are a security risk
        // (an attacker could place a binary at the expected path and it would auto-run)
        if !FileManager.default.fileExists(atPath: path) {
            return (.notFound, .warning, "")
        }

        // 2. Check if it's a Homebrew-managed binary (never signed, this is expected)
        let resolvedPath = (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) ?? path
        if homebrewPrefixes.contains(where: { path.hasPrefix($0) || resolvedPath.hasPrefix($0) }) {
            return (.homebrew, .safe, "Homebrew")
        }

        // 3. Check if we have read permissions
        if !FileManager.default.isReadableFile(atPath: path) {
            return (.permissionDenied, .safe, "")
        }

        // 4. Try codesign verification
        let check = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", path])

        // 5. Get detailed info (Authority) regardless of result
        let detail = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", path])
        let detailText = detail.output + "\n" + detail.error
        var authority = ""
        if let line = detailText.components(separatedBy: "\n").first(where: { $0.contains("Authority=") }),
           let range = line.range(of: "Authority=") {
            authority = String(line[range.upperBound...])
        }

        if check.exitCode == 0 {
            return (.valid, .safe, authority)
        }

        // 6. codesign failed — check WHY before flagging
        let errorText = check.error + " " + check.output

        if errorText.lowercased().contains("permission denied") {
            return (.permissionDenied, .safe, "")
        }

        if detailText.lowercased().contains("permission denied") {
            return (.permissionDenied, .safe, "")
        }

        if !authority.isEmpty {
            // Has a signature but verification failed (modified after signing)
            let reason = errorText.trimmingCharacters(in: .whitespacesAndNewlines)
            return (.invalid(reason: reason), .warning, authority)
        }

        // 7. Truly unsigned — check if inside a signed .app bundle
        if let appRange = path.range(of: ".app/") {
            let appPath = String(path[..<appRange.upperBound].dropLast())
            let appCheck = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", appPath])
            if appCheck.exitCode == 0 {
                return (.valid, .safe, authority)
            }
        }

        return (.invalid(reason: "No code signature found"), .suspicious, "")
    }

    // MARK: - App Bundle Detection

    /// Check if a path is inside a .app bundle and return the bundle path.
    nonisolated static func findParentApp(_ path: String) -> String? {
        let components = path.components(separatedBy: "/")
        for (i, comp) in components.enumerated() where comp.hasSuffix(".app") {
            return components[0...i].joined(separator: "/")
        }
        return nil
    }

    // MARK: - Plist Parsing

    /// Extracts the executable path from plutil -p output.
    /// Tries "Program" key first, then ProgramArguments[0].
    nonisolated static func extractProgramPath(from output: String) -> String? {
        // 1. Try "Program" key (direct path)
        if let program = extractValue(from: output, key: "Program") {
            return program
        }

        // 2. Try ProgramArguments array — extract the first element (index 0)
        // We need to find the ProgramArguments block first, then get 0 => "..."
        // Pattern: "ProgramArguments" => [ ... 0 => "/path/to/exe" ... ]
        guard let argsStart = output.range(of: "\"ProgramArguments\" => [") else {
            return nil
        }

        // Find the closing bracket of ProgramArguments
        let afterArgs = output[argsStart.upperBound...]
        guard let argsEnd = afterArgs.range(of: "]") else {
            return nil
        }

        let argsBlock = String(afterArgs[..<argsEnd.lowerBound])

        // Now extract 0 => "..." from within the ProgramArguments block only
        let pattern = #"0 => "(.+?)""#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: argsBlock, range: NSRange(argsBlock.startIndex..., in: argsBlock)),
              let range = Range(match.range(at: 1), in: argsBlock) else {
            return nil
        }

        return String(argsBlock[range])
    }

    /// Extracts a simple "Key" => "Value" from plutil -p output.
    nonisolated static func extractValue(from output: String, key: String) -> String? {
        let pattern = "\"\(key)\" => \"(.+?)\""
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)),
              let range = Range(match.range(at: 1), in: output) else { return nil }
        return String(output[range])
    }
}
