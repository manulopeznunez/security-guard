import Foundation

@Observable
@MainActor
final class ProcessScannerViewModel {
    var processes: [ProcessEntry] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Listing processes..."
        let results = await Self.performScan { [weak self] msg in
            Task { @MainActor in self?.progress = msg }
        }
        processes = results
        progress = "Done. Found \(results.count) non-Apple processes."
        isScanning = false

        // Cache flagged items for Security Status
        let flagged = results.filter { $0.signatureValid == false }.map(\.path)
        ApprovalManager.recordScanResults(.process, flaggedIDs: flagged)
    }

    nonisolated static func performScan(onProgress: @Sendable @escaping (String) -> Void) async -> [ProcessEntry] {
        // Use 'args' instead of 'comm' to get full command path (comm can truncate)
        let result = ShellExecutor.shell("ps -eo pid,pcpu,pmem,rss,args")
        let lines = result.output.components(separatedBy: "\n").dropFirst() // skip header

        let applePathPrefixes = [
            "/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/",
            "/sbin/", "/bin/", "/kernel",
            "/Library/Apple/", "/Library/Developer/CommandLineTools/"
        ]

        var entries: [ProcessEntry] = []
        var signatureCache: [String: (valid: Bool, reason: String)] = [:]

        onProgress("Parsing processes...")

        // Parse all processes
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Split into at most 5 parts: PID, CPU, MEM, RSS, COMMAND+ARGS
            let components = trimmed.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: true).map(String.init)
            guard components.count >= 5,
                  let pid = Int(components[0]),
                  let cpu = Double(components[1]),
                  let rss = Double(components[3]) else { continue }

            // Extract just the executable path (first token before any arguments)
            let fullArgs = components[4]
            let path: String
            if fullArgs.hasPrefix("/") {
                // Path may contain spaces (e.g. "/Applications/Google Chrome.app/.../Google Chrome")
                // Try to find the longest prefix that exists as a file
                path = resolveExecutablePath(fullArgs)
            } else {
                // No absolute path — skip (system daemons without full path are kernel/Apple processes)
                continue
            }

            // Filter Apple/system processes
            if applePathPrefixes.contains(where: { path.hasPrefix($0) }) { continue }
            if path.contains("com.apple.") { continue }
            if path.contains("/Library/Apple/") { continue }

            let memMB = rss / 1024.0
            let name = URL(fileURLWithPath: path).lastPathComponent

            let appPath = findParentApp(path)
            let appName = appPath.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent }

            entries.append(ProcessEntry(
                pid: pid, name: name, cpuPercent: cpu,
                memoryMB: memMB, path: path,
                parentAppName: appName, parentAppPath: appPath,
                signatureValid: nil, risk: .safe, details: ""
            ))
        }

        // Verify signatures (deduplicated by path)
        let uniquePaths = Array(Set(entries.map(\.path)))
        onProgress("Verifying \(uniquePaths.count) unique binaries...")

        for (index, path) in uniquePaths.enumerated() {
            onProgress("Verifying: \(index + 1)/\(uniquePaths.count) — \(URL(fileURLWithPath: path).lastPathComponent)")

            // First check if file exists and is readable
            guard FileManager.default.isReadableFile(atPath: path) else {
                signatureCache[path] = (false, "File not readable (needs root)")
                continue
            }

            let check = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", path])
            if check.exitCode == 0 {
                signatureCache[path] = (true, "")
            } else {
                let errText = check.error + " " + check.output
                if errText.contains("not signed") {
                    // Check if it's inside a signed .app bundle
                    if let appPath = findParentApp(path) {
                        let appCheck = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", appPath])
                        signatureCache[path] = (appCheck.exitCode == 0, appCheck.exitCode == 0 ? "Bundle signed" : "Bundle invalid")
                    } else if isHomebrew(path) {
                        signatureCache[path] = (true, "Homebrew")
                    } else {
                        signatureCache[path] = (false, "Not signed")
                    }
                } else if errText.contains("a sealed resource is missing or invalid") {
                    signatureCache[path] = (false, "Modified since signing")
                } else {
                    signatureCache[path] = (false, errText.prefix(80).trimmingCharacters(in: .whitespacesAndNewlines))
                }
            }
        }

        // Apply risk assessment
        for i in entries.indices {
            let e = entries[i]
            let sig = signatureCache[e.path]
            entries[i].signatureValid = sig?.valid

            var reasons: [String] = []
            if sig?.valid == false {
                reasons.append(sig?.reason ?? "Invalid signature")
            }
            if e.cpuPercent > 80 { reasons.append("High CPU: \(String(format: "%.1f", e.cpuPercent))%") }
            if e.memoryMB > 500 { reasons.append("High RAM: \(Int(e.memoryMB))MB") }

            entries[i].details = reasons.joined(separator: "; ")

            if (sig?.valid == false && sig?.reason != "File not readable (needs root)" && sig?.reason != "Homebrew")
                || e.cpuPercent > 150 || e.memoryMB > 2048 {
                entries[i].risk = .suspicious
            } else if e.cpuPercent > 80 || e.memoryMB > 500 {
                entries[i].risk = .warning
            }
        }

        return entries.sorted { $0.risk > $1.risk }
    }

    /// Resolve an executable path from a full command line (which may include arguments).
    /// Handles paths with spaces like "/Applications/Google Chrome.app/.../Google Chrome".
    nonisolated private static func resolveExecutablePath(_ fullArgs: String) -> String {
        // If the entire string is a valid file, use it
        if FileManager.default.fileExists(atPath: fullArgs) {
            return fullArgs
        }
        // Try progressively shorter prefixes (split by space from the end)
        var candidate = fullArgs
        while let spaceRange = candidate.range(of: " ", options: .backwards) {
            candidate = String(candidate[..<spaceRange.lowerBound])
            if FileManager.default.fileExists(atPath: candidate) {
                return candidate
            }
        }
        // Fallback: take everything up to the first space
        return fullArgs.components(separatedBy: " ").first ?? fullArgs
    }

    /// Check if a path is inside a .app bundle.
    nonisolated static func findParentApp(_ path: String) -> String? {
        let components = path.components(separatedBy: "/")
        for (i, comp) in components.enumerated() where comp.hasSuffix(".app") {
            return components[0...i].joined(separator: "/")
        }
        return nil
    }

    /// Check if a binary comes from Homebrew.
    nonisolated static func isHomebrew(_ path: String) -> Bool {
        let brewPrefixes = ["/usr/local/Cellar/", "/opt/homebrew/Cellar/",
                            "/usr/local/opt/", "/opt/homebrew/opt/",
                            "/usr/local/bin/", "/opt/homebrew/bin/"]
        return brewPrefixes.contains(where: { path.hasPrefix($0) })
    }
}
