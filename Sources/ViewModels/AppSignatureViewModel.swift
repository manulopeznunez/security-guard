import Foundation

@Observable
@MainActor
final class AppSignatureViewModel {
    var apps: [AppSignatureEntry] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Listing applications..."
        let results = await Self.performScan { [weak self] msg in
            Task { @MainActor in self?.progress = msg }
        }
        apps = results
        progress = "Done. Checked \(results.count) apps."
        isScanning = false

        // Cache flagged items for Security Status
        let flagged = results.filter { !$0.isValid }.map(\.appPath)
        ApprovalManager.recordScanResults(.appSignature, flaggedIDs: flagged)

        Self.saveCachedResult(results)
        ScanDateTracker.record(.appSignatures)
        DatabaseManager.shared.insertScanHistory(
            scanner: "appSignatures", total: results.count, flagged: flagged.count,
            summary: "\(results.count) apps, \(flagged.count) invalid signatures"
        )
    }

    func loadCached() {
        if let cached = Self.loadCachedResult() { apps = cached }
    }

    // MARK: - JSON Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("app-signatures-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: [AppSignatureEntry]) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> [AppSignatureEntry]? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode([AppSignatureEntry].self, from: data)
    }

    nonisolated static func performScan(onProgress: @Sendable @escaping (String) -> Void) async -> [AppSignatureEntry] {
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: "/Applications")) ?? []
        let appPaths = contents.filter { $0.hasSuffix(".app") }
            .map { "/Applications/\($0)" }
            .sorted()

        var results: [AppSignatureEntry] = []

        for (index, path) in appPaths.enumerated() {
            let name = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
            onProgress("Checking \(index + 1)/\(appPaths.count): \(name)")

            let verify = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", path])
            let isValid = verify.exitCode == 0

            var authority = "Unknown"
            let info = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", path])
            let infoText = info.output + "\n" + info.error
            if let line = infoText.components(separatedBy: "\n").first(where: { $0.contains("Authority=") }),
               let range = line.range(of: "Authority=") {
                authority = String(line[range.upperBound...])
            }

            let details = isValid ? "" : (verify.error.isEmpty ? verify.output : verify.error)

            results.append(AppSignatureEntry(
                appName: name,
                appPath: path,
                isValid: isValid,
                authority: authority,
                details: details,
                risk: isValid ? .safe : .suspicious
            ))
        }

        return results.sorted { $0.risk > $1.risk }
    }
}
