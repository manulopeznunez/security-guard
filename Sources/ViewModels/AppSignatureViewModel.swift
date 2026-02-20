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
        ApprovalManager.saveFlagged(.appSignature, ids: flagged)
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
