import Foundation
import os.log

@Observable
@MainActor
final class KnockKnockViewModel {
    var result: KnockKnockResult?
    var isScanning = false
    var progress = ""

    nonisolated(unsafe) private static let cliPath = "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"

    nonisolated(unsafe) private static var cacheURL: URL {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!
        return appSupport
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("knockknock-cache.json")
    }

    func scan() async {
        isScanning = true
        progress = "Running KnockKnock scan..."
        let scanResult = await Self.performScan { [weak self] msg in
            Task { @MainActor in self?.progress = msg }
        }
        result = scanResult
        isScanning = false

        let flaggedKK = scanResult.flaggedItems.map(\.path)
        ApprovalManager.recordScanResults(.knockknock, flaggedIDs: flaggedKK)
        ScanDateTracker.record(.knockknock)
        DatabaseManager.shared.insertScanHistory(
            scanner: "knockknock", total: scanResult.totalItems, flagged: flaggedKK.count,
            summary: "\(scanResult.totalItems) items, \(scanResult.unsignedCount) unsigned, \(scanResult.vtFlaggedCount) VT flagged"
        )
    }

    func loadCached() {
        result = Self.loadCachedResult()
    }

    // MARK: - Static scan (callable from BackgroundMonitor)

    nonisolated static func performScan(
        onProgress: @Sendable @escaping (String) -> Void = { _ in }
    ) async -> KnockKnockResult {
        guard FileManager.default.isExecutableFile(atPath: cliPath) else {
            AuditLogger.security.info("KnockKnock not installed — skipping scan")
            return errorResult("KnockKnock not installed", fdaAvailable: false)
        }

        onProgress("Running KnockKnock CLI (this may take 30-120 seconds)...")
        AuditLogger.security.info("Starting KnockKnock CLI scan")

        let shellResult = await Task.detached {
            ShellExecutor.run(
                cliPath,
                arguments: ["-whosthere", "-pretty", "-skipVT"],
                timeout: .scan
            )
        }.value

        if shellResult.timedOut {
            AuditLogger.security.warning("KnockKnock scan timed out after 180s")
            return errorResult("Scan timed out after 180s", fdaAvailable: true)
        }

        if shellResult.exitCode != 0 {
            let msg = shellResult.error.isEmpty ? shellResult.output : shellResult.error
            let isFDA = msg.contains("Full Disk Access") ||
                        msg.contains("Operation not permitted") ||
                        msg.contains("kTCCServiceSystemPolicyAllFiles")
            AuditLogger.security.warning("KnockKnock failed: \(msg, privacy: .public)")
            return errorResult(
                isFDA
                    ? "Full Disk Access required for the app running KnockKnock. Grant it to Security Guard (or Terminal if running via swift run) in System Settings > Privacy & Security > Full Disk Access."
                    : msg,
                fdaAvailable: !isFDA
            )
        }

        onProgress("Parsing KnockKnock results...")
        let parsed = parseJSON(shellResult.output)
        saveCachedResult(parsed)
        AuditLogger.security.info(
            "KnockKnock scan complete: \(parsed.totalItems) items, \(parsed.unsignedCount) unsigned, \(parsed.vtFlaggedCount) VT flagged"
        )
        return parsed
    }

    // MARK: - JSON Parsing (pure, testable)

    nonisolated static func parseJSON(_ jsonString: String) -> KnockKnockResult {
        guard let data = jsonString.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return errorResult("Failed to parse KnockKnock JSON output", fdaAvailable: true)
        }

        var categories: [String: [KnockKnockItem]] = [:]
        var totalItems = 0
        var appleCount = 0
        var devIDCount = 0
        var unsignedCount = 0
        var vtFlagged = 0

        for (categoryName, value) in root {
            guard let items = value as? [[String: Any]] else { continue }
            var parsedItems: [KnockKnockItem] = []

            for item in items {
                let name = item["name"] as? String ?? ""
                let path = item["path"] as? String ?? ""
                let plist = item["plist"] as? String ?? ""
                let hashes = item["hashes"] as? [String: String] ?? [:]
                let vtDetection = item["VT detection"] as? String ?? ""

                let sigDict = item["signature(s)"] as? [String: Any] ?? [:]
                let sigStatus = sigDict["signatureStatus"] as? Int ?? -1
                let sigSigner = sigDict["signatureSigner"] as? Int ?? 0
                let sigAuthorities = sigDict["signatureAuthorities"] as? [String] ?? []
                let sigIdentifier = sigDict["signatureIdentifier"] as? String ?? ""

                parsedItems.append(KnockKnockItem(
                    category: categoryName,
                    name: name,
                    path: path,
                    plist: plist,
                    md5: hashes["md5"] ?? "",
                    sha256: hashes["sha256"] ?? "",
                    vtDetection: vtDetection,
                    signatureStatus: sigStatus,
                    signatureSigner: sigSigner,
                    signatureAuthorities: sigAuthorities,
                    signatureIdentifier: sigIdentifier
                ))

                totalItems += 1

                switch sigSigner {
                case 1: appleCount += 1
                case 2, 3: devIDCount += 1
                default: unsignedCount += 1
                }

                if !vtDetection.isEmpty,
                   let slash = vtDetection.firstIndex(of: "/"),
                   let detections = Int(vtDetection[vtDetection.startIndex..<slash]),
                   detections > 0 {
                    vtFlagged += 1
                }
            }

            if !parsedItems.isEmpty {
                categories[categoryName] = parsedItems
            }
        }

        return KnockKnockResult(
            scanDate: Date(),
            totalItems: totalItems,
            appleSignedCount: appleCount,
            devIDSignedCount: devIDCount,
            unsignedCount: unsignedCount,
            vtFlaggedCount: vtFlagged,
            categories: categories,
            fdaAvailable: true,
            error: nil
        )
    }

    // MARK: - File-based JSON loading

    nonisolated static func parseJSONFile(at url: URL) -> KnockKnockResult? {
        guard let data = try? Data(contentsOf: url),
              let jsonString = String(data: data, encoding: .utf8) else {
            return nil
        }
        let result = parseJSON(jsonString)
        if result.error == nil {
            saveCachedResult(result)
        }
        return result
    }

    // MARK: - Cache

    nonisolated private static func saveCachedResult(_ result: KnockKnockResult) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        let dir = cacheURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> KnockKnockResult? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode(KnockKnockResult.self, from: data)
    }

    nonisolated private static func errorResult(_ message: String, fdaAvailable: Bool) -> KnockKnockResult {
        KnockKnockResult(
            scanDate: Date(), totalItems: 0,
            appleSignedCount: 0, devIDSignedCount: 0,
            unsignedCount: 0, vtFlaggedCount: 0,
            categories: [:], fdaAvailable: fdaAvailable,
            error: message
        )
    }
}
