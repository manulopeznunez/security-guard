import Foundation

/// A single persistent item found by KnockKnock CLI.
struct KnockKnockItem: Identifiable, Sendable, Codable {
    var id: String { path }
    let category: String
    let name: String
    let path: String
    let plist: String
    let md5: String
    let sha256: String
    let vtDetection: String
    let signatureStatus: Int
    let signatureSigner: Int
    let signatureAuthorities: [String]
    let signatureIdentifier: String
}

/// Aggregated results from a single KnockKnock scan.
struct KnockKnockResult: Sendable, Codable {
    let scanDate: Date
    let totalItems: Int
    let appleSignedCount: Int
    let devIDSignedCount: Int
    let unsignedCount: Int
    let vtFlaggedCount: Int
    let categories: [String: [KnockKnockItem]]
    let fdaAvailable: Bool
    let error: String?

    var flaggedItems: [KnockKnockItem] {
        categories.values.flatMap { $0 }.filter { item in
            item.signatureSigner == 0 ||
            item.signatureStatus != 0 ||
            vtDetections(item.vtDetection) > 0
        }
    }

    var nonAppleItems: [KnockKnockItem] {
        categories.values.flatMap { $0 }.filter { $0.signatureSigner != 1 }
    }

    private func vtDetections(_ detection: String) -> Int {
        guard !detection.isEmpty, let slash = detection.firstIndex(of: "/") else { return 0 }
        return Int(detection[detection.startIndex..<slash]) ?? 0
    }
}
