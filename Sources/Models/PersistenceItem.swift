import Foundation

enum SignatureStatus: Sendable {
    case valid
    case invalid(reason: String)
    case notFound
    case unchecked
    case apple
    case homebrew
    case permissionDenied
}

struct PersistenceEntry: Identifiable, Sendable {
    let id = UUID()
    let source: String
    let label: String
    let executablePath: String
    let isApple: Bool
    let parentAppName: String?
    let parentAppPath: String?
    var signatureStatus: SignatureStatus
    var signatureAuthority: String
    var risk: ProcessRisk

    /// Only items with a real cryptographic signature (valid codesign or Apple) are trusted.
    /// Everything else — including Homebrew (path-based, not signed) — needs human review.
    var needsReview: Bool {
        switch signatureStatus {
        case .valid, .apple: return false
        default: return true
        }
    }
}
