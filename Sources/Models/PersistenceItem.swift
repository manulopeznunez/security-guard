import Foundation

enum SignatureStatus: Sendable, Codable {
    case valid
    case invalid(reason: String)
    case notFound
    case unchecked
    case apple
    case homebrew
    case permissionDenied

    private enum Kind: String, Codable {
        case valid, invalid, notFound, unchecked, apple, homebrew, permissionDenied
    }

    private enum CodingKeys: String, CodingKey {
        case kind, reason
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .valid: try c.encode(Kind.valid, forKey: .kind)
        case .invalid(let reason):
            try c.encode(Kind.invalid, forKey: .kind)
            try c.encode(reason, forKey: .reason)
        case .notFound: try c.encode(Kind.notFound, forKey: .kind)
        case .unchecked: try c.encode(Kind.unchecked, forKey: .kind)
        case .apple: try c.encode(Kind.apple, forKey: .kind)
        case .homebrew: try c.encode(Kind.homebrew, forKey: .kind)
        case .permissionDenied: try c.encode(Kind.permissionDenied, forKey: .kind)
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .valid: self = .valid
        case .invalid: self = .invalid(reason: try c.decode(String.self, forKey: .reason))
        case .notFound: self = .notFound
        case .unchecked: self = .unchecked
        case .apple: self = .apple
        case .homebrew: self = .homebrew
        case .permissionDenied: self = .permissionDenied
        }
    }
}

struct PersistenceEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case source, label, executablePath, isApple, parentAppName, parentAppPath
        case signatureStatus, signatureAuthority, risk
    }
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
