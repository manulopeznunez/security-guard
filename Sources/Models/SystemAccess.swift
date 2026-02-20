import SwiftUI

// MARK: - Access Risk

enum AccessRisk: Int, Comparable, Sendable, Codable {
    case safe = 0
    case warning = 1
    case suspicious = 2

    static func < (lhs: AccessRisk, rhs: AccessRisk) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var color: Color {
        switch self {
        case .safe: .green
        case .warning: .orange
        case .suspicious: .red
        }
    }

    var label: String {
        switch self {
        case .safe: "Safe"
        case .warning: "Warning"
        case .suspicious: "Suspicious"
        }
    }
}

// MARK: - Sudo Entry

struct SudoEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case rule, user, hasNOPASSWD, commands, source, risk, riskReason
    }
    let rule: String
    let user: String
    let hasNOPASSWD: Bool
    let commands: String
    let source: String
    var risk: AccessRisk
    var riskReason: String

    var approvalID: String {
        "\(user):\(source):\(rule.hashValue)"
    }

    var needsReview: Bool {
        risk != .safe
    }
}

// MARK: - User Account Entry

struct UserAccountEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case username, uid, fullName, homeDirectory, shell, isAdmin, isHidden, isGuest, risk, riskReason
    }
    let username: String
    let uid: Int
    let fullName: String
    let homeDirectory: String
    let shell: String
    let isAdmin: Bool
    let isHidden: Bool
    let isGuest: Bool
    var risk: AccessRisk
    var riskReason: String

    var approvalID: String {
        "\(username):\(uid)"
    }

    var needsReview: Bool {
        risk != .safe
    }
}

// MARK: - Group Entry

struct GroupEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case name, gid, members, isSensitive, risk, riskReason, actionHint
    }
    let name: String
    let gid: Int
    let members: [String]
    let isSensitive: Bool
    var risk: AccessRisk
    var riskReason: String
    var actionHint: String
}

// MARK: - Config Guard

enum ConfigChangeType: String, Sendable, Codable {
    case unchanged = "Unchanged"
    case modified = "Modified"
    case newFile = "New File"
    case deleted = "Deleted"
    case insecurePermissions = "Insecure Permissions"

    var color: Color {
        switch self {
        case .unchanged: .green
        case .modified: .red
        case .newFile: .orange
        case .deleted: .red
        case .insecurePermissions: .orange
        }
    }
}

struct ConfigGuardEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case filePath, absolutePath, exists, currentHash, baselineHash, permissions
        case changeType, risk, riskReason
    }
    let filePath: String
    let absolutePath: String
    let exists: Bool
    let currentHash: String?
    let baselineHash: String?
    let permissions: String
    let changeType: ConfigChangeType
    var risk: AccessRisk
    var riskReason: String

    var approvalID: String {
        filePath
    }

    var needsReview: Bool {
        risk != .safe
    }
}
