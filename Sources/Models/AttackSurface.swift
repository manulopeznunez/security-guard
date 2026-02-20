import SwiftUI

// MARK: - Port Risk

enum PortRisk: Int, Comparable, Sendable {
    case safe = 0
    case warning = 1
    case dangerous = 2

    static func < (lhs: PortRisk, rhs: PortRisk) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var color: Color {
        switch self {
        case .safe: .green
        case .warning: .orange
        case .dangerous: .red
        }
    }

    var label: String {
        switch self {
        case .safe: "Safe"
        case .warning: "Warning"
        case .dangerous: "Dangerous"
        }
    }
}

// MARK: - Listening Ports

struct ListeningPortSnapshot: Sendable {
    let processName: String
    let pid: Int
    let localPort: String
    let localAddress: String
    let processPath: String
    let parentSignature: String
}

struct ListeningPortSummary: Identifiable, Sendable {
    let id = UUID()
    let localPort: String
    let localAddress: String
    let processName: String
    let processPath: String
    let parentSignature: String
    let firstSeen: String
    let lastSeen: String
    let timesSeen: Int
    let isCurrentlyOpen: Bool
    let risk: PortRisk
    let riskReason: String

    var approvalID: String {
        "\(localPort):\(processName)"
    }

    var needsReview: Bool {
        risk != .safe
    }
}

// MARK: - SSH Audit

struct SSHAuditResult: Sendable {
    let sshEnabled: Bool
    let authorizedKeysCount: Int
    let authorizedKeysEntries: [SSHKeyEntry]
    let privateKeyCount: Int
    let privateKeys: [SSHKeyInfo]
    let configIssues: [String]
    let agentKeysLoaded: Int
}

struct SSHKeyEntry: Identifiable, Sendable {
    let id = UUID()
    let keyType: String
    let comment: String
    let fingerprint: String
}

struct SSHKeyInfo: Identifiable, Sendable {
    let id = UUID()
    let filename: String
    let keyType: String
    let permissions: String
    let permissionsOK: Bool
}

// MARK: - Exposed Services

struct ExposedService: Identifiable, Sendable {
    let id = UUID()
    let name: String
    let port: String
    let processName: String
    let isEnabled: Bool
    let risk: PortRisk
    let description: String
    let howToDisable: String
}
