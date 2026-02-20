import SwiftUI

enum PackageManager: String, Sendable, Codable, CaseIterable, Identifiable {
    case npm = "npm"
    case pip = "pip"
    case cargo = "Cargo"

    var id: String { rawValue }

    var lockFile: String {
        switch self {
        case .npm: "package-lock.json"
        case .pip: "requirements.txt"
        case .cargo: "Cargo.lock"
        }
    }

    var icon: String {
        switch self {
        case .npm: "shippingbox"
        case .pip: "leaf"
        case .cargo: "gearshape"
        }
    }

    var color: Color {
        switch self {
        case .npm: .red
        case .pip: .blue
        case .cargo: .orange
        }
    }
}

enum VulnerabilitySeverity: Int, Comparable, Sendable, Codable {
    case info = 0
    case low = 1
    case moderate = 2
    case high = 3
    case critical = 4

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

    var label: String {
        switch self {
        case .info: "Info"
        case .low: "Low"
        case .moderate: "Moderate"
        case .high: "High"
        case .critical: "Critical"
        }
    }

    var color: Color {
        switch self {
        case .info: .secondary
        case .low: .green
        case .moderate: .orange
        case .high: .red
        case .critical: .purple
        }
    }

    var risk: ProcessRisk {
        switch self {
        case .info, .low: .safe
        case .moderate: .warning
        case .high, .critical: .suspicious
        }
    }
}

struct DevVulnerability: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case packageName, installedVersion, vulnerableRange, severity
        case title, url, manager, projectPath
    }

    let packageName: String
    let installedVersion: String
    let vulnerableRange: String
    let severity: VulnerabilitySeverity
    let title: String
    let url: String
    let manager: PackageManager
    let projectPath: String

    var approvalID: String { "\(manager.rawValue):\(projectPath):\(packageName)" }
    var needsReview: Bool { severity >= .high }
}

struct DevProjectSummary: Identifiable, Sendable {
    let id = UUID()
    let projectPath: String
    let manager: PackageManager
    let totalDeps: Int
    let vulnerabilities: [DevVulnerability]

    var worstSeverity: VulnerabilitySeverity {
        vulnerabilities.map(\.severity).max() ?? .info
    }
}
