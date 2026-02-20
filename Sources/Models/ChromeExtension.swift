import SwiftUI

enum ExtensionRisk: Int, Comparable, Sendable {
    case low = 0
    case medium = 1
    case high = 2

    static func < (lhs: ExtensionRisk, rhs: ExtensionRisk) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var color: Color {
        switch self {
        case .low: .green
        case .medium: .orange
        case .high: .red
        }
    }

    var label: String {
        switch self {
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        }
    }
}

struct ChromeExtensionEntry: Identifiable, Sendable {
    let id = UUID()
    let name: String
    let extensionId: String
    let version: String
    let description: String
    let permissions: [String]
    let hostPermissions: [String]
    let profile: String
    let risk: ExtensionRisk
    let riskReasons: [String]
    let isFromWebStore: Bool
    let source: String        // "Chrome Web Store", "Sideloaded", "Policy", "Built-in"
    let author: String        // from manifest.json "author" field
    let homepageURL: String   // from manifest.json "homepage_url"
    let profileDisplayName: String  // human-readable profile name (Google account name)

    var isApproved: Bool {
        ApprovalManager.isApproved(.chromeExtension, id: extensionId)
    }

    var isQuarantined: Bool {
        ApprovalManager.isQuarantined(.chromeExtension, id: extensionId)
    }

    var effectiveLabel: String {
        if risk == .high && isQuarantined {
            return "High (Quarantined)"
        } else if risk == .high && isApproved {
            return "High (Approved)"
        } else if risk == .high {
            return "High (Pending review)"
        }
        return risk.label
    }

    var effectiveColor: Color {
        if risk == .high && isQuarantined {
            return .red
        } else if risk == .high && isApproved {
            return .orange
        }
        return risk.color
    }
}
