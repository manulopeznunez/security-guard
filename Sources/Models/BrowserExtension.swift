import SwiftUI

enum BrowserType: String, Sendable, Codable, CaseIterable, Identifiable {
    case chrome = "Chrome"
    case safari = "Safari"
    case firefox = "Firefox"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .chrome: "globe"
        case .safari: "safari"
        case .firefox: "flame"
        }
    }

    var color: Color {
        switch self {
        case .chrome: .blue
        case .safari: .cyan
        case .firefox: .orange
        }
    }
}

struct BrowserExtensionEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case name, extensionId, version, description, permissions, hostPermissions
        case profile, risk, riskReasons, isFromStore, source, author, homepageURL
        case profileDisplayName, browser
    }

    let name: String
    let extensionId: String
    let version: String
    let description: String
    let permissions: [String]
    let hostPermissions: [String]
    let profile: String
    let risk: ExtensionRisk
    let riskReasons: [String]
    let isFromStore: Bool
    let source: String
    let author: String
    let homepageURL: String
    let profileDisplayName: String
    let browser: BrowserType

    var approvalID: String { "\(browser.rawValue):\(extensionId)" }
    var needsReview: Bool { risk == .high }

    var isApproved: Bool {
        ApprovalManager.isApproved(.browserExtension, id: approvalID)
    }

    var isQuarantined: Bool {
        ApprovalManager.isQuarantined(.browserExtension, id: approvalID)
    }

    var effectiveLabel: String {
        if risk == .high && isQuarantined { return "High (Quarantined)" }
        if risk == .high && isApproved { return "High (Approved)" }
        if risk == .high { return "High (Pending review)" }
        return risk.label
    }

    var effectiveColor: Color {
        if risk == .high && isQuarantined { return .red }
        if risk == .high && isApproved { return .orange }
        return risk.color
    }
}
