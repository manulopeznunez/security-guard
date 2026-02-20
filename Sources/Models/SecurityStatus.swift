import SwiftUI

enum SecurityCategory: String, Sendable, CaseIterable {
    case builtIn = "macOS Built-in Protection"
    case recommended = "Recommended Security Tools"
    case blindSpots = "Potential Blind Spots"

    var icon: String {
        switch self {
        case .builtIn: "desktopcomputer"
        case .recommended: "wrench.and.screwdriver.fill"
        case .blindSpots: "eye.trianglebadge.exclamationmark"
        }
    }
}

enum SecurityItemStatus: Sendable {
    case enabled, disabled, unknown

    var color: Color {
        switch self {
        case .enabled: .fpeSuccess
        case .disabled: .fpeDestructive
        case .unknown: .fpeMuted
        }
    }

    var icon: String {
        switch self {
        case .enabled: "checkmark.circle.fill"
        case .disabled: "xmark.circle.fill"
        case .unknown: "questionmark.circle.fill"
        }
    }

    var label: String {
        switch self {
        case .enabled: "Enabled"
        case .disabled: "Disabled"
        case .unknown: "Unknown"
        }
    }

    var pillBackground: Color {
        switch self {
        case .enabled: .fpeSuccess.opacity(0.12)
        case .disabled: .fpeDestructive.opacity(0.12)
        case .unknown: .fpeMuted.opacity(0.12)
        }
    }
}

enum SecurityAction: Sendable {
    case none
    case installBrew(formula: String)
    case openSystemSettings(path: String)
    case openURL(url: String)
}

struct SecurityItem: Identifiable, Sendable {
    let id = UUID()
    let name: String
    let explanation: String
    let howToUse: String
    let description: String
    let status: SecurityItemStatus
    let action: SecurityAction
    let category: SecurityCategory
    /// Tab to navigate to when this card is clicked (nil = no navigation).
    var targetTab: TabSection? = nil
}
