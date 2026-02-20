import SwiftUI

// MARK: - TCC Risk

enum TCCRisk: Int, Comparable, Sendable {
    case safe = 0
    case warning = 1
    case dangerous = 2

    static func < (lhs: TCCRisk, rhs: TCCRisk) -> Bool {
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

// MARK: - TCC Entry

struct TCCEntry: Identifiable, Sendable {
    let id = UUID()
    let service: String
    let serviceFriendly: String
    let client: String
    let clientType: Int
    let authValue: Int
    let authReason: Int
    let lastModified: Date?
    let isAppleApp: Bool
    let isSigned: Bool?  // nil = unknown, true = valid sig, false = unsigned/invalid
    var risk: TCCRisk
    var riskReason: String

    var approvalID: String {
        "\(service):\(client)"
    }

    var needsReview: Bool {
        risk != .safe
    }

    var authLabel: String {
        switch authValue {
        case 0: "Denied"
        case 2: "Allowed"
        case 3: "Limited"
        default: "Unknown (\(authValue))"
        }
    }

    /// System Settings Privacy pane anchor for this TCC service
    var privacySettingsAnchor: String? {
        let map: [String: String] = [
            "kTCCServiceSystemPolicyAllFiles": "Privacy_AllFiles",
            "kTCCServiceAccessibility": "Privacy_Accessibility",
            "kTCCServiceScreenCapture": "Privacy_ScreenCapture",
            "kTCCServiceCamera": "Privacy_Camera",
            "kTCCServiceMicrophone": "Privacy_Microphone",
            "kTCCServiceAppleEvents": "Privacy_Automation",
            "kTCCServiceSystemPolicyDesktopFolder": "Privacy_DesktopFolder",
            "kTCCServiceSystemPolicyDocumentsFolder": "Privacy_DocumentsFolder",
            "kTCCServiceSystemPolicyDownloadsFolder": "Privacy_DownloadsFolder",
            "kTCCServiceContactsFull": "Privacy_Contacts",
            "kTCCServiceCalendar": "Privacy_Calendars",
            "kTCCServiceReminders": "Privacy_Reminders",
            "kTCCServicePhotos": "Privacy_Photos",
            "kTCCServiceListenEvent": "Privacy_ListenEvent",
            "kTCCServicePostEvent": "Privacy_ListenEvent",
            "kTCCServiceDeveloperTool": "Privacy_DevTools",
            "kTCCServiceBluetoothAlways": "Privacy_Bluetooth",
        ]
        return map[service]
    }
}
