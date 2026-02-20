import SwiftUI

// MARK: - TCC Risk

enum TCCRisk: Int, Comparable, Sendable, Codable {
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

struct TCCEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case service, serviceFriendly, client, clientType, authValue, authReason
        case lastModified, isAppleApp, isSigned, appName, appIconData, risk, riskReason
    }
    let service: String
    let serviceFriendly: String
    let client: String
    let clientType: Int
    let authValue: Int
    let authReason: Int
    let lastModified: Date?
    let isAppleApp: Bool
    let isSigned: Bool?
    let appName: String
    let appIconData: Data?
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

    var isRecentlyGranted: Bool {
        guard let modified = lastModified else { return false }
        return modified > Date().addingTimeInterval(-7 * 24 * 3600)
    }

    var permissionExplanation: String {
        let map: [String: String] = [
            "kTCCServiceSystemPolicyAllFiles": "Can read and write ALL files including private data",
            "kTCCServiceAccessibility": "Can control your computer, simulate keystrokes, read screen content",
            "kTCCServiceScreenCapture": "Can capture everything visible on screen",
            "kTCCServiceCamera": "Can access your camera without notification",
            "kTCCServiceMicrophone": "Can listen through your microphone",
            "kTCCServiceAppleEvents": "Can control other apps via AppleScript",
            "kTCCServiceListenEvent": "Can log all keyboard input",
            "kTCCServicePostEvent": "Can simulate keyboard and mouse events",
            "kTCCServiceSystemPolicyDesktopFolder": "Can read all files on your Desktop",
            "kTCCServiceSystemPolicyDocumentsFolder": "Can read all files in Documents",
            "kTCCServiceSystemPolicyDownloadsFolder": "Can read all files in Downloads",
            "kTCCServiceContactsFull": "Can read your contact list",
            "kTCCServiceCalendar": "Can read your calendar events",
            "kTCCServiceReminders": "Can read your reminders",
            "kTCCServicePhotos": "Can access your photo library",
            "kTCCServiceSpeechRecognition": "Can transcribe audio through speech recognition",
            "kTCCServiceDeveloperTool": "Can attach a debugger to other processes",
            "kTCCServiceBluetoothAlways": "Can access Bluetooth devices",
        ]
        return map[service] ?? "Has \(serviceFriendly) permission"
    }

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

// MARK: - TCC App Group (for "By App" view)

struct TCCAppGroup: Identifiable {
    let id: String
    let client: String
    let appName: String
    let appIconData: Data?
    let permissions: [TCCEntry]

    var aggregateRisk: TCCRisk {
        permissions.map(\.risk).max() ?? .safe
    }

    var permissionCount: Int {
        permissions.count
    }

    var hasHighExposure: Bool {
        let nonSafe = permissions.filter { $0.risk != .safe }.count
        let hasDangerous = permissions.contains { $0.risk == .dangerous }
        return nonSafe >= 3 || hasDangerous
    }

    var recentCount: Int {
        let cutoff = Date().addingTimeInterval(-7 * 24 * 3600)
        return permissions.filter { ($0.lastModified ?? .distantPast) > cutoff }.count
    }
}
