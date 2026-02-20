import SwiftUI

struct BreachResult: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case email, breachName, breachTitle, breachDomain, breachDate
        case pwnCount, dataClasses, isVerified, isSensitive, breachDescription
    }

    let email: String
    let breachName: String
    let breachTitle: String
    let breachDomain: String
    let breachDate: String
    let pwnCount: Int
    let dataClasses: [String]
    let isVerified: Bool
    let isSensitive: Bool
    let breachDescription: String

    var risk: ProcessRisk {
        let sensitiveData = dataClasses.contains {
            $0.lowercased().contains("password") ||
            $0.lowercased().contains("credit card") ||
            $0.lowercased().contains("social security")
        }
        if sensitiveData || dataClasses.count >= 5 { return .suspicious }
        return .warning
    }

    var approvalID: String { "\(email):\(breachName)" }
    var needsReview: Bool { true }
}

struct EmailAccount: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case email, source, breachCount, lastChecked
    }

    let email: String
    let source: String
    var breachCount: Int = 0
    var lastChecked: Date?
}
