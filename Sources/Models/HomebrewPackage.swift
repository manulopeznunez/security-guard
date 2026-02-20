import Foundation

enum HomebrewPackageType: String, Sendable, Codable {
    case formula
    case cask
}

struct HomebrewPackage: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case name, type, installedVersion, currentVersion, pinned, isLeaf, risk, riskReason
    }
    let name: String
    let type: HomebrewPackageType
    let installedVersion: String
    let currentVersion: String?
    let pinned: Bool
    let isLeaf: Bool
    var risk: ProcessRisk
    var riskReason: String

    var approvalID: String {
        "\(name):\(installedVersion)"
    }

    var needsReview: Bool {
        risk != .safe
    }

    var isOutdated: Bool {
        currentVersion != nil
    }
}
