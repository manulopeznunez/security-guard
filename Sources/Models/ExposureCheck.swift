import SwiftUI

enum ExposureSection: String, Sendable, Codable, CaseIterable, Identifiable {
    case wifi = "Wi-Fi Security"
    case bluetooth = "Bluetooth"
    case sharing = "Sharing Services"
    case dns = "DNS Security"
    case kernelExtensions = "Kernel Extensions"
    case systemExtensions = "System Extensions"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .wifi: "wifi"
        case .bluetooth: "wave.3.right"
        case .sharing: "square.and.arrow.up"
        case .dns: "server.rack"
        case .kernelExtensions: "memorychip"
        case .systemExtensions: "gearshape.2"
        }
    }
}

struct ExposureCheckEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case section, name, detail, risk, riskReason, remediation
    }

    let section: ExposureSection
    let name: String
    let detail: String
    let risk: ProcessRisk
    let riskReason: String
    let remediation: String

    var approvalID: String { "\(section.rawValue):\(name)" }
    var needsReview: Bool { risk != .safe }
}
