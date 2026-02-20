import SwiftUI

enum ProcessRisk: Int, Comparable, Sendable, Codable {
    case safe = 0
    case warning = 1
    case suspicious = 2

    static func < (lhs: ProcessRisk, rhs: ProcessRisk) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var color: Color {
        switch self {
        case .safe: .green
        case .warning: .yellow
        case .suspicious: .red
        }
    }
}

struct ProcessEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case pid, name, cpuPercent, memoryMB, path, parentAppName, parentAppPath
        case signatureValid, risk, details
    }
    let pid: Int
    let name: String
    let cpuPercent: Double
    let memoryMB: Double
    let path: String
    let parentAppName: String?
    let parentAppPath: String?
    var signatureValid: Bool?
    var risk: ProcessRisk
    var details: String
}
