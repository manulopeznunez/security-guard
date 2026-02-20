import SwiftUI

enum ProcessRisk: Int, Comparable, Sendable {
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

struct ProcessEntry: Identifiable, Sendable {
    let id = UUID()
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
