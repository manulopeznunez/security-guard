import Foundation

struct AppSignatureEntry: Identifiable, Sendable {
    let id = UUID()
    let appName: String
    let appPath: String
    var isValid: Bool
    var authority: String
    var details: String
    var risk: ProcessRisk
}
