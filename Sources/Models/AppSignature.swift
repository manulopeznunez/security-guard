import Foundation

struct AppSignatureEntry: Identifiable, Sendable, Codable {
    let id = UUID()

    private enum CodingKeys: String, CodingKey {
        case appName, appPath, isValid, authority, details, risk
    }
    let appName: String
    let appPath: String
    var isValid: Bool
    var authority: String
    var details: String
    var risk: ProcessRisk
}
