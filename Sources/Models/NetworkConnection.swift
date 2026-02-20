import Foundation

struct NetworkConnection: Identifiable, Sendable {
    let id = UUID()
    let processName: String
    let pid: Int
    let localAddress: String
    let localPort: String
    let remoteAddress: String
    let remotePort: String
    let state: String
    var country: String
    var countryCode: String
    var organization: String
    var hostname: String
    var isLocal: Bool
    var isSigned: Bool
    var signatureAuthority: String
}

struct GeoInfo: Decodable, Sendable {
    let status: String
    let country: String?
    let countryCode: String?
    let org: String?
    let query: String?
}
