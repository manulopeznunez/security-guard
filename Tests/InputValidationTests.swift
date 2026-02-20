import Testing
import Foundation
@testable import MacSecurityGuard

struct InputValidationTests {

    @Test func geoInfoDecodingWithNulls() throws {
        let json = """
        {"status":"fail","query":"invalid"}
        """
        let data = json.data(using: .utf8)!
        let geo = try JSONDecoder().decode(GeoInfo.self, from: data)
        #expect(geo.status == "fail")
        #expect(geo.country == nil)
        #expect(geo.countryCode == nil)
    }

    @Test func geoInfoDecodingValid() throws {
        let json = """
        {"status":"success","country":"United States","countryCode":"US","org":"Google LLC","query":"8.8.8.8"}
        """
        let data = json.data(using: .utf8)!
        let geo = try JSONDecoder().decode(GeoInfo.self, from: data)
        #expect(geo.status == "success")
        #expect(geo.country == "United States")
        #expect(geo.query == "8.8.8.8")
    }

    @Test func geoInfoBatchDecoding() throws {
        let json = """
        [{"status":"success","country":"US","countryCode":"US","org":"Google","query":"8.8.8.8"},{"status":"fail","query":"invalid"}]
        """
        let data = json.data(using: .utf8)!
        let results = try JSONDecoder().decode([GeoInfo].self, from: data)
        #expect(results.count == 2)
        #expect(results[0].status == "success")
        #expect(results[1].status == "fail")
    }

    @Test func flagWithInvalidCode() {
        #expect(FormatUtils.flag(for: "") == "")
        #expect(FormatUtils.flag(for: "X") == "")
    }

    @Test func flagWithValidCode() {
        let result = FormatUtils.flag(for: "US")
        #expect(!result.isEmpty)
    }

    @Test func friendlyHostnameKnownDomain() {
        let result = FormatUtils.friendlyHostname("mad41s13-in-f27.1e100.net")
        #expect(result == "Google (1e100.net)")
    }

    @Test func friendlyHostnameEmpty() {
        let result = FormatUtils.friendlyHostname("")
        #expect(result == "")
    }

    @Test func bytesFormatter() {
        let result = FormatUtils.bytes(1024)
        #expect(!result.isEmpty)
    }
}
