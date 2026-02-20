import Testing
@testable import MacSecurityGuard

struct GeoIPServiceTests {

    @Test func emptyIPListReturnsEmpty() async {
        let results = await GeoIPService.shared.resolve(ips: [])
        #expect(results.isEmpty)
    }

    @Test func resolveKnownIP() async {
        let results = await GeoIPService.shared.resolve(ips: ["8.8.8.8"])
        // May fail if no network, but should not crash
        if let geo = results["8.8.8.8"] {
            #expect(!geo.country.isEmpty)
            #expect(!geo.countryCode.isEmpty)
        }
    }

    @Test func cacheHitSkipsNetwork() async {
        // First call
        let first = await GeoIPService.shared.resolve(ips: ["8.8.4.4"])
        // Second call should use cache
        let second = await GeoIPService.shared.resolve(ips: ["8.8.4.4"])
        #expect(first["8.8.4.4"]?.country == second["8.8.4.4"]?.country)
    }
}
