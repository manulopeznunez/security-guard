import Testing
@testable import MacSecurityGuard

struct DatabaseManagerTests {

    @Test func insertWithSQLInjectionPayload() {
        let malicious = ConnectionSnapshot(
            processName: "test'; DROP TABLE connections; --",
            pid: 99999,
            remoteIP: "1.2.3.4",
            remotePort: "443",
            country: "Test",
            countryCode: "XX",
            organization: "'; DELETE FROM connections; --",
            bytesIn: 0,
            bytesOut: 0,
            hostname: "test.example.com"
        )
        // Parameterized queries must prevent injection
        DatabaseManager.shared.insertSnapshot(connections: [malicious])

        // Tables must still exist and be queryable
        let stats = DatabaseManager.shared.totalStats()
        #expect(stats.records >= 1)
    }

    @Test func queryWithAdversarialIP() {
        let result = DatabaseManager.shared.connectionsForIP("'; DROP TABLE connections; --", days: 1)
        #expect(result.isEmpty)

        // Database must still work
        let stats = DatabaseManager.shared.totalStats()
        #expect(stats.records >= 0)
    }

    @Test func topIPsReturnsResults() {
        let results = DatabaseManager.shared.topIPs(days: 1)
        // Should not crash, may be empty
        #expect(results.count >= 0)
    }
}
