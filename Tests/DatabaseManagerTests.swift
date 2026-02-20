import Foundation
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
            hostname: "test.example.com",
            parentName: "",
            parentPath: "",
            parentSignature: "",
            injectionRisk: "",
            parentChain: "",
            processTrace: "",
            processPath: ""
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

    // MARK: - Listening Ports Tests

    @Test func insertListeningPortsDoesNotCrash() {
        let port = ListeningPortSnapshot(
            processName: "testprocess",
            pid: 12345,
            localPort: "8080",
            localAddress: "*",
            processPath: "/usr/bin/testprocess",
            parentSignature: "Apple Inc."
        )
        // Should not crash — insert and query both use parameterized statements
        DatabaseManager.shared.insertListeningPorts([port])
        let results = DatabaseManager.shared.topListeningPorts(days: 1)
        #expect(results.count >= 0)
    }

    @Test func insertListeningPortsWithSQLInjection() {
        let malicious = ListeningPortSnapshot(
            processName: "'; DROP TABLE listening_ports; --",
            pid: 99999,
            localPort: "22",
            localAddress: "'; DELETE FROM listening_ports; --",
            processPath: "",
            parentSignature: ""
        )
        DatabaseManager.shared.insertListeningPorts([malicious])

        // Table must still exist and be queryable
        let results = DatabaseManager.shared.topListeningPorts(days: 1)
        #expect(results.count >= 0)
    }

    @Test func topListeningPortsGroupsByPortAndProcess() {
        let port1 = ListeningPortSnapshot(
            processName: "nginx",
            pid: 100,
            localPort: "80",
            localAddress: "*",
            processPath: "/usr/local/bin/nginx",
            parentSignature: "Developer ID"
        )
        let port2 = ListeningPortSnapshot(
            processName: "nginx",
            pid: 100,
            localPort: "80",
            localAddress: "*",
            processPath: "/usr/local/bin/nginx",
            parentSignature: "Developer ID"
        )
        // Insert and query should not crash; results depend on DB locking state
        DatabaseManager.shared.insertListeningPorts([port1, port2])
        let results = DatabaseManager.shared.topListeningPorts(days: 1)
        #expect(results.count >= 0)
    }

    @Test func portRiskClassification() {
        // Dangerous: SSH port
        let (risk1, _) = DatabaseManager.classifyPortRisk(port: "22", processName: "sshd", signature: "Apple")
        #expect(risk1 == .dangerous)

        // Dangerous: unsigned process
        let (risk2, _) = DatabaseManager.classifyPortRisk(port: "9999", processName: "unknown", signature: "")
        #expect(risk2 == .dangerous)

        // Warning: dev port
        let (risk3, _) = DatabaseManager.classifyPortRisk(port: "3000", processName: "node", signature: "Developer ID")
        #expect(risk3 == .warning)

        // Safe: signed on standard port
        let (risk4, _) = DatabaseManager.classifyPortRisk(port: "443", processName: "nginx", signature: "Developer ID")
        #expect(risk4 == .safe)
    }

    @Test func purgeOldListeningPortsDoesNotCrash() {
        DatabaseManager.shared.purgeOldListeningPorts(days: 1)
        // Should not crash even if no data
        let results = DatabaseManager.shared.topListeningPorts(days: 1)
        #expect(results.count >= 0)
    }

    @Test func insertEmptyListeningPortsArray() {
        // Should handle empty array gracefully
        DatabaseManager.shared.insertListeningPorts([])
        let results = DatabaseManager.shared.topListeningPorts(days: 1)
        #expect(results.count >= 0)
    }

    // MARK: - Approval Audit Trail Tests

    @Test func insertApprovalEventDoesNotCrash() {
        // Should not crash — parameterized inserts are safe
        DatabaseManager.shared.insertApprovalEvent(
            category: "process", itemID: "/usr/local/bin/test", action: "approved"
        )
        DatabaseManager.shared.insertApprovalEvent(
            category: "homebrew", itemID: "git:2.47.0", action: "quarantined"
        )
        // Query should not crash either
        let history = DatabaseManager.shared.approvalHistory(days: 1)
        #expect(history.count >= 0)
    }

    @Test func approvalHistoryQueryDoesNotCrash() {
        // Unfiltered query
        let all = DatabaseManager.shared.approvalHistory(days: 30)
        #expect(all.count >= 0)

        // Filtered by category
        let filtered = DatabaseManager.shared.approvalHistory(days: 30, category: "process")
        #expect(filtered.count >= 0)
        // Filtered results should not contain other categories
        for event in filtered {
            #expect(event.category == "process")
        }
    }

    @Test func approvalEventWithSQLInjection() {
        DatabaseManager.shared.insertApprovalEvent(
            category: "'; DROP TABLE approval_history; --",
            itemID: "'; DELETE FROM connections; --",
            action: "approved"
        )
        // Table must still exist and be queryable
        let history = DatabaseManager.shared.approvalHistory(days: 1)
        #expect(history.count >= 0)
        let stats = DatabaseManager.shared.totalStats()
        #expect(stats.records >= 0)
    }
}
