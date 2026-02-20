import Testing
@testable import MacSecurityGuard

struct SystemCVEDatabaseTests {

    // MARK: - Version Comparison

    @Test func versionLessThan() {
        #expect(SystemCVEDatabase.compareVersions("15.1", isLessThan: "15.4") == true)
        #expect(SystemCVEDatabase.compareVersions("15.3.1", isLessThan: "15.4") == true)
        #expect(SystemCVEDatabase.compareVersions("14.7", isLessThan: "14.7.5") == true)
        #expect(SystemCVEDatabase.compareVersions("13.0", isLessThan: "13.7.5") == true)
    }

    @Test func versionNotLessThan() {
        #expect(SystemCVEDatabase.compareVersions("15.4", isLessThan: "15.4") == false)
        #expect(SystemCVEDatabase.compareVersions("15.4.1", isLessThan: "15.4") == false)
        #expect(SystemCVEDatabase.compareVersions("15.5", isLessThan: "15.4") == false)
        #expect(SystemCVEDatabase.compareVersions("16.0", isLessThan: "15.4") == false)
    }

    @Test func versionEdgeCases() {
        #expect(SystemCVEDatabase.compareVersions("15", isLessThan: "15.4") == true)
        #expect(SystemCVEDatabase.compareVersions("15.4", isLessThan: "15") == false)
        #expect(SystemCVEDatabase.compareVersions("", isLessThan: "15.4") == true)
    }

    // MARK: - Service Fingerprinting

    @Test func identifyAirPlay() {
        #expect(SystemCVEDatabase.identifyService(processName: "ControlCenter", port: "5000") == "AirPlay Receiver")
        #expect(SystemCVEDatabase.identifyService(processName: "ControlCenter", port: "7000") == "AirPlay Receiver")
    }

    @Test func identifySSH() {
        #expect(SystemCVEDatabase.identifyService(processName: "sshd", port: "22") == "Remote Login (SSH)")
    }

    @Test func identifyUnknown() {
        #expect(SystemCVEDatabase.identifyService(processName: "nginx", port: "80") == nil)
        #expect(SystemCVEDatabase.identifyService(processName: "node", port: "3000") == nil)
    }

    // MARK: - CVE Lookup

    @Test func airPlayVulnerabilitiesOnOldOS() {
        let cves = SystemCVEDatabase.vulnerabilities(for: "AirPlay Receiver", osVersion: "15.1")
        #expect(cves.count == 3)
        #expect(cves.contains { $0.id == "CVE-2025-24252" })
        #expect(cves.contains { $0.wormable })
    }

    @Test func airPlayVulnerabilitiesOnPatchedOS() {
        let cves = SystemCVEDatabase.vulnerabilities(for: "AirPlay Receiver", osVersion: "15.4")
        #expect(cves.isEmpty)
    }

    @Test func unknownServiceReturnsEmpty() {
        let cves = SystemCVEDatabase.vulnerabilities(for: "Unknown Service", osVersion: "15.1")
        #expect(cves.isEmpty)
    }

    // MARK: - OS Patch Level

    @Test func outdatedOS() {
        let result = SystemCVEDatabase.checkOSPatchLevel("15.1")
        #expect(result.isSafe == false)
        #expect(result.minimumRequired == "15.4")
    }

    @Test func patchedOS() {
        let result = SystemCVEDatabase.checkOSPatchLevel("15.4")
        #expect(result.isSafe == true)
        #expect(result.minimumRequired == "15.4")
    }

    @Test func newerOS() {
        let result = SystemCVEDatabase.checkOSPatchLevel("15.5")
        #expect(result.isSafe == true)
    }

    @Test func unknownMajorVersion() {
        let result = SystemCVEDatabase.checkOSPatchLevel("16.0")
        #expect(result.isSafe == true)
        #expect(result.minimumRequired == nil)
    }
}
