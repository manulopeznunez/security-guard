import Foundation
import Testing
@testable import MacSecurityGuard

struct ScanPersistenceTests {

    // MARK: - ScanDateTracker

    @Test func scanDateTrackerRecordAndRetrieve() {
        // Use a specific scanner for testing
        ScanDateTracker.record(.processes)
        let date = ScanDateTracker.lastDate(for: .processes)
        #expect(date != nil)
        // Should be within the last second
        #expect(abs(date!.timeIntervalSinceNow) < 2)
    }

    @Test func scanDateTrackerIsNotStaleForToday() {
        ScanDateTracker.record(.homebrew)
        #expect(!ScanDateTracker.isStale(for: .homebrew))
    }

    @Test func scanDateTrackerFormattedDateContainsToday() {
        ScanDateTracker.record(.persistence)
        let text = ScanDateTracker.formattedDate(for: .persistence)
        #expect(text != nil)
        #expect(text!.contains("Today"))
    }

    @Test func scanDateTrackerNeverScannedReturnsNil() {
        // Use a unique key to avoid collisions — clear it first
        UserDefaults.standard.removeObject(forKey: "LastScanDate_configGuard")
        let date = ScanDateTracker.lastDate(for: .configGuard)
        #expect(date == nil)
        let text = ScanDateTracker.formattedDate(for: .configGuard)
        #expect(text == nil)
        #expect(ScanDateTracker.isStale(for: .configGuard))
    }

    // MARK: - Codable Round-Trips: ProcessEntry

    @Test func processEntryCodableRoundTrip() throws {
        let original = ProcessEntry(
            pid: 123, name: "test", cpuPercent: 5.5, memoryMB: 128.0,
            path: "/usr/local/bin/test", parentAppName: "TestApp",
            parentAppPath: "/Applications/TestApp.app",
            signatureValid: true, risk: .warning, details: "test detail"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ProcessEntry.self, from: data)
        #expect(decoded.pid == original.pid)
        #expect(decoded.name == original.name)
        #expect(decoded.cpuPercent == original.cpuPercent)
        #expect(decoded.memoryMB == original.memoryMB)
        #expect(decoded.path == original.path)
        #expect(decoded.parentAppName == original.parentAppName)
        #expect(decoded.signatureValid == original.signatureValid)
        #expect(decoded.risk == original.risk)
        #expect(decoded.details == original.details)
        // id should be different (fresh UUID on decode)
        #expect(decoded.id != original.id)
    }

    // MARK: - Codable Round-Trips: PersistenceEntry

    @Test func persistenceEntryCodableRoundTrip() throws {
        let original = PersistenceEntry(
            source: "~/Library/LaunchAgents", label: "com.test.agent",
            executablePath: "/usr/local/bin/test", isApple: false,
            parentAppName: "TestApp", parentAppPath: "/Applications/TestApp.app",
            signatureStatus: .valid, signatureAuthority: "Developer ID",
            risk: .safe
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(PersistenceEntry.self, from: data)
        #expect(decoded.source == original.source)
        #expect(decoded.label == original.label)
        #expect(decoded.executablePath == original.executablePath)
        #expect(decoded.isApple == original.isApple)
        #expect(decoded.parentAppName == original.parentAppName)
        #expect(decoded.signatureAuthority == original.signatureAuthority)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: SignatureStatus (all cases)

    @Test func signatureStatusCodableValid() throws {
        let original = SignatureStatus.valid
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .valid = decoded {} else { Issue.record("Expected .valid") }
    }

    @Test func signatureStatusCodableInvalidWithReason() throws {
        let original = SignatureStatus.invalid(reason: "modified after signing")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .invalid(let reason) = decoded {
            #expect(reason == "modified after signing")
        } else {
            Issue.record("Expected .invalid(reason:)")
        }
    }

    @Test func signatureStatusCodableNotFound() throws {
        let original = SignatureStatus.notFound
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .notFound = decoded {} else { Issue.record("Expected .notFound") }
    }

    @Test func signatureStatusCodableApple() throws {
        let original = SignatureStatus.apple
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .apple = decoded {} else { Issue.record("Expected .apple") }
    }

    @Test func signatureStatusCodableHomebrew() throws {
        let original = SignatureStatus.homebrew
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .homebrew = decoded {} else { Issue.record("Expected .homebrew") }
    }

    @Test func signatureStatusCodablePermissionDenied() throws {
        let original = SignatureStatus.permissionDenied
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .permissionDenied = decoded {} else { Issue.record("Expected .permissionDenied") }
    }

    @Test func signatureStatusCodableUnchecked() throws {
        let original = SignatureStatus.unchecked
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SignatureStatus.self, from: data)
        if case .unchecked = decoded {} else { Issue.record("Expected .unchecked") }
    }

    // MARK: - Codable Round-Trips: ChromeExtensionEntry

    @Test func chromeExtensionEntryCodableRoundTrip() throws {
        let original = ChromeExtensionEntry(
            name: "Test Extension", extensionId: "abc123", version: "1.0",
            description: "A test extension",
            permissions: ["tabs", "cookies"], hostPermissions: ["<all_urls>"],
            profile: "Default", risk: .high,
            riskReasons: ["Access to ALL websites", "Can read/write cookies"],
            isFromWebStore: true, source: "Chrome Web Store",
            author: "Test Author", homepageURL: "https://example.com",
            profileDisplayName: "Test User"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ChromeExtensionEntry.self, from: data)
        #expect(decoded.name == original.name)
        #expect(decoded.extensionId == original.extensionId)
        #expect(decoded.version == original.version)
        #expect(decoded.permissions == original.permissions)
        #expect(decoded.hostPermissions == original.hostPermissions)
        #expect(decoded.risk == original.risk)
        #expect(decoded.riskReasons == original.riskReasons)
        #expect(decoded.isFromWebStore == original.isFromWebStore)
        #expect(decoded.source == original.source)
        #expect(decoded.profileDisplayName == original.profileDisplayName)
    }

    // MARK: - Codable Round-Trips: HomebrewPackage

    @Test func homebrewPackageCodableRoundTrip() throws {
        let original = HomebrewPackage(
            name: "openssl", type: .formula, installedVersion: "3.1.0",
            currentVersion: "3.2.0", pinned: false, isLeaf: true,
            risk: .suspicious, riskReason: "Security-critical package outdated"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(HomebrewPackage.self, from: data)
        #expect(decoded.name == original.name)
        #expect(decoded.type == original.type)
        #expect(decoded.installedVersion == original.installedVersion)
        #expect(decoded.currentVersion == original.currentVersion)
        #expect(decoded.pinned == original.pinned)
        #expect(decoded.isLeaf == original.isLeaf)
        #expect(decoded.risk == original.risk)
        #expect(decoded.riskReason == original.riskReason)
    }

    @Test func homebrewPackageCaskCodableRoundTrip() throws {
        let original = HomebrewPackage(
            name: "firefox", type: .cask, installedVersion: "120.0",
            currentVersion: nil, pinned: false, isLeaf: true,
            risk: .safe, riskReason: "Up to date"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(HomebrewPackage.self, from: data)
        #expect(decoded.name == "firefox")
        #expect(decoded.type == .cask)
        #expect(decoded.currentVersion == nil)
        #expect(decoded.risk == .safe)
    }

    // MARK: - Codable Round-Trips: AppSignatureEntry

    @Test func appSignatureEntryCodableRoundTrip() throws {
        let original = AppSignatureEntry(
            appName: "TestApp", appPath: "/Applications/TestApp.app",
            isValid: false, authority: "Unknown",
            details: "not signed", risk: .suspicious
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AppSignatureEntry.self, from: data)
        #expect(decoded.appName == original.appName)
        #expect(decoded.appPath == original.appPath)
        #expect(decoded.isValid == original.isValid)
        #expect(decoded.authority == original.authority)
        #expect(decoded.details == original.details)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: TCCEntry

    @Test func tccEntryCodableRoundTrip() throws {
        let original = TCCEntry(
            service: "kTCCServiceCamera", serviceFriendly: "Camera",
            client: "us.zoom.xos", clientType: 0, authValue: 2, authReason: 0,
            lastModified: Date(timeIntervalSince1970: 1700000000),
            isAppleApp: false, isSigned: true,
            appName: "Zoom", appIconData: nil,
            risk: .warning, riskReason: "Non-Apple app with Camera access"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(TCCEntry.self, from: data)
        #expect(decoded.service == original.service)
        #expect(decoded.serviceFriendly == original.serviceFriendly)
        #expect(decoded.client == original.client)
        #expect(decoded.authValue == original.authValue)
        #expect(decoded.isSigned == original.isSigned)
        #expect(decoded.appName == original.appName)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: SudoEntry

    @Test func sudoEntryCodableRoundTrip() throws {
        let original = SudoEntry(
            rule: "manu ALL=(ALL) NOPASSWD: ALL", user: "manu",
            hasNOPASSWD: true, commands: "ALL",
            source: "sudo -nl", risk: .suspicious,
            riskReason: "NOPASSWD allows running commands without password"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SudoEntry.self, from: data)
        #expect(decoded.rule == original.rule)
        #expect(decoded.user == original.user)
        #expect(decoded.hasNOPASSWD == original.hasNOPASSWD)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: UserAccountEntry

    @Test func userAccountEntryCodableRoundTrip() throws {
        let original = UserAccountEntry(
            username: "manu", uid: 501, fullName: "Manu",
            homeDirectory: "/Users/manu", shell: "/bin/zsh",
            isAdmin: true, isHidden: false, isGuest: false,
            risk: .warning, riskReason: "Admin user"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(UserAccountEntry.self, from: data)
        #expect(decoded.username == original.username)
        #expect(decoded.uid == original.uid)
        #expect(decoded.isAdmin == original.isAdmin)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: GroupEntry

    @Test func groupEntryCodableRoundTrip() throws {
        let original = GroupEntry(
            name: "admin", gid: 80, members: ["manu", "test"],
            isSensitive: true, risk: .warning,
            riskReason: "2 admin users", actionHint: "Review periodically"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(GroupEntry.self, from: data)
        #expect(decoded.name == original.name)
        #expect(decoded.gid == original.gid)
        #expect(decoded.members == original.members)
        #expect(decoded.isSensitive == original.isSensitive)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: ConfigGuardEntry

    @Test func configGuardEntryCodableRoundTrip() throws {
        let original = ConfigGuardEntry(
            filePath: "~/.zshrc", absolutePath: "/Users/manu/.zshrc",
            exists: true, currentHash: "abc123", baselineHash: "def456",
            permissions: "644", changeType: .modified,
            risk: .suspicious, riskReason: "File content changed since baseline"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ConfigGuardEntry.self, from: data)
        #expect(decoded.filePath == original.filePath)
        #expect(decoded.exists == original.exists)
        #expect(decoded.currentHash == original.currentHash)
        #expect(decoded.baselineHash == original.baselineHash)
        #expect(decoded.changeType == original.changeType)
        #expect(decoded.risk == original.risk)
    }

    // MARK: - Codable Round-Trips: CVERecord + CVESeverity

    @Test func cveRecordCodableRoundTrip() throws {
        let original = CVERecord(
            id: "GHSA-abc-123", aliases: ["CVE-2024-1234"],
            summary: "A test vulnerability", severity: .high,
            fixedVersion: "3.2.1"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(CVERecord.self, from: data)
        #expect(decoded.id == original.id)
        #expect(decoded.aliases == original.aliases)
        #expect(decoded.summary == original.summary)
        #expect(decoded.severity == original.severity)
        #expect(decoded.fixedVersion == original.fixedVersion)
        #expect(decoded.displayID == "CVE-2024-1234")
    }

    @Test func cveSeverityAllCasesEncodable() throws {
        for severity in [CVESeverity.unknown, .low, .medium, .high, .critical] {
            let data = try JSONEncoder().encode(severity)
            let decoded = try JSONDecoder().decode(CVESeverity.self, from: data)
            #expect(decoded == severity)
        }
    }

    // MARK: - Codable Round-Trips: Enum risks

    @Test func processRiskCodableRoundTrip() throws {
        for risk in [ProcessRisk.safe, .warning, .suspicious] {
            let data = try JSONEncoder().encode(risk)
            let decoded = try JSONDecoder().decode(ProcessRisk.self, from: data)
            #expect(decoded == risk)
        }
    }

    @Test func extensionRiskCodableRoundTrip() throws {
        for risk in [ExtensionRisk.low, .medium, .high] {
            let data = try JSONEncoder().encode(risk)
            let decoded = try JSONDecoder().decode(ExtensionRisk.self, from: data)
            #expect(decoded == risk)
        }
    }

    @Test func tccRiskCodableRoundTrip() throws {
        for risk in [TCCRisk.safe, .warning, .dangerous] {
            let data = try JSONEncoder().encode(risk)
            let decoded = try JSONDecoder().decode(TCCRisk.self, from: data)
            #expect(decoded == risk)
        }
    }

    @Test func accessRiskCodableRoundTrip() throws {
        for risk in [AccessRisk.safe, .warning, .suspicious] {
            let data = try JSONEncoder().encode(risk)
            let decoded = try JSONDecoder().decode(AccessRisk.self, from: data)
            #expect(decoded == risk)
        }
    }

    @Test func configChangeTypeCodableRoundTrip() throws {
        for ct in [ConfigChangeType.unchanged, .modified, .newFile, .deleted, .insecurePermissions] {
            let data = try JSONEncoder().encode(ct)
            let decoded = try JSONDecoder().decode(ConfigChangeType.self, from: data)
            #expect(decoded == ct)
        }
    }
}
