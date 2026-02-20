import Testing
@testable import MacSecurityGuard

struct ChromeExtensionRiskTests {

    // MARK: - HIGH Risk Permissions

    @Test func allUrlsPermissionIsHighRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: ["<all_urls>"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
        #expect(reasons.contains("Access to ALL websites"))
    }

    @Test func wildcardHostPermissionIsHighRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: [],
            hostPermissions: ["*://*/*"],
            contentScriptMatches: []
        )
        #expect(risk == .high)
        #expect(reasons.contains("Access to ALL websites"))
    }

    @Test func debuggerPermissionIsHighRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["debugger"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
    }

    @Test func nativeMessagingIsHighRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: ["nativeMessaging"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
        #expect(reasons.contains("Can communicate with local programs"))
    }

    @Test func proxyPermissionIsHighRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["proxy"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
    }

    // MARK: - MEDIUM Risk Permissions

    @Test func cookiesPermissionIsMediumRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: ["cookies"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .medium)
        #expect(reasons.contains("Can read/write cookies"))
    }

    @Test func tabsPermissionIsMediumRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["tabs"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .medium)
    }

    @Test func historyPermissionIsMediumRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: ["history"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .medium)
        #expect(reasons.contains("Can read browsing history"))
    }

    @Test func clipboardReadIsMediumRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["clipboardRead"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .medium)
    }

    // MARK: - LOW Risk

    @Test func noPermissionsIsLowRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: [],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .low)
        #expect(reasons.contains("Limited permissions"))
    }

    @Test func safePermissionsOnlyIsLowRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["storage", "activeTab", "alarms"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .low)
    }

    // MARK: - Content Script Matches

    @Test func broadContentScriptIsHighRisk() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: [],
            hostPermissions: [],
            contentScriptMatches: ["*://*/*"]
        )
        #expect(risk == .high)
        #expect(reasons.contains(where: { $0.contains("ALL") }))
    }

    @Test func httpWildcardContentScriptIsHighRisk() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: [],
            hostPermissions: [],
            contentScriptMatches: ["https://*/*"]
        )
        #expect(risk == .high)
    }

    // MARK: - Combined Permissions

    @Test func multipleHighRiskPermissionsAccumulateReasons() {
        let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
            permissions: ["<all_urls>", "debugger", "nativeMessaging"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
        #expect(reasons.count >= 3)
    }

    @Test func mediumDoesNotOverrideHigh() {
        let (risk, _) = ChromeExtensionViewModel.assessRisk(
            permissions: ["<all_urls>", "cookies", "tabs"],
            hostPermissions: [],
            contentScriptMatches: []
        )
        #expect(risk == .high)
    }
}
