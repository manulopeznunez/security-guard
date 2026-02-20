import Testing
@testable import MacSecurityGuard

struct PermissionsTests {

    // MARK: - TCC Risk Classification

    @Test func appleAppWithFDAIsSafe() {
        let (risk, _) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceSystemPolicyAllFiles",
            client: "com.apple.Terminal",
            isApple: true,
            authValue: 2
        )
        #expect(risk == .safe)
    }

    @Test func nonAppleWithFDAIsDangerous() {
        let (risk, reason) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceSystemPolicyAllFiles",
            client: "com.unknown.app",
            isApple: false,
            authValue: 2
        )
        #expect(risk == .dangerous)
        #expect(reason.contains("Full Disk Access"))
    }

    @Test func nonAppleWithAccessibilityIsDangerous() {
        let (risk, reason) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceAccessibility",
            client: "com.example.keylogger",
            isApple: false,
            authValue: 2
        )
        #expect(risk == .dangerous)
        #expect(reason.contains("Accessibility"))
    }

    @Test func nonAppleWithScreenCaptureIsWarning() {
        let (risk, _) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceScreenCapture",
            client: "us.zoom.xos",
            isApple: false,
            authValue: 2
        )
        #expect(risk == .warning)
    }

    @Test func nonAppleWithCameraIsWarning() {
        let (risk, _) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceCamera",
            client: "us.zoom.xos",
            isApple: false,
            authValue: 2
        )
        #expect(risk == .warning)
    }

    @Test func deniedPermissionIsSafe() {
        let (risk, _) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceAccessibility",
            client: "com.malware.app",
            isApple: false,
            authValue: 0
        )
        #expect(risk == .safe)
    }

    @Test func lowSensitivityPermissionIsSafe() {
        let (risk, _) = PermissionsViewModel.classifyTCCRisk(
            service: "kTCCServiceCalendar",
            client: "com.example.app",
            isApple: false,
            authValue: 2
        )
        #expect(risk == .safe)
    }

    // MARK: - TCC Model Properties

    @Test func tccApprovalIDFormat() {
        let entry = TCCEntry(
            service: "kTCCServiceCamera",
            serviceFriendly: "Camera",
            client: "us.zoom.xos",
            clientType: 0, authValue: 2, authReason: 0,
            lastModified: nil, isAppleApp: false, isSigned: nil,
            risk: .warning, riskReason: "test"
        )
        #expect(entry.approvalID == "kTCCServiceCamera:us.zoom.xos")
    }

    @Test func tccNeedsReviewWhenNotSafe() {
        let dangerous = TCCEntry(
            service: "x", serviceFriendly: "x", client: "x",
            clientType: 0, authValue: 2, authReason: 0,
            lastModified: nil, isAppleApp: false, isSigned: nil,
            risk: .dangerous, riskReason: ""
        )
        #expect(dangerous.needsReview)

        let safe = TCCEntry(
            service: "x", serviceFriendly: "x", client: "x",
            clientType: 0, authValue: 2, authReason: 0,
            lastModified: nil, isAppleApp: true, isSigned: nil,
            risk: .safe, riskReason: ""
        )
        #expect(!safe.needsReview)
    }

    @Test func tccAuthLabels() {
        let denied = TCCEntry(
            service: "x", serviceFriendly: "x", client: "x",
            clientType: 0, authValue: 0, authReason: 0,
            lastModified: nil, isAppleApp: false, isSigned: nil,
            risk: .safe, riskReason: ""
        )
        #expect(denied.authLabel == "Denied")

        let allowed = TCCEntry(
            service: "x", serviceFriendly: "x", client: "x",
            clientType: 0, authValue: 2, authReason: 0,
            lastModified: nil, isAppleApp: false, isSigned: nil,
            risk: .safe, riskReason: ""
        )
        #expect(allowed.authLabel == "Allowed")

        let limited = TCCEntry(
            service: "x", serviceFriendly: "x", client: "x",
            clientType: 0, authValue: 3, authReason: 0,
            lastModified: nil, isAppleApp: false, isSigned: nil,
            risk: .safe, riskReason: ""
        )
        #expect(limited.authLabel == "Limited")
    }

    // MARK: - TCC Friendly Names

    @Test func friendlyServiceNames() {
        #expect(PermissionsViewModel.friendlyServiceName("kTCCServiceSystemPolicyAllFiles") == "Full Disk Access")
        #expect(PermissionsViewModel.friendlyServiceName("kTCCServiceAccessibility") == "Accessibility")
        #expect(PermissionsViewModel.friendlyServiceName("kTCCServiceCamera") == "Camera")
        #expect(PermissionsViewModel.friendlyServiceName("kTCCServiceScreenCapture") == "Screen Recording")
    }

    @Test func unknownServiceFallback() {
        let name = PermissionsViewModel.friendlyServiceName("kTCCServiceSomethingNew")
        #expect(name == "SomethingNew")
    }

    // MARK: - Sudo Model Properties

    @Test func nopasswdEntryIsSuspicious() {
        let entry = SudoEntry(
            rule: "manu ALL=(ALL) NOPASSWD: ALL",
            user: "manu",
            hasNOPASSWD: true,
            commands: "ALL",
            source: "sudo -nl",
            risk: .suspicious,
            riskReason: "NOPASSWD allows running commands without password"
        )
        #expect(entry.risk == .suspicious)
        #expect(entry.needsReview)
    }

    @Test func adminGroupIsWarning() {
        let entry = SudoEntry(
            rule: "manu is in admin group",
            user: "manu",
            hasNOPASSWD: false,
            commands: "ALL (with password)",
            source: "admin group",
            risk: .warning,
            riskReason: "Admin users can sudo with password"
        )
        #expect(entry.risk == .warning)
        #expect(entry.needsReview)
    }

    @Test func sudoApprovalIDFormat() {
        let entry = SudoEntry(
            rule: "test rule",
            user: "manu",
            hasNOPASSWD: false,
            commands: "ALL",
            source: "sudo -nl",
            risk: .safe,
            riskReason: ""
        )
        #expect(entry.approvalID.hasPrefix("manu:"))
    }

    // MARK: - User Account Model Properties

    @Test func normalUserIsSafe() {
        let entry = UserAccountEntry(
            username: "manu", uid: 501, fullName: "Manu",
            homeDirectory: "/Users/manu", shell: "/bin/zsh",
            isAdmin: false, isHidden: false, isGuest: false,
            risk: .safe, riskReason: "Standard user"
        )
        #expect(entry.risk == .safe)
        #expect(!entry.needsReview)
    }

    @Test func uid0NonRootIsSuspicious() {
        let entry = UserAccountEntry(
            username: "backdoor", uid: 0, fullName: "Backdoor",
            homeDirectory: "/var/backdoor", shell: "/bin/sh",
            isAdmin: true, isHidden: false, isGuest: false,
            risk: .suspicious, riskReason: "Non-root user with UID 0"
        )
        #expect(entry.risk == .suspicious)
        #expect(entry.needsReview)
    }

    @Test func guestAccountIsWarning() {
        let entry = UserAccountEntry(
            username: "Guest", uid: 201, fullName: "Guest User",
            homeDirectory: "/Users/Guest", shell: "/bin/sh",
            isAdmin: false, isHidden: false, isGuest: true,
            risk: .warning, riskReason: "Guest account exists"
        )
        #expect(entry.risk == .warning)
        #expect(entry.needsReview)
    }

    @Test func adminUserIsWarning() {
        let entry = UserAccountEntry(
            username: "admin", uid: 502, fullName: "Admin",
            homeDirectory: "/Users/admin", shell: "/bin/zsh",
            isAdmin: true, isHidden: false, isGuest: false,
            risk: .warning, riskReason: "Admin user (can sudo)"
        )
        #expect(entry.risk == .warning)
        #expect(entry.needsReview)
    }

    @Test func userApprovalIDFormat() {
        let entry = UserAccountEntry(
            username: "manu", uid: 501, fullName: "Manu",
            homeDirectory: "/Users/manu", shell: "/bin/zsh",
            isAdmin: false, isHidden: false, isGuest: false,
            risk: .safe, riskReason: ""
        )
        #expect(entry.approvalID == "manu:501")
    }
}
