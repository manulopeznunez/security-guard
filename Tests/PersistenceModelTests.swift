import Testing
@testable import MacSecurityGuard

struct PersistenceModelTests {

    // MARK: - needsReview

    @Test func validSignatureDoesNotNeedReview() {
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/usr/bin/test",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .valid, signatureAuthority: "Test", risk: .safe
        )
        #expect(entry.needsReview == false)
    }

    @Test func appleSignatureDoesNotNeedReview() {
        let entry = PersistenceEntry(
            source: "test", label: "com.apple.test", executablePath: "/usr/bin/test",
            isApple: true, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .apple, signatureAuthority: "Apple", risk: .safe
        )
        #expect(entry.needsReview == false)
    }

    @Test func homebrewNeedsReview() {
        // Homebrew binaries are path-based (not cryptographically signed), so they need review
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/opt/homebrew/bin/test",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .homebrew, signatureAuthority: "Homebrew", risk: .safe
        )
        #expect(entry.needsReview == true)
    }

    @Test func invalidSignatureNeedsReview() {
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/usr/bin/test",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .invalid(reason: "modified"), signatureAuthority: "", risk: .warning
        )
        #expect(entry.needsReview == true)
    }

    @Test func notFoundNeedsReview() {
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/missing",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .notFound, signatureAuthority: "", risk: .safe
        )
        #expect(entry.needsReview == true)
    }

    @Test func suspiciousRiskNeedsReview() {
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/usr/bin/test",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .unchecked, signatureAuthority: "", risk: .suspicious
        )
        #expect(entry.needsReview == true)
    }

    @Test func permissionDeniedNeedsReview() {
        // Can't verify signature → needs review
        let entry = PersistenceEntry(
            source: "test", label: "test", executablePath: "/usr/bin/test",
            isApple: false, parentAppName: nil, parentAppPath: nil,
            signatureStatus: .permissionDenied, signatureAuthority: "", risk: .safe
        )
        #expect(entry.needsReview == true)
    }
}
