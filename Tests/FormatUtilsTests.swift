import Testing
@testable import MacSecurityGuard

struct FormatUtilsTests {

    // MARK: - cleanAuthority

    @Test func cleanDeveloperIDApplication() {
        let result = FormatUtils.cleanAuthority("Developer ID Application: SLACK TECHNOLOGIES L.L.C. (BQR82RBBHL)")
        #expect(result == "Slack Technologies L.L.C.")
    }

    @Test func cleanAppStoreAuthority() {
        let result = FormatUtils.cleanAuthority("Apple Mac OS Application Signing")
        #expect(result == "App Store (Apple)")
    }

    @Test func cleanAppleDevelopment() {
        let result = FormatUtils.cleanAuthority("Apple Development: John Doe (ABC123XYZ1)")
        #expect(result == "John Doe")
    }

    @Test func clean3rdPartyDeveloper() {
        let result = FormatUtils.cleanAuthority("3rd Party Mac Developer Application: Company Inc (TEAMID1234)")
        #expect(result == "Company Inc")
    }

    @Test func cleanPreservesAbbreviations() {
        let result = FormatUtils.cleanAuthority("Developer ID Application: MY LLC (ABC1234567)")
        #expect(result.contains("LLC"))
    }

    @Test func cleanEmptyInput() {
        let result = FormatUtils.cleanAuthority("")
        #expect(result == "")
    }

    @Test func cleanNoPrefix() {
        let result = FormatUtils.cleanAuthority("Some Unknown Authority")
        #expect(!result.isEmpty)
    }

    // MARK: - friendlyHostname

    @Test func googleDomain() {
        let result = FormatUtils.friendlyHostname("server.1e100.net")
        #expect(result == "Google (1e100.net)")
    }

    @Test func cloudfrontDomain() {
        let result = FormatUtils.friendlyHostname("server-52-84.cloudfront.net")
        #expect(result == "Amazon CDN (cloudfront.net)")
    }

    @Test func appleDomain() {
        let result = FormatUtils.friendlyHostname("p31-keyvalueservice.icloud.com")
        #expect(result == "iCloud (icloud.com)")
    }

    @Test func slackDomain() {
        let result = FormatUtils.friendlyHostname("api.slack.com")
        #expect(result == "Slack (slack.com)")
    }

    @Test func unknownDomain() {
        let result = FormatUtils.friendlyHostname("server.unknown-domain.org")
        #expect(result == "unknown-domain.org")
    }

    @Test func emptyHostname() {
        let result = FormatUtils.friendlyHostname("")
        #expect(result == "")
    }

    @Test func singlePartHostname() {
        let result = FormatUtils.friendlyHostname("localhost")
        #expect(result == "localhost")
    }

    // MARK: - flag

    @Test func validCountryCode() {
        let flag = FormatUtils.flag(for: "US")
        #expect(!flag.isEmpty)
        #expect(flag.unicodeScalars.count == 2)
    }

    @Test func emptyCountryCode() {
        #expect(FormatUtils.flag(for: "") == "")
    }

    @Test func invalidLengthCountryCode() {
        #expect(FormatUtils.flag(for: "A") == "")
        #expect(FormatUtils.flag(for: "ABC") == "")
    }

    // MARK: - bytes

    @Test func bytesFormatsCorrectly() {
        let result = FormatUtils.bytes(1024)
        #expect(result.contains("1") && result.contains("KB"))
    }

    @Test func bytesZero() {
        let result = FormatUtils.bytes(0)
        #expect(result.contains("0") || result.contains("Zero"))
    }
}
