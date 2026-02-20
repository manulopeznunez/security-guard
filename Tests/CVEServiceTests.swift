import Testing
@testable import MacSecurityGuard

struct CVEServiceTests {

    // MARK: - Mapping Completeness

    @Test func allSecurityCriticalPackagesHaveMapping() {
        // Every package in the securityCritical set should have an OSV mapping
        let criticalPackages: Set<String> = [
            "openssl", "openssl@3", "openssl@1.1",
            "gnutls", "libressl",
            "curl", "wget",
            "git", "git-lfs",
            "openssh", "ssh-copy-id",
            "gnupg", "gpg",
            "python", "python@3.12", "python@3.13", "python@3.14",
            "node", "go", "ruby",
            "nginx", "httpd", "postgresql", "mysql", "redis",
        ]

        for name in criticalPackages {
            #expect(
                CVEService.osvMappings[name] != nil,
                "Missing OSV mapping for security-critical package: \(name)"
            )
        }
    }

    // MARK: - Tag Format Generation

    @Test func tagFormatOpenSSL() {
        let mapping = CVEService.osvMappings["openssl"]!
        let candidates = mapping.tagCandidates(for: "3.1.0")
        #expect(candidates.first == "openssl-3.1.0")
    }

    @Test func tagFormatCurl() {
        let mapping = CVEService.osvMappings["curl"]!
        let candidates = mapping.tagCandidates(for: "8.5.0")
        #expect(candidates.first == "curl-8_5_0")
    }

    @Test func tagFormatGit() {
        let mapping = CVEService.osvMappings["git"]!
        let candidates = mapping.tagCandidates(for: "2.43.0")
        #expect(candidates.first == "v2.43.0")
    }

    @Test func tagFormatGo() {
        let mapping = CVEService.osvMappings["go"]!
        let candidates = mapping.tagCandidates(for: "1.22.0")
        #expect(candidates.first == "go1.22.0")
    }

    @Test func tagFormatPostgreSQL() {
        let mapping = CVEService.osvMappings["postgresql"]!
        let candidates = mapping.tagCandidates(for: "16.1")
        #expect(candidates.first == "REL_16_1")
    }

    @Test func tagFormatNode() {
        let mapping = CVEService.osvMappings["node"]!
        let candidates = mapping.tagCandidates(for: "21.5.0")
        #expect(candidates.first == "v21.5.0")
    }

    @Test func tagFormatPython() {
        let mapping = CVEService.osvMappings["python"]!
        let candidates = mapping.tagCandidates(for: "3.12.4")
        #expect(candidates.first == "v3.12.4")
    }

    @Test func tagFormatOpenSSH() {
        let mapping = CVEService.osvMappings["openssh"]!
        let candidates = mapping.tagCandidates(for: "9.6")
        #expect(candidates.first == "V_9_6")
    }

    @Test func tagFormatGnupg() {
        let mapping = CVEService.osvMappings["gnupg"]!
        let candidates = mapping.tagCandidates(for: "2.4.3")
        #expect(candidates.first == "gnupg-2.4.3")
    }

    @Test func tagFormatNginx() {
        let mapping = CVEService.osvMappings["nginx"]!
        let candidates = mapping.tagCandidates(for: "1.25.3")
        #expect(candidates.first == "release-1.25.3")
    }

    @Test func tagFormatRedis() {
        let mapping = CVEService.osvMappings["redis"]!
        let candidates = mapping.tagCandidates(for: "7.2.3")
        #expect(candidates.first == "7.2.3")
    }

    @Test func tagFormatMySQL() {
        let mapping = CVEService.osvMappings["mysql"]!
        let candidates = mapping.tagCandidates(for: "8.2.0")
        #expect(candidates.first == "mysql-8.2.0")
    }

    @Test func tagFormatHasFallbacks() {
        // Most mappings should have at least 2 tag formats for robustness
        let mapping = CVEService.osvMappings["openssl"]!
        #expect(mapping.tagCandidates(for: "3.1.0").count >= 2)
    }

    // MARK: - CVSS Severity

    @Test func cvssVectorCritical() {
        let severity = CVESeverity.from(cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        #expect(severity == .critical)
    }

    @Test func cvssVectorHigh() {
        let severity = CVESeverity.from(cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
        #expect(severity == .high)
    }

    @Test func cvssVectorMedium() {
        let severity = CVESeverity.from(cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        #expect(severity == .medium)
    }

    @Test func cvssVectorLow() {
        let severity = CVESeverity.from(cvssVector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        #expect(severity == .low)
    }

    @Test func cvssScoreCritical() {
        #expect(CVESeverity.from(cvssScore: 9.8) == .critical)
        #expect(CVESeverity.from(cvssScore: 10.0) == .critical)
    }

    @Test func cvssScoreHigh() {
        #expect(CVESeverity.from(cvssScore: 7.0) == .high)
        #expect(CVESeverity.from(cvssScore: 8.9) == .high)
    }

    @Test func cvssScoreMedium() {
        #expect(CVESeverity.from(cvssScore: 4.0) == .medium)
        #expect(CVESeverity.from(cvssScore: 6.9) == .medium)
    }

    @Test func cvssScoreLow() {
        #expect(CVESeverity.from(cvssScore: 0.1) == .low)
        #expect(CVESeverity.from(cvssScore: 3.9) == .low)
    }

    @Test func cvssScoreUnknown() {
        #expect(CVESeverity.from(cvssScore: 0.0) == .unknown)
    }

    // MARK: - CVERecord

    @Test func cveRecordDisplayIDPrefersCVE() {
        let record = CVERecord(
            id: "GHSA-xxxx-yyyy",
            aliases: ["CVE-2024-12345", "GHSA-xxxx-yyyy"],
            summary: "Test",
            severity: .high,
            fixedVersion: nil
        )
        #expect(record.displayID == "CVE-2024-12345")
    }

    @Test func cveRecordDisplayIDFallsBackToId() {
        let record = CVERecord(
            id: "OSV-2024-999",
            aliases: [],
            summary: "Test",
            severity: .medium,
            fixedVersion: nil
        )
        #expect(record.displayID == "OSV-2024-999")
    }

    @Test func cveSeverityComparable() {
        #expect(CVESeverity.low < CVESeverity.medium)
        #expect(CVESeverity.medium < CVESeverity.high)
        #expect(CVESeverity.high < CVESeverity.critical)
        #expect(CVESeverity.unknown < CVESeverity.low)
    }

    @Test func cveSeverityLabels() {
        #expect(CVESeverity.critical.label == "Critical")
        #expect(CVESeverity.high.label == "High")
        #expect(CVESeverity.medium.label == "Medium")
        #expect(CVESeverity.low.label == "Low")
        #expect(CVESeverity.unknown.label == "Unknown")
    }

    // MARK: - Project Dependency Warning

    @Test func projectWarningForPython() {
        let warning = HomebrewScannerViewModel.projectDependencyWarning(
            for: "python", version: "3.12.4", latest: "3.14.0"
        )
        #expect(warning != nil)
        #expect(warning!.contains("pyenv"))
        #expect(warning!.contains("pyproject.toml"))
    }

    @Test func projectWarningForNode() {
        let warning = HomebrewScannerViewModel.projectDependencyWarning(
            for: "node", version: "20.0.0", latest: "22.0.0"
        )
        #expect(warning != nil)
        #expect(warning!.contains("nvm"))
        #expect(warning!.contains(".nvmrc"))
    }

    @Test func projectWarningForGo() {
        let warning = HomebrewScannerViewModel.projectDependencyWarning(
            for: "go", version: "1.21.0", latest: "1.22.0"
        )
        #expect(warning != nil)
        #expect(warning!.contains("go.mod"))
    }

    @Test func projectWarningForRuby() {
        let warning = HomebrewScannerViewModel.projectDependencyWarning(
            for: "ruby", version: "3.2.0", latest: "3.3.0"
        )
        #expect(warning != nil)
        #expect(warning!.contains("rbenv"))
    }

    @Test func noProjectWarningForNonRuntime() {
        #expect(HomebrewScannerViewModel.projectDependencyWarning(
            for: "openssl", version: "3.1.0", latest: "3.2.0"
        ) == nil)
        #expect(HomebrewScannerViewModel.projectDependencyWarning(
            for: "curl", version: "8.5.0", latest: "8.6.0"
        ) == nil)
    }

    @Test func projectWarningForVersionedPython() {
        let warning = HomebrewScannerViewModel.projectDependencyWarning(
            for: "python@3.12", version: "3.12.4", latest: "3.12.8"
        )
        #expect(warning != nil)
        #expect(warning!.contains("pyenv"))
    }
}
