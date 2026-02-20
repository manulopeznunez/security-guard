import Testing
@testable import MacSecurityGuard

struct HomebrewScannerTests {

    // MARK: - parseInstalledList

    @Test func parsesInstalledListBasic() {
        let output = """
        git 2.53.0
        node 22.1.0
        python@3.12 3.12.4
        """
        let result = HomebrewScannerViewModel.parseInstalledList(output)
        #expect(result["git"] == "2.53.0")
        #expect(result["node"] == "22.1.0")
        #expect(result["python@3.12"] == "3.12.4")
    }

    @Test func parsesInstalledListMultipleVersions() {
        let output = "python@3.12 3.12.3 3.12.4"
        let result = HomebrewScannerViewModel.parseInstalledList(output)
        #expect(result["python@3.12"] == "3.12.4")
    }

    @Test func parsesInstalledListEmpty() {
        let result = HomebrewScannerViewModel.parseInstalledList("")
        #expect(result.isEmpty)
    }

    @Test func parsesInstalledListWhitespace() {
        let output = "  git    2.53.0  \n\n  node   22.1.0  \n"
        let result = HomebrewScannerViewModel.parseInstalledList(output)
        #expect(result["git"] == "2.53.0")
        #expect(result["node"] == "22.1.0")
    }

    // MARK: - parseOutdatedJSON

    @Test func parsesOutdatedJSONWithFormulaeAndCasks() {
        let json = """
        {
            "formulae": [
                {
                    "name": "git",
                    "installed_versions": ["2.47.0"],
                    "current_version": "2.53.0",
                    "pinned": false
                },
                {
                    "name": "openssl@3",
                    "installed_versions": ["3.1.0"],
                    "current_version": "3.4.0",
                    "pinned": true
                }
            ],
            "casks": [
                {
                    "name": "ngrok",
                    "installed_versions": ["3.21.0,abc"],
                    "current_version": "3.36.1,def"
                }
            ]
        }
        """
        let result = HomebrewScannerViewModel.parseOutdatedJSON(json)
        #expect(result.formulae.count == 2)
        #expect(result.formulae["git"]?.currentVersion == "2.53.0")
        #expect(result.formulae["git"]?.pinned == false)
        #expect(result.formulae["openssl@3"]?.pinned == true)
        #expect(result.casks.count == 1)
        #expect(result.casks["ngrok"]?.currentVersion == "3.36.1,def")
    }

    @Test func parsesOutdatedJSONEmpty() {
        let json = """
        {"formulae": [], "casks": []}
        """
        let result = HomebrewScannerViewModel.parseOutdatedJSON(json)
        #expect(result.formulae.isEmpty)
        #expect(result.casks.isEmpty)
    }

    @Test func parsesOutdatedJSONInvalid() {
        let result = HomebrewScannerViewModel.parseOutdatedJSON("not json")
        #expect(result.formulae.isEmpty)
        #expect(result.casks.isEmpty)
    }

    @Test func parsesOutdatedJSONMissingFields() {
        let json = """
        {
            "formulae": [
                {"name": "git"}
            ],
            "casks": []
        }
        """
        let result = HomebrewScannerViewModel.parseOutdatedJSON(json)
        #expect(result.formulae.isEmpty)
    }

    // MARK: - Risk Assessment

    @Test func upToDatePackageIsSafe() {
        let (risk, reason) = HomebrewScannerViewModel.assessRisk(
            name: "jq",
            installedVersion: "1.7.1",
            latestVersion: nil,
            pinned: false,
            type: .formula
        )
        #expect(risk == .safe)
        #expect(reason.contains("Up to date"))
    }

    @Test func securityCriticalOutdatedIsSuspicious() {
        let (risk, reason) = HomebrewScannerViewModel.assessRisk(
            name: "git",
            installedVersion: "2.47.0",
            latestVersion: "2.53.0",
            pinned: false,
            type: .formula
        )
        #expect(risk == .suspicious)
        #expect(reason.contains("Security-critical"))
    }

    @Test func securityCriticalPinnedIsWarning() {
        let (risk, reason) = HomebrewScannerViewModel.assessRisk(
            name: "openssl@3",
            installedVersion: "3.1.0",
            latestVersion: "3.4.0",
            pinned: true,
            type: .formula
        )
        #expect(risk == .warning)
        #expect(reason.contains("pinned"))
    }

    @Test func opensslOutdatedIsSuspicious() {
        let (risk, _) = HomebrewScannerViewModel.assessRisk(
            name: "openssl",
            installedVersion: "3.0.0",
            latestVersion: "3.0.1",
            pinned: false,
            type: .formula
        )
        #expect(risk == .suspicious)
    }

    @Test func curlOutdatedIsSuspicious() {
        let (risk, _) = HomebrewScannerViewModel.assessRisk(
            name: "curl",
            installedVersion: "8.0.0",
            latestVersion: "8.5.0",
            pinned: false,
            type: .formula
        )
        #expect(risk == .suspicious)
    }

    @Test func nonCriticalSlightlyOutdatedIsWarning() {
        let (risk, _) = HomebrewScannerViewModel.assessRisk(
            name: "jq",
            installedVersion: "1.6",
            latestVersion: "1.7.1",
            pinned: false,
            type: .formula
        )
        #expect(risk == .warning)
    }

    @Test func nonCriticalSeverelyOutdatedIsSuspicious() {
        let (risk, reason) = HomebrewScannerViewModel.assessRisk(
            name: "ffmpeg",
            installedVersion: "4.0",
            latestVersion: "7.1",
            pinned: false,
            type: .formula
        )
        #expect(risk == .suspicious)
        #expect(reason.contains("3 major"))
    }

    @Test func pinnedNonCriticalIsWarning() {
        let (risk, reason) = HomebrewScannerViewModel.assessRisk(
            name: "jq",
            installedVersion: "1.6",
            latestVersion: "1.7.1",
            pinned: true,
            type: .formula
        )
        #expect(risk == .warning)
        #expect(reason.contains("Pinned"))
    }

    @Test func caskOutdatedAssessment() {
        let (risk, _) = HomebrewScannerViewModel.assessRisk(
            name: "visual-studio-code",
            installedVersion: "1.80.0",
            latestVersion: "1.95.0",
            pinned: false,
            type: .cask
        )
        #expect(risk == .warning)
    }

    // MARK: - Version Distance

    @Test func sameVersionDistanceIsZero() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "2.53.0", latest: "2.53.0"
        )
        #expect(distance == 0)
    }

    @Test func sameMajorDistanceIsZero() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "2.47.0", latest: "2.53.0"
        )
        #expect(distance == 0)
    }

    @Test func oneMajorVersionBehind() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "21.0.0", latest: "22.1.0"
        )
        #expect(distance == 1)
    }

    @Test func threeMajorVersionsBehind() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "4.0", latest: "7.1"
        )
        #expect(distance == 3)
    }

    @Test func caskVersionWithMetadata() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "3.21.0,abc", latest: "3.36.1,def"
        )
        #expect(distance == 0)
    }

    @Test func unparsableVersionFallback() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "abc", latest: "def"
        )
        #expect(distance == 1)
    }

    @Test func unparsableButSameVersionReturnsZero() {
        let distance = HomebrewScannerViewModel.estimateVersionDistance(
            installed: "abc", latest: "abc"
        )
        #expect(distance == 0)
    }
}
