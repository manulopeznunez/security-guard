import Testing
@testable import MacSecurityGuard

struct ProcessScannerTests {

    // MARK: - isHomebrew

    @Test func homebrewCellarPath() {
        #expect(ProcessScannerViewModel.isHomebrew("/usr/local/Cellar/node/20.0/bin/node") == true)
        #expect(ProcessScannerViewModel.isHomebrew("/opt/homebrew/Cellar/python3/3.12/bin/python3") == true)
    }

    @Test func homebrewOptPath() {
        #expect(ProcessScannerViewModel.isHomebrew("/usr/local/opt/openssl/bin/openssl") == true)
        #expect(ProcessScannerViewModel.isHomebrew("/opt/homebrew/opt/curl/bin/curl") == true)
    }

    @Test func homebrewBinPath() {
        #expect(ProcessScannerViewModel.isHomebrew("/usr/local/bin/node") == true)
        #expect(ProcessScannerViewModel.isHomebrew("/opt/homebrew/bin/python3") == true)
    }

    @Test func nonHomebrewPath() {
        #expect(ProcessScannerViewModel.isHomebrew("/usr/bin/python3") == false)
        #expect(ProcessScannerViewModel.isHomebrew("/Applications/Foo.app/Contents/MacOS/foo") == false)
    }

    // MARK: - findParentApp

    @Test func findAppInPath() {
        let result = ProcessScannerViewModel.findParentApp("/Applications/Slack.app/Contents/MacOS/Slack")
        #expect(result == "/Applications/Slack.app")
    }

    @Test func noAppInPath() {
        let result = ProcessScannerViewModel.findParentApp("/usr/local/bin/node")
        #expect(result == nil)
    }
}
