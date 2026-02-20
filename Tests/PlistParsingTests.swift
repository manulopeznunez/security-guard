import Testing
@testable import MacSecurityGuard

struct PlistParsingTests {

    // MARK: - extractValue

    @Test func extractSimpleValue() {
        let output = """
        "Label" => "com.example.agent"
        "Program" => "/usr/bin/foo"
        """
        let label = PersistenceScannerViewModel.extractValue(from: output, key: "Label")
        #expect(label == "com.example.agent")
    }

    @Test func extractMissingKey() {
        let output = """
        "Label" => "com.example.agent"
        """
        let result = PersistenceScannerViewModel.extractValue(from: output, key: "Program")
        #expect(result == nil)
    }

    @Test func extractFromEmptyString() {
        let result = PersistenceScannerViewModel.extractValue(from: "", key: "Label")
        #expect(result == nil)
    }

    // MARK: - extractProgramPath

    @Test func extractProgramKey() {
        let output = """
        "Label" => "com.example.agent"
        "Program" => "/usr/local/bin/myapp"
        """
        let path = PersistenceScannerViewModel.extractProgramPath(from: output)
        #expect(path == "/usr/local/bin/myapp")
    }

    @Test func extractProgramArguments() {
        let output = """
        "Label" => "com.example.agent"
        "ProgramArguments" => [
            0 => "/usr/bin/python3"
            1 => "-m"
            2 => "mymodule"
        ]
        """
        let path = PersistenceScannerViewModel.extractProgramPath(from: output)
        #expect(path == "/usr/bin/python3")
    }

    @Test func programKeyTakesPrecedenceOverArguments() {
        let output = """
        "Program" => "/usr/bin/direct"
        "ProgramArguments" => [
            0 => "/usr/bin/fallback"
        ]
        """
        let path = PersistenceScannerViewModel.extractProgramPath(from: output)
        #expect(path == "/usr/bin/direct")
    }

    @Test func noProgramKeyOrArguments() {
        let output = """
        "Label" => "com.example.agent"
        "KeepAlive" => 1
        """
        let path = PersistenceScannerViewModel.extractProgramPath(from: output)
        #expect(path == nil)
    }

    @Test func malformedProgramArguments() {
        let output = """
        "ProgramArguments" => [
        """
        let path = PersistenceScannerViewModel.extractProgramPath(from: output)
        #expect(path == nil)
    }

    // MARK: - findParentApp

    @Test func findAppBundle() {
        let path = "/Applications/Foo.app/Contents/MacOS/foo"
        let result = PersistenceScannerViewModel.findParentApp(path)
        #expect(result == "/Applications/Foo.app")
    }

    @Test func noAppBundle() {
        let path = "/usr/local/bin/foo"
        let result = PersistenceScannerViewModel.findParentApp(path)
        #expect(result == nil)
    }

    @Test func nestedAppBundle() {
        let path = "/Applications/Xcode.app/Contents/Developer/Foo.app/Contents/MacOS/bar"
        let result = PersistenceScannerViewModel.findParentApp(path)
        // Returns the FIRST .app in the path
        #expect(result == "/Applications/Xcode.app")
    }
}
