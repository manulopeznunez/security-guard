import Testing
@testable import MacSecurityGuard

struct ConfigGuardTests {

    // MARK: - Change Type Classification

    @Test func unchangedFileIsSafe() {
        let entry = ConfigGuardEntry(
            filePath: "~/.zshrc",
            absolutePath: "/Users/test/.zshrc",
            exists: true,
            currentHash: "abc123",
            baselineHash: "abc123",
            permissions: "644",
            changeType: .unchanged,
            risk: .safe,
            riskReason: "Unchanged since baseline"
        )
        #expect(entry.risk == .safe)
        #expect(!entry.needsReview)
    }

    @Test func modifiedFileIsSuspicious() {
        let entry = ConfigGuardEntry(
            filePath: "~/.zshrc",
            absolutePath: "/Users/test/.zshrc",
            exists: true,
            currentHash: "new456",
            baselineHash: "old123",
            permissions: "644",
            changeType: .modified,
            risk: .suspicious,
            riskReason: "File content changed since baseline"
        )
        #expect(entry.risk == .suspicious)
        #expect(entry.needsReview)
    }

    @Test func deletedFileIsSuspicious() {
        let entry = ConfigGuardEntry(
            filePath: "~/.ssh/authorized_keys",
            absolutePath: "/Users/test/.ssh/authorized_keys",
            exists: false,
            currentHash: nil,
            baselineHash: "old123",
            permissions: "",
            changeType: .deleted,
            risk: .suspicious,
            riskReason: "File was present in baseline but has been deleted"
        )
        #expect(entry.risk == .suspicious)
        #expect(entry.needsReview)
    }

    @Test func newFileIsWarning() {
        let entry = ConfigGuardEntry(
            filePath: "~/.npmrc",
            absolutePath: "/Users/test/.npmrc",
            exists: true,
            currentHash: "abc123",
            baselineHash: nil,
            permissions: "644",
            changeType: .newFile,
            risk: .warning,
            riskReason: "File not in baseline — created since last scan"
        )
        #expect(entry.risk == .warning)
        #expect(entry.needsReview)
    }

    @Test func insecurePermissionsIsWarning() {
        let entry = ConfigGuardEntry(
            filePath: "~/.netrc",
            absolutePath: "/Users/test/.netrc",
            exists: true,
            currentHash: "abc123",
            baselineHash: "abc123",
            permissions: "755",
            changeType: .insecurePermissions,
            risk: .warning,
            riskReason: "File has insecure permissions (755)"
        )
        #expect(entry.risk == .warning)
        #expect(entry.needsReview)
    }

    // MARK: - Model Properties

    @Test func approvalIDIsFilePath() {
        let entry = ConfigGuardEntry(
            filePath: "~/.gitconfig",
            absolutePath: "/Users/test/.gitconfig",
            exists: true, currentHash: "x", baselineHash: "x",
            permissions: "644", changeType: .unchanged,
            risk: .safe, riskReason: ""
        )
        #expect(entry.approvalID == "~/.gitconfig")
    }

    @Test func monitoredFilesListIsNotEmpty() {
        let files = ConfigGuardViewModel.monitoredFiles
        #expect(!files.isEmpty)
        // Shell
        #expect(files.contains("~/.zshrc"))
        #expect(files.contains("~/.profile"))
        // Git
        #expect(files.contains("~/.gitconfig"))
        // SSH
        #expect(files.contains("~/.ssh/config"))
        #expect(files.contains("~/.ssh/id_ed25519"))
        #expect(files.contains("~/.ssh/id_rsa"))
        #expect(files.contains("~/.ssh/known_hosts"))
        // Cloud credentials
        #expect(files.contains("~/.aws/credentials"))
        #expect(files.contains("~/.kube/config"))
        #expect(files.contains("~/.docker/config.json"))
        #expect(files.contains("~/.config/gh/hosts.yml"))
        // System
        #expect(files.contains("/etc/hosts"))
    }

    // MARK: - Permission Classification

    // Sensitive files: 600/644/400 OK
    @Test func sshConfigInsecurePermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.ssh/config", permissions: "755"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.ssh/config", permissions: "600"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.ssh/config", permissions: "644"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.ssh/config", permissions: "400"))
    }

    @Test func netrcInsecurePermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.netrc", permissions: "777"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.netrc", permissions: "600"))
    }

    // Strict files: ONLY 600/400 OK (private keys, credentials)
    @Test func sshPrivateKeyStrictPermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.ssh/id_rsa", permissions: "644"))
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.ssh/id_ed25519", permissions: "755"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.ssh/id_rsa", permissions: "600"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.ssh/id_ed25519", permissions: "400"))
    }

    @Test func awsCredentialsStrictPermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.aws/credentials", permissions: "644"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.aws/credentials", permissions: "600"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.aws/credentials", permissions: "400"))
    }

    @Test func kubeConfigStrictPermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.kube/config", permissions: "755"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.kube/config", permissions: "600"))
    }

    @Test func dockerConfigStrictPermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.docker/config.json", permissions: "644"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.docker/config.json", permissions: "600"))
    }

    @Test func ghTokenStrictPermissions() {
        #expect(ConfigGuardViewModel.isInsecurePermissions("~/.config/gh/hosts.yml", permissions: "644"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.config/gh/hosts.yml", permissions: "600"))
    }

    // Regular files: no permission check
    @Test func regularFilePermissionsAlwaysSafe() {
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.zshrc", permissions: "755"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("~/.gitconfig", permissions: "644"))
        #expect(!ConfigGuardViewModel.isInsecurePermissions("/etc/hosts", permissions: "644"))
    }

    // MARK: - Change Type Display

    @Test func changeTypeColors() {
        #expect(ConfigChangeType.unchanged.rawValue == "Unchanged")
        #expect(ConfigChangeType.modified.rawValue == "Modified")
        #expect(ConfigChangeType.newFile.rawValue == "New File")
        #expect(ConfigChangeType.deleted.rawValue == "Deleted")
        #expect(ConfigChangeType.insecurePermissions.rawValue == "Insecure Permissions")
    }
}
