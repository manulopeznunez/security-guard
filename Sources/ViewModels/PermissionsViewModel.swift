import Foundation

@Observable
@MainActor
final class PermissionsViewModel {
    // Sub-tab 1: TCC Permissions
    var tccEntries: [TCCEntry] = []
    var fdaAvailable = true

    // Sub-tab 2: Sudo Config
    var sudoEntries: [SudoEntry] = []

    // Sub-tab 3: Users & Groups
    var userEntries: [UserAccountEntry] = []
    var groupEntries: [GroupEntry] = []
    var adminUsers: [String] = []
    var guestEnabled = false

    var isScanning = false
    var progress = ""

    // MARK: - Scan All

    func scanAll() async {
        isScanning = true
        await scanTCC()
        await scanSudo()
        await scanUsers()
        isScanning = false
        progress = ""
    }

    // MARK: - TCC Scan

    func scanTCC() async {
        progress = "Reading TCC permissions..."
        let result = await Self.performTCCScan()
        tccEntries = result.entries
        fdaAvailable = result.fdaAvailable

        if result.fdaAvailable {
            let flagged = result.entries.filter(\.needsReview).map(\.approvalID)
            ApprovalManager.recordScanResults(.tccPermission, flaggedIDs: flagged)
        }
    }

    // MARK: - Sudo Scan

    func scanSudo() async {
        progress = "Checking sudo configuration..."
        let result = await Self.performSudoScan()
        sudoEntries = result

        let flagged = result.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.sudoConfig, flaggedIDs: flagged)
    }

    // MARK: - Users Scan

    func scanUsers() async {
        progress = "Scanning users and groups..."
        let result = await Self.performUsersScan()
        userEntries = result.users
        groupEntries = result.groups
        adminUsers = result.admins
        guestEnabled = result.guestEnabled

        let flagged = result.users.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.usersGroups, flaggedIDs: flagged)
    }

    // MARK: - Static TCC Scan

    nonisolated static func performTCCScan() async -> (entries: [TCCEntry], fdaAvailable: Bool) {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let tccPath = "\(home)/Library/Application Support/com.apple.TCC/TCC.db"

        let result = await Task.detached {
            ShellExecutor.run("/usr/bin/sqlite3", arguments: [
                tccPath,
                "-separator", "|",
                "SELECT service, client, client_type, auth_value, auth_reason, last_modified FROM access WHERE auth_value != 0;",
            ], timeout: .local)
        }.value

        if result.exitCode != 0 {
            let noAccess = result.error.contains("not permitted") ||
                result.error.contains("unable to open database") ||
                result.error.contains("authorization denied")
            return (entries: [], fdaAvailable: !noAccess)
        }

        // Collect unique clients for signature checking
        struct RawTCC {
            let service: String
            let client: String
            let clientType: Int
            let authValue: Int
            let authReason: Int
            let lastModified: Date?
            let isApple: Bool
        }

        var rawEntries: [RawTCC] = []
        var clientsToCheck = Set<String>()

        for line in result.output.components(separatedBy: "\n") where !line.isEmpty {
            let parts = line.components(separatedBy: "|")
            guard parts.count >= 6 else { continue }

            let service = parts[0]
            let client = parts[1]
            let clientType = Int(parts[2]) ?? 0
            let authValue = Int(parts[3]) ?? 0
            let authReason = Int(parts[4]) ?? 0
            let lastModified = Double(parts[5]).flatMap { Date(timeIntervalSince1970: $0) }
            let isApple = client.hasPrefix("com.apple.")

            rawEntries.append(RawTCC(
                service: service, client: client, clientType: clientType,
                authValue: authValue, authReason: authReason,
                lastModified: lastModified, isApple: isApple
            ))

            if !isApple {
                clientsToCheck.insert(client)
            }
        }

        // Check signatures for non-Apple clients
        var signatureCache: [String: Bool] = [:]
        for client in clientsToCheck {
            signatureCache[client] = checkClientSignature(client)
        }

        var entries: [TCCEntry] = []
        for raw in rawEntries {
            let (risk, reason) = classifyTCCRisk(
                service: raw.service, client: raw.client,
                isApple: raw.isApple, authValue: raw.authValue
            )

            let isSigned: Bool? = raw.isApple ? true : signatureCache[raw.client]

            entries.append(TCCEntry(
                service: raw.service,
                serviceFriendly: friendlyServiceName(raw.service),
                client: raw.client,
                clientType: raw.clientType,
                authValue: raw.authValue,
                authReason: raw.authReason,
                lastModified: raw.lastModified,
                isAppleApp: raw.isApple,
                isSigned: isSigned,
                risk: risk,
                riskReason: reason
            ))
        }

        // Sort by service (grouped), then by risk within each service
        return (entries: entries.sorted {
            if $0.serviceFriendly != $1.serviceFriendly {
                return $0.serviceFriendly < $1.serviceFriendly
            }
            return $0.risk > $1.risk
        }, fdaAvailable: true)
    }

    // MARK: - TCC Risk Classification

    nonisolated static func classifyTCCRisk(
        service: String, client: String, isApple: Bool, authValue: Int
    ) -> (TCCRisk, String) {
        if authValue == 0 { return (.safe, "Permission denied") }
        if isApple { return (.safe, "Apple system app") }

        let dangerousServices: Set<String> = [
            "kTCCServiceSystemPolicyAllFiles",
            "kTCCServiceAccessibility",
        ]

        let warningServices: Set<String> = [
            "kTCCServiceScreenCapture",
            "kTCCServiceCamera",
            "kTCCServiceMicrophone",
            "kTCCServiceAppleEvents",
            "kTCCServiceSystemPolicyDesktopFolder",
            "kTCCServiceSystemPolicyDocumentsFolder",
            "kTCCServiceSystemPolicyDownloadsFolder",
            "kTCCServiceListenEvent",
            "kTCCServicePostEvent",
        ]

        let friendly = friendlyServiceName(service)

        if dangerousServices.contains(service) {
            return (.dangerous, "Non-Apple app with \(friendly) access")
        }

        if warningServices.contains(service) {
            return (.warning, "Non-Apple app with \(friendly) access")
        }

        return (.safe, "Low-sensitivity permission")
    }

    // MARK: - TCC Friendly Names

    nonisolated static func friendlyServiceName(_ service: String) -> String {
        let map: [String: String] = [
            "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
            "kTCCServiceAccessibility": "Accessibility",
            "kTCCServiceScreenCapture": "Screen Recording",
            "kTCCServiceCamera": "Camera",
            "kTCCServiceMicrophone": "Microphone",
            "kTCCServiceAppleEvents": "Automation",
            "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
            "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
            "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
            "kTCCServiceContactsFull": "Contacts",
            "kTCCServiceCalendar": "Calendar",
            "kTCCServiceReminders": "Reminders",
            "kTCCServicePhotos": "Photos",
            "kTCCServiceAddressBook": "Address Book",
            "kTCCServiceListenEvent": "Input Monitoring",
            "kTCCServicePostEvent": "Input Monitoring (Post)",
            "kTCCServiceDeveloperTool": "Developer Tools",
            "kTCCServiceMediaLibrary": "Media & Apple Music",
            "kTCCServiceSpeechRecognition": "Speech Recognition",
            "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
            "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
            "kTCCServiceBluetoothAlways": "Bluetooth",
        ]
        return map[service] ?? service
            .replacingOccurrences(of: "kTCCService", with: "")
            .replacingOccurrences(of: "SystemPolicy", with: "")
    }

    // MARK: - Client Signature Check

    /// Resolve a TCC client (bundle ID or path) to an app path and check codesign.
    nonisolated private static func checkClientSignature(_ client: String) -> Bool {
        // If client looks like a path, check directly
        if client.hasPrefix("/") {
            let result = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", client])
            return result.exitCode == 0
        }

        // Bundle ID — try to find the app via mdfind
        let findResult = ShellExecutor.run(
            "/usr/bin/mdfind", arguments: ["kMDItemCFBundleIdentifier == '\(client)'"],
            timeout: .local
        )
        let appPath = findResult.output
            .components(separatedBy: "\n")
            .first(where: { $0.hasSuffix(".app") && !$0.isEmpty })?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let path = appPath, !path.isEmpty else { return true }  // assume signed if can't find

        let result = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", path])
        return result.exitCode == 0
    }

    // MARK: - Static Sudo Scan

    nonisolated static func performSudoScan() async -> [SudoEntry] {
        var entries: [SudoEntry] = []

        // sudo -nl: non-interactive listing of current user's sudo rules
        let sudoResult = await Task.detached {
            ShellExecutor.run("/usr/bin/sudo", arguments: ["-nl"], timeout: .local)
        }.value

        if sudoResult.exitCode == 0 {
            entries.append(contentsOf: parseSudoOutput(sudoResult.output))
        }

        // Check for extra files in /etc/sudoers.d/
        let sudoersDResult = await Task.detached {
            ShellExecutor.run("/bin/ls", arguments: ["/etc/sudoers.d/"], timeout: .local)
        }.value

        if sudoersDResult.exitCode == 0 {
            for filename in sudoersDResult.output.components(separatedBy: "\n") {
                let name = filename.trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty, name != "README" else { continue }
                entries.append(SudoEntry(
                    rule: "Custom sudoers.d file: \(name)",
                    user: "varies",
                    hasNOPASSWD: false,
                    commands: "Unknown (requires root to read)",
                    source: "sudoers.d/\(name)",
                    risk: .warning,
                    riskReason: "Extra sudoers.d file detected"
                ))
            }
        }

        // Check if current user is in admin group
        let adminResult = await Task.detached {
            ShellExecutor.run(
                "/usr/bin/dscl", arguments: [".", "-read", "/Groups/admin", "GroupMembership"],
                timeout: .local
            )
        }.value

        if adminResult.exitCode == 0 {
            let currentUser = NSUserName()
            let members =
                adminResult.output
                .components(separatedBy: "GroupMembership:").last?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let adminSet = Set(members.split(separator: " ").map(String.init))
            if adminSet.contains(currentUser) {
                entries.append(SudoEntry(
                    rule: "\(currentUser) is in admin group",
                    user: currentUser,
                    hasNOPASSWD: false,
                    commands: "ALL (with password)",
                    source: "admin group",
                    risk: .warning,
                    riskReason: "Admin users can sudo with password"
                ))
            }
        }

        return entries.sorted { $0.risk > $1.risk }
    }

    nonisolated private static func parseSudoOutput(_ output: String) -> [SudoEntry] {
        let currentUser = NSUserName()
        var entries: [SudoEntry] = []

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            // Skip header lines like "User manu may run..."
            guard !trimmed.hasPrefix("User ") && !trimmed.hasPrefix("Sudoers")
                && !trimmed.hasPrefix("Matching")
            else { continue }

            let hasNOPASSWD = trimmed.contains("NOPASSWD")
            let risk: AccessRisk
            let reason: String

            if hasNOPASSWD {
                risk = .suspicious
                reason = "NOPASSWD allows running commands without password"
            } else if trimmed.contains("(ALL)") || trimmed.contains("(root)") {
                risk = .warning
                reason = "Broad sudo access"
            } else {
                risk = .safe
                reason = "Limited sudo rule"
            }

            entries.append(SudoEntry(
                rule: trimmed,
                user: currentUser,
                hasNOPASSWD: hasNOPASSWD,
                commands: trimmed,
                source: "sudo -nl",
                risk: risk,
                riskReason: reason
            ))
        }

        return entries
    }

    // MARK: - Static Users Scan

    nonisolated static func performUsersScan() async -> (
        users: [UserAccountEntry], groups: [GroupEntry], admins: [String], guestEnabled: Bool
    ) {
        // List all users with UIDs
        let usersResult = await Task.detached {
            ShellExecutor.run(
                "/usr/bin/dscl", arguments: [".", "-list", "/Users", "UniqueID"],
                timeout: .local
            )
        }.value

        // Get admin group members
        let adminResult = await Task.detached {
            ShellExecutor.run(
                "/usr/bin/dscl", arguments: [".", "-read", "/Groups/admin", "GroupMembership"],
                timeout: .local
            )
        }.value
        let adminLine =
            adminResult.output
            .components(separatedBy: "GroupMembership:").last?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let admins = adminLine.split(separator: " ").map(String.init)
        let adminSet = Set(admins)

        // Check guest account
        let guestResult = await Task.detached {
            ShellExecutor.run(
                "/usr/bin/dscl", arguments: [".", "-read", "/Users/Guest", "AuthenticationAuthority"],
                timeout: .local
            )
        }.value
        let guestEnabled = guestResult.exitCode == 0
            && !guestResult.output.contains("No such key")

        var entries: [UserAccountEntry] = []

        for line in usersResult.output.components(separatedBy: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 2, let uid = Int(parts.last!) else { continue }
            let username = parts[0]
            let isHidden = uid < 200 || username.hasPrefix("_")

            // Get full name
            let nameResult = ShellExecutor.run(
                "/usr/bin/dscl",
                arguments: [".", "-read", "/Users/\(username)", "RealName"],
                timeout: .local
            )
            let fullName =
                nameResult.output
                .replacingOccurrences(of: "RealName:", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .components(separatedBy: "\n").last?
                .trimmingCharacters(in: .whitespaces) ?? username

            // Get home directory
            let homeResult = ShellExecutor.run(
                "/usr/bin/dscl",
                arguments: [".", "-read", "/Users/\(username)", "NFSHomeDirectory"],
                timeout: .local
            )
            let homeDir =
                homeResult.output
                .replacingOccurrences(of: "NFSHomeDirectory:", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)

            // Get shell
            let shellResult = ShellExecutor.run(
                "/usr/bin/dscl",
                arguments: [".", "-read", "/Users/\(username)", "UserShell"],
                timeout: .local
            )
            let shell =
                shellResult.output
                .replacingOccurrences(of: "UserShell:", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)

            let isAdmin = adminSet.contains(username)
            let isGuest = username == "Guest"

            let risk: AccessRisk
            let reason: String
            if uid == 0 && username != "root" {
                risk = .suspicious
                reason = "Non-root user with UID 0 (root-equivalent)"
            } else if isGuest {
                risk = .warning
                reason = "Guest account exists"
            } else if isAdmin && !isHidden {
                risk = .warning
                reason = "Admin user (can sudo)"
            } else {
                risk = .safe
                reason = isHidden ? "System account" : "Standard user"
            }

            // Show real users + any suspicious hidden ones
            if !isHidden || risk != .safe {
                entries.append(UserAccountEntry(
                    username: username,
                    uid: uid,
                    fullName: fullName,
                    homeDirectory: homeDir,
                    shell: shell,
                    isAdmin: isAdmin,
                    isHidden: isHidden,
                    isGuest: isGuest,
                    risk: risk,
                    riskReason: reason
                ))
            }
        }

        // Scan security-relevant groups
        let groups = await scanGroups(adminSet: adminSet)

        return (
            users: entries.sorted { $0.risk > $1.risk },
            groups: groups,
            admins: admins,
            guestEnabled: guestEnabled
        )
    }

    // MARK: - Static Groups Scan

    nonisolated private static func scanGroups(adminSet: Set<String>) async -> [GroupEntry] {
        let sensitiveGroups: [String: String] = [
            "admin": "Full admin privileges — members can sudo",
            "wheel": "Root-level group — can su to root",
            "staff": "Standard staff group for local users",
            "com.apple.access_ssh": "Remote Login (SSH) access",
            "com.apple.access_screensharing": "Screen Sharing access",
            "com.apple.remote_ae": "Remote Apple Events access",
            "_developer": "Developer Tools access — can attach debugger to processes",
        ]

        var entries: [GroupEntry] = []

        for (groupName, description) in sensitiveGroups {
            let result = await Task.detached {
                ShellExecutor.run(
                    "/usr/bin/dscl", arguments: [".", "-read", "/Groups/\(groupName)"],
                    timeout: .local
                )
            }.value

            guard result.exitCode == 0 else { continue }

            // Parse GID
            let gid: Int
            if let gidLine = result.output.components(separatedBy: "\n")
                .first(where: { $0.hasPrefix("PrimaryGroupID:") })
            {
                gid = Int(
                    gidLine.replacingOccurrences(of: "PrimaryGroupID:", with: "")
                        .trimmingCharacters(in: .whitespaces)
                ) ?? -1
            } else {
                gid = -1
            }

            // Parse members
            let members: [String]
            if let memberLine = result.output.components(separatedBy: "\n")
                .first(where: { $0.hasPrefix("GroupMembership:") })
            {
                members = memberLine
                    .replacingOccurrences(of: "GroupMembership:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .split(separator: " ")
                    .map(String.init)
                    .filter { !$0.isEmpty }
            } else {
                members = []
            }

            let (risk, reason, hint) = classifyGroupRisk(
                name: groupName, members: members, description: description
            )

            entries.append(GroupEntry(
                name: groupName,
                gid: gid,
                members: members,
                isSensitive: true,
                risk: risk,
                riskReason: reason,
                actionHint: hint
            ))
        }

        return entries.sorted { $0.risk > $1.risk }
    }

    nonisolated private static func classifyGroupRisk(
        name: String, members: [String], description: String
    ) -> (AccessRisk, String, String) {
        switch name {
        case "admin":
            if members.count > 2 {
                return (
                    .warning,
                    "\(members.count) admin users — review if all need admin",
                    "System Settings > Users & Groups — demote unnecessary admins"
                )
            }
            return (.warning, description, "Review admin membership periodically")

        case "wheel":
            if !members.isEmpty {
                return (
                    .suspicious,
                    "wheel group has \(members.count) member(s) — root-level access",
                    "Remove users from wheel unless root su is required"
                )
            }
            return (.safe, "wheel group is empty", "No action needed")

        case "com.apple.access_ssh":
            if !members.isEmpty {
                return (
                    .warning,
                    "SSH enabled for: \(members.joined(separator: ", "))",
                    "System Settings > General > Sharing > Remote Login — remove users who don't need SSH"
                )
            }
            return (.safe, "No users have SSH access", "No action needed")

        case "com.apple.access_screensharing":
            if !members.isEmpty {
                return (
                    .warning,
                    "Screen Sharing enabled for: \(members.joined(separator: ", "))",
                    "System Settings > General > Sharing > Screen Sharing — disable if not needed"
                )
            }
            return (.safe, "Screen Sharing not enabled for any user", "No action needed")

        case "com.apple.remote_ae":
            if !members.isEmpty {
                return (
                    .suspicious,
                    "Remote Apple Events enabled for: \(members.joined(separator: ", "))",
                    "System Settings > General > Sharing > Remote Apple Events — disable unless required"
                )
            }
            return (.safe, "Remote Apple Events not enabled", "No action needed")

        case "_developer":
            if !members.isEmpty {
                return (
                    .warning,
                    "Developer Tools access: \(members.joined(separator: ", "))",
                    "Expected for Xcode users. Review if non-developers have access"
                )
            }
            return (.safe, "No users in developer group", "No action needed")

        default:
            if !members.isEmpty {
                return (.safe, description, "Review membership if unexpected")
            }
            return (.safe, description, "No action needed")
        }
    }
}
