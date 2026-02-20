import Foundation

@Observable
@MainActor
final class AttackSurfaceViewModel {
    // Sub-tab 1: Listening Ports
    var listeningPorts: [ListeningPortSummary] = []
    var selectedDays = 7

    // Sub-tab 2: SSH
    var sshAudit: SSHAuditResult?

    // Sub-tab 3: Exposed Services
    var exposedServices: [ExposedService] = []

    // Sub-tab 4: Sharing
    var sharingServices: [SharingService] = []

    var isScanning = false
    var progress = ""

    // MARK: - Refresh Listening Ports from DB

    func refreshPorts() async {
        isScanning = true
        progress = "Loading listening port history..."
        let days = selectedDays

        let dbPorts = await Task.detached {
            DatabaseManager.shared.topListeningPorts(days: days)
        }.value

        // Get currently open ports to mark them
        let currentPorts = await Task.detached {
            await BackgroundMonitor.collectListeningPorts()
        }.value
        let currentKeys = Set(currentPorts.map { "\($0.localPort):\($0.processName)" })

        listeningPorts = dbPorts.map { port in
            var updated = port
            // Mark as currently open if it matches a live listening port
            if currentKeys.contains("\(port.localPort):\(port.processName)") {
                updated = ListeningPortSummary(
                    localPort: port.localPort,
                    localAddress: port.localAddress,
                    processName: port.processName,
                    processPath: port.processPath,
                    parentSignature: port.parentSignature,
                    firstSeen: port.firstSeen,
                    lastSeen: port.lastSeen,
                    timesSeen: port.timesSeen,
                    isCurrentlyOpen: true,
                    risk: port.risk,
                    riskReason: port.riskReason
                )
            }
            return updated
        }

        // Add any currently open ports not yet in history
        for current in currentPorts {
            let key = "\(current.localPort):\(current.processName)"
            if !dbPorts.contains(where: { "\($0.localPort):\($0.processName)" == key }) {
                let (risk, reason) = DatabaseManager.classifyPortRisk(
                    port: current.localPort,
                    processName: current.processName,
                    signature: current.parentSignature,
                    localAddress: current.localAddress
                )
                listeningPorts.append(ListeningPortSummary(
                    localPort: current.localPort,
                    localAddress: current.localAddress,
                    processName: current.processName,
                    processPath: current.processPath,
                    parentSignature: current.parentSignature,
                    firstSeen: "Now",
                    lastSeen: "Now",
                    timesSeen: 1,
                    isCurrentlyOpen: true,
                    risk: risk,
                    riskReason: reason
                ))
            }
        }

        // Sort: dangerous first, then warning, then safe; within same risk, pending review first
        listeningPorts.sort { a, b in
            let aPending = a.needsReview && !ApprovalManager.isApproved(.attackSurface, id: a.approvalID)
            let bPending = b.needsReview && !ApprovalManager.isApproved(.attackSurface, id: b.approvalID)
            if aPending != bPending { return aPending }
            if a.risk != b.risk { return a.risk > b.risk }
            return a.timesSeen > b.timesSeen
        }

        // Sync flagged items
        let flagged = listeningPorts.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.attackSurface, flaggedIDs: flagged)

        isScanning = false
        progress = ""
    }

    // MARK: - SSH Audit

    func scanSSH() async {
        isScanning = true
        progress = "Auditing SSH configuration..."

        let result = await Task.detached {
            Self.performSSHAudit()
        }.value

        sshAudit = result
        isScanning = false
        progress = ""
    }

    nonisolated private static func performSSHAudit() -> SSHAuditResult {
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Check if sshd is listening
        let sshdResult = ShellExecutor.shell("lsof -i :22 -n -P 2>/dev/null | grep LISTEN")
        let sshEnabled = sshdResult.exitCode == 0 && !sshdResult.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

        // Parse authorized_keys
        let authKeysPath = "\(home)/.ssh/authorized_keys"
        var authEntries: [SSHKeyEntry] = []
        if let content = try? String(contentsOfFile: authKeysPath, encoding: .utf8) {
            for line in content.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
                let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true).map(String.init)
                guard parts.count >= 2 else { continue }

                let keyType = parts[0]
                let comment = parts.count >= 3 ? parts[2] : ""

                // Get fingerprint
                let fpResult = ShellExecutor.shell("echo '\(trimmed)' | ssh-keygen -l -f - 2>/dev/null")
                let fingerprint: String
                if fpResult.exitCode == 0 {
                    fingerprint = fpResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
                } else {
                    fingerprint = "Unable to read"
                }

                authEntries.append(SSHKeyEntry(keyType: keyType, comment: comment, fingerprint: fingerprint))
            }
        }

        // Scan private keys in ~/.ssh/
        var privateKeys: [SSHKeyInfo] = []
        let sshDir = "\(home)/.ssh"
        if let files = try? FileManager.default.contentsOfDirectory(atPath: sshDir) {
            let privateKeyFiles = files.filter { name in
                let lower = name.lowercased()
                // Private key indicators: no extension, or common private key names
                return (lower.hasPrefix("id_") && !lower.hasSuffix(".pub"))
                    || lower == "identity"
            }

            for filename in privateKeyFiles {
                let fullPath = "\(sshDir)/\(filename)"

                // Get file permissions
                let permResult = ShellExecutor.run("/usr/bin/stat", arguments: ["-f", "%Lp", fullPath])
                let permissions = permResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
                let permissionsOK = permissions == "600" || permissions == "400"

                // Detect key type from file content
                let typeResult = ShellExecutor.shell("ssh-keygen -l -f '\(fullPath)' 2>/dev/null")
                let keyType: String
                if typeResult.exitCode == 0 {
                    let parts = typeResult.output.split(separator: " ")
                    keyType = parts.count >= 4 ? String(parts.last!).replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "") : "unknown"
                } else {
                    keyType = "unknown"
                }

                privateKeys.append(SSHKeyInfo(
                    filename: filename,
                    keyType: keyType,
                    permissions: permissions,
                    permissionsOK: permissionsOK
                ))
            }
        }

        // Check ssh-agent loaded keys
        let agentResult = ShellExecutor.shell("ssh-add -l 2>/dev/null")
        let agentKeysLoaded: Int
        if agentResult.exitCode == 0 && !agentResult.output.contains("no identities") {
            agentKeysLoaded = agentResult.output.components(separatedBy: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
        } else {
            agentKeysLoaded = 0
        }

        // Check config issues
        var configIssues: [String] = []

        // Check permissions on ~/.ssh directory
        let dirPermResult = ShellExecutor.run("/usr/bin/stat", arguments: ["-f", "%Lp", sshDir])
        let dirPerms = dirPermResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if dirPerms != "700" {
            configIssues.append("~/.ssh directory permissions are \(dirPerms) (should be 700)")
        }

        // Check authorized_keys permissions
        if FileManager.default.fileExists(atPath: authKeysPath) {
            let akPermResult = ShellExecutor.run("/usr/bin/stat", arguments: ["-f", "%Lp", authKeysPath])
            let akPerms = akPermResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if akPerms != "600" && akPerms != "644" {
                configIssues.append("authorized_keys permissions are \(akPerms) (should be 600)")
            }
        }

        // Check for private keys with bad permissions
        for key in privateKeys where !key.permissionsOK {
            configIssues.append("\(key.filename) has permissions \(key.permissions) (should be 600)")
        }

        return SSHAuditResult(
            sshEnabled: sshEnabled,
            authorizedKeysCount: authEntries.count,
            authorizedKeysEntries: authEntries,
            privateKeyCount: privateKeys.count,
            privateKeys: privateKeys,
            configIssues: configIssues,
            agentKeysLoaded: agentKeysLoaded
        )
    }

    // MARK: - Exposed Services

    func scanServices() async {
        isScanning = true
        progress = "Scanning for exposed services..."

        let result = await Task.detached {
            Self.detectExposedServices()
        }.value

        exposedServices = result
        isScanning = false
        progress = ""
    }

    nonisolated private static func detectExposedServices() -> [ExposedService] {
        var services: [ExposedService] = []

        struct ServiceCheck {
            let name: String
            let port: String
            let description: String
            let howToDisable: String
            let risk: PortRisk
        }

        let checks: [ServiceCheck] = [
            ServiceCheck(
                name: "SSH (Remote Login)",
                port: "22",
                description: "Allows remote shell access to this Mac. Any user with credentials or an authorized SSH key can connect.",
                howToDisable: "System Settings → General → Sharing → Remote Login → Off",
                risk: .dangerous
            ),
            ServiceCheck(
                name: "VNC (Screen Sharing)",
                port: "5900",
                description: "Allows remote desktop control of this Mac. Exposes your screen to anyone who can connect.",
                howToDisable: "System Settings → General → Sharing → Screen Sharing → Off",
                risk: .dangerous
            ),
            ServiceCheck(
                name: "Apple Remote Desktop",
                port: "3283",
                description: "Allows remote management and file transfer via Apple Remote Desktop.",
                howToDisable: "System Settings → General → Sharing → Remote Management → Off",
                risk: .dangerous
            ),
            ServiceCheck(
                name: "SMB (File Sharing)",
                port: "445",
                description: "Shares files over the network via SMB protocol. Visible to other devices on the network.",
                howToDisable: "System Settings → General → Sharing → File Sharing → Off",
                risk: .warning
            ),
            ServiceCheck(
                name: "AFP (Apple File Sharing)",
                port: "548",
                description: "Legacy Apple file sharing protocol. Less common but still exposes files on the network.",
                howToDisable: "System Settings → General → Sharing → File Sharing → Off",
                risk: .warning
            ),
            ServiceCheck(
                name: "AirPlay Receiver",
                port: "7000",
                description: "Allows other Apple devices to stream content to this Mac.",
                howToDisable: "System Settings → General → AirDrop & Handoff → AirPlay Receiver → Off",
                risk: .safe
            ),
        ]

        for check in checks {
            let result = ShellExecutor.shell("lsof -i :\(check.port) -n -P 2>/dev/null | grep LISTEN")
            let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !output.isEmpty else { continue }

            // Extract process name from first line
            let firstLine = output.components(separatedBy: "\n").first ?? ""
            let parts = firstLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            let processName = parts.first ?? "unknown"

            services.append(ExposedService(
                name: check.name,
                port: check.port,
                processName: processName,
                isEnabled: true,
                risk: check.risk,
                description: check.description,
                howToDisable: check.howToDisable
            ))
        }

        return services.sorted { $0.risk > $1.risk }
    }

    // MARK: - Sharing Preferences

    func scanSharing() async {
        isScanning = true
        progress = "Auditing sharing preferences..."
        let result = await Task.detached {
            Self.detectSharingServices()
        }.value
        sharingServices = result
        isScanning = false
        progress = ""
    }

    nonisolated private static func detectSharingServices() -> [SharingService] {
        var services: [SharingService] = []

        let osVersion = ShellExecutor.run("/usr/bin/sw_vers", arguments: ["-productVersion"])
            .output.trimmingCharacters(in: .whitespacesAndNewlines)

        // 1. AirPlay Receiver (port 5000)
        let airplayListening = ShellExecutor.shell(
            "lsof +c 0 -i :5000 -n -P 2>/dev/null | grep -i ControlCenter | grep LISTEN"
        )
        let airplayOn = !airplayListening.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        if airplayOn {
            let cves = SystemCVEDatabase.vulnerabilities(for: "AirPlay Receiver", osVersion: osVersion)
            let risk: PortRisk = cves.isEmpty ? .safe : (cves.contains { $0.wormable } ? .dangerous : .warning)
            services.append(SharingService(
                name: "AirPlay Receiver",
                isEnabled: true,
                risk: risk,
                description: cves.isEmpty
                    ? "Allows other Apple devices to stream to this Mac."
                    : "\(cves.count) unpatched CVE\(cves.count == 1 ? "" : "s"): \(cves.map(\.id).joined(separator: ", "))",
                howToDisable: "System Settings > General > AirDrop & Handoff > AirPlay Receiver > Off",
                configDetail: "Ports 5000/7000 listening on all interfaces"
            ))
        }

        // 2. Remote Login (SSH)
        let sshResult = ShellExecutor.shell("lsof -i :22 -n -P 2>/dev/null | grep LISTEN")
        if !sshResult.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            services.append(SharingService(
                name: "Remote Login (SSH)",
                isEnabled: true,
                risk: .dangerous,
                description: "Allows remote terminal access. Should be OFF unless actively needed.",
                howToDisable: "System Settings > General > Sharing > Remote Login > Off",
                configDetail: "Port 22 listening"
            ))
        }

        // 3. Screen Sharing (VNC)
        let vncResult = ShellExecutor.shell("lsof -i :5900 -n -P 2>/dev/null | grep LISTEN")
        if !vncResult.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            services.append(SharingService(
                name: "Screen Sharing (VNC)",
                isEnabled: true,
                risk: .dangerous,
                description: "Remote desktop control. Exposes your screen to network users.",
                howToDisable: "System Settings > General > Sharing > Screen Sharing > Off",
                configDetail: "Port 5900 listening"
            ))
        }

        // 4. File Sharing (SMB)
        let smbResult = ShellExecutor.shell("lsof -i :445 -n -P 2>/dev/null | grep LISTEN")
        if !smbResult.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            services.append(SharingService(
                name: "File Sharing (SMB)",
                isEnabled: true,
                risk: .warning,
                description: "Shares files over the network via SMB protocol.",
                howToDisable: "System Settings > General > Sharing > File Sharing > Off",
                configDetail: "Port 445 listening"
            ))
        }

        // 5. Remote Management (ARD)
        let ardResult = ShellExecutor.shell("lsof -i :3283 -n -P 2>/dev/null | grep LISTEN")
        if !ardResult.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            services.append(SharingService(
                name: "Remote Management",
                isEnabled: true,
                risk: .dangerous,
                description: "Apple Remote Desktop agent. Allows full remote control and file transfer.",
                howToDisable: "System Settings > General > Sharing > Remote Management > Off",
                configDetail: "Port 3283 listening"
            ))
        }

        // 6. Internet Sharing
        let internetSharing = ShellExecutor.shell("pgrep -x InternetSharing 2>/dev/null")
        if internetSharing.exitCode == 0 {
            services.append(SharingService(
                name: "Internet Sharing",
                isEnabled: true,
                risk: .warning,
                description: "Shares your internet connection. Runs DHCP/DNS servers.",
                howToDisable: "System Settings > General > Sharing > Internet Sharing > Off",
                configDetail: "InternetSharing process running"
            ))
        }

        // 7. Content Caching
        let contentCaching = ShellExecutor.shell("pgrep -x AssetCache 2>/dev/null")
        if contentCaching.exitCode == 0 {
            services.append(SharingService(
                name: "Content Caching",
                isEnabled: true,
                risk: .safe,
                description: "Caches Apple software updates and iCloud content for local devices.",
                howToDisable: "System Settings > General > Sharing > Content Caching > Off",
                configDetail: "AssetCache process running"
            ))
        }

        return services.sorted { $0.risk > $1.risk }
    }

    // MARK: - Scan All

    func scanAll() async {
        isScanning = true
        await refreshPorts()
        await scanSSH()
        await scanServices()
        await scanSharing()
        isScanning = false
        ScanDateTracker.record(.attackSurface)
        let totalPorts = listeningPorts.count
        let flaggedPorts = listeningPorts.filter(\.needsReview).count
        let exposedCount = exposedServices.count
        DatabaseManager.shared.insertScanHistory(
            scanner: "attackSurface", total: totalPorts + exposedCount, flagged: flaggedPorts + exposedCount,
            summary: "\(totalPorts) ports, \(exposedCount) exposed services, \(flaggedPorts) flagged"
        )
    }

    // MARK: - Purge

    func purgeOldPorts() async {
        await Task.detached { DatabaseManager.shared.purgeOldListeningPorts(days: 90) }.value
        await refreshPorts()
    }
}
