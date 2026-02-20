import SwiftUI

struct AttackSurfaceView: View {
    @State private var viewModel = AttackSurfaceViewModel()
    @State private var monitor = BackgroundMonitor.shared
    @State private var selectedTab = 0
    @State private var approvalVersion = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "network.badge.shield.half.filled")
                    .font(.title)
                    .foregroundStyle(.red)
                Text("Attack Surface")
                    .font(.title.bold())
                ScanDateLabel(scanner: .attackSurface)
                Spacer()

                // Monitor status
                HStack(spacing: 6) {
                    Circle()
                        .fill(monitor.isRunning ? .green : .red)
                        .frame(width: 8, height: 8)
                    Text(monitor.isRunning
                         ? "Recording (every 60s)"
                         : "Stopped")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if viewModel.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Button(action: { Task { await viewModel.scanAll() } }) {
                    Label("Scan All", systemImage: "shield.lefthalf.filled")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.red)
                .disabled(viewModel.isScanning)

                Button(action: { Task { await viewModel.refreshPorts() } }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            // Sub-tabs
            Picker("View", selection: $selectedTab) {
                Text("Listening Ports").tag(0)
                Text("SSH Security").tag(1)
                Text("Exposed Services").tag(2)
                Text("Sharing").tag(3)
            }
            .pickerStyle(.segmented)
            .frame(width: 500)
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            switch selectedTab {
            case 0: listeningPortsTab
            case 1: sshSecurityTab
            case 2: exposedServicesTab
            case 3: sharingTab
            default: EmptyView()
            }
        }
        .task {
            await viewModel.refreshPorts()
            await viewModel.scanSSH()
            await viewModel.scanServices()
            await viewModel.scanSharing()
        }
    }

    // MARK: - Tab 1: Listening Ports

    private var listeningPortsTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Stats bar
            HStack(spacing: 20) {
                Picker("Period", selection: $viewModel.selectedDays) {
                    Text("24h").tag(1)
                    Text("7 days").tag(7)
                    Text("30 days").tag(30)
                    Text("All").tag(9999)
                }
                .pickerStyle(.segmented)
                .frame(width: 250)
                .onChange(of: viewModel.selectedDays) {
                    Task { await viewModel.refreshPorts() }
                }

                Spacer()

                portStatsPills

                Button("Purge >90 days") { Task { await viewModel.purgeOldPorts() } }
                    .controlSize(.mini)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            if viewModel.listeningPorts.isEmpty && !viewModel.isScanning {
                emptyPortsView
            } else {
                portsTable
            }
        }
    }

    private var portStatsPills: some View {
        let total = viewModel.listeningPorts.count
        let dangerous = viewModel.listeningPorts.filter { $0.risk == .dangerous }.count
        let warning = viewModel.listeningPorts.filter { $0.risk == .warning }.count
        let currentlyOpen = viewModel.listeningPorts.filter(\.isCurrentlyOpen).count

        return HStack(spacing: 8) {
            pill("\(total) ports", color: .secondary)
            if dangerous > 0 {
                pill("\(dangerous) dangerous", color: .red)
            }
            if warning > 0 {
                pill("\(warning) warning", color: .orange)
            }
            pill("\(currentlyOpen) open now", color: .blue)
        }
    }

    private func pill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private var emptyPortsView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No listening ports recorded yet")
                .font(.headline)
            Text("The background monitor captures listening ports every 60 seconds.\nData will appear here after the first snapshot.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var portsTable: some View {
        Table(viewModel.listeningPorts) {
            TableColumn("") { port in
                let _ = approvalVersion
                let approved = ApprovalManager.isApproved(.attackSurface, id: port.approvalID)
                if port.risk == .dangerous && !approved {
                    Image(systemName: "circle.fill")
                        .foregroundStyle(.red)
                        .font(.caption2)
                } else if port.risk == .warning && !approved {
                    Image(systemName: "circle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption2)
                } else if approved {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.blue)
                        .font(.caption2)
                } else {
                    Image(systemName: "circle.fill")
                        .foregroundStyle(.green)
                        .font(.caption2)
                }
            }
            .width(25)

            TableColumn("Port") { port in
                Text(port.localPort)
                    .font(.system(.callout, design: .monospaced).bold())
                    .foregroundStyle(port.risk == .dangerous ? .red : .primary)
            }
            .width(60)

            TableColumn("Address") { port in
                Text(port.localAddress)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .width(80)

            TableColumn("Process") { port in
                Text(port.processName)
                    .font(.callout)
            }
            .width(min: 120)

            TableColumn("Signature") { port in
                if port.parentSignature.isEmpty || port.parentSignature == "unsigned" {
                    Text("Unsigned")
                        .font(.caption.bold())
                        .foregroundStyle(.red)
                } else {
                    Text(FormatUtils.cleanAuthority(port.parentSignature))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(port.parentSignature)
                }
            }
            .width(min: 130)

            TableColumn("Risk") { port in
                Text(port.riskReason)
                    .font(.caption)
                    .foregroundStyle(port.risk.color)
                    .lineLimit(1)
            }
            .width(min: 160)

            TableColumn("First Seen") { port in
                Text(port.firstSeen)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .width(min: 100)

            TableColumn("Times") { port in
                Text("\(port.timesSeen)")
                    .font(.callout)
            }
            .width(50)

            TableColumn("Open") { port in
                if port.isCurrentlyOpen {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                } else {
                    Image(systemName: "xmark.circle")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
            }
            .width(40)

            TableColumn("") { port in
                let _ = approvalVersion
                if port.needsReview {
                    let approved = ApprovalManager.isApproved(.attackSurface, id: port.approvalID)
                    HStack(spacing: 4) {
                        if approved {
                            Button("Revoke") {
                                ApprovalManager.revoke(.attackSurface, id: port.approvalID)
                                approvalVersion += 1
                            }
                            .controlSize(.mini)
                            .buttonStyle(.bordered)
                            .tint(.red)
                        } else {
                            Button("Approve") {
                                ApprovalManager.approve(.attackSurface, id: port.approvalID)
                                approvalVersion += 1
                            }
                            .controlSize(.mini)
                            .buttonStyle(.borderedProminent)
                            .tint(.blue)
                        }
                        Button("Ask Claude") {
                            investigatePort(port)
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)
                    }
                }
            }
            .width(160)
        }
    }

    // MARK: - Ask Claude

    private func investigatePort(_ port: ListeningPortSummary) {
        let prompt = """
        Investigate this listening port on my Mac and assess its security risk.

        PORT DETAILS:
        - Local port: \(port.localPort)
        - Local address: \(port.localAddress)
        - Process: \(port.processName)
        - Process path: \(port.processPath)
        - Signature: \(port.parentSignature.isEmpty ? "UNSIGNED" : port.parentSignature)
        - Risk level: \(port.risk.label)
        - Risk reason: \(port.riskReason)
        - First seen: \(port.firstSeen)
        - Last seen: \(port.lastSeen)
        - Times seen: \(port.timesSeen)
        - Currently open: \(port.isCurrentlyOpen ? "Yes" : "No")

        INVESTIGATION STEPS:
        1. Identify what this process is and why it's listening on this port
        2. Is this port commonly used by legitimate software?
        3. Is the process signed? If unsigned, is that expected?
        4. Should this port be exposed? Could it be restricted to localhost?
        5. Search the web for any known security issues with this process/port

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / INVESTIGATE FURTHER
        - WHAT IS IT: Brief explanation of the process and port
        - RISK ASSESSMENT: Why this is or isn't a concern
        - RECOMMENDED ACTION: Should the user approve, investigate, or block this?
        """
        UninstallHelper.launchClaude(with: prompt)
    }

    // MARK: - Tab 2: SSH Security

    private var sshSecurityTab: some View {
        ScrollView {
            if let audit = viewModel.sshAudit {
                VStack(alignment: .leading, spacing: 16) {
                    // SSH Server Status
                    sshServerCard(audit: audit)

                    // Config Issues
                    if !audit.configIssues.isEmpty {
                        configIssuesCard(issues: audit.configIssues)
                    }

                    // Authorized Keys
                    authorizedKeysCard(audit: audit)

                    // Private Keys
                    privateKeysCard(audit: audit)

                    // Agent Keys
                    agentKeysCard(audit: audit)
                }
                .padding()
            } else {
                VStack(spacing: 12) {
                    Spacer()
                    ProgressView()
                    Text("Scanning SSH configuration...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    private func sshServerCard(audit: SSHAuditResult) -> some View {
        HStack(spacing: 12) {
            Image(systemName: audit.sshEnabled ? "lock.open.fill" : "lock.fill")
                .font(.title2)
                .foregroundStyle(audit.sshEnabled ? .red : .green)

            VStack(alignment: .leading, spacing: 2) {
                Text("SSH Server (Remote Login)")
                    .font(.headline)
                HStack(spacing: 4) {
                    Circle()
                        .fill(audit.sshEnabled ? .red : .green)
                        .frame(width: 8, height: 8)
                    Text(audit.sshEnabled
                         ? "Enabled — your Mac accepts SSH connections from the network"
                         : "Disabled — no remote terminal access")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            if audit.sshEnabled {
                Button("Disable in Settings") {
                    Task {
                        _ = await Task.detached {
                            ShellExecutor.run("/usr/bin/open", arguments: ["x-apple.systempreferences:com.apple.preferences.sharing"])
                        }.value
                    }
                }
                .controlSize(.small)
                .buttonStyle(.bordered)
                .tint(.red)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(audit.sshEnabled ? Color.red.opacity(0.06) : Color.green.opacity(0.06))
                .strokeBorder(audit.sshEnabled ? Color.red.opacity(0.2) : Color.green.opacity(0.2), lineWidth: 1)
        )
    }

    private func configIssuesCard(issues: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("Configuration Issues")
                    .font(.headline)
            }

            ForEach(Array(issues.enumerated()), id: \.offset) { _, issue in
                HStack(spacing: 6) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption)
                    Text(issue)
                        .font(.caption)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.orange.opacity(0.06))
                .strokeBorder(Color.orange.opacity(0.2), lineWidth: 1)
        )
    }

    private func authorizedKeysCard(audit: SSHAuditResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "key.fill")
                    .foregroundStyle(audit.authorizedKeysCount > 0 ? .orange : .green)
                Text("Authorized Keys")
                    .font(.headline)
                Spacer()
                Text("\(audit.authorizedKeysCount) entr\(audit.authorizedKeysCount == 1 ? "y" : "ies")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if audit.authorizedKeysEntries.isEmpty {
                Text("No authorized_keys file or no entries — no one has SSH key access to this Mac.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("These public keys can log in to this Mac without a password:")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                ForEach(audit.authorizedKeysEntries) { entry in
                    HStack(spacing: 8) {
                        Image(systemName: "key")
                            .font(.caption)
                            .foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(entry.comment.isEmpty ? "No comment" : entry.comment)
                                .font(.caption.bold())
                            Text("\(entry.keyType) — \(entry.fingerprint)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.controlBackgroundColor))
        )
    }

    private func privateKeysCard(audit: SSHAuditResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "lock.shield")
                    .foregroundStyle(.blue)
                Text("Private Keys")
                    .font(.headline)
                Spacer()
                Text("\(audit.privateKeyCount) key\(audit.privateKeyCount == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if audit.privateKeys.isEmpty {
                Text("No private keys found in ~/.ssh/")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(audit.privateKeys) { key in
                    HStack(spacing: 8) {
                        Image(systemName: key.permissionsOK ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(key.permissionsOK ? .green : .red)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(key.filename)
                                .font(.caption.bold())
                            HStack(spacing: 8) {
                                Text(key.keyType)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text("permissions: \(key.permissions)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(key.permissionsOK ? Color.secondary : Color.red)
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.controlBackgroundColor))
        )
    }

    private func agentKeysCard(audit: SSHAuditResult) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "person.badge.key.fill")
                .font(.title3)
                .foregroundStyle(audit.agentKeysLoaded > 0 ? .blue : .secondary)

            VStack(alignment: .leading, spacing: 2) {
                Text("SSH Agent")
                    .font(.headline)
                Text(audit.agentKeysLoaded > 0
                     ? "\(audit.agentKeysLoaded) key\(audit.agentKeysLoaded == 1 ? "" : "s") loaded in ssh-agent"
                     : "No keys loaded in ssh-agent")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.controlBackgroundColor))
        )
    }

    // MARK: - Tab 3: Exposed Services

    private var exposedServicesTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            if viewModel.exposedServices.isEmpty && !viewModel.isScanning {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.green)
                    Text("No exposed services detected")
                        .font(.headline)
                    Text("SSH, VNC, SMB, AFP, Remote Desktop, and AirPlay are all inactive.\nYour Mac is not accepting any well-known service connections.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                servicesTable
            }
        }
    }

    private var servicesTable: some View {
        Table(viewModel.exposedServices) {
            TableColumn("") { service in
                Image(systemName: "circle.fill")
                    .foregroundStyle(service.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Service") { service in
                Text(service.name)
                    .font(.callout.bold())
            }
            .width(min: 160)

            TableColumn("Port") { service in
                Text(service.port)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.blue)
            }
            .width(60)

            TableColumn("Process") { service in
                Text(service.processName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 100)

            TableColumn("Risk") { service in
                Text(service.risk.label)
                    .font(.caption.bold())
                    .foregroundStyle(service.risk.color)
            }
            .width(70)

            TableColumn("Description") { service in
                Text(service.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .width(min: 200)

            TableColumn("How to Disable") { service in
                Text(service.howToDisable)
                    .font(.caption)
                    .foregroundStyle(.blue)
                    .lineLimit(2)
            }
            .width(min: 200)
        }
    }

    // MARK: - Tab 4: Sharing Preferences

    private var sharingTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            if viewModel.sharingServices.isEmpty && !viewModel.isScanning {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.green)
                    Text("No sharing services active")
                        .font(.headline)
                    Text("AirPlay, SSH, Screen Sharing, File Sharing, Remote Management,\nInternet Sharing, and Content Caching are all inactive.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 500)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                sharingTable
            }
        }
    }

    private var sharingTable: some View {
        Table(viewModel.sharingServices) {
            TableColumn("") { service in
                Image(systemName: "circle.fill")
                    .foregroundStyle(service.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Service") { service in
                Text(service.name)
                    .font(.callout.bold())
            }
            .width(min: 160)

            TableColumn("Risk") { service in
                Text(service.risk.label)
                    .font(.caption.bold())
                    .foregroundStyle(service.risk.color)
            }
            .width(70)

            TableColumn("Configuration") { service in
                Text(service.configDetail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 180)

            TableColumn("Description") { service in
                Text(service.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .width(min: 200)

            TableColumn("How to Disable") { service in
                Text(service.howToDisable)
                    .font(.caption)
                    .foregroundStyle(.blue)
                    .lineLimit(2)
            }
            .width(min: 220)
        }
    }
}
