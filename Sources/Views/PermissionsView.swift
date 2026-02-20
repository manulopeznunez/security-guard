import SwiftUI

struct PermissionsView: View {
    @State private var viewModel = PermissionsViewModel()
    @State private var selectedTab = 0
    @State private var approvalVersion = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Permissions")
                    .font(.title.bold())
                Spacer()

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
                .tint(.blue)
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            // Sub-tabs
            Picker("View", selection: $selectedTab) {
                Text("TCC Permissions").tag(0)
                Text("Sudo Config").tag(1)
                Text("Users & Groups").tag(2)
            }
            .pickerStyle(.segmented)
            .frame(width: 450)
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            switch selectedTab {
            case 0: tccTab
            case 1: sudoTab
            case 2: usersTab
            default: EmptyView()
            }
        }
        .task {
            await viewModel.scanAll()
        }
    }

    // MARK: - Tab 1: TCC Permissions

    @ViewBuilder
    private var tccTab: some View {
        if !viewModel.fdaAvailable {
            fdaRequiredView
        } else if viewModel.tccEntries.isEmpty && !viewModel.isScanning {
            VStack {
                Spacer()
                Text("No TCC permissions found, or scan has not been run yet.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            tccSummaryBar
            Divider()
            tccTable
        }
    }

    private var tccSummaryBar: some View {
        HStack(spacing: 20) {
            let total = viewModel.tccEntries.count
            let dangerous = viewModel.tccEntries.filter { $0.risk == .dangerous }.count
            let warning = viewModel.tccEntries.filter { $0.risk == .warning }.count
            let safe = viewModel.tccEntries.filter { $0.risk == .safe }.count

            summaryPill("Total: \(total)", color: .secondary)
            summaryPill("Dangerous: \(dangerous)", color: .red)
            summaryPill("Warning: \(warning)", color: .orange)
            summaryPill("Safe: \(safe)", color: .green)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var tccTable: some View {
        Table(viewModel.tccEntries) {
            TableColumn("") { entry in
                Image(systemName: "circle.fill")
                    .foregroundStyle(entry.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Service") { entry in
                Text(entry.serviceFriendly)
                    .font(.system(.body, design: .default, weight: entry.risk == .dangerous ? .semibold : .regular))
            }
            .width(min: 120, ideal: 150)

            TableColumn("App") { entry in
                HStack(spacing: 4) {
                    if let signed = entry.isSigned {
                        Image(systemName: signed ? "checkmark.seal.fill" : "xmark.seal.fill")
                            .foregroundStyle(signed ? .green : .red)
                            .font(.caption2)
                            .help(signed ? "Valid code signature" : "Unsigned or invalid signature")
                    } else {
                        Image(systemName: "questionmark.circle")
                            .foregroundStyle(.secondary)
                            .font(.caption2)
                            .help("Signature not checked")
                    }
                    Text(entry.client)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                }
            }
            .width(min: 200, ideal: 300)

            TableColumn("Auth") { entry in
                Text(entry.authLabel)
                    .font(.caption)
                    .foregroundStyle(entry.authValue == 2 ? .primary : .secondary)
            }
            .width(70)

            TableColumn("Risk") { entry in
                Text(entry.riskReason)
                    .font(.caption)
                    .foregroundStyle(entry.risk.color)
            }
            .width(min: 150, ideal: 200)

            TableColumn("") { entry in
                let _ = approvalVersion
                if entry.needsReview {
                    let approved = ApprovalManager.isApproved(.tccPermission, id: entry.approvalID)
                    HStack(spacing: 3) {
                        Button(approved ? "Revoke" : "Approve") {
                            if approved {
                                ApprovalManager.revoke(.tccPermission, id: entry.approvalID)
                            } else {
                                ApprovalManager.approve(.tccPermission, id: entry.approvalID)
                            }
                            approvalVersion += 1
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                        .tint(approved ? .red : .green)

                        if let anchor = entry.privacySettingsAnchor {
                            Button("Disallow") {
                                openPrivacySettings(anchor: anchor)
                            }
                            .font(.caption)
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .tint(.red)
                            .help("Open System Settings to revoke this permission")
                        }

                        Button("Ask Claude") {
                            investigateTCC(entry)
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                    }
                }
            }
            .width(230)
        }
    }

    private func openPrivacySettings(anchor: String) {
        Task {
            _ = await Task.detached {
                ShellExecutor.run(
                    "/usr/bin/open",
                    arguments: [
                        "x-apple.systempreferences:com.apple.preference.security?\(anchor)",
                    ]
                )
            }.value
        }
    }

    private var fdaRequiredView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 48))
                .foregroundStyle(.red)
            Text("Full Disk Access Required")
                .font(.headline)
            Text(
                "Reading TCC permissions requires Full Disk Access.\nGrant it to Security Guard in System Settings > Privacy & Security > Full Disk Access."
            )
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)
            .frame(maxWidth: 450)

            Button("Open Privacy Settings") {
                Task {
                    _ = await Task.detached {
                        ShellExecutor.run(
                            "/usr/bin/open",
                            arguments: [
                                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
                            ]
                        )
                    }.value
                }
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Tab 2: Sudo Config

    @ViewBuilder
    private var sudoTab: some View {
        if viewModel.sudoEntries.isEmpty && !viewModel.isScanning {
            VStack {
                Spacer()
                Image(systemName: "checkmark.shield")
                    .font(.system(size: 48))
                    .foregroundStyle(.green)
                Text("No sudo rules detected")
                    .font(.headline)
                Text("Standard macOS configuration with no custom sudo rules.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            sudoSummaryBar
            Divider()
            sudoTable
        }
    }

    private var sudoSummaryBar: some View {
        HStack(spacing: 20) {
            let nopasswd = viewModel.sudoEntries.filter(\.hasNOPASSWD).count
            let total = viewModel.sudoEntries.count
            let files = viewModel.sudoEntries.filter { $0.source.hasPrefix("sudoers.d/") }.count

            summaryPill("Rules: \(total)", color: .secondary)
            if nopasswd > 0 {
                summaryPill("NOPASSWD: \(nopasswd)", color: .red)
            }
            if files > 0 {
                summaryPill("sudoers.d files: \(files)", color: .orange)
            }
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var sudoTable: some View {
        Table(viewModel.sudoEntries) {
            TableColumn("") { entry in
                Image(systemName: "circle.fill")
                    .foregroundStyle(entry.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Rule") { entry in
                Text(entry.rule)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(2)
            }
            .width(min: 250, ideal: 400)

            TableColumn("Source") { entry in
                Text(entry.source)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(min: 100, ideal: 130)

            TableColumn("NOPASSWD") { entry in
                if entry.hasNOPASSWD {
                    Text("YES")
                        .font(.caption.bold())
                        .foregroundStyle(.red)
                }
            }
            .width(80)

            TableColumn("Risk") { entry in
                Text(entry.riskReason)
                    .font(.caption)
                    .foregroundStyle(entry.risk.color)
            }
            .width(min: 150, ideal: 250)

            TableColumn("") { entry in
                let _ = approvalVersion
                if entry.needsReview {
                    let approved = ApprovalManager.isApproved(.sudoConfig, id: entry.approvalID)
                    HStack(spacing: 4) {
                        Button(approved ? "Revoke" : "Approve") {
                            if approved {
                                ApprovalManager.revoke(.sudoConfig, id: entry.approvalID)
                            } else {
                                ApprovalManager.approve(.sudoConfig, id: entry.approvalID)
                            }
                            approvalVersion += 1
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                        .tint(approved ? .red : .green)

                        Button("Ask Claude") {
                            investigateSudo(entry)
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                    }
                }
            }
            .width(160)
        }
    }

    // MARK: - Tab 3: Users & Groups

    @ViewBuilder
    private var usersTab: some View {
        if viewModel.userEntries.isEmpty && viewModel.groupEntries.isEmpty && !viewModel.isScanning {
            VStack {
                Spacer()
                Text("Press 'Scan All' to list system users and groups.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            usersSummaryBar
            Divider()
            VSplitView {
                usersTable
                    .frame(minHeight: 120)
                groupsSection
                    .frame(minHeight: 120)
            }
        }
    }

    private var usersSummaryBar: some View {
        HStack(spacing: 20) {
            let total = viewModel.userEntries.count
            let admins = viewModel.userEntries.filter(\.isAdmin).count
            let groupWarnings = viewModel.groupEntries.filter { $0.risk != .safe }.count

            summaryPill("Users: \(total)", color: .secondary)
            summaryPill("Admins: \(admins)", color: admins > 1 ? .orange : .blue)
            summaryPill(
                "Guest: \(viewModel.guestEnabled ? "Enabled" : "Disabled")",
                color: viewModel.guestEnabled ? .orange : .green
            )
            if groupWarnings > 0 {
                summaryPill("Group Warnings: \(groupWarnings)", color: .orange)
            }
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var usersTable: some View {
        Table(viewModel.userEntries) {
            TableColumn("") { entry in
                Image(systemName: "circle.fill")
                    .foregroundStyle(entry.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Username") { entry in
                Text(entry.username)
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 100, ideal: 130)

            TableColumn("Full Name") { entry in
                Text(entry.fullName)
            }
            .width(min: 120, ideal: 180)

            TableColumn("UID") { entry in
                Text("\(entry.uid)")
                    .font(.system(.caption, design: .monospaced))
            }
            .width(50)

            TableColumn("Admin") { entry in
                if entry.isAdmin {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.orange)
                }
            }
            .width(50)

            TableColumn("Shell") { entry in
                Text(entry.shell)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
            }
            .width(min: 100, ideal: 150)

            TableColumn("Risk") { entry in
                Text(entry.riskReason)
                    .font(.caption)
                    .foregroundStyle(entry.risk.color)
            }
            .width(min: 150, ideal: 200)
        }
    }

    // MARK: - Groups Section

    private var groupsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "person.3")
                    .foregroundStyle(.blue)
                Text("Security-Relevant Groups")
                    .font(.headline)
                Spacer()
            }
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            if viewModel.groupEntries.isEmpty {
                VStack {
                    Spacer()
                    Text("No group data yet.")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                groupsTable
            }
        }
    }

    private var groupsTable: some View {
        Table(viewModel.groupEntries) {
            TableColumn("") { entry in
                Image(systemName: "circle.fill")
                    .foregroundStyle(entry.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Group") { entry in
                Text(entry.name)
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 130, ideal: 170)

            TableColumn("GID") { entry in
                Text("\(entry.gid)")
                    .font(.system(.caption, design: .monospaced))
            }
            .width(45)

            TableColumn("Members") { entry in
                if entry.members.isEmpty {
                    Text("(none)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text(entry.members.joined(separator: ", "))
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(2)
                }
            }
            .width(min: 180, ideal: 280)

            TableColumn("Risk") { entry in
                Text(entry.riskReason)
                    .font(.caption)
                    .foregroundStyle(entry.risk.color)
            }
            .width(min: 150, ideal: 250)

            TableColumn("Action") { entry in
                if !entry.actionHint.isEmpty && entry.risk != .safe {
                    Text(entry.actionHint)
                        .font(.caption)
                        .foregroundStyle(.blue)
                        .lineLimit(2)
                }
            }
            .width(min: 200, ideal: 300)
        }
    }

    // MARK: - Ask Claude

    private func investigateTCC(_ entry: TCCEntry) {
        let prompt = """
        Investigate this macOS TCC permission and assess its security risk.

        PERMISSION DETAILS:
        - Service: \(entry.serviceFriendly) (\(entry.service))
        - App: \(entry.client)
        - Authorization: \(entry.authLabel)
        - Is Apple app: \(entry.isAppleApp ? "Yes" : "No")
        - Risk level: \(entry.risk.label)
        - Risk reason: \(entry.riskReason)

        INVESTIGATION STEPS:
        1. What is this app (\(entry.client))? Is it legitimate software?
        2. Why would it need \(entry.serviceFriendly) permission?
        3. Is this permission grant expected for this type of application?
        4. Could this app abuse this permission (keylogging, screen capture, data exfiltration)?
        5. Search the web for any known security issues with this app

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / INVESTIGATE FURTHER
        - WHAT IS IT: Brief explanation of the app
        - PERMISSION ASSESSMENT: Is this permission appropriate?
        - RECOMMENDED ACTION: Should the user keep, revoke, or investigate this permission?
        """
        UninstallHelper.launchClaude(with: prompt)
    }

    private func investigateSudo(_ entry: SudoEntry) {
        let prompt = """
        Investigate this sudo configuration entry and assess its security risk.

        SUDO RULE:
        - Rule: \(entry.rule)
        - User: \(entry.user)
        - NOPASSWD: \(entry.hasNOPASSWD ? "YES — no password required" : "No")
        - Source: \(entry.source)
        - Risk level: \(entry.risk.label)
        - Risk reason: \(entry.riskReason)

        CONTEXT:
        I'm using AI coding agents that may run sudo commands.
        NOPASSWD entries allow running commands as root without a password prompt.

        INVESTIGATION STEPS:
        1. What does this sudo rule allow?
        2. Is this a standard macOS configuration or was it added manually?
        3. If NOPASSWD, could an AI agent or malware exploit this for privilege escalation?
        4. Read /etc/sudoers.d/ if there are custom files
        5. What's the safest way to handle this?

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / INVESTIGATE FURTHER
        - WHAT IS IT: Explanation of the rule
        - RISK ASSESSMENT: How dangerous is this configuration?
        - RECOMMENDED ACTION: Should the user modify or remove this rule?
        """
        UninstallHelper.launchClaude(with: prompt)
    }

    // MARK: - Helpers

    private func summaryPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
            .foregroundStyle(color)
    }
}
