import SwiftUI

struct PermissionsView: View {
    @State private var viewModel = PermissionsViewModel()
    @State private var selectedTab = 0
    @State private var tccViewMode = 0
    @State private var approvalVersion = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
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

            Picker("View", selection: $selectedTab) {
                Text("TCC Permissions").tag(0)
                Text("Users & Groups").tag(1)
            }
            .pickerStyle(.segmented)
            .frame(width: 300)
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            switch selectedTab {
            case 0: tccTab
            case 1: usersTab
            default: EmptyView()
            }
        }
        .task {
            viewModel.loadCached()
            await viewModel.scanAll()
        }
    }

    // MARK: - TCC Tab

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
            if tccViewMode == 0 {
                tccTable
            } else {
                tccByAppView
            }
        }
    }

    private var tccSummaryBar: some View {
        HStack(spacing: 12) {
            Picker("Mode", selection: $tccViewMode) {
                Text("By Service").tag(0)
                Text("By App").tag(1)
            }
            .pickerStyle(.segmented)
            .frame(width: 200)

            Divider().frame(height: 20)

            if tccViewMode == 0 {
                let total = viewModel.tccEntries.count
                let dangerous = viewModel.tccEntries.filter { $0.risk == .dangerous }.count
                let warning = viewModel.tccEntries.filter { $0.risk == .warning }.count
                let safe = viewModel.tccEntries.filter { $0.risk == .safe }.count
                let recent = viewModel.tccEntries.filter(\.isRecentlyGranted).count

                summaryPill("Total: \(total)", color: .secondary)
                summaryPill("Dangerous: \(dangerous)", color: .red)
                summaryPill("Warning: \(warning)", color: .orange)
                summaryPill("Safe: \(safe)", color: .green)
                if recent > 0 { summaryPill("Recent: \(recent)", color: .purple) }
            } else {
                let groups = viewModel.tccAppGroups
                summaryPill("Apps: \(groups.count)", color: .secondary)
                let high = groups.filter(\.hasHighExposure).count
                if high > 0 { summaryPill("High Exposure: \(high)", color: .red) }
                let recent = groups.reduce(0) { $0 + $1.recentCount }
                if recent > 0 { summaryPill("Recently Granted: \(recent)", color: .purple) }
            }

            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    // MARK: - TCC By Service Table

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
                    if let iconData = entry.appIconData, let nsImage = NSImage(data: iconData) {
                        Image(nsImage: nsImage)
                            .resizable()
                            .frame(width: 16, height: 16)
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    if let signed = entry.isSigned {
                        Image(systemName: signed ? "checkmark.seal.fill" : "xmark.seal.fill")
                            .foregroundStyle(signed ? .green : .red)
                            .font(.caption2)
                            .help(signed ? "Valid code signature" : "Unsigned or invalid signature")
                    }
                    VStack(alignment: .leading, spacing: 0) {
                        Text(entry.appName)
                            .font(.caption)
                            .lineLimit(1)
                        if entry.appName != entry.client {
                            Text(entry.client)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                    if entry.isRecentlyGranted { newBadge }
                }
                .help(entry.permissionExplanation)
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
                if entry.needsReview { tccActionButtons(entry) }
            }
            .width(230)
        }
    }

    // MARK: - TCC By App View

    private var tccByAppView: some View {
        List {
            ForEach(viewModel.tccAppGroups) { group in
                DisclosureGroup {
                    ForEach(group.permissions) { entry in
                        tccPermissionRow(entry)
                    }
                } label: {
                    tccAppGroupLabel(group)
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func tccAppGroupLabel(_ group: TCCAppGroup) -> some View {
        HStack(spacing: 8) {
            if let iconData = group.appIconData, let nsImage = NSImage(data: iconData) {
                Image(nsImage: nsImage)
                    .resizable()
                    .frame(width: 24, height: 24)
                    .clipShape(RoundedRectangle(cornerRadius: 5))
            } else {
                Image(systemName: "app.fill")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .frame(width: 24, height: 24)
            }

            Text(group.appName)
                .font(.system(.body, weight: .medium))

            Text("\(group.permissionCount)")
                .font(.caption2.bold())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.15), in: Capsule())

            if group.hasHighExposure {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
                    .help("High exposure: multiple sensitive permissions")
            }
            if group.recentCount > 0 { newBadge }

            Spacer()

            Image(systemName: "circle.fill")
                .foregroundStyle(group.aggregateRisk.color)
                .font(.caption2)
        }
    }

    private func tccPermissionRow(_ entry: TCCEntry) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "circle.fill")
                .foregroundStyle(entry.risk.color)
                .font(.system(size: 6))

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(entry.serviceFriendly)
                        .font(.system(.callout, weight: entry.risk == .dangerous ? .semibold : .regular))
                    if entry.isRecentlyGranted { newBadge }
                    Text(entry.authLabel)
                        .font(.caption)
                        .foregroundStyle(entry.authValue == 2 ? .primary : .secondary)
                }
                Text(entry.permissionExplanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            let _ = approvalVersion
            if entry.needsReview { tccActionButtons(entry) }
        }
        .padding(.vertical, 3)
    }

    // MARK: - TCC Shared

    private func tccActionButtons(_ entry: TCCEntry) -> some View {
        let approved = ApprovalManager.isApproved(.tccPermission, id: entry.approvalID)
        return HStack(spacing: 3) {
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

            Button("Ask Claude") { investigateTCC(entry) }
                .font(.caption)
                .buttonStyle(.bordered)
                .controlSize(.mini)
        }
    }

    private var newBadge: some View {
        Text("NEW")
            .font(.system(size: 8, weight: .bold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Color.purple.opacity(0.2), in: Capsule())
            .foregroundStyle(.purple)
    }

    private func openPrivacySettings(anchor: String) {
        Task {
            _ = await Task.detached {
                ShellExecutor.run("/usr/bin/open", arguments: [
                    "x-apple.systempreferences:com.apple.preference.security?\(anchor)",
                ])
            }.value
        }
    }

    private var fdaRequiredView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.shield").font(.system(size: 48)).foregroundStyle(.red)
            Text("Full Disk Access Required").font(.headline)
            Text("Reading TCC permissions requires Full Disk Access.\nGrant it to Security Guard in System Settings > Privacy & Security > Full Disk Access.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 450)
            Button("Open Privacy Settings") { openPrivacySettings(anchor: "Privacy_AllFiles") }
                .buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Users & Groups Tab (with Sudo)

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
                usersTable.frame(minHeight: 120)
                groupsSection.frame(minHeight: 100)
                if !viewModel.sudoEntries.isEmpty {
                    sudoSection.frame(minHeight: 100)
                }
            }
        }
    }

    private var usersSummaryBar: some View {
        HStack(spacing: 20) {
            let total = viewModel.userEntries.count
            let admins = viewModel.userEntries.filter(\.isAdmin).count
            let groupWarnings = viewModel.groupEntries.filter { $0.risk != .safe }.count
            let nopasswd = viewModel.sudoEntries.filter(\.hasNOPASSWD).count
            let sudoersFiles = viewModel.sudoEntries.filter { $0.source.hasPrefix("sudoers.d/") }.count

            summaryPill("Users: \(total)", color: .secondary)
            summaryPill("Admins: \(admins)", color: admins > 1 ? .orange : .blue)
            summaryPill("Guest: \(viewModel.guestEnabled ? "Enabled" : "Disabled")",
                        color: viewModel.guestEnabled ? .orange : .green)
            if groupWarnings > 0 { summaryPill("Group Warnings: \(groupWarnings)", color: .orange) }
            if nopasswd > 0 { summaryPill("NOPASSWD: \(nopasswd)", color: .red) }
            if sudoersFiles > 0 { summaryPill("sudoers.d: \(sudoersFiles)", color: .orange) }
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var usersTable: some View {
        Table(viewModel.userEntries) {
            TableColumn("") { e in Image(systemName: "circle.fill").foregroundStyle(e.risk.color).font(.caption2) }.width(25)
            TableColumn("Username") { e in Text(e.username).font(.system(.body, design: .monospaced)) }.width(min: 100, ideal: 130)
            TableColumn("Full Name") { e in Text(e.fullName) }.width(min: 120, ideal: 180)
            TableColumn("UID") { e in Text("\(e.uid)").font(.system(.caption, design: .monospaced)) }.width(50)
            TableColumn("Admin") { e in if e.isAdmin { Image(systemName: "checkmark.circle.fill").foregroundStyle(.orange) } }.width(50)
            TableColumn("Shell") { e in Text(e.shell).font(.system(.caption, design: .monospaced)).lineLimit(1) }.width(min: 100, ideal: 150)
            TableColumn("Risk") { e in Text(e.riskReason).font(.caption).foregroundStyle(e.risk.color) }.width(min: 150, ideal: 200)
        }
    }

    // MARK: - Groups Section

    private var groupsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "person.3").foregroundStyle(.blue)
                Text("Security-Relevant Groups").font(.headline)
                Spacer()
            }
            .padding(.horizontal).padding(.vertical, 6)
            Divider()
            if viewModel.groupEntries.isEmpty {
                VStack { Spacer(); Text("No group data yet.").foregroundStyle(.secondary); Spacer() }
                    .frame(maxWidth: .infinity)
            } else { groupsTable }
        }
    }

    private var groupsTable: some View {
        Table(viewModel.groupEntries) {
            TableColumn("") { e in Image(systemName: "circle.fill").foregroundStyle(e.risk.color).font(.caption2) }.width(25)
            TableColumn("Group") { e in Text(e.name).font(.system(.body, design: .monospaced)) }.width(min: 130, ideal: 170)
            TableColumn("GID") { e in Text("\(e.gid)").font(.system(.caption, design: .monospaced)) }.width(45)
            TableColumn("Members") { e in
                if e.members.isEmpty { Text("(none)").font(.caption).foregroundStyle(.secondary) }
                else { Text(e.members.joined(separator: ", ")).font(.system(.caption, design: .monospaced)).lineLimit(2) }
            }.width(min: 180, ideal: 280)
            TableColumn("Risk") { e in Text(e.riskReason).font(.caption).foregroundStyle(e.risk.color) }.width(min: 150, ideal: 250)
            TableColumn("Action") { e in
                if !e.actionHint.isEmpty && e.risk != .safe { Text(e.actionHint).font(.caption).foregroundStyle(.blue).lineLimit(2) }
            }.width(min: 200, ideal: 300)
        }
    }

    // MARK: - Sudo Section

    private var sudoSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "terminal").foregroundStyle(.red)
                Text("Sudo Rules").font(.headline)
                Spacer()
            }
            .padding(.horizontal).padding(.vertical, 6)
            Divider()
            sudoTable
        }
    }

    private var sudoTable: some View {
        Table(viewModel.sudoEntries) {
            TableColumn("") { e in Image(systemName: "circle.fill").foregroundStyle(e.risk.color).font(.caption2) }.width(25)
            TableColumn("Rule") { e in Text(e.rule).font(.system(.caption, design: .monospaced)).lineLimit(2) }.width(min: 250, ideal: 400)
            TableColumn("Source") { e in Text(e.source).font(.caption).foregroundStyle(.secondary) }.width(min: 100, ideal: 130)
            TableColumn("NOPASSWD") { e in if e.hasNOPASSWD { Text("YES").font(.caption.bold()).foregroundStyle(.red) } }.width(80)
            TableColumn("Risk") { e in Text(e.riskReason).font(.caption).foregroundStyle(e.risk.color) }.width(min: 150, ideal: 250)
            TableColumn("") { entry in
                let _ = approvalVersion
                if entry.needsReview {
                    let approved = ApprovalManager.isApproved(.sudoConfig, id: entry.approvalID)
                    HStack(spacing: 4) {
                        Button(approved ? "Revoke" : "Approve") {
                            if approved { ApprovalManager.revoke(.sudoConfig, id: entry.approvalID) }
                            else { ApprovalManager.approve(.sudoConfig, id: entry.approvalID) }
                            approvalVersion += 1
                        }
                        .font(.caption).buttonStyle(.bordered).controlSize(.mini).tint(approved ? .red : .green)
                        Button("Ask Claude") { investigateSudo(entry) }
                            .font(.caption).buttonStyle(.bordered).controlSize(.mini)
                    }
                }
            }.width(160)
        }
    }

    // MARK: - Ask Claude

    private func investigateTCC(_ entry: TCCEntry) {
        let prompt = """
        Investigate this macOS TCC permission and assess its security risk.

        PERMISSION DETAILS:
        - Service: \(entry.serviceFriendly) (\(entry.service))
        - App: \(entry.appName) (\(entry.client))
        - Authorization: \(entry.authLabel)
        - Is Apple app: \(entry.isAppleApp ? "Yes" : "No")
        - Signed: \(entry.isSigned == true ? "Yes" : entry.isSigned == false ? "NO" : "Unknown")
        - Risk level: \(entry.risk.label)
        - Permission impact: \(entry.permissionExplanation)

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
