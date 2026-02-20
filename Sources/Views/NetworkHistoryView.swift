import SwiftUI
import AppKit

struct NetworkHistoryView: View {
    @State private var viewModel = NetworkHistoryViewModel()
    @State private var monitor = BackgroundMonitor.shared
    @State private var selectedTab = 0
    @State private var selectedApp: AppSummary?
    @State private var approvalVersion = 0  // Increment to refresh approval state
    @State private var appToQuarantine: AppSummary?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "clock.arrow.2.circlepath")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Network History")
                    .font(.title.bold())
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
                    if !monitor.lastSnapshot.isEmpty {
                        Text("Last: \(monitor.lastSnapshot)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }

                Button(action: {
                    if monitor.isRunning { monitor.stop() } else { monitor.start() }
                }) {
                    Label(monitor.isRunning ? "Stop" : "Start Recording",
                          systemImage: monitor.isRunning ? "stop.circle" : "record.circle")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button(action: { Task { await viewModel.refresh() } }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
            }
            .padding()

            Divider()

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
                    Task { await viewModel.refresh() }
                }

                Spacer()

                Label("\(viewModel.totalRecords) records", systemImage: "cylinder")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Label("\(viewModel.dbSizeKB) KB", systemImage: "internaldrive")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button("Purge >90 days") { Task { await viewModel.purgeOld() } }
                    .controlSize(.mini)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            // Suspicious items banner
            suspiciousBanner

            if viewModel.totalRecords == 0 && !viewModel.isLoading {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "clock.badge.questionmark")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("No history yet")
                        .font(.headline)
                    Text("Press \"Start Recording\" to begin capturing network connections every 60 seconds.\nData will accumulate over time, giving you insights into which apps connect where and how much data they transfer.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                // Sub-tabs for different views
                Picker("View", selection: $selectedTab) {
                    Text("By IP").tag(0)
                    Text("By App").tag(1)
                    Text("By Country").tag(2)
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
                .padding(.horizontal)
                .padding(.vertical, 6)

                switch selectedTab {
                case 0: ipTable
                case 1: appTable
                case 2: countryTable
                default: EmptyView()
                }
            }
        }
        .task {
            await viewModel.refresh()
        }
        .alert("Quarantine this item?",
               isPresented: Binding(
                   get: { appToQuarantine != nil },
                   set: { if !$0 { appToQuarantine = nil } }
               )
        ) {
            Button("Cancel", role: .cancel) { appToQuarantine = nil }
            Button("Quarantine", role: .destructive) {
                if let app = appToQuarantine {
                    ApprovalManager.quarantine(.networkMonitor, id: approvalKey(for: app))
                    approvalVersion += 1
                }
                appToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }

    // MARK: - IP Table

    private var ipTable: some View {
        Table(viewModel.topIPs) {
            TableColumn("Country") { ip in
                HStack(spacing: 4) {
                    if !ip.countryCode.isEmpty && ip.countryCode != "?" {
                        Text(FormatUtils.flag(for: ip.countryCode))
                    }
                    Text(ip.country)
                        .font(.callout)
                }
            }
            .width(min: 90)

            TableColumn("IP") { ip in
                Text(ip.remoteIP)
                    .font(.system(.caption, design: .monospaced))
            }
            .width(min: 120)

            TableColumn("Organization") { ip in
                Text(ip.organization)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .width(min: 130)

            TableColumn("Host") { ip in
                let friendly = FormatUtils.friendlyHostname(ip.hostname)
                Text(friendly.isEmpty ? "-" : friendly)
                    .font(.caption)
                    .foregroundStyle(friendly.isEmpty ? Color.secondary : Color.primary)
                    .lineLimit(1)
                    .help(ip.hostname.isEmpty ? ip.remoteIP : ip.hostname)
            }
            .width(min: 140)

            TableColumn("Times Seen") { ip in
                Text("\(ip.timesSeen)")
                    .font(.callout)
            }
            .width(70)

            TableColumn("Apps") { ip in
                Text(ip.appNames)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .help(ip.appNames)
            }
            .width(min: 120)

            TableColumn("Received") { ip in
                Text(FormatUtils.bytes(ip.totalBytesIn))
                    .font(.callout)
                    .foregroundStyle(.green)
            }
            .width(70)

            TableColumn("Sent") { ip in
                Text(FormatUtils.bytes(ip.totalBytesOut))
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            .width(70)

            TableColumn("First Seen") { ip in
                Text(ip.firstSeen)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .width(min: 100)
        }
    }

    // MARK: - App Table

    private var appTable: some View {
        Table(viewModel.topApps) {
            TableColumn("App") { app in
                HStack(spacing: 6) {
                    if isFlagged(app) && isApproved(app) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.blue)
                            .font(.caption)
                            .help("Reviewed and approved")
                    } else if !app.injectionRisk.isEmpty {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                            .help(app.injectionRisk)
                    } else if app.signatureAuthority.isEmpty && app.parentSignature.isEmpty {
                        Image(systemName: "app.fill")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    } else if app.isSigned {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                            .font(.caption)
                            .help("Signed: \(app.signatureAuthority)")
                    } else {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                            .help("UNSIGNED")
                    }
                    Text(app.processName)
                        .font(.callout)
                }
            }
            .width(min: 130)

            TableColumn("Signature") { app in
                let cleanName = FormatUtils.cleanAuthority(app.signatureAuthority)
                if !app.signatureAuthority.isEmpty && app.isSigned {
                    Text(cleanName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(app.signatureAuthority)
                } else if !app.signatureAuthority.isEmpty {
                    Text(cleanName.isEmpty ? "Unsigned" : cleanName)
                        .font(.caption.bold())
                        .foregroundStyle(.red)
                        .lineLimit(1)
                } else if !app.parentSignature.isEmpty {
                    HStack(spacing: 3) {
                        Image(systemName: "link")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Text("via \(app.parentName) (\(FormatUtils.cleanAuthority(app.parentSignature)))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    .help("Parent process: \(app.parentName) signed by \(app.parentSignature)")
                } else {
                    Text("...")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .width(min: 150)

            TableColumn("Times Seen") { app in
                Text("\(app.timesSeen)")
                    .font(.callout)
            }
            .width(70)

            TableColumn("Unique IPs") { app in
                Text("\(app.uniqueIPs)")
                    .font(.callout)
            }
            .width(70)

            TableColumn("Countries") { app in
                Text("\(app.uniqueCountries)")
                    .font(.callout)
            }
            .width(60)

            TableColumn("Received") { app in
                Text(FormatUtils.bytes(app.totalBytesIn))
                    .font(.callout)
                    .foregroundStyle(.green)
            }
            .width(80)

            TableColumn("Sent") { app in
                Text(FormatUtils.bytes(app.totalBytesOut))
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            .width(80)

            TableColumn("") { app in
                Button(action: { selectedApp = app }) {
                    Image(systemName: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.blue)
                }
                .buttonStyle(.plain)
                .help("See details")
                .popover(isPresented: Binding(
                    get: { selectedApp?.id == app.id },
                    set: { if !$0 { selectedApp = nil } }
                ), arrowEdge: .leading) {
                    appDetailPopover(app: app)
                }
            }
            .width(30)
        }
    }

    // MARK: - App Detail Popover

    private func appDetailPopover(app: AppSummary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header
            HStack(spacing: 6) {
                if app.isSigned {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else if !app.injectionRisk.isEmpty {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(.red)
                } else {
                    Image(systemName: "app.fill")
                        .foregroundStyle(.secondary)
                }
                Text(app.processName)
                    .font(.system(size: 13, weight: .semibold))
            }

            if app.isSigned {
                Text("Signed by \(FormatUtils.cleanAuthority(app.signatureAuthority))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Unsigned process")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Divider()

            // Process Chain
            VStack(alignment: .leading, spacing: 4) {
                Text("Process Chain")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)

                if app.parentChain.isEmpty {
                    Text("No parent chain available")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    let hops = app.parentChain.components(separatedBy: " \u{2192} ")
                    ForEach(Array(hops.enumerated()), id: \.offset) { index, hop in
                        HStack(spacing: 4) {
                            if index > 0 {
                                Text(String(repeating: "  ", count: index) + "\u{2192}")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.tertiary)
                            }
                            Text(hop)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(index == hops.count - 1 ? .primary : .secondary)
                        }
                    }
                }
            }

            // Injection Risk
            if !app.injectionRisk.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                        Text("Injection Risk")
                            .font(.caption.bold())
                            .foregroundStyle(.red)
                    }
                    Text(app.injectionRisk)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.red.opacity(0.8))
                }
            }

            Divider()

            // Network Activity
            VStack(alignment: .leading, spacing: 4) {
                Text("Network Activity")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)

                HStack(spacing: 12) {
                    Label("\(app.timesSeen) connections", systemImage: "network")
                    Label("\(app.uniqueIPs) IPs", systemImage: "globe")
                    Label("\(app.uniqueCountries) countries", systemImage: "flag")
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                HStack(spacing: 12) {
                    HStack(spacing: 2) {
                        Image(systemName: "arrow.down")
                            .font(.caption2)
                            .foregroundStyle(.green)
                        Text(FormatUtils.bytes(app.totalBytesIn))
                            .font(.caption)
                    }
                    HStack(spacing: 2) {
                        Image(systemName: "arrow.up")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                        Text(FormatUtils.bytes(app.totalBytesOut))
                            .font(.caption)
                    }
                }
            }

            // Full Process Trace (scrollable)
            if !app.processTrace.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Full Trace")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)

                    ScrollView {
                        Text(app.processTrace)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 150)
                }
            }

            Divider()

            // Action buttons
            HStack(spacing: 8) {
                Button(action: { copyTrace(app: app) }) {
                    Label("Copy Full Trace", systemImage: "doc.on.doc")
                }
                .controlSize(.small)

                Button(action: { investigateWithClaude(app: app) }) {
                    Label("Ask Claude Code", systemImage: "magnifyingglass")
                }
                .controlSize(.small)
                .tint(.blue)
            }

            // Process path (when available)
            if !app.processPath.isEmpty {
                Divider()
                HStack(spacing: 4) {
                    Image(systemName: "terminal")
                        .foregroundStyle(.secondary)
                        .font(.caption2)
                    ClickablePath(path: app.processPath, font: .caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            // Approval / Quarantine (only for flagged items)
            if isFlagged(app) {
                Divider()
                let quarantined = isQuarantined(app)
                let approved = isApproved(app)
                HStack(spacing: 8) {
                    if quarantined {
                        Image(systemName: "exclamationmark.octagon.fill")
                            .foregroundStyle(.red)
                        Text("Quarantined — flagged as dangerous")
                            .font(.caption)
                            .foregroundStyle(.red)
                        Spacer()
                        Button("Remove Quarantine") {
                            ApprovalManager.unquarantine(.networkMonitor, id: approvalKey(for: app))
                            approvalVersion += 1
                        }
                        .controlSize(.small)
                    } else if approved {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.blue)
                        Text("Reviewed and approved")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Revoke") {
                            revokeAll(for: app)
                        }
                        .controlSize(.small)
                        .tint(.red)
                    } else {
                        Image(systemName: "shield.lefthalf.filled")
                            .foregroundStyle(.orange)
                        Text("Flagged — review recommended")
                            .font(.caption)
                            .foregroundStyle(.orange)
                        Spacer()
                        Button("Mark as Reviewed") {
                            ApprovalManager.approve(.networkMonitor, id: approvalKey(for: app))
                            approvalVersion += 1
                        }
                        .controlSize(.small)
                        .tint(.blue)
                        Button("Quarantine") {
                            appToQuarantine = app
                        }
                        .controlSize(.small)
                        .tint(.red)
                    }
                }
            }
        }
        .padding(14)
        .frame(width: 420)
    }

    private func copyTrace(app: AppSummary) {
        let signedStatus = app.isSigned ? "Yes (\(FormatUtils.cleanAuthority(app.signatureAuthority)))" : "No"
        var text = """
        Process: \(app.processName)
        Signed: \(signedStatus)
        Parent chain: \(app.parentChain.isEmpty ? "Unknown" : app.parentChain)
        Injection risk: \(app.injectionRisk.isEmpty ? "None" : app.injectionRisk)
        Network: \(app.timesSeen) connections, \(app.uniqueIPs) IPs, \(app.uniqueCountries) countries
        Data: \(FormatUtils.bytes(app.totalBytesIn)) received, \(FormatUtils.bytes(app.totalBytesOut)) sent
        """
        if !app.processTrace.isEmpty {
            text += "\n\n" + app.processTrace
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func investigateWithClaude(app: AppSummary) {
        let traceSection = app.processTrace.isEmpty ? "Not available" : app.processTrace
        let prompt = """
        Investigate this network-active process and assess its security risk.

        PROCESS DETAILS:
        - Name: \(app.processName)
        - Signature: \(app.signatureAuthority.isEmpty ? "NONE" : app.signatureAuthority)
        - Parent chain: \(app.parentChain.isEmpty ? "Unknown" : app.parentChain)
        - Injection risk: \(app.injectionRisk.isEmpty ? "None detected" : app.injectionRisk)
        - Network activity: \(app.timesSeen) connections, \(app.uniqueIPs) unique IPs, \(app.uniqueCountries) countries
        - Data transferred: \(FormatUtils.bytes(app.totalBytesIn)) received, \(FormatUtils.bytes(app.totalBytesOut)) sent

        FULL PROCESS TRACE:
        \(traceSection)

        INVESTIGATION STEPS:
        1. Identify what this process is and what app it belongs to
        2. Analyze the codesign details and parent chain
        3. Check the open connections and files for anything suspicious
        4. Check if the network activity volume/pattern is normal
        5. If injection risk detected, investigate the flagged dylibs
        6. Search the web for any known security issues with this process

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / INVESTIGATE FURTHER
        - WHAT IS IT: Brief explanation
        - PARENT CHAIN ANALYSIS: Is this chain expected?
        - NETWORK ASSESSMENT: Is the traffic volume/pattern normal?
        - OPEN FILES ASSESSMENT: Anything suspicious in the open files?
        - RECOMMENDED ACTION: Specific steps to take
        """
        UninstallHelper.launchClaude(with: prompt)
        selectedApp = nil
    }

    // MARK: - Approval & Quarantine Helpers

    /// Build an approval key using the full process path when available.
    /// Falls back to process name for legacy data without paths.
    private func approvalKey(for app: AppSummary) -> String {
        let identifier = app.processPath.isEmpty ? app.processName : app.processPath
        if app.injectionRisk.isEmpty {
            return identifier
        }
        return "\(identifier)|\(app.injectionRisk)"
    }

    /// Legacy key using only the process name (for backward compatibility).
    private func legacyKey(for app: AppSummary) -> String {
        if app.injectionRisk.isEmpty {
            return app.processName
        }
        return "\(app.processName)|\(app.injectionRisk)"
    }

    private func isApproved(_ app: AppSummary) -> Bool {
        let _ = approvalVersion
        let key = approvalKey(for: app)
        if ApprovalManager.isApproved(.networkMonitor, id: key) { return true }
        // Legacy fallback: check by name only
        let legacy = legacyKey(for: app)
        if legacy != key { return ApprovalManager.isApproved(.networkMonitor, id: legacy) }
        return false
    }

    private func isQuarantined(_ app: AppSummary) -> Bool {
        let _ = approvalVersion
        let key = approvalKey(for: app)
        if ApprovalManager.isQuarantined(.networkMonitor, id: key) { return true }
        let legacy = legacyKey(for: app)
        if legacy != key { return ApprovalManager.isQuarantined(.networkMonitor, id: legacy) }
        return false
    }

    private func isFlagged(_ app: AppSummary) -> Bool {
        !app.injectionRisk.isEmpty || (!app.isSigned && app.signatureAuthority.isEmpty && app.parentSignature.isEmpty)
    }

    /// Revoke both current and legacy keys for complete cleanup.
    private func revokeAll(for app: AppSummary) {
        ApprovalManager.revoke(.networkMonitor, id: approvalKey(for: app))
        let legacy = legacyKey(for: app)
        if legacy != approvalKey(for: app) {
            ApprovalManager.revoke(.networkMonitor, id: legacy)
        }
        approvalVersion += 1
    }

    // MARK: - Suspicious & Quarantine Banners

    private var unreviewedApps: [AppSummary] {
        let _ = approvalVersion
        return viewModel.topApps.filter { isFlagged($0) && !isApproved($0) && !isQuarantined($0) }
    }

    private var quarantinedApps: [AppSummary] {
        let _ = approvalVersion
        return viewModel.topApps.filter { isQuarantined($0) }
    }

    @ViewBuilder
    private var suspiciousBanner: some View {
        // Quarantine banner (red, separate, on top)
        let quarantined = quarantinedApps
        if !quarantined.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.octagon.fill")
                        .foregroundStyle(.red)
                    Text("\(quarantined.count) quarantined app\(quarantined.count == 1 ? "" : "s") active")
                        .font(.callout.bold())
                        .foregroundStyle(.primary)
                    Spacer()
                }

                ForEach(quarantined) { app in
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.octagon.fill")
                            .foregroundStyle(.red)
                            .font(.caption)

                        VStack(alignment: .leading, spacing: 1) {
                            Text(app.processName)
                                .font(.caption.bold())
                            Text("Quarantined — flagged as dangerous")
                                .font(.caption2)
                                .foregroundStyle(.red)
                        }

                        Spacer()

                        Text("\(app.timesSeen) conn, \(app.uniqueIPs) IPs")
                            .font(.caption2)
                            .foregroundStyle(.secondary)

                        Button("Ask Claude") {
                            investigateWithClaude(app: app)
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)

                        Button("Remove") {
                            ApprovalManager.unquarantine(.networkMonitor, id: approvalKey(for: app))
                            approvalVersion += 1
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                    .padding(.vertical, 2)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(.red.opacity(0.08))
                    .strokeBorder(.red.opacity(0.3), lineWidth: 1)
            )
            .padding(.horizontal)
            .padding(.vertical, 4)
        }

        // Suspicious banner (orange, existing pattern)
        let suspicious = unreviewedApps
        if !suspicious.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("\(suspicious.count) suspicious app\(suspicious.count == 1 ? "" : "s") need\(suspicious.count == 1 ? "s" : "") review")
                        .font(.callout.bold())
                        .foregroundStyle(.primary)
                    Spacer()
                    if selectedTab != 1 {
                        Button("Show in Apps tab") {
                            selectedTab = 1
                        }
                        .controlSize(.small)
                    }
                }

                ForEach(suspicious) { app in
                    HStack(spacing: 8) {
                        if !app.injectionRisk.isEmpty {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundStyle(.red)
                                .font(.caption)
                        } else {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                                .font(.caption)
                        }

                        VStack(alignment: .leading, spacing: 1) {
                            Text(app.processName)
                                .font(.caption.bold())
                            Text(!app.injectionRisk.isEmpty ? "Injection risk detected" : "Unsigned process")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Text("\(app.timesSeen) conn, \(app.uniqueIPs) IPs")
                            .font(.caption2)
                            .foregroundStyle(.secondary)

                        Button("Ask Claude") {
                            investigateWithClaude(app: app)
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)

                        Button("Mark Reviewed") {
                            ApprovalManager.approve(.networkMonitor, id: approvalKey(for: app))
                            approvalVersion += 1
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)
                        .tint(.blue)

                        Button("Quarantine") {
                            appToQuarantine = app
                        }
                        .controlSize(.mini)
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                    .padding(.vertical, 2)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(.orange.opacity(0.08))
                    .strokeBorder(.orange.opacity(0.3), lineWidth: 1)
            )
            .padding(.horizontal)
            .padding(.vertical, 4)
        }

        if !quarantined.isEmpty || !suspicious.isEmpty {
            Divider()
        }
    }

    // MARK: - Country Table

    private var countryTable: some View {
        Table(viewModel.topCountries) {
            TableColumn("Country") { c in
                HStack(spacing: 6) {
                    Text(FormatUtils.flag(for: c.countryCode))
                        .font(.title3)
                    Text(c.country)
                        .font(.callout)
                }
            }
            .width(min: 130)

            TableColumn("Connections") { c in
                Text("\(c.timesSeen)")
                    .font(.callout)
            }
            .width(80)

            TableColumn("Unique IPs") { c in
                Text("\(c.uniqueIPs)")
                    .font(.callout)
            }
            .width(70)

            TableColumn("Apps") { c in
                Text("\(c.appCount)")
                    .font(.callout)
            }
            .width(50)

            TableColumn("Received") { c in
                Text(FormatUtils.bytes(c.totalBytesIn))
                    .font(.callout)
                    .foregroundStyle(.green)
            }
            .width(80)

            TableColumn("Sent") { c in
                Text(FormatUtils.bytes(c.totalBytesOut))
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            .width(80)

            TableColumn("Total") { c in
                Text(FormatUtils.bytes(c.totalBytesIn + c.totalBytesOut))
                    .font(.callout.bold())
            }
            .width(80)
        }
    }
}
