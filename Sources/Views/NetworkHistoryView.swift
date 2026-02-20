import SwiftUI

struct NetworkHistoryView: View {
    @State private var viewModel = NetworkHistoryViewModel()
    @State private var monitor = BackgroundMonitor.shared
    @State private var selectedTab = 0

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
                    if app.signatureAuthority.isEmpty {
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
                if app.signatureAuthority.isEmpty {
                    Text("...")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else if app.isSigned {
                    Text(cleanName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(app.signatureAuthority)
                } else {
                    Text(cleanName.isEmpty ? "Unsigned" : cleanName)
                        .font(.caption.bold())
                        .foregroundStyle(.red)
                        .lineLimit(1)
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

            TableColumn("Total") { app in
                Text(FormatUtils.bytes(app.totalBytesIn + app.totalBytesOut))
                    .font(.callout.bold())
            }
            .width(80)
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
