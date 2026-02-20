import SwiftUI

struct NetworkMonitorView: View {
    @State private var viewModel = NetworkMonitorViewModel()
    @State private var showListening = false

    /// Connections sorted: unsigned first, then by app name, then by country.
    private var sorted: [NetworkConnection] {
        viewModel.connections
            .filter { showListening || $0.state != "LISTEN" }
            .sorted {
                // Unsigned processes bubble to the top
                if $0.isSigned != $1.isSigned { return !$0.isSigned }
                if $0.processName != $1.processName {
                    return $0.processName.lowercased() < $1.processName.lowercased()
                }
                if $0.country != $1.country {
                    return $0.country < $1.country
                }
                return $0.remoteAddress < $1.remoteAddress
            }
    }

    /// Summary stats
    private var uniqueApps: Int { Set(sorted.map(\.processName)).count }
    private var uniqueCountries: Int { Set(sorted.map(\.country)).count }
    private var unsignedCount: Int { Set(sorted.filter { !$0.isSigned && !$0.signatureAuthority.isEmpty }.map(\.pid)).count }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "network")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Network Monitor")
                    .font(.title.bold())
                ScanDateLabel(scanner: .networkMonitor)
                Spacer()
                if viewModel.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Toggle("Show Listening", isOn: $showListening)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .help("Show ports waiting for incoming connections (LISTEN)")
                Button(action: { Task { await viewModel.scan() } }) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            if viewModel.connections.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to see all active network connections with geo-location")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                // Summary bar
                HStack(spacing: 16) {
                    Label("\(uniqueApps) apps", systemImage: "app.connected.to.app.below.fill")
                    Label("\(sorted.count) connections", systemImage: "arrow.left.arrow.right")
                    Label("\(uniqueCountries) countries", systemImage: "globe")
                    if unsignedCount > 0 {
                        Label("\(unsignedCount) unsigned", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
                .padding(.vertical, 6)

                Divider()

                Table(sorted) {
                    TableColumn("App") { (conn: NetworkConnection) in
                        HStack(spacing: 6) {
                            // Signature status icon
                            if conn.signatureAuthority.isEmpty {
                                Image(systemName: "app.fill")
                                    .foregroundStyle(.secondary)
                                    .font(.caption)
                            } else if conn.isSigned {
                                Image(systemName: "checkmark.seal.fill")
                                    .foregroundStyle(.green)
                                    .font(.caption)
                                    .help("Signed: \(conn.signatureAuthority)")
                            } else {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.red)
                                    .font(.caption)
                                    .help("UNSIGNED: \(conn.signatureAuthority)")
                            }
                            VStack(alignment: .leading, spacing: 0) {
                                Text(conn.processName)
                                    .font(.callout)
                                    .foregroundColor(conn.isSigned || conn.signatureAuthority.isEmpty ? nil : .red)
                                Text("PID \(conn.pid)")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                    .width(min: 130)

                    TableColumn("Signature") { conn in
                        let cleanName = FormatUtils.cleanAuthority(conn.signatureAuthority)
                        if conn.signatureAuthority.isEmpty {
                            Text("...")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        } else if conn.isSigned {
                            Text(cleanName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .help(conn.signatureAuthority)
                        } else {
                            Text(cleanName.isEmpty ? "Unsigned" : cleanName)
                                .font(.caption.bold())
                                .foregroundStyle(.red)
                                .lineLimit(1)
                                .help(conn.signatureAuthority)
                        }
                    }
                    .width(min: 160)

                    TableColumn("Country") { conn in
                        HStack(spacing: 4) {
                            if conn.isLocal {
                                Image(systemName: "house.fill")
                                    .foregroundStyle(.blue)
                                    .font(.caption)
                                Text("Local")
                                    .font(.callout)
                            } else if !conn.countryCode.isEmpty && conn.countryCode != "?" {
                                Text(NetworkMonitorViewModel.flag(for: conn.countryCode))
                                Text(conn.country)
                                    .font(.callout)
                            } else {
                                Text(conn.country)
                                    .font(.callout)
                            }
                        }
                    }
                    .width(min: 100)

                    TableColumn("Organization") { conn in
                        Text(conn.organization)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 140)

                    TableColumn("Host") { conn in
                        let friendly = FormatUtils.friendlyHostname(conn.hostname)
                        Text(friendly.isEmpty ? "-" : friendly)
                            .font(.caption)
                            .foregroundStyle(friendly.isEmpty ? Color.secondary : Color.primary)
                            .lineLimit(1)
                            .help(conn.hostname.isEmpty ? conn.remoteAddress : conn.hostname)
                    }
                    .width(min: 140)

                    TableColumn("Remote IP") { conn in
                        Text(conn.remoteAddress)
                            .font(.system(.caption, design: .monospaced))
                    }
                    .width(min: 120)

                    TableColumn("Port") { conn in
                        Text(conn.remotePort)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.blue)
                    }
                    .width(45)

                    TableColumn("State") { conn in
                        Text(conn.state)
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(conn.state == "ESTABLISHED" ? Color.green.opacity(0.12) : Color.orange.opacity(0.12))
                            .clipShape(Capsule())
                    }
                    .width(85)
                }
            }
        }
    }
}
