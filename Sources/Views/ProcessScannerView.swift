import SwiftUI

struct ProcessScannerView: View {
    @State private var viewModel = ProcessScannerViewModel()
    @State private var itemToQuarantine: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "cpu")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Process Scanner")
                    .font(.title.bold())
                Spacer()
                if viewModel.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Button(action: { Task { await viewModel.scan() } }) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            if viewModel.processes.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to analyze running processes")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                // Summary bar
                HStack(spacing: 16) {
                    let total = viewModel.processes.count
                    let unsigned = viewModel.processes.filter { $0.signatureValid == false }
                    let pending = unsigned.filter { !ApprovalManager.isApproved(.process, id: $0.path) }.count
                    let approved = unsigned.count - pending
                    let warnings = viewModel.processes.filter { $0.risk == .warning }.count

                    Label("\(total) processes", systemImage: "cpu")
                        .font(.caption)
                    if pending > 0 {
                        Label("\(pending) unsigned pending review", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption.bold())
                            .foregroundStyle(.red)
                    }
                    if approved > 0 {
                        Label("\(approved) unsigned approved", systemImage: "checkmark.shield.fill")
                            .font(.caption)
                            .foregroundStyle(.green)
                    }
                    if warnings > 0 {
                        Label("\(warnings) warnings", systemImage: "exclamationmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if pending == 0 && warnings == 0 && unsigned.isEmpty {
                        Label("All OK", systemImage: "checkmark.shield")
                            .font(.caption)
                            .foregroundStyle(.green)
                    }
                    Spacer()
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal)
                .padding(.vertical, 6)

                Divider()

                Table(viewModel.processes) {
                    TableColumn("") { process in
                        Image(systemName: "circle.fill")
                            .foregroundStyle(process.risk.color)
                            .font(.caption2)
                    }
                    .width(20)

                    TableColumn("Name") { p in
                        Text(p.name)
                            .font(.callout)
                            .help(p.path)
                    }
                    .width(min: 120)

                    TableColumn("App") { p in
                        if let appName = p.parentAppName {
                            Text(appName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .help(p.parentAppPath ?? "")
                        } else {
                            Text("—")
                                .font(.caption)
                                .foregroundStyle(.quaternary)
                        }
                    }
                    .width(min: 100)

                    TableColumn("PID") { p in
                        Text("\(p.pid)")
                            .font(.system(.caption, design: .monospaced))
                    }
                    .width(50)

                    TableColumn("CPU %") { p in
                        Text(String(format: "%.1f", p.cpuPercent))
                            .font(.callout)
                            .foregroundStyle(p.cpuPercent > 80 ? Color.orange : Color.primary)
                    }
                    .width(55)

                    TableColumn("RAM (MB)") { p in
                        Text(String(format: "%.0f", p.memoryMB))
                            .font(.callout)
                            .foregroundStyle(p.memoryMB > 500 ? Color.orange : Color.primary)
                    }
                    .width(70)

                    TableColumn("Signed") { p in
                        if let valid = p.signatureValid {
                            Image(systemName: valid ? "checkmark.seal.fill" : "xmark.seal.fill")
                                .foregroundStyle(valid ? .green : .red)
                        } else {
                            ProgressView()
                                .controlSize(.mini)
                        }
                    }
                    .width(50)

                    TableColumn("Path") { p in
                        Text(p.path)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .help(p.path)
                    }
                    .width(min: 150)

                    TableColumn("Details") { p in
                        Text(p.details)
                            .font(.caption)
                            .foregroundStyle(p.risk == .suspicious ? Color.red : (p.risk == .warning ? Color.orange : Color.secondary))
                    }
                    .width(min: 150)

                    TableColumn("Actions") { p in
                        HStack(spacing: 4) {
                            if p.signatureValid == false {
                                let approved = ApprovalManager.isApproved(.process, id: p.path)
                                let quarantined = ApprovalManager.isQuarantined(.process, id: p.path)
                                if quarantined {
                                    Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                        .font(.caption2)
                                        .foregroundStyle(.white)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.red)
                                        .clipShape(Capsule())
                                    Button {
                                        ApprovalManager.unquarantine(.process, id: p.path)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Remove", systemImage: "arrow.uturn.backward")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                } else if approved {
                                    Button {
                                        ApprovalManager.revoke(.process, id: p.path)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Revoke", systemImage: "xmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                } else {
                                    Button {
                                        ApprovalManager.approve(.process, id: p.path)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Approve", systemImage: "checkmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                                    .tint(.green)
                                    Button {
                                        itemToQuarantine = p.path
                                    } label: {
                                        Label("Quarantine", systemImage: "exclamationmark.octagon")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                }
                            }

                            if p.signatureValid == false {
                                Button {
                                    UninstallHelper.investigateProcessWithClaude(process: p)
                                } label: {
                                    Image(systemName: "sparkle.magnifyingglass")
                                        .foregroundStyle(.purple)
                                }
                                .buttonStyle(.plain)
                                .help("Investigate with Claude Code")
                            }

                            if let appPath = p.parentAppPath, let appName = p.parentAppName {
                                Button {
                                    UninstallHelper.uninstallApp(name: appName, path: appPath)
                                } label: {
                                    Image(systemName: "trash")
                                        .foregroundStyle(.red)
                                }
                                .buttonStyle(.plain)
                                .help("Uninstall \(appName)")
                            }
                        }
                    }
                    .width(min: 100)
                }
            }
        }
        .alert("Quarantine this item?",
               isPresented: Binding(
                   get: { itemToQuarantine != nil },
                   set: { if !$0 { itemToQuarantine = nil } }
               )
        ) {
            Button("Cancel", role: .cancel) { itemToQuarantine = nil }
            Button("Quarantine", role: .destructive) {
                if let id = itemToQuarantine {
                    ApprovalManager.quarantine(.process, id: id)
                    Task { await viewModel.scan() }
                }
                itemToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }
}
