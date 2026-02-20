import SwiftUI

struct PersistenceScannerView: View {
    @State private var viewModel = PersistenceScannerViewModel()
    @State private var itemToQuarantine: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "clock.arrow.circlepath")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Persistence Scanner")
                    .font(.title.bold())
                Spacer()
                if viewModel.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button(action: { Task { await viewModel.scan() } }) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            if viewModel.items.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to check LaunchAgents, LaunchDaemons, Login Items and Cron Jobs")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                Table(viewModel.items) {
                    TableColumn("") { item in
                        Image(systemName: "circle.fill")
                            .foregroundStyle(item.risk.color)
                            .font(.caption2)
                    }
                    .width(25)

                    TableColumn("Source", value: \.source)
                        .width(min: 120)

                    TableColumn("App") { item in
                        if let appName = item.parentAppName {
                            Text(appName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .help(item.parentAppPath ?? "")
                        } else {
                            Text("—")
                                .font(.caption)
                                .foregroundStyle(.quaternary)
                        }
                    }
                    .width(min: 100)

                    TableColumn("Label", value: \.label)
                        .width(min: 180)

                    TableColumn("Executable", value: \.executablePath)
                        .width(min: 200)

                    TableColumn("Signed") { item in
                        let cleanName = FormatUtils.cleanAuthority(item.signatureAuthority)
                        switch item.signatureStatus {
                        case .apple:
                            HStack(spacing: 4) {
                                Image(systemName: "apple.logo")
                                    .foregroundStyle(.secondary)
                                Text("Apple")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        case .valid:
                            HStack(spacing: 4) {
                                Image(systemName: "checkmark.seal.fill")
                                    .foregroundStyle(.green)
                                Text(cleanName.isEmpty ? "Valid" : cleanName)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .help(item.signatureAuthority)
                            }
                        case .homebrew:
                            HStack(spacing: 4) {
                                Image(systemName: "mug.fill")
                                    .foregroundStyle(.orange)
                                Text("Homebrew")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        case .permissionDenied:
                            HStack(spacing: 4) {
                                Image(systemName: "lock.fill")
                                    .foregroundStyle(.gray)
                                Text("Needs sudo")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        case .invalid:
                            HStack(spacing: 4) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(item.risk.color)
                                Text(cleanName.isEmpty ? "Unsigned" : cleanName)
                                    .font(.caption)
                                    .foregroundStyle(.red)
                                    .lineLimit(1)
                                    .help(item.signatureAuthority)
                            }
                        case .notFound:
                            HStack(spacing: 4) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.yellow)
                                Text("Orphaned plist")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                            .help("Binary not found — this plist should be removed")
                        case .unchecked:
                            Text("--")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 160)

                    TableColumn("Review") { item in
                        if item.needsReview {
                            HStack(spacing: 4) {
                                let approved = ApprovalManager.isApproved(.persistence, id: item.executablePath)
                                let quarantined = ApprovalManager.isQuarantined(.persistence, id: item.executablePath)
                                if quarantined {
                                    Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                        .font(.caption2)
                                        .foregroundStyle(.white)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.red)
                                        .clipShape(Capsule())
                                    Button {
                                        ApprovalManager.unquarantine(.persistence, id: item.executablePath)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Remove", systemImage: "arrow.uturn.backward")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                } else if approved {
                                    Button {
                                        ApprovalManager.revoke(.persistence, id: item.executablePath)
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
                                        ApprovalManager.approve(.persistence, id: item.executablePath)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Approve", systemImage: "checkmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                                    .tint(.green)
                                    Button {
                                        itemToQuarantine = item.executablePath
                                    } label: {
                                        Label("Quarantine", systemImage: "exclamationmark.octagon")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                }

                                Button {
                                    UninstallHelper.investigateWithClaude(item: item)
                                } label: {
                                    Image(systemName: "sparkle.magnifyingglass")
                                        .foregroundStyle(.purple)
                                }
                                .buttonStyle(.plain)
                                .help("Investigate with Claude Code")
                            }
                        }
                    }
                    .width(130)

                    TableColumn("") { item in
                        HStack(spacing: 6) {
                            Button {
                                UninstallHelper.revealInFinder(source: item.source)
                            } label: {
                                Image(systemName: "folder")
                                    .foregroundStyle(.blue)
                            }
                            .buttonStyle(.plain)
                            .help("Open \(item.source) in Finder")

                            if let appPath = item.parentAppPath, let appName = item.parentAppName {
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
                    .width(60)
                }
            }
        }
        .alert("Quarantine this item?", isPresented: Binding<Bool>(
            get: { itemToQuarantine != nil },
            set: { if !$0 { itemToQuarantine = nil } }
        )) {
            Button("Quarantine", role: .destructive) {
                if let id = itemToQuarantine {
                    ApprovalManager.quarantine(.persistence, id: id)
                    itemToQuarantine = nil
                    Task { await viewModel.scan() }
                }
            }
            Button("Cancel", role: .cancel) {
                itemToQuarantine = nil
            }
        } message: {
            Text("This will flag the item as quarantined. You can undo this later.")
        }
    }
}
