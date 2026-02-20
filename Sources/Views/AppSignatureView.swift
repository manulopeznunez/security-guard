import SwiftUI

struct AppSignatureView: View {
    @State private var viewModel = AppSignatureViewModel()
    @State private var itemToQuarantine: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "signature")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("App Signatures")
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

            if viewModel.apps.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to verify all app signatures in /Applications/")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                Table(viewModel.apps) {
                    TableColumn("") { app in
                        Image(systemName: app.isValid ? "checkmark.seal.fill" : "xmark.seal.fill")
                            .foregroundStyle(app.risk.color)
                    }
                    .width(30)

                    TableColumn("App", value: \.appName)
                        .width(min: 140)

                    TableColumn("Authority") { app in
                        Text(FormatUtils.cleanAuthority(app.authority))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .help(app.authority)
                    }
                    .width(min: 200)

                    TableColumn("Details", value: \.details)
                        .width(min: 150)

                    TableColumn("Review") { app in
                        if !app.isValid {
                            HStack(spacing: 4) {
                                let approved = ApprovalManager.isApproved(.appSignature, id: app.appPath)
                                let quarantined = ApprovalManager.isQuarantined(.appSignature, id: app.appPath)
                                if quarantined {
                                    Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                        .font(.caption2)
                                        .foregroundStyle(.white)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.red)
                                        .clipShape(Capsule())
                                    Button {
                                        ApprovalManager.unquarantine(.appSignature, id: app.appPath)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Remove", systemImage: "arrow.uturn.backward")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                } else if approved {
                                    Button {
                                        ApprovalManager.revoke(.appSignature, id: app.appPath)
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
                                        ApprovalManager.approve(.appSignature, id: app.appPath)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Approve", systemImage: "checkmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                                    .tint(.green)
                                    Button {
                                        itemToQuarantine = app.appPath
                                    } label: {
                                        Label("Quarantine", systemImage: "exclamationmark.octagon")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                }

                                Button {
                                    UninstallHelper.investigateAppWithClaude(app: app)
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

                    TableColumn("") { app in
                        Button {
                            UninstallHelper.uninstallApp(name: app.appName, path: app.appPath)
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                        .help("Uninstall \(app.appName)")
                    }
                    .width(30)
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
                    ApprovalManager.quarantine(.appSignature, id: id)
                    Task { await viewModel.scan() }
                }
                itemToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }
}
