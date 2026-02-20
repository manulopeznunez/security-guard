import SwiftUI

struct ChromeExtensionView: View {
    @State private var viewModel = ChromeExtensionViewModel()
    @State private var itemToQuarantine: String?

    private var highRisk: Int { viewModel.extensions.filter { $0.risk == .high }.count }
    private var pendingReview: Int { viewModel.extensions.filter { $0.risk == .high && !$0.isApproved }.count }
    private var mediumRisk: Int { viewModel.extensions.filter { $0.risk == .medium }.count }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "puzzlepiece.extension")
                    .font(.title)
                    .foregroundStyle(.blue)
                Text("Chrome Extensions")
                    .font(.title.bold())
                ScanDateLabel(scanner: .chromeExtensions)
                Spacer()
                if viewModel.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button(action: {
                    _ = ShellExecutor.shell("open 'chrome://extensions'")
                }) {
                    Label("Open in Chrome", systemImage: "arrow.up.forward.app")
                }
                .controlSize(.small)
                Button(action: { Task { await viewModel.scan() } }) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            if viewModel.extensions.isEmpty && !viewModel.isScanning {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "puzzlepiece.extension")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("Press Scan to audit Chrome extensions")
                        .foregroundStyle(.secondary)
                    Text("Checks permissions of every installed extension across all Chrome profiles.\nFlags extensions that can access all your data, read passwords, or modify traffic.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 450)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                // Summary bar
                HStack(spacing: 16) {
                    Label("\(viewModel.extensions.count) extensions", systemImage: "puzzlepiece.extension")
                        .font(.caption)
                    if highRisk > 0 {
                        if pendingReview > 0 {
                            Label("\(pendingReview) pending review", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption.bold())
                                .foregroundStyle(.red)
                        }
                        let approved = highRisk - pendingReview
                        if approved > 0 {
                            Label("\(approved) approved", systemImage: "checkmark.shield.fill")
                                .font(.caption)
                                .foregroundStyle(.green)
                        }
                    }
                    if mediumRisk > 0 {
                        Label("\(mediumRisk) medium risk", systemImage: "exclamationmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if highRisk == 0 && mediumRisk == 0 {
                        Label("All low risk", systemImage: "checkmark.shield")
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

                List(viewModel.extensions) { ext in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            Image(systemName: "circle.fill")
                                .foregroundStyle(ext.effectiveColor)
                                .font(.caption2)

                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(ext.name)
                                        .font(.headline)
                                    Text("v\(ext.version)")
                                        .font(.caption)
                                        .foregroundStyle(.tertiary)

                                    // Web Store verification badge
                                    if ext.isFromWebStore {
                                        HStack(spacing: 2) {
                                            Image(systemName: "checkmark.seal.fill")
                                                .foregroundStyle(.blue)
                                            Text("Web Store")
                                                .foregroundStyle(.blue)
                                        }
                                        .font(.caption2)
                                    } else {
                                        HStack(spacing: 2) {
                                            Image(systemName: "exclamationmark.triangle.fill")
                                                .foregroundStyle(.orange)
                                            Text("Sideloaded")
                                                .foregroundStyle(.orange)
                                        }
                                        .font(.caption2)
                                    }
                                }

                                HStack(spacing: 8) {
                                    if !ext.author.isEmpty {
                                        Label(ext.author, systemImage: "person.fill")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    if !ext.description.isEmpty {
                                        Text(ext.description)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                            }

                            Spacer()

                            // Risk pill with verification context
                            Text(ext.effectiveLabel)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(ext.effectiveColor)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(ext.effectiveColor.opacity(0.12))
                                .clipShape(Capsule())

                            // Source pill
                            ClickablePath(path: ext.source, font: .caption2)
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.1))
                                .clipShape(Capsule())

                            Text(ext.profileDisplayName)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.1))
                                .clipShape(Capsule())
                                .help("Chrome profile: \(ext.profile)")

                            // Approve / Revoke / Quarantine button for high risk
                            if ext.risk == .high {
                                let quarantined = ApprovalManager.isQuarantined(.chromeExtension, id: ext.extensionId)
                                if quarantined {
                                    Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                        .font(.caption2)
                                        .foregroundStyle(.white)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.red)
                                        .clipShape(Capsule())
                                    Button {
                                        ApprovalManager.unquarantine(.chromeExtension, id: ext.extensionId)
                                        Task { await viewModel.scan() }
                                    } label: {
                                        Label("Remove", systemImage: "arrow.uturn.backward")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                } else if ext.isApproved {
                                    Button(action: {
                                        ApprovalManager.revoke(.chromeExtension, id: ext.extensionId)
                                        Task { await viewModel.scan() }
                                    }) {
                                        Label("Revoke", systemImage: "xmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                } else {
                                    Button(action: {
                                        ApprovalManager.approve(.chromeExtension, id: ext.extensionId)
                                        Task { await viewModel.scan() }
                                    }) {
                                        Label("Approve", systemImage: "checkmark.shield")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                                    .tint(.green)
                                    Button {
                                        itemToQuarantine = ext.extensionId
                                    } label: {
                                        Label("Quarantine", systemImage: "exclamationmark.octagon")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.mini)
                                    .tint(.red)
                                }

                                Button {
                                    UninstallHelper.investigateChromeExtensionWithClaude(ext: ext)
                                } label: {
                                    Image(systemName: "sparkle.magnifyingglass")
                                        .foregroundStyle(.purple)
                                }
                                .buttonStyle(.plain)
                                .help("Investigate with Claude Code")
                            }
                        }

                        // Risk reasons
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: ext.risk == .high ? "exclamationmark.triangle.fill" :
                                    (ext.risk == .medium ? "exclamationmark.circle.fill" : "checkmark.circle.fill"))
                                .foregroundStyle(ext.effectiveColor)
                                .font(.caption)

                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(ext.riskReasons, id: \.self) { reason in
                                    Text("• \(reason)")
                                        .font(.caption)
                                        .foregroundStyle(ext.risk == .low ? Color.secondary : ext.effectiveColor)
                                }
                            }
                        }
                        .padding(.leading, 18)

                        // Permissions detail + actions
                        HStack(alignment: .top) {
                            if !ext.permissions.isEmpty {
                                Text("Permissions: \(ext.permissions.joined(separator: ", "))")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(2)
                            }

                            Spacer()

                            // Homepage link
                            if !ext.homepageURL.isEmpty {
                                Button(action: {
                                    if let url = URL(string: ext.homepageURL) {
                                        NSWorkspace.shared.open(url)
                                    }
                                }) {
                                    Label("Homepage", systemImage: "globe")
                                        .font(.caption2)
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(.blue)
                            }

                            // Open in Chrome Web Store
                            if ext.isFromWebStore {
                                Button(action: {
                                    let url = URL(string: "https://chromewebstore.google.com/detail/\(ext.extensionId)")!
                                    NSWorkspace.shared.open(url)
                                }) {
                                    Label("Web Store", systemImage: "storefront")
                                        .font(.caption2)
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(.blue)
                            }

                            // Manage in Chrome — open the extension detail page in the correct profile
                            Button(action: {
                                let chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                                let process = Process()
                                process.executableURL = URL(fileURLWithPath: chromePath)
                                process.arguments = [
                                    "--profile-directory=\(ext.profile)",
                                    "chrome://extensions/?id=\(ext.extensionId)"
                                ]
                                try? process.run()
                            }) {
                                Label("Manage", systemImage: "gearshape")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                        }
                        .padding(.leading, 18)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .task {
            viewModel.loadCached()
            await viewModel.scan()
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
                    ApprovalManager.quarantine(.chromeExtension, id: id)
                    Task { await viewModel.scan() }
                }
                itemToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }
}
