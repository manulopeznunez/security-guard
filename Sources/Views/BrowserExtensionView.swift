import SwiftUI

struct BrowserExtensionView: View {
    @State private var viewModel = BrowserExtensionViewModel()
    @State private var itemToQuarantine: String?

    private var highRisk: Int { viewModel.filteredExtensions.filter { $0.risk == .high }.count }
    private var pendingReview: Int { viewModel.filteredExtensions.filter { $0.risk == .high && !$0.isApproved }.count }
    private var mediumRisk: Int { viewModel.filteredExtensions.filter { $0.risk == .medium }.count }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if viewModel.extensions.isEmpty && !viewModel.isScanning {
                emptyState
            } else {
                browserPicker
                Divider()
                summaryBar
                Divider()
                extensionList
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
                    ApprovalManager.quarantine(.browserExtension, id: id)
                    Task { await viewModel.scan() }
                }
                itemToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "puzzlepiece.extension")
                .font(.title)
                .foregroundStyle(.blue)
            Text("Browser Extensions")
                .font(.title.bold())
            ScanDateLabel(scanner: .browserExtensions)
            Spacer()
            if viewModel.isScanning {
                ProgressView().controlSize(.small)
                Text(viewModel.progress).font(.caption).foregroundStyle(.secondary)
            }
            Button(action: { Task { await viewModel.scan() } }) {
                Label("Scan", systemImage: "magnifyingglass")
            }
            .disabled(viewModel.isScanning)
        }
        .padding()
    }

    private var browserPicker: some View {
        HStack(spacing: 8) {
            Text("Browser:")
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker("", selection: $viewModel.selectedBrowser) {
                Text("All (\(viewModel.extensions.count))").tag(nil as BrowserType?)
                ForEach(viewModel.availableBrowsers) { browser in
                    HStack(spacing: 4) {
                        Image(systemName: browser.icon)
                        Text("\(browser.rawValue) (\(viewModel.extensions.filter { $0.browser == browser }.count))")
                    }
                    .tag(browser as BrowserType?)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 500)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var summaryBar: some View {
        HStack(spacing: 16) {
            Label("\(viewModel.filteredExtensions.count) extensions", systemImage: "puzzlepiece.extension")
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
                        .font(.caption).foregroundStyle(.green)
                }
            }
            if mediumRisk > 0 {
                Label("\(mediumRisk) medium risk", systemImage: "exclamationmark.circle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
            if highRisk == 0 && mediumRisk == 0 {
                Label("All low risk", systemImage: "checkmark.shield")
                    .font(.caption).foregroundStyle(.green)
            }
            Spacer()
            Text(viewModel.progress).font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "puzzlepiece.extension").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Press Scan to audit browser extensions").foregroundStyle(.secondary)
            Text("Checks permissions of extensions across Chrome, Safari, and Firefox.\nFlags extensions that can access all your data, read passwords, or modify traffic.")
                .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center).frame(maxWidth: 450)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var extensionList: some View {
        List(viewModel.filteredExtensions) { ext in
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Image(systemName: "circle.fill")
                        .foregroundStyle(ext.effectiveColor)
                        .font(.caption2)

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            // Browser badge
                            Image(systemName: ext.browser.icon)
                                .font(.caption)
                                .foregroundStyle(ext.browser.color)

                            Text(ext.name).font(.headline)
                            Text("v\(ext.version)").font(.caption).foregroundStyle(.tertiary)

                            if ext.isFromStore {
                                HStack(spacing: 2) {
                                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.blue)
                                    Text(ext.source).foregroundStyle(.blue)
                                }.font(.caption2)
                            } else {
                                HStack(spacing: 2) {
                                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                                    Text("Sideloaded").foregroundStyle(.orange)
                                }.font(.caption2)
                            }
                        }

                        HStack(spacing: 8) {
                            if !ext.author.isEmpty {
                                Label(ext.author, systemImage: "person.fill")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            if !ext.description.isEmpty {
                                Text(ext.description)
                                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                    }

                    Spacer()

                    // Risk pill
                    Text(ext.effectiveLabel)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(ext.effectiveColor)
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(ext.effectiveColor.opacity(0.12))
                        .clipShape(Capsule())

                    Text(ext.profileDisplayName)
                        .font(.caption2).foregroundStyle(.tertiary)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.1))
                        .clipShape(Capsule())

                    // Approve / Quarantine for high risk
                    if ext.risk == .high {
                        approvalButtons(for: ext)
                    }
                }

                // Risk reasons
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: ext.risk == .high ? "exclamationmark.triangle.fill" :
                            (ext.risk == .medium ? "exclamationmark.circle.fill" : "checkmark.circle.fill"))
                        .foregroundStyle(ext.effectiveColor).font(.caption)

                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(ext.riskReasons, id: \.self) { reason in
                            Text("• \(reason)")
                                .font(.caption)
                                .foregroundStyle(ext.risk == .low ? Color.secondary : ext.effectiveColor)
                        }
                    }
                }
                .padding(.leading, 18)

                // Permissions
                if !ext.permissions.isEmpty {
                    Text("Permissions: \(ext.permissions.joined(separator: ", "))")
                        .font(.caption2).foregroundStyle(.tertiary).lineLimit(2)
                        .padding(.leading, 18)
                }
            }
            .padding(.vertical, 4)
        }
    }

    @ViewBuilder
    private func approvalButtons(for ext: BrowserExtensionEntry) -> some View {
        let quarantined = ext.isQuarantined
        if quarantined {
            Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                .font(.caption2).foregroundStyle(.white)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Color.red).clipShape(Capsule())
            Button {
                ApprovalManager.unquarantine(.browserExtension, id: ext.approvalID)
                Task { await viewModel.scan() }
            } label: {
                Label("Remove", systemImage: "arrow.uturn.backward").font(.caption2)
            }
            .buttonStyle(.bordered).controlSize(.mini)
        } else if ext.isApproved {
            Button(action: {
                ApprovalManager.revoke(.browserExtension, id: ext.approvalID)
                Task { await viewModel.scan() }
            }) {
                Label("Revoke", systemImage: "xmark.shield").font(.caption2)
            }
            .buttonStyle(.bordered).controlSize(.mini).tint(.red)
        } else {
            Button(action: {
                ApprovalManager.approve(.browserExtension, id: ext.approvalID)
                Task { await viewModel.scan() }
            }) {
                Label("Approve", systemImage: "checkmark.shield").font(.caption2)
            }
            .buttonStyle(.borderedProminent).controlSize(.mini).tint(.green)
            Button {
                itemToQuarantine = ext.approvalID
            } label: {
                Label("Quarantine", systemImage: "exclamationmark.octagon").font(.caption2)
            }
            .buttonStyle(.bordered).controlSize(.mini).tint(.red)
        }
    }
}
