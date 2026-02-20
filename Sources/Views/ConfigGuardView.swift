import SwiftUI

struct ConfigGuardView: View {
    @State private var viewModel = ConfigGuardViewModel()
    @State private var approvalVersion = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.title)
                    .foregroundStyle(.purple)
                Text("Config Guard")
                    .font(.title.bold())
                ScanDateLabel(scanner: .configGuard)
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

                Button(action: { Task { await viewModel.setBaseline() } }) {
                    Label("Set Baseline", systemImage: "arrow.counterclockwise")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.purple)
                .disabled(viewModel.isScanning)
            }
            .padding()

            Divider()

            if !viewModel.hasBaseline && !viewModel.isScanning {
                noBaselineView
            } else if viewModel.entries.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to check your configuration files.")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                if !viewModel.entries.isEmpty {
                    summaryBar
                    Divider()
                }
                configTable
            }
        }
        .task {
            viewModel.loadCached()
            await viewModel.scan()
        }
    }

    // MARK: - No Baseline State

    private var noBaselineView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 48))
                .foregroundStyle(.purple)
            Text("No Baseline Established")
                .font(.headline)
            Text(
                "Click 'Set Baseline' to take SHA-256 snapshots of your dotfiles.\nFuture scans will alert you to any changes made by AI agents or other tools."
            )
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)
            .frame(maxWidth: 450)

            Button("Set Baseline") {
                Task { await viewModel.setBaseline() }
            }
            .buttonStyle(.borderedProminent)
            .tint(.purple)

            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Summary Bar

    private var summaryBar: some View {
        HStack(spacing: 20) {
            let total = viewModel.entries.count
            let existing = viewModel.entries.filter(\.exists).count
            let changed = viewModel.entries.filter { $0.changeType == .modified }.count
            let deleted = viewModel.entries.filter { $0.changeType == .deleted }.count
            let newFiles = viewModel.entries.filter { $0.changeType == .newFile }.count

            summaryPill("Monitored: \(total)", color: .secondary)
            summaryPill("Exists: \(existing)", color: .blue)
            if changed > 0 { summaryPill("Modified: \(changed)", color: .red) }
            if deleted > 0 { summaryPill("Deleted: \(deleted)", color: .red) }
            if newFiles > 0 { summaryPill("New: \(newFiles)", color: .orange) }
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    // MARK: - Table

    private var configTable: some View {
        Table(viewModel.entries) {
            TableColumn("") { entry in
                Image(systemName: "circle.fill")
                    .foregroundStyle(entry.risk.color)
                    .font(.caption2)
            }
            .width(25)

            TableColumn("File") { entry in
                ClickablePath(path: entry.filePath, font: .system(.body, design: .monospaced))
            }
            .width(min: 180, ideal: 250)

            TableColumn("Status") { entry in
                Text(entry.changeType.rawValue)
                    .font(.caption.bold())
                    .foregroundStyle(entry.changeType.color)
            }
            .width(100)

            TableColumn("Permissions") { entry in
                if entry.exists {
                    Text(entry.permissions)
                        .font(.system(.caption, design: .monospaced))
                }
            }
            .width(80)

            TableColumn("Hash") { entry in
                if let hash = entry.currentHash {
                    Text(String(hash.prefix(16)) + "...")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            .width(min: 120, ideal: 160)

            TableColumn("Details") { entry in
                Text(entry.riskReason)
                    .font(.caption)
                    .foregroundStyle(entry.risk.color)
            }
            .width(min: 200, ideal: 300)

            TableColumn("") { entry in
                let _ = approvalVersion
                if entry.needsReview {
                    let approved = ApprovalManager.isApproved(.configGuard, id: entry.approvalID)
                    HStack(spacing: 4) {
                        if approved {
                            Button("Revoke") {
                                ApprovalManager.revoke(.configGuard, id: entry.approvalID)
                                approvalVersion += 1
                            }
                            .font(.caption)
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .tint(.red)
                        } else if entry.changeType == .modified || entry.changeType == .newFile {
                            Button("Approve") {
                                viewModel.approveChange(for: entry)
                                approvalVersion += 1
                            }
                            .font(.caption)
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .tint(.green)
                        }

                        Button("Ask Claude") {
                            investigateConfig(entry)
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

    // MARK: - Ask Claude

    private func investigateConfig(_ entry: ConfigGuardEntry) {
        let hashInfo: String
        if let current = entry.currentHash, let baseline = entry.baselineHash {
            hashInfo = "Baseline hash: \(baseline)\nCurrent hash: \(current)"
        } else if let current = entry.currentHash {
            hashInfo = "Current hash: \(current) (no baseline)"
        } else {
            hashInfo = "File does not exist"
        }

        let prompt = """
        Investigate this configuration file change on my Mac and assess whether it's suspicious.

        FILE DETAILS:
        - Path: \(entry.filePath)
        - Change type: \(entry.changeType.rawValue)
        - Permissions: \(entry.permissions.isEmpty ? "N/A" : entry.permissions)
        - \(hashInfo)

        CONTEXT:
        I'm using AI coding agents (like Claude Code) that may modify dotfiles.
        This file was flagged because: \(entry.riskReason)

        INVESTIGATION STEPS:
        1. What is this file used for?
        2. Read the current file contents at \(entry.absolutePath) and show me what changed
        3. Is this a normal change from a coding agent or package manager?
        4. Could this change introduce a security risk (PATH injection, credential theft, etc.)?
        5. Check file permissions — are they appropriate?

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / INVESTIGATE FURTHER
        - WHAT CHANGED: Summary of likely changes
        - RISK ASSESSMENT: Could this be malicious?
        - RECOMMENDED ACTION: Should I approve this change or revert it?
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
