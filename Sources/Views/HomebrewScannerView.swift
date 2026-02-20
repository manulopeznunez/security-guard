import SwiftUI

struct HomebrewScannerView: View {
    @State private var viewModel = HomebrewScannerViewModel()
    @State private var selectedPackage: HomebrewPackage?
    @State private var detailDependents: [String] = []
    @State private var detailDependencies: [String] = []
    @State private var detailCVEs: [CVERecord] = []
    @State private var detailCVEsLoading = false
    @State private var detailLoading = false
    @State private var bulkAnalysis: HomebrewScannerViewModel.BulkAnalysisResult?
    @State private var showBulkAnalysis = false
    @State private var bulkAnalyzing = false
    @State private var itemToQuarantine: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "mug.fill")
                    .font(.title)
                    .foregroundStyle(.orange)
                Text("Homebrew Health")
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

            if !viewModel.brewInstalled && !viewModel.isScanning {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "mug")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("Homebrew Not Installed")
                        .font(.headline)
                    Text("This scanner checks Homebrew-installed packages for outdated versions.\nInstall Homebrew from https://brew.sh to use this feature.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else if viewModel.packages.isEmpty && !viewModel.isScanning {
                VStack {
                    Spacer()
                    Text("Press Scan to check your Homebrew packages for outdated versions")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                if !viewModel.packages.isEmpty {
                    summaryBar
                    Divider()
                }

                Table(viewModel.packages) {
                    TableColumn("") { pkg in
                        Image(systemName: "circle.fill")
                            .foregroundStyle(pkg.risk.color)
                            .font(.caption2)
                    }
                    .width(25)

                    TableColumn("Type") { pkg in
                        HStack(spacing: 3) {
                            Text(pkg.type == .formula ? "Formula" : "Cask")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if !pkg.isLeaf {
                                Image(systemName: "link")
                                    .font(.system(size: 8))
                                    .foregroundStyle(.tertiary)
                                    .help("Installed as a dependency of another package")
                            }
                        }
                    }
                    .width(80)

                    TableColumn("Package", value: \.name)
                        .width(min: 140)

                    TableColumn("Version") { pkg in
                        if pkg.isOutdated {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(pkg.installedVersion)
                                    .font(.caption)
                                    .strikethrough()
                                    .foregroundStyle(.secondary)
                                HStack(spacing: 2) {
                                    Image(systemName: "arrow.right")
                                        .font(.system(size: 8))
                                    Text(pkg.currentVersion ?? "")
                                        .font(.caption.bold())
                                }
                                .foregroundStyle(pkg.risk.color)
                            }
                        } else {
                            Text(pkg.installedVersion)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 120)

                    TableColumn("Status") { pkg in
                        HStack(spacing: 4) {
                            if pkg.pinned {
                                Image(systemName: "pin.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                                    .help("This package is pinned — version held intentionally")
                            }
                            Text(pkg.riskReason)
                                .font(.caption)
                                .foregroundStyle(pkg.risk == .safe ? .secondary : pkg.risk.color)
                                .lineLimit(2)
                        }
                    }
                    .width(min: 220)

                    TableColumn("Review") { pkg in
                        if pkg.needsReview {
                            let approved = ApprovalManager.isApproved(.homebrew, id: pkg.approvalID)
                            let quarantined = ApprovalManager.isQuarantined(.homebrew, id: pkg.approvalID)
                            if quarantined {
                                Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.red)
                                    .clipShape(Capsule())
                                Button {
                                    ApprovalManager.unquarantine(.homebrew, id: pkg.approvalID)
                                    Task { await viewModel.scan() }
                                } label: {
                                    Label("Remove", systemImage: "arrow.uturn.backward")
                                        .font(.caption2)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.mini)
                            } else if approved {
                                Button {
                                    ApprovalManager.revoke(.homebrew, id: pkg.approvalID)
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
                                    ApprovalManager.approve(.homebrew, id: pkg.approvalID)
                                    Task { await viewModel.scan() }
                                } label: {
                                    Label("Approve", systemImage: "checkmark.shield")
                                        .font(.caption2)
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.mini)
                                .tint(.green)
                                Button {
                                    itemToQuarantine = pkg.approvalID
                                } label: {
                                    Label("Quarantine", systemImage: "exclamationmark.octagon")
                                        .font(.caption2)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.mini)
                                .tint(.red)
                            }
                        }
                    }
                    .width(140)

                    TableColumn("") { pkg in
                        HStack(spacing: 6) {
                            Button {
                                Task { await showDetail(for: pkg) }
                            } label: {
                                Image(systemName: "info.circle")
                                    .foregroundStyle(.blue)
                            }
                            .buttonStyle(.plain)
                            .help("Show dependencies and usage")

                            if pkg.isOutdated {
                                Button {
                                    Task { await viewModel.updatePackageWithImpactCheck(pkg) }
                                } label: {
                                    Image(systemName: "arrow.triangle.2.circlepath")
                                        .foregroundStyle(.blue)
                                }
                                .buttonStyle(.plain)
                                .help("Update \(pkg.name)")
                            }

                            Button {
                                Task { await viewModel.uninstallPackage(pkg) }
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundStyle(.red)
                            }
                            .buttonStyle(.plain)
                            .help("Uninstall \(pkg.name)")

                            Button {
                                UninstallHelper.investigateHomebrewWithClaude(pkg: pkg)
                            } label: {
                                Image(systemName: "sparkle.magnifyingglass")
                                    .foregroundStyle(.purple)
                            }
                            .buttonStyle(.plain)
                            .help("Investigate with Claude Code")
                        }
                    }
                    .width(110)
                }
            }
        }
        .sheet(item: $selectedPackage) { pkg in
            packageDetailSheet(pkg)
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
                    ApprovalManager.quarantine(.homebrew, id: id)
                    Task { await viewModel.scan() }
                }
                itemToQuarantine = nil
            }
        } message: {
            Text("This will mark the item as dangerous. You will be alerted if it reappears.")
        }
    }

    // MARK: - Summary Bar

    private var summaryBar: some View {
        HStack(spacing: 16) {
            let outdatedCount = viewModel.packages.filter(\.isOutdated).count
            let suspiciousCount = viewModel.packages.filter { $0.risk == .suspicious }.count
            let warningCount = viewModel.packages.filter { $0.risk == .warning }.count
            let leafCount = viewModel.packages.filter(\.isLeaf).count

            Label("\(viewModel.packages.count) packages", systemImage: "shippingbox")
                .font(.caption)
                .foregroundStyle(.secondary)

            Label("\(leafCount) direct, \(viewModel.packages.count - leafCount) dependencies", systemImage: "link")
                .font(.caption)
                .foregroundStyle(.secondary)

            if suspiciousCount > 0 {
                Label("\(suspiciousCount) high risk", systemImage: "xmark.octagon")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if warningCount > 0 {
                Label("\(warningCount) outdated", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            if outdatedCount == 0 {
                Label("All up to date", systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.green)
            }

            Spacer()

            if outdatedCount > 0 {
                Button {
                    Task {
                        bulkAnalyzing = true
                        showBulkAnalysis = true
                        bulkAnalysis = await viewModel.analyzeBulkUpdate()
                        bulkAnalyzing = false
                    }
                } label: {
                    Label("Analyze All Updates", systemImage: "checklist")
                        .font(.caption)
                }
                .disabled(bulkAnalyzing || viewModel.isScanning)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
        .sheet(isPresented: $showBulkAnalysis) {
            bulkAnalysisSheet
        }
    }

    // MARK: - Detail Sheet

    private func showDetail(for pkg: HomebrewPackage) async {
        detailLoading = true
        detailDependents = []
        detailDependencies = []
        detailCVEs = []
        detailCVEsLoading = true
        selectedPackage = pkg

        async let deps = HomebrewScannerViewModel.checkDependencies(for: pkg.name)
        async let uses = HomebrewScannerViewModel.checkDependents(for: pkg.name)
        detailDependencies = await deps
        detailDependents = await uses
        detailLoading = false

        // CVE lookup on-demand (not during scan to save API calls)
        let cveResults = await CVEService.shared.lookup(
            packages: [(name: pkg.name, version: pkg.installedVersion)]
        )
        detailCVEs = cveResults[pkg.name] ?? []
        detailCVEsLoading = false
    }

    private func packageDetailSheet(_ pkg: HomebrewPackage) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                Image(systemName: "mug.fill")
                    .font(.title2)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(pkg.name)
                        .font(.title2.bold())
                    Text("\(pkg.installedVersion) \(pkg.type == .formula ? "Formula" : "Cask")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Close") { selectedPackage = nil }
                    .keyboardShortcut(.cancelAction)
            }

            Divider()

            if detailLoading {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Loading dependency info...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                // Dependencies (what this package needs)
                VStack(alignment: .leading, spacing: 6) {
                    Label("Dependencies (\(detailDependencies.count))", systemImage: "arrow.down.circle")
                        .font(.headline)

                    if detailDependencies.isEmpty {
                        Text("No dependencies")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(detailDependencies.joined(separator: ", "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Divider()

                // Dependents (what depends on this package)
                VStack(alignment: .leading, spacing: 6) {
                    Label("Used by (\(detailDependents.count))", systemImage: "arrow.up.circle")
                        .font(.headline)

                    if detailDependents.isEmpty {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            Text("Nothing depends on this package — safe to uninstall or update")
                                .font(.caption)
                        }
                    } else {
                        Text(detailDependents.joined(separator: ", "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Text("Removing or updating this package may affect \(detailDependents.count) package\(detailDependents.count == 1 ? "" : "s")")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                }

                Divider()

                // Install type
                HStack(spacing: 4) {
                    Image(systemName: pkg.isLeaf ? "person.fill" : "link")
                        .foregroundStyle(pkg.isLeaf ? .blue : .secondary)
                    Text(pkg.isLeaf ? "Directly installed by you" : "Installed as a dependency of another package")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Divider()

                // CVE Vulnerabilities (on-demand)
                VStack(alignment: .leading, spacing: 6) {
                    Label("Known Vulnerabilities", systemImage: "shield.exclamationmark")
                        .font(.headline)

                    if detailCVEsLoading {
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.mini)
                            Text("Checking OSV database...")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else if detailCVEs.isEmpty {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundStyle(.green)
                            Text("No known vulnerabilities for \(pkg.name) \(pkg.installedVersion)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(detailCVEs) { cve in
                                    HStack(spacing: 6) {
                                        Text(cve.severity.label)
                                            .font(.system(size: 9, weight: .bold))
                                            .padding(.horizontal, 4)
                                            .padding(.vertical, 1)
                                            .background(cveSeverityColor(cve.severity).opacity(0.2))
                                            .clipShape(RoundedRectangle(cornerRadius: 3))
                                            .foregroundStyle(cveSeverityColor(cve.severity))
                                        Text(cve.displayID)
                                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                                        Text(cve.summary)
                                            .font(.system(size: 10))
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                }

                                if let fixedIn = detailCVEs.compactMap(\.fixedVersion).first {
                                    Text("Fixed in: \(fixedIn)")
                                        .font(.system(size: 10, weight: .medium))
                                        .foregroundStyle(.green)
                                        .padding(.top, 2)
                                }
                            }
                        }
                        .frame(maxHeight: 120)
                    }
                }
            }

            Spacer()

            // Action buttons
            HStack {
                Button {
                    selectedPackage = nil
                    UninstallHelper.investigateHomebrewWithClaude(pkg: pkg)
                } label: {
                    Label("Investigate with Claude", systemImage: "sparkle.magnifyingglass")
                }
                .tint(.purple)

                Spacer()

                if pkg.isOutdated {
                    Button {
                        selectedPackage = nil
                        Task { await viewModel.updatePackageWithImpactCheck(pkg) }
                    } label: {
                        Label("Update", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .tint(.blue)
                }

                Button {
                    selectedPackage = nil
                    Task { await viewModel.uninstallPackage(pkg) }
                } label: {
                    Label("Uninstall", systemImage: "trash")
                }
                .tint(.red)
            }
        }
        .padding(20)
        .frame(width: 520, height: 500)
    }

    // MARK: - Bulk Analysis Sheet

    private var bulkAnalysisSheet: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "checklist")
                    .font(.title2)
                    .foregroundStyle(.orange)
                Text("Bulk Update Analysis")
                    .font(.title2.bold())
                Spacer()
                Button("Close") { showBulkAnalysis = false }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()

            Divider()

            if bulkAnalyzing {
                VStack(spacing: 12) {
                    Spacer()
                    ProgressView()
                    Text(viewModel.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Checking dependencies for each outdated package...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else if let analysis = bulkAnalysis {
                let totalCount = analysis.safeUpdates.count + analysis.cautionUpdates.count + analysis.securityCritical.count

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        // Summary
                        HStack(spacing: 20) {
                            summaryPill(
                                count: totalCount,
                                label: "total updates",
                                icon: "shippingbox",
                                color: .secondary
                            )
                            summaryPill(
                                count: analysis.securityCritical.count,
                                label: "security-critical",
                                icon: "exclamationmark.shield",
                                color: .red
                            )
                            summaryPill(
                                count: analysis.cautionUpdates.count,
                                label: "may affect others",
                                icon: "exclamationmark.triangle",
                                color: .orange
                            )
                            summaryPill(
                                count: analysis.safeUpdates.count,
                                label: "safe",
                                icon: "checkmark.circle",
                                color: .green
                            )

                            let totalCVEs = (analysis.securityCritical + analysis.cautionUpdates + analysis.safeUpdates)
                                .flatMap(\.vulnerabilities).count
                            if totalCVEs > 0 {
                                summaryPill(
                                    count: totalCVEs,
                                    label: "known CVEs",
                                    icon: "shield.exclamationmark",
                                    color: .red
                                )
                            }
                        }
                        .padding(.horizontal)

                        Divider()

                        // Security Critical
                        if !analysis.securityCritical.isEmpty {
                            bulkSection(
                                title: "Security-Critical — Update Immediately",
                                icon: "exclamationmark.shield.fill",
                                color: .red,
                                entries: analysis.securityCritical
                            )
                        }

                        // Caution
                        if !analysis.cautionUpdates.isEmpty {
                            bulkSection(
                                title: "Update with Caution — May Affect Other Packages",
                                icon: "exclamationmark.triangle.fill",
                                color: .orange,
                                entries: analysis.cautionUpdates
                            )
                        }

                        // Safe
                        if !analysis.safeUpdates.isEmpty {
                            bulkSection(
                                title: "Safe to Update — No Dependents at Risk",
                                icon: "checkmark.circle.fill",
                                color: .green,
                                entries: analysis.safeUpdates
                            )
                        }
                    }
                    .padding(.vertical)
                }

                Divider()

                // Action bar
                HStack {
                    if analysis.cautionUpdates.isEmpty {
                        Text("All updates are safe to apply.")
                            .font(.caption)
                            .foregroundStyle(.green)
                    } else {
                        Text("\(analysis.cautionUpdates.count) update\(analysis.cautionUpdates.count == 1 ? "" : "s") may affect other packages. Review before proceeding.")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }

                    Spacer()

                    Button {
                        showBulkAnalysis = false
                        Task { await viewModel.updateAll() }
                    } label: {
                        Label("Update All", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .tint(.blue)
                }
                .padding()
            }
        }
        .frame(width: 780, height: 660)
    }

    private func summaryPill(count: Int, label: String, icon: String, color: Color) -> some View {
        VStack(spacing: 4) {
            Label("\(count)", systemImage: icon)
                .font(.title3.bold())
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
    }

    private func bulkSection(
        title: String,
        icon: String,
        color: Color,
        entries: [HomebrewScannerViewModel.BulkAnalysisEntry]
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.headline)
                .foregroundStyle(color)
                .padding(.horizontal)

            ForEach(entries) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    // Header: name + version + badges
                    HStack(spacing: 4) {
                        Image(systemName: "circle.fill")
                            .font(.system(size: 6))
                            .foregroundStyle(color)
                        Text(entry.name).font(.caption.bold())
                        Text("\(entry.installedVersion) \u{2192} \(entry.latestVersion)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if entry.isMajorVersionBump {
                            Text("MAJOR")
                                .font(.system(size: 9, weight: .bold))
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.orange.opacity(0.2))
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                                .foregroundStyle(.orange)
                        }
                        if !entry.isLeaf {
                            Text("dependency")
                                .font(.system(size: 9))
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.15))
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                                .foregroundStyle(.secondary)
                        }
                        if !entry.vulnerabilities.isEmpty {
                            let maxSev = entry.vulnerabilities.map(\.severity).max() ?? .unknown
                            HStack(spacing: 2) {
                                Image(systemName: "shield.exclamationmark")
                                    .font(.system(size: 8))
                                Text("\(entry.vulnerabilities.count) CVE\(entry.vulnerabilities.count == 1 ? "" : "s")")
                            }
                            .font(.system(size: 9, weight: .bold))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(cveSeverityColor(maxSev).opacity(0.2))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                            .foregroundStyle(cveSeverityColor(maxSev))
                        }
                    }

                    // Recommendation
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.right.circle.fill")
                            .font(.system(size: 10))
                        Text(entry.recommendation)
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(color)
                    .padding(.leading, 14)

                    if !entry.dependentsAtRisk.isEmpty {
                        Text("May affect: \(entry.dependentsAtRisk.joined(separator: ", "))")
                            .font(.system(size: 11))
                            .foregroundStyle(.orange)
                            .padding(.leading, 14)
                    }

                    if !entry.dependentsAlsoUpdating.isEmpty {
                        Text("Also updating: \(entry.dependentsAlsoUpdating.joined(separator: ", "))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .padding(.leading, 14)
                    }

                    // Expandable consequences
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 8) {
                            // CVE list
                            if !entry.vulnerabilities.isEmpty {
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(
                                        "Known Vulnerabilities (\(entry.vulnerabilities.count))",
                                        systemImage: "shield.exclamationmark.fill"
                                    )
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(.red)

                                    ForEach(entry.vulnerabilities) { cve in
                                        HStack(spacing: 6) {
                                            Text(cve.severity.label)
                                                .font(.system(size: 9, weight: .bold))
                                                .padding(.horizontal, 4)
                                                .padding(.vertical, 1)
                                                .background(cveSeverityColor(cve.severity).opacity(0.2))
                                                .clipShape(RoundedRectangle(cornerRadius: 3))
                                                .foregroundStyle(cveSeverityColor(cve.severity))
                                            Text(cve.displayID)
                                                .font(.system(size: 10, weight: .medium, design: .monospaced))
                                            Text(cve.summary)
                                                .font(.system(size: 10))
                                                .foregroundStyle(.secondary)
                                                .lineLimit(1)
                                        }
                                    }

                                    if let fixedIn = entry.vulnerabilities.compactMap(\.fixedVersion).first {
                                        Text("Fixed in: \(fixedIn)")
                                            .font(.system(size: 10, weight: .medium))
                                            .foregroundStyle(.green)
                                    }
                                }
                                Divider()
                            }

                            // Project dependency warning
                            if let warning = entry.projectWarning {
                                VStack(alignment: .leading, spacing: 2) {
                                    Label("Project Dependency Warning", systemImage: "folder.badge.gearshape")
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundStyle(.purple)
                                    Text(warning)
                                        .font(.system(size: 11))
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                Divider()
                            }

                            consequenceRow(icon: "arrow.triangle.2.circlepath", label: "If you update", text: entry.ifUpdate, color: .blue)
                            consequenceRow(icon: "hand.raised", label: "If you don't update", text: entry.ifIgnore, color: .orange)
                            consequenceRow(icon: "checkmark.shield", label: "If you approve (accept risk)", text: entry.ifApprove, color: .green)
                            consequenceRow(icon: "exclamationmark.octagon", label: "If you quarantine", text: entry.ifQuarantine, color: .red)
                            consequenceRow(icon: "trash", label: "If you delete", text: entry.ifDelete, color: entry.dependents.isEmpty ? .blue : .red)
                        }
                        .padding(.top, 4)
                    } label: {
                        Text("What happens if...")
                            .font(.system(size: 11))
                            .foregroundStyle(.blue)
                    }
                    .padding(.leading, 14)
                    .font(.caption)
                }
                .padding(.horizontal)
                .padding(.vertical, 4)
            }
        }
    }

    private func consequenceRow(icon: String, label: String, text: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(label, systemImage: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
            Text(text)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func cveSeverityColor(_ severity: CVESeverity) -> Color {
        switch severity {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .secondary
        case .unknown: .secondary
        }
    }
}
