import SwiftUI
import UniformTypeIdentifiers

struct KnockKnockView: View {
    @State private var viewModel = KnockKnockViewModel()
    @State private var selectedCategory: String? = nil
    @State private var showFileImporter = false
    @State private var itemToQuarantine: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if let result = viewModel.result, result.error == nil {
                summaryBar(result)
                Divider()

                HSplitView {
                    categorySidebar(result)
                        .frame(minWidth: 180, maxWidth: 220)
                    itemTable(result)
                }
            } else if let result = viewModel.result, let error = result.error {
                errorState(error, fdaAvailable: result.fdaAvailable)
            } else {
                emptyState
            }
        }
        .task { viewModel.loadCached() }
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [UTType.json],
            allowsMultipleSelection: false
        ) { fileResult in
            if case .success(let urls) = fileResult, let url = urls.first {
                _ = url.startAccessingSecurityScopedResource()
                defer { url.stopAccessingSecurityScopedResource() }
                if let parsed = KnockKnockViewModel.parseJSONFile(at: url) {
                    viewModel.result = parsed
                    let flagged = parsed.flaggedItems.map(\.path)
                    ApprovalManager.saveFlagged(.knockknock, ids: flagged)
                }
            }
        }
        .alert("Quarantine this item?", isPresented: Binding<Bool>(
            get: { itemToQuarantine != nil },
            set: { if !$0 { itemToQuarantine = nil } }
        )) {
            Button("Quarantine", role: .destructive) {
                if let id = itemToQuarantine {
                    ApprovalManager.quarantine(.knockknock, id: id)
                    itemToQuarantine = nil
                    viewModel.loadCached()
                }
            }
            Button("Cancel", role: .cancel) {
                itemToQuarantine = nil
            }
        } message: {
            Text("This will flag the item as quarantined. You can undo this later.")
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            Image(systemName: "door.left.hand.open")
                .font(.title)
                .foregroundStyle(.purple)
            Text("KnockKnock Scanner")
                .font(.title.bold())
            Spacer()
            if viewModel.isScanning {
                ProgressView()
                    .controlSize(.small)
                Text(viewModel.progress)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button(action: { showFileImporter = true }) {
                Label("Load JSON", systemImage: "doc.badge.arrow.up")
            }
            Button(action: { Task { await viewModel.scan() } }) {
                Label("Scan", systemImage: "magnifyingglass")
            }
            .disabled(viewModel.isScanning)
        }
        .padding()
    }

    // MARK: - Summary Bar

    private func summaryBar(_ result: KnockKnockResult) -> some View {
        HStack(spacing: 16) {
            pill("\(result.totalItems) total", .secondary)
            pill("\(result.appleSignedCount) Apple", .green)
            pill("\(result.devIDSignedCount) Dev ID", .blue)
            pill("\(result.unsignedCount) unsigned", result.unsignedCount > 0 ? .orange : .green)
            pill("\(result.vtFlaggedCount) VT flagged", result.vtFlaggedCount > 0 ? .red : .green)
            Spacer()
            Text("Scanned: \(formatDate(result.scanDate))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private func pill(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    // MARK: - Category Sidebar

    private func categorySidebar(_ result: KnockKnockResult) -> some View {
        List(selection: $selectedCategory) {
            Button(action: { selectedCategory = nil }) {
                HStack {
                    Text("All Categories")
                        .font(.system(size: 11, weight: selectedCategory == nil ? .semibold : .regular))
                    Spacer()
                    Text("\(result.totalItems)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            ForEach(result.categories.keys.sorted(), id: \.self) { category in
                Button(action: { selectedCategory = category }) {
                    HStack {
                        Text(category)
                            .font(.system(size: 11, weight: selectedCategory == category ? .semibold : .regular))
                            .lineLimit(1)
                        Spacer()
                        Text("\(result.categories[category]?.count ?? 0)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: - Item Table

    private func itemTable(_ result: KnockKnockResult) -> some View {
        let items: [KnockKnockItem] = {
            let raw: [KnockKnockItem]
            if let cat = selectedCategory {
                raw = result.categories[cat] ?? []
            } else {
                raw = result.categories.values.flatMap { $0 }
            }
            // Sort: flagged items needing review first, then by name
            return raw.sorted { a, b in
                let aNeeds = isFlagged(a) && !ApprovalManager.isApproved(.knockknock, id: a.path)
                let bNeeds = isFlagged(b) && !ApprovalManager.isApproved(.knockknock, id: b.path)
                if aNeeds != bNeeds { return aNeeds }
                return a.name.localizedCompare(b.name) == .orderedAscending
            }
        }()

        return Table(items) {
            TableColumn("") { item in
                Image(systemName: "circle.fill")
                    .foregroundStyle(itemColor(item))
                    .font(.caption2)
            }
            .width(25)

            TableColumn("Name", value: \.name)
                .width(min: 140)

            TableColumn("Category", value: \.category)
                .width(min: 120)

            TableColumn("Path") { item in
                Text(item.path)
                    .font(.caption)
                    .lineLimit(1)
                    .help(item.path)
            }
            .width(min: 200)

            TableColumn("Signature") { item in
                signatureView(item)
            }
            .width(min: 160)

            TableColumn("VT") { item in
                if item.vtDetection.isEmpty {
                    Text("—")
                        .font(.caption)
                        .foregroundStyle(.quaternary)
                } else {
                    Text(item.vtDetection)
                        .font(.caption)
                        .foregroundStyle(isVTFlagged(item) ? .red : .secondary)
                }
            }
            .width(60)

            TableColumn("Review") { item in
                if isFlagged(item) {
                    HStack(spacing: 4) {
                        let approved = ApprovalManager.isApproved(.knockknock, id: item.path)
                        let quarantined = ApprovalManager.isQuarantined(.knockknock, id: item.path)
                        if quarantined {
                            Label("Quarantined", systemImage: "exclamationmark.octagon.fill")
                                .font(.caption2)
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.red)
                                .clipShape(Capsule())
                            Button {
                                ApprovalManager.unquarantine(.knockknock, id: item.path)
                                viewModel.loadCached()
                            } label: {
                                Label("Remove", systemImage: "arrow.uturn.backward")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                        } else if approved {
                            Button {
                                ApprovalManager.revoke(.knockknock, id: item.path)
                                viewModel.loadCached()
                            } label: {
                                Label("Revoke", systemImage: "xmark.shield")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .tint(.red)
                        } else {
                            Button {
                                ApprovalManager.approve(.knockknock, id: item.path)
                                viewModel.loadCached()
                            } label: {
                                Label("Approve", systemImage: "checkmark.shield")
                                    .font(.caption2)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.mini)
                            .tint(.green)
                            Button {
                                itemToQuarantine = item.path
                            } label: {
                                Label("Quarantine", systemImage: "exclamationmark.octagon")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .tint(.red)
                        }

                        Button {
                            UninstallHelper.investigateKnockKnockWithClaude(item: item)
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
        }
    }

    // MARK: - Helpers

    private func signatureView(_ item: KnockKnockItem) -> some View {
        Group {
            if item.signatureSigner == 1 {
                HStack(spacing: 4) {
                    Image(systemName: "apple.logo")
                        .foregroundStyle(.secondary)
                    Text("Apple")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if item.signatureStatus == 0 && !item.signatureAuthorities.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                    Text(FormatUtils.cleanAuthority(item.signatureAuthorities.first ?? ""))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .help(item.signatureAuthorities.joined(separator: " > "))
                }
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Unsigned")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private func itemColor(_ item: KnockKnockItem) -> Color {
        if isVTFlagged(item) { return .red }
        if item.signatureStatus != 0 || item.signatureSigner == 0 { return .orange }
        if item.signatureSigner == 1 { return .green.opacity(0.6) }
        return .blue
    }

    private func isFlagged(_ item: KnockKnockItem) -> Bool {
        item.signatureSigner == 0 || item.signatureStatus != 0 || isVTFlagged(item)
    }

    private func isVTFlagged(_ item: KnockKnockItem) -> Bool {
        guard !item.vtDetection.isEmpty,
              let slash = item.vtDetection.firstIndex(of: "/"),
              let n = Int(item.vtDetection[item.vtDetection.startIndex..<slash]) else { return false }
        return n > 0
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        let calendar = Calendar.current
        if calendar.isDateInToday(date) {
            formatter.dateFormat = "'Today' HH:mm"
        } else {
            formatter.dateFormat = "dd/MM/yyyy HH:mm"
        }
        return formatter.string(from: date)
    }

    // MARK: - States

    private var emptyState: some View {
        VStack {
            Spacer()
            Image(systemName: "door.left.hand.open")
                .font(.system(size: 48))
                .foregroundStyle(Color.fpeMuted)
            Text("No KnockKnock results")
                .font(.headline)
            Text("Press Scan to run KnockKnock CLI, or Load JSON to import a saved scan")
                .foregroundStyle(.secondary)
                .font(.callout)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private func errorState(_ error: String, fdaAvailable: Bool) -> some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: fdaAvailable ? "exclamationmark.triangle" : "lock.shield")
                .font(.system(size: 48))
                .foregroundStyle(fdaAvailable ? .orange : .red)
            Text(fdaAvailable ? "Scan Failed" : "Full Disk Access Required")
                .font(.headline)
            if !fdaAvailable {
                Text("KnockKnock CLI needs Full Disk Access granted to Security Guard (or Terminal if running via swift run).")
                    .foregroundStyle(.secondary)
                    .font(.callout)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 400)
            } else {
                Text(error)
                    .foregroundStyle(.secondary)
                    .font(.callout)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 400)
            }
            if !fdaAvailable {
                Button("Open Privacy Settings") {
                    Task {
                        _ = await Task.detached {
                            ShellExecutor.run("/usr/bin/open", arguments: [
                                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
                            ])
                        }.value
                    }
                }
                .buttonStyle(.borderedProminent)
            }
            HStack {
                Text("Or load a saved scan:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Load JSON") { showFileImporter = true }
                    .controlSize(.small)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}
