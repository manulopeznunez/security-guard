import SwiftUI

struct StatusDashboardView: View {
    @Binding var selectedTab: TabSection
    @State private var viewModel = SecurityStatusViewModel()

    var body: some View {
        VStack(spacing: 0) {
            // Refresh bar
            HStack {
                Spacer()
                if let action = viewModel.actionInProgress {
                    ProgressView()
                        .controlSize(.small)
                    Text(action)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button(action: { Task { await viewModel.scanAll() } }) {
                    Label("Scan All", systemImage: "shield.checkered")
                }
                .disabled(viewModel.isLoading)

                Button(action: { Task { await viewModel.refresh() } }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(viewModel.isLoading)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 6)

            if viewModel.isLoading {
                loadingState
            } else if viewModel.items.isEmpty {
                emptyState
            } else {
                ScrollView {
                    VStack(spacing: 16) {
                        scoreBar
                        scoreHistory

                        ForEach(viewModel.groupedItems, id: \.category) { group in
                            categoryGrid(group.category, items: group.items)
                        }
                    }
                    .padding(16)
                }
            }
        }
        .task {
            await viewModel.refresh()
        }
        .alert("Installation Error", isPresented: Binding(
            get: { viewModel.installError != nil },
            set: { if !$0 { viewModel.installError = nil } }
        )) {
            Button("OK") { viewModel.installError = nil }
        } message: {
            Text(viewModel.installError ?? "")
        }
    }

    // MARK: - Score Bar (compact inline)

    private var scoreBar: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .stroke(Color.fpeBorder, lineWidth: 4)
                Circle()
                    .trim(from: 0, to: viewModel.scoreProgress)
                    .stroke(
                        viewModel.scoreProgress >= 1.0 ? Color.fpeSuccess : Color.fpePrimary,
                        style: StrokeStyle(lineWidth: 4, lineCap: .round)
                    )
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 1.0), value: viewModel.scoreProgress)
                Text("\(viewModel.enabledCount)/\(viewModel.items.count)")
                    .font(.system(size: 11, weight: .bold, design: .rounded))
            }
            .frame(width: 36, height: 36)

            VStack(alignment: .leading, spacing: 1) {
                Text(scoreMessage)
                    .font(.system(size: 12, weight: .medium))
                Text("\(viewModel.enabledCount) of \(viewModel.items.count) protections active")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            // Auto-scan info
            if !BackgroundMonitor.shared.lastDailyScan.isEmpty {
                VStack(alignment: .trailing, spacing: 1) {
                    Text("Auto-scan: \(BackgroundMonitor.shared.lastDailyScan)")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                    Text("\(Int(BackgroundMonitor.shared.lastScore * 100))% score")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(BackgroundMonitor.shared.lastScore >= 0.8 ? Color.fpeSuccess : Color.fpePrimary)
                }
            }
        }
        .padding(.horizontal, 4)
    }

    @ViewBuilder
    private var scoreHistory: some View {
        let history = DatabaseManager.shared.scoreHistory(days: 30)
        if !history.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: "chart.line.uptrend.xyaxis")
                        .foregroundStyle(Color.fpePrimary)
                        .font(.caption)
                    Text("Score History")
                        .font(.system(size: 11, weight: .semibold))
                    Spacer()
                    Text("Last \(history.count) scan\(history.count == 1 ? "" : "s")")
                        .font(.system(size: 10))
                        .foregroundStyle(Color.fpeMuted)
                }

                HStack(spacing: 2) {
                    ForEach(history.reversed()) { snap in
                        VStack(spacing: 2) {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(snap.score >= 0.8 ? Color.fpeSuccess : (snap.score >= 0.5 ? Color.fpePrimary : Color.fpeDestructive))
                                .frame(width: 8, height: CGFloat(snap.score * 30))
                        }
                        .help("\(formatHistoryDate(snap.timestamp)): \(snap.enabledCount)/\(snap.totalCount) (\(Int(snap.score * 100))%)")
                    }
                    Spacer()
                }
                .frame(height: 32)
            }
            .padding(.horizontal, 4)
        }
    }

    private func formatHistoryDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "dd/MM HH:mm"
        return formatter.string(from: date)
    }

    private var scoreMessage: String {
        let enabled = viewModel.enabledCount
        let total = viewModel.items.count
        if enabled == total {
            return "All protections active"
        } else if enabled >= total - 1 {
            return "Almost there!"
        } else {
            return "\(total - enabled) protections need attention"
        }
    }

    // MARK: - Category Grid

    private func categoryGrid(
        _ category: SecurityCategory,
        items: [SecurityItem]
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: category.icon)
                    .foregroundStyle(Color.fpePrimary)
                    .font(.caption)
                Text(category.rawValue)
                    .font(.system(size: 11, weight: .semibold))
                Spacer()
                let active = items.filter { $0.status == .enabled }.count
                Text("\(active)/\(items.count)")
                    .font(.system(size: 10))
                    .foregroundStyle(Color.fpeMuted)
            }

            LazyVGrid(
                columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4),
                spacing: 10
            ) {
                ForEach(items) { item in
                    SecurityGridCard(item: item, viewModel: viewModel, selectedTab: $selectedTab)
                }
            }
        }
    }

    // MARK: - Loading State

    private var loadingState: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView()
                .controlSize(.large)
            Text("Checking security status...")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Scanning system protections and installed tools")
                .font(.caption)
                .foregroundStyle(.tertiary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "shield.slash")
                .font(.system(size: 48))
                .foregroundStyle(Color.fpeMuted)
            Text("No Security Data")
                .font(.headline)
            Text("Press Refresh to check your Mac's security status")
                .font(.callout)
                .foregroundStyle(.secondary)
            Button(action: { Task { await viewModel.refresh() } }) {
                Label("Check Now", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .tint(.fpePrimary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Grid Card

struct SecurityGridCard: View {
    let item: SecurityItem
    let viewModel: SecurityStatusViewModel
    @Binding var selectedTab: TabSection

    @State private var isHovering = false
    @State private var showDetail = false

    private var isNavigable: Bool { item.targetTab != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Top row: icon + pill
            HStack {
                Image(systemName: item.status.icon)
                    .font(.system(size: 20))
                    .foregroundStyle(item.status.color)
                Spacer()
                HStack(spacing: 4) {
                    if isNavigable {
                        Image(systemName: "arrow.right.circle.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(Color.fpeMuted.opacity(isHovering ? 1 : 0.5))
                    }
                    Text(item.status.label)
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(item.status.color)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(item.status.pillBackground)
                        .clipShape(Capsule())
                }
            }

            // Name
            Text(item.name)
                .font(.system(size: 11, weight: .semibold))
                .lineLimit(2)

            // Description
            Text(item.description)
                .font(.system(size: 9))
                .foregroundStyle(.secondary)
                .lineLimit(2)

            // Explanation
            Text(item.explanation)
                .font(.system(size: 9))
                .foregroundStyle(.tertiary)
                .lineLimit(3)

            Spacer(minLength: 0)

            // Bottom row: how-to + action
            HStack(spacing: 4) {
                Button(action: { showDetail.toggle() }) {
                    HStack(spacing: 2) {
                        Image(systemName: "questionmark.circle")
                            .font(.system(size: 10))
                        Text("How to use")
                            .font(.system(size: 9))
                    }
                    .foregroundStyle(Color.fpePrimary)
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showDetail, arrowEdge: .bottom) {
                    detailPopover
                }

                Spacer(minLength: 0)

                if shouldShowAction {
                    actionButton
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, minHeight: 140, alignment: .topLeading)
        .background(.background)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(isHovering ? Color.fpePrimary.opacity(0.5) : Color.fpeBorder, lineWidth: 1)
        )
        .shadow(color: .black.opacity(isHovering ? 0.08 : 0.02), radius: isHovering ? 6 : 2, y: isHovering ? 3 : 1)
        .contentShape(Rectangle())
        .onTapGesture {
            if let tab = item.targetTab {
                selectedTab = tab
            }
        }
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
                isHovering = hovering
            }
            if isNavigable {
                if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
        }
    }

    // MARK: - Detail Popover

    private var detailPopover: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: item.status.icon)
                    .foregroundStyle(item.status.color)
                Text(item.name)
                    .font(.system(size: 13, weight: .semibold))
            }

            Divider()

            Text("How to use")
                .font(.caption.bold())
                .foregroundStyle(Color.fpeMuted)
            Text(item.howToUse)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(width: 300)
    }

    // MARK: - Action Button

    private var shouldShowAction: Bool {
        if item.status == .disabled { return true }
        if item.status == .enabled, case .openURL = item.action { return true }
        return false
    }

    @ViewBuilder
    private var actionButton: some View {
        switch item.action {
        case .none:
            EmptyView()
        case .installBrew:
            Button(action: { Task { await viewModel.performAction(item.action) } }) {
                Text("Install")
                    .font(.system(size: 9, weight: .medium))
            }
            .buttonStyle(.borderedProminent)
            .tint(.fpePrimary)
            .controlSize(.mini)
            .disabled(viewModel.actionInProgress != nil)
        case .openSystemSettings:
            Button(action: { Task { await viewModel.performAction(item.action) } }) {
                Text("Settings")
                    .font(.system(size: 9, weight: .medium))
            }
            .buttonStyle(.bordered)
            .controlSize(.mini)
        case .openURL(let url):
            Button(action: { Task { await viewModel.performAction(item.action) } }) {
                Text(url.hasPrefix("/Applications/") ? "Open" : "Learn")
                    .font(.system(size: 9, weight: .medium))
            }
            .buttonStyle(.bordered)
            .controlSize(.mini)
        }
    }
}
