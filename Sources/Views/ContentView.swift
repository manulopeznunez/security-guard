import SwiftUI

enum TabSection: String, CaseIterable, Identifiable {
    case securityStatus = "Status"
    case processes = "Processes"
    case persistence = "Persistence"
    case knockKnock = "KnockKnock"
    case homebrew = "Homebrew"
    case appSignatures = "Signatures"
    case extensions = "Extensions"
    case network = "Network"
    case history = "History"
    case attackSurface = "Surface"
    case configGuard = "Config"
    case permissions = "Permissions"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .securityStatus: "shield.checkered"
        case .processes: "cpu"
        case .persistence: "clock.arrow.circlepath"
        case .knockKnock: "door.left.hand.open"
        case .homebrew: "mug.fill"
        case .appSignatures: "signature"
        case .extensions: "puzzlepiece.extension"
        case .network: "network"
        case .history: "clock.arrow.2.circlepath"
        case .attackSurface: "network.badge.shield.half.filled"
        case .configGuard: "doc.text.magnifyingglass"
        case .permissions: "lock.shield"
        }
    }

    var shortName: String {
        switch self {
        case .securityStatus: "Status"
        case .processes: "Proc"
        case .persistence: "Persist"
        case .knockKnock: "KK"
        case .homebrew: "Brew"
        case .appSignatures: "Sigs"
        case .extensions: "Ext"
        case .network: "Net"
        case .history: "Hist"
        case .attackSurface: "Surf"
        case .configGuard: "Cfg"
        case .permissions: "Perms"
        }
    }
}

private struct TabGroup {
    let label: String
    let tabs: [TabSection]
}

private let tabGroups: [TabGroup] = [
    TabGroup(label: "System", tabs: [.processes, .persistence, .knockKnock, .homebrew, .configGuard]),
    TabGroup(label: "Apps", tabs: [.appSignatures, .extensions]),
    TabGroup(label: "Network", tabs: [.network, .history, .attackSurface]),
    TabGroup(label: "Access", tabs: [.permissions]),
]

struct ContentView: View {
    @State private var selectedTab: TabSection = .securityStatus

    var body: some View {
        VStack(spacing: 0) {
            appHeader
            Divider()
            tabBar
            Divider()
            tabContent
        }
        .frame(minWidth: 900, minHeight: 600)
        .task {
            BackgroundMonitor.shared.start()
        }
    }

    private var appHeader: some View {
        VStack(spacing: 0) {
            Rectangle()
                .fill(Color.fpePrimary)
                .frame(height: 3)

            HStack(spacing: 10) {
                FPELogo(size: 32)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Guard")
                        .font(.system(size: 14, weight: .semibold))
                    Text("Engineering Tools")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary.opacity(0.6))
                        .tracking(0.5)
                }

                Spacer()

                statusButton
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
        }
    }

    private var statusButton: some View {
        Button {
            selectedTab = .securityStatus
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 12))
                Text("Status")
                    .font(.system(size: 12, weight: .medium))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 7)
                    .fill(selectedTab == .securityStatus ? Color.accentColor.opacity(0.15) : Color.secondary.opacity(0.08))
            )
            .foregroundStyle(selectedTab == .securityStatus ? Color.accentColor : .secondary)
        }
        .buttonStyle(.plain)
    }

    private enum TabDensity {
        case full, short, iconOnly
    }

    private var tabBar: some View {
        ViewThatFits(in: .horizontal) {
            tabBarRow(density: .full)
            tabBarRow(density: .short)
            tabBarRow(density: .iconOnly)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
    }

    private func tabBarRow(density: TabDensity) -> some View {
        HStack(spacing: 0) {
            ForEach(Array(tabGroups.enumerated()), id: \.offset) { index, group in
                if index > 0 {
                    Rectangle()
                        .fill(.quaternary)
                        .frame(width: 1, height: 16)
                        .padding(.horizontal, 8)
                }

                Text(group.label.uppercased())
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .padding(.trailing, 4)

                HStack(spacing: 2) {
                    ForEach(group.tabs) { tab in
                        tabButton(tab, density: density)
                    }
                }
            }
        }
    }

    private func tabButton(_ tab: TabSection, density: TabDensity) -> some View {
        Button {
            selectedTab = tab
        } label: {
            HStack(spacing: density == .iconOnly ? 0 : 3) {
                Image(systemName: tab.icon)
                    .font(.system(size: 10))
                switch density {
                case .full:
                    Text(tab.rawValue)
                        .font(.system(size: 10, weight: .medium))
                case .short:
                    Text(tab.shortName)
                        .font(.system(size: 10, weight: .medium))
                case .iconOnly:
                    EmptyView()
                }
            }
            .padding(.horizontal, density == .iconOnly ? 6 : 7)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 5)
                    .fill(selectedTab == tab ? Color.accentColor.opacity(0.15) : Color.clear)
            )
            .foregroundStyle(selectedTab == tab ? Color.accentColor : .secondary)
        }
        .buttonStyle(.plain)
        .help(tab.rawValue)
    }

    @ViewBuilder
    private var tabContent: some View {
        switch selectedTab {
        case .securityStatus: StatusDashboardView()
        case .processes: ProcessScannerView()
        case .persistence: PersistenceScannerView()
        case .knockKnock: KnockKnockView()
        case .homebrew: HomebrewScannerView()
        case .appSignatures: AppSignatureView()
        case .extensions: ChromeExtensionView()
        case .network: NetworkMonitorView()
        case .history: NetworkHistoryView()
        case .attackSurface: AttackSurfaceView()
        case .configGuard: ConfigGuardView()
        case .permissions: PermissionsView()
        }
    }
}
