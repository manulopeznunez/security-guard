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
    case devDeps = "DevDeps"
    case permissions = "Permissions"
    case exposure = "Exposure"
    case breaches = "Breaches"

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
        case .devDeps: "ladybug"
        case .permissions: "lock.shield"
        case .exposure: "antenna.radiowaves.left.and.right"
        case .breaches: "exclamationmark.lock"
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
        case .devDeps: "Deps"
        case .permissions: "Perms"
        case .exposure: "Exp"
        case .breaches: "Leak"
        }
    }

    /// ApprovalManager categories tracked by this tab.
    var approvalCategories: [ApprovalManager.Category] {
        switch self {
        case .securityStatus: []
        case .processes: [.process]
        case .persistence: [.persistence]
        case .knockKnock: [.knockknock]
        case .homebrew: [.homebrew]
        case .appSignatures: [.appSignature]
        case .extensions: [.chromeExtension, .browserExtension]
        case .network: [.networkMonitor]
        case .history: []
        case .attackSurface: [.attackSurface]
        case .configGuard: [.configGuard]
        case .devDeps: [.devDeps]
        case .permissions: [.tccPermission, .sudoConfig, .usersGroups]
        case .exposure: [.exposure]
        case .breaches: [.breachCheck]
        }
    }

    /// True when any mapped category has pending or quarantined items.
    var hasAlert: Bool {
        approvalCategories.contains { cat in
            ApprovalManager.pendingCount(for: cat) > 0
                || ApprovalManager.quarantinedCount(for: cat) > 0
        }
    }
}

private struct TabGroup {
    let label: String
    let tabs: [TabSection]
}

private let tabGroups: [TabGroup] = [
    TabGroup(label: "System", tabs: [.processes, .persistence, .knockKnock, .homebrew, .configGuard, .devDeps]),
    TabGroup(label: "Apps", tabs: [.appSignatures, .extensions]),
    TabGroup(label: "Network", tabs: [.network, .history, .attackSurface]),
    TabGroup(label: "Access", tabs: [.permissions, .exposure]),
    TabGroup(label: "Identity", tabs: [.breaches]),
]

struct ContentView: View {
    @State private var selectedTab: TabSection = .securityStatus
    /// Incremented when approval state changes so tab badges re-evaluate.
    @State private var badgeRevision = 0

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
        .onReceive(NotificationCenter.default.publisher(for: ApprovalManager.stateDidChangeNotification)) { _ in
            badgeRevision += 1
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
        // badgeRevision dependency ensures SwiftUI re-evaluates hasAlert after state changes.
        let _ = badgeRevision
        let showAlert = tab.hasAlert

        return Button {
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
            .overlay(alignment: .topTrailing) {
                if showAlert {
                    Circle()
                        .fill(Color.fpeDestructive)
                        .frame(width: 6, height: 6)
                        .offset(x: 2, y: -2)
                }
            }
        }
        .buttonStyle(.plain)
        .help(tab.rawValue)
    }

    @ViewBuilder
    private var tabContent: some View {
        switch selectedTab {
        case .securityStatus: StatusDashboardView(selectedTab: $selectedTab)
        case .processes: ProcessScannerView()
        case .persistence: PersistenceScannerView()
        case .knockKnock: KnockKnockView()
        case .homebrew: HomebrewScannerView()
        case .appSignatures: AppSignatureView()
        case .extensions: BrowserExtensionView()
        case .network: NetworkMonitorView()
        case .history: NetworkHistoryView()
        case .attackSurface: AttackSurfaceView()
        case .configGuard: ConfigGuardView()
        case .devDeps: DevDepsView()
        case .permissions: PermissionsView()
        case .exposure: ExposureView()
        case .breaches: BreachCheckView()
        }
    }
}
