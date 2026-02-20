import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 0) {
            appHeader
            Divider()

            TabView {
                StatusDashboardView()
                    .tabItem {
                        Label("Security Status", systemImage: "shield.checkered")
                    }

                ProcessScannerView()
                    .tabItem {
                        Label("Processes", systemImage: "cpu")
                    }

                PersistenceScannerView()
                    .tabItem {
                        Label("Persistence", systemImage: "clock.arrow.circlepath")
                    }

                KnockKnockView()
                    .tabItem {
                        Label("KnockKnock", systemImage: "door.left.hand.open")
                    }

                AppSignatureView()
                    .tabItem {
                        Label("App Signatures", systemImage: "signature")
                    }

                ChromeExtensionView()
                    .tabItem {
                        Label("Extensions", systemImage: "puzzlepiece.extension")
                    }

                NetworkMonitorView()
                    .tabItem {
                        Label("Network", systemImage: "network")
                    }

                NetworkHistoryView()
                    .tabItem {
                        Label("History", systemImage: "clock.arrow.2.circlepath")
                    }
            }
        }
        .frame(minWidth: 900, minHeight: 600)
        .task {
            // Auto-start background recording
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
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
        }
    }
}
