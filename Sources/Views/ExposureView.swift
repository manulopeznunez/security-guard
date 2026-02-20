import SwiftUI

struct ExposureView: View {
    @State private var viewModel = ExposureViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if viewModel.entries.isEmpty && !viewModel.isScanning {
                emptyState
            } else {
                summaryBar
                Divider()
                sectionList
            }
        }
        .task {
            viewModel.loadCached()
            await viewModel.scan()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.title).foregroundStyle(.purple)
            Text("System Exposure").font(.title.bold())
            ScanDateLabel(scanner: .exposure)
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

    private var summaryBar: some View {
        HStack(spacing: 16) {
            let flagged = viewModel.entries.filter(\.needsReview).count
            Label("\(viewModel.entries.count) checks", systemImage: "checkmark.circle")
                .font(.caption)
            if flagged > 0 {
                Label("\(flagged) need attention", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.bold()).foregroundStyle(.orange)
            } else {
                Label("All clear", systemImage: "checkmark.shield")
                    .font(.caption).foregroundStyle(.green)
            }
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Press Scan to check system exposure").foregroundStyle(.secondary)
            Text("Checks Wi-Fi security, Bluetooth, Sharing Services, DNS, Kernel and System Extensions.")
                .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center).frame(maxWidth: 450)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var sectionList: some View {
        List {
            ForEach(ExposureSection.allCases) { section in
                let items = viewModel.entriesForSection(section)
                if !items.isEmpty {
                    DisclosureGroup {
                        ForEach(items) { entry in
                            HStack(spacing: 10) {
                                Image(systemName: "circle.fill")
                                    .foregroundStyle(entry.risk.color)
                                    .font(.caption2)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.name).font(.headline)
                                    Text(entry.detail).font(.caption).foregroundStyle(.secondary)
                                    Text(entry.riskReason).font(.caption2).foregroundStyle(entry.risk.color)
                                    if entry.risk != .safe {
                                        Text(entry.remediation)
                                            .font(.caption2).foregroundStyle(.tertiary).italic()
                                    }
                                }
                                Spacer()
                            }
                            .padding(.vertical, 2)
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: section.icon)
                                .frame(width: 20)
                            Text(section.rawValue).font(.headline)
                            let sectionFlagged = items.filter(\.needsReview).count
                            if sectionFlagged > 0 {
                                Text("\(sectionFlagged)")
                                    .font(.caption2.bold())
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(Color.orange).clipShape(Capsule())
                            }
                            Spacer()
                            Text("\(items.count) items").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }
}
