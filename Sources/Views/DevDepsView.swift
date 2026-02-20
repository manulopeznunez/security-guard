import SwiftUI

struct DevDepsView: View {
    @State private var viewModel = DevDepsViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if viewModel.projects.isEmpty && !viewModel.isScanning {
                emptyState
            } else {
                summaryBar
                Divider()
                projectList
            }
        }
        .task {
            await viewModel.scan()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "ladybug")
                .font(.title).foregroundStyle(.red)
            Text("Dev Dependencies").font(.title.bold())
            ScanDateLabel(scanner: .devDeps)
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
            let totalVulns = viewModel.projects.reduce(0) { $0 + $1.vulnerabilities.count }
            Label("\(viewModel.projects.count) projects", systemImage: "folder")
                .font(.caption)
            if totalVulns > 0 {
                Label("\(totalVulns) vulnerabilities", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.bold()).foregroundStyle(.red)
            } else {
                Label("No known vulnerabilities", systemImage: "checkmark.shield")
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
            Image(systemName: "ladybug").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Press Scan to audit dev dependencies").foregroundStyle(.secondary)
            Text("Scans for npm, pip, and cargo projects in common directories.\nRuns audit commands to find known vulnerabilities.")
                .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center).frame(maxWidth: 450)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var projectList: some View {
        List {
            ForEach(viewModel.projects) { project in
                DisclosureGroup {
                    if project.vulnerabilities.isEmpty {
                        HStack {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                            Text("No known vulnerabilities").font(.caption).foregroundStyle(.secondary)
                        }
                    } else {
                        ForEach(project.vulnerabilities) { vuln in
                            HStack(spacing: 10) {
                                Text(vuln.severity.label)
                                    .font(.caption2.bold())
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(vuln.severity.color).clipShape(Capsule())

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(vuln.packageName).font(.headline)
                                    if !vuln.installedVersion.isEmpty {
                                        Text("v\(vuln.installedVersion)").font(.caption).foregroundStyle(.secondary)
                                    }
                                    Text(vuln.title).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                                    if !vuln.vulnerableRange.isEmpty {
                                        Text(vuln.vulnerableRange).font(.caption2).foregroundStyle(.tertiary)
                                    }
                                }
                                Spacer()
                            }
                            .padding(.vertical, 2)
                        }
                    }
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: project.manager.icon)
                            .foregroundStyle(project.manager.color)
                            .frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(project.manager.rawValue).font(.caption.bold())
                            Text(abbreviatePath(project.projectPath))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        if !project.vulnerabilities.isEmpty {
                            Text("\(project.vulnerabilities.count) vulns")
                                .font(.caption2.bold()).foregroundStyle(.white)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(project.worstSeverity.color).clipShape(Capsule())
                        } else {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green).font(.caption)
                        }
                        Text("\(project.totalDeps) deps").font(.caption).foregroundStyle(.tertiary)
                    }
                }
            }
        }
    }

    private func abbreviatePath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.replacingOccurrences(of: home, with: "~")
    }
}
