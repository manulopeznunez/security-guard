import Foundation

@Observable
@MainActor
final class DevDepsViewModel {
    var projects: [DevProjectSummary] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Scanning for development projects..."
        let results = await Task.detached { Self.performScan() }.value
        projects = results
        let totalVulns = results.reduce(0) { $0 + $1.vulnerabilities.count }
        progress = "Found \(results.count) projects, \(totalVulns) vulnerabilities"
        isScanning = false

        let flagged = results.flatMap(\.vulnerabilities).filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.devDeps, flaggedIDs: flagged)
        Self.saveCachedResult(results.flatMap(\.vulnerabilities))
        ScanDateTracker.record(.devDeps)
        DatabaseManager.shared.insertScanHistory(
            scanner: "devDeps", total: results.count, flagged: flagged.count,
            summary: "\(results.count) projects, \(totalVulns) vulnerabilities"
        )
    }

    func loadCached() {
        // DevProjectSummary isn't Codable (contains non-serializable fields), so we skip caching summaries
    }

    // MARK: - Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("devdeps-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: [DevVulnerability]) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    // MARK: - Scan

    nonisolated static func performScan() -> [DevProjectSummary] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let searchPaths = [
            "\(home)/Developer", "\(home)/Projects", "\(home)/Code",
            "\(home)/repos", "\(home)/work", "\(home)/development",
            "\(home)/src", "\(home)/workspace"
        ].filter { FileManager.default.fileExists(atPath: $0) }

        var projects: [DevProjectSummary] = []

        for basePath in searchPaths {
            // Find lock files up to depth 3
            let found = findLockFiles(in: basePath, maxDepth: 3)
            for (lockPath, manager) in found {
                let projectDir = (lockPath as NSString).deletingLastPathComponent
                if let summary = auditProject(at: projectDir, manager: manager) {
                    projects.append(summary)
                }
            }
        }

        return projects.sorted { $0.worstSeverity > $1.worstSeverity }
    }

    nonisolated private static func findLockFiles(in basePath: String, maxDepth: Int) -> [(path: String, manager: PackageManager)] {
        var results: [(String, PackageManager)] = []
        let fm = FileManager.default

        func recurse(_ path: String, depth: Int) {
            guard depth <= maxDepth else { return }
            guard let contents = try? fm.contentsOfDirectory(atPath: path) else { return }

            for item in contents {
                if item.hasPrefix(".") || item == "node_modules" || item == "__pycache__" || item == "target" { continue }
                let fullPath = "\(path)/\(item)"

                if item == "package-lock.json" { results.append((fullPath, .npm)) }
                else if item == "requirements.txt" { results.append((fullPath, .pip)) }
                else if item == "Cargo.lock" { results.append((fullPath, .cargo)) }

                var isDir: ObjCBool = false
                if fm.fileExists(atPath: fullPath, isDirectory: &isDir), isDir.boolValue {
                    recurse(fullPath, depth: depth + 1)
                }
            }
        }

        recurse(basePath, depth: 0)
        return results
    }

    nonisolated private static func auditProject(at path: String, manager: PackageManager) -> DevProjectSummary? {
        switch manager {
        case .npm: return auditNpm(at: path)
        case .pip: return auditPip(at: path)
        case .cargo: return auditCargo(at: path)
        }
    }

    // MARK: - npm audit

    nonisolated private static func auditNpm(at path: String) -> DevProjectSummary? {
        let which = ShellExecutor.run("/usr/bin/which", arguments: ["npm"])
        guard which.exitCode == 0 else { return nil }
        let npmPath = which.output.trimmingCharacters(in: .whitespacesAndNewlines)

        let result = ShellExecutor.run(npmPath, arguments: ["audit", "--json"], workingDirectory: path, timeout: .network)
        guard !result.output.isEmpty,
              let data = result.output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var vulns: [DevVulnerability] = []

        // npm audit v2+ format: "vulnerabilities" object
        if let vulnerabilities = json["vulnerabilities"] as? [String: Any] {
            for (pkgName, value) in vulnerabilities {
                guard let vulnDict = value as? [String: Any] else { continue }
                let severity = vulnDict["severity"] as? String ?? "info"
                let range = vulnDict["range"] as? String ?? ""
                let fixAvailable = vulnDict["fixAvailable"] as? Bool ?? false

                // Get advisories
                var title = fixAvailable ? "Fix available" : "No fix available"
                if let via = vulnDict["via"] as? [[String: Any]], let first = via.first {
                    title = first["title"] as? String ?? title
                }

                let sev = parseSeverity(severity)
                vulns.append(DevVulnerability(
                    packageName: pkgName, installedVersion: "",
                    vulnerableRange: range, severity: sev,
                    title: title, url: "",
                    manager: .npm, projectPath: path
                ))
            }
        }

        let totalDeps = (json["metadata"] as? [String: Any])?["dependencies"] as? [String: Any]
        let depCount = totalDeps?.values.reduce(0) { $0 + (($1 as? Int) ?? 0) } ?? 0

        return DevProjectSummary(
            projectPath: path, manager: .npm,
            totalDeps: depCount, vulnerabilities: vulns
        )
    }

    // MARK: - pip audit

    nonisolated private static func auditPip(at path: String) -> DevProjectSummary? {
        // Try pip-audit first
        let which = ShellExecutor.run("/usr/bin/which", arguments: ["pip-audit"])
        if which.exitCode == 0 {
            let pipAuditPath = which.output.trimmingCharacters(in: .whitespacesAndNewlines)
            let result = ShellExecutor.run(pipAuditPath, arguments: ["-r", "\(path)/requirements.txt", "--format", "json"], timeout: .network)
            if let data = result.output.data(using: .utf8),
               let items = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                var vulns: [DevVulnerability] = []
                for item in items {
                    let name = item["name"] as? String ?? ""
                    let version = item["version"] as? String ?? ""
                    let vulnEntries = item["vulns"] as? [[String: Any]] ?? []
                    for vuln in vulnEntries {
                        let vulnId = vuln["id"] as? String ?? ""
                        let desc = vuln["description"] as? String ?? ""
                        let fixVersions = vuln["fix_versions"] as? [String] ?? []
                        vulns.append(DevVulnerability(
                            packageName: name, installedVersion: version,
                            vulnerableRange: fixVersions.isEmpty ? "no fix" : "fix: \(fixVersions.joined(separator: ", "))",
                            severity: .high, title: "\(vulnId): \(desc.prefix(80))",
                            url: "", manager: .pip, projectPath: path
                        ))
                    }
                }
                return DevProjectSummary(
                    projectPath: path, manager: .pip,
                    totalDeps: items.count, vulnerabilities: vulns
                )
            }
        }

        // Fallback: just count deps from requirements.txt
        if let content = try? String(contentsOfFile: "\(path)/requirements.txt", encoding: .utf8) {
            let deps = content.components(separatedBy: "\n").filter { !$0.isEmpty && !$0.hasPrefix("#") }
            return DevProjectSummary(
                projectPath: path, manager: .pip,
                totalDeps: deps.count, vulnerabilities: []
            )
        }
        return nil
    }

    // MARK: - cargo audit

    nonisolated private static func auditCargo(at path: String) -> DevProjectSummary? {
        let which = ShellExecutor.run("/usr/bin/which", arguments: ["cargo-audit"])
        guard which.exitCode == 0 else {
            // cargo-audit not installed, just report the project exists
            return DevProjectSummary(
                projectPath: path, manager: .cargo,
                totalDeps: 0, vulnerabilities: []
            )
        }
        let cargoAuditPath = which.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let result = ShellExecutor.run(cargoAuditPath, arguments: ["audit", "--json"], workingDirectory: path, timeout: .network)
        guard let data = result.output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let vulnSection = json["vulnerabilities"] as? [String: Any],
              let list = vulnSection["list"] as? [[String: Any]] else {
            return DevProjectSummary(projectPath: path, manager: .cargo, totalDeps: 0, vulnerabilities: [])
        }

        var vulns: [DevVulnerability] = []
        for item in list {
            let advisory = item["advisory"] as? [String: Any] ?? [:]
            let pkg = item["package"] as? [String: Any] ?? [:]
            let name = pkg["name"] as? String ?? ""
            let version = pkg["version"] as? String ?? ""
            let title = advisory["title"] as? String ?? ""
            let id = advisory["id"] as? String ?? ""
            vulns.append(DevVulnerability(
                packageName: name, installedVersion: version,
                vulnerableRange: "", severity: .high,
                title: "\(id): \(title)", url: "",
                manager: .cargo, projectPath: path
            ))
        }

        return DevProjectSummary(projectPath: path, manager: .cargo, totalDeps: list.count, vulnerabilities: vulns)
    }

    // MARK: - Helpers

    nonisolated private static func parseSeverity(_ str: String) -> VulnerabilitySeverity {
        switch str.lowercased() {
        case "critical": .critical
        case "high": .high
        case "moderate", "medium": .moderate
        case "low": .low
        default: .info
        }
    }
}
