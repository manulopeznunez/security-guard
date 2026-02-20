import Foundation
import os.log

@Observable
@MainActor
final class BackgroundMonitor {
    static let shared = BackgroundMonitor()

    var isRunning = false
    var lastSnapshot = ""
    var snapshotCount = 0
    var lastDailyScan = ""
    var lastScore: Double = 0
    private var dailyScanRunning = false

    private var timer: Timer?

    func start() {
        guard !isRunning else { return }
        isRunning = true
        AuditLogger.audit.info("Background monitor started")
        // Take first snapshot immediately, then check daily scan
        Task {
            await captureSnapshot()
            await checkDailyScan()
        }
        // Then every 60 seconds
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.captureSnapshot()
                await self?.checkDailyScan()
            }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        isRunning = false
        AuditLogger.audit.info("Background monitor stopped")
    }

    private func captureSnapshot() async {
        AuditLogger.audit.info("Snapshot #\(self.snapshotCount + 1) starting")
        let snapshots = await Self.collectData()
        if !snapshots.isEmpty {
            DatabaseManager.shared.insertSnapshot(connections: snapshots)
            snapshotCount += 1
            let formatter = DateFormatter()
            formatter.dateFormat = "HH:mm:ss"
            lastSnapshot = formatter.string(from: Date())
            AuditLogger.audit.info("Snapshot captured: \(snapshots.count) connections")
        } else {
            AuditLogger.audit.info("Snapshot empty: no active connections")
        }
    }

    // MARK: - Daily Security Scan

    private func checkDailyScan() async {
        guard !dailyScanRunning else { return }

        // Load last score for display
        if let history = DatabaseManager.shared.scoreHistory(days: 1).first {
            lastScore = history.score
            lastDailyScan = formatScanDate(history.timestamp)
        }

        // Check if 24h have passed since last scan
        let lastDate = DatabaseManager.shared.lastScanDate()
        let needsScan: Bool
        if let last = lastDate {
            needsScan = Date().timeIntervalSince(last) > 86400  // 24 hours
        } else {
            needsScan = true  // Never scanned
        }

        guard needsScan else { return }
        dailyScanRunning = true

        // Run entirely in background — no UI impact
        Task.detached { [weak self] in
            // 1. Quick security checks (SIP, Gatekeeper, etc.)
            let items = await SecurityStatusViewModel.checkAll()
            let enabled = items.filter { $0.status == .enabled }.count
            let total = items.count

            // 2. Build details string
            let details = items.map { item in
                "\(item.name):\(item.status == .enabled ? "OK" : "OFF")"
            }.joined(separator: " | ")

            // 3. Save to database
            DatabaseManager.shared.insertScore(enabled: enabled, total: total, details: details)

            // 4. Run full scanners and cache flagged items
            let processResults = await ProcessScannerViewModel.performScan(onProgress: { _ in })
            let flaggedProcesses = processResults.filter { $0.signatureValid == false }.map(\.path)
            ApprovalManager.saveFlagged(.process, ids: flaggedProcesses)

            let persistenceResults = await PersistenceScannerViewModel.performScan()
            let flaggedPersistence = persistenceResults.filter(\.needsReview).map(\.executablePath)
            ApprovalManager.saveFlagged(.persistence, ids: flaggedPersistence)

            let appResults = await AppSignatureViewModel.performScan(onProgress: { _ in })
            let flaggedApps = appResults.filter { !$0.isValid }.map(\.appPath)
            ApprovalManager.saveFlagged(.appSignature, ids: flaggedApps)

            let extResults = ChromeExtensionViewModel.performScan()
            let flaggedExts = extResults.filter { $0.risk == .high }.map(\.extensionId)
            ApprovalManager.saveFlagged(.chromeExtension, ids: flaggedExts)

            // 4b. KnockKnock deep persistence scan (if installed)
            if FileManager.default.isExecutableFile(
                atPath: "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"
            ) {
                let kkResult = await KnockKnockViewModel.performScan()
                let flaggedKK = kkResult.flaggedItems.map(\.path)
                ApprovalManager.saveFlagged(.knockknock, ids: flaggedKK)
            }

            // 5. Update UI properties on MainActor
            let score = total > 0 ? Double(enabled) / Double(total) : 0
            let scanDate = self?.formatScanDate(Date()) ?? ""
            await MainActor.run { [weak self] in
                self?.lastScore = score
                self?.lastDailyScan = scanDate
                self?.dailyScanRunning = false
            }
        }
    }

    nonisolated private func formatScanDate(_ date: Date) -> String {
        let calendar = Calendar.current
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        let time = formatter.string(from: date)

        if calendar.isDateInToday(date) {
            return "Today \(time)"
        } else if calendar.isDateInYesterday(date) {
            return "Yesterday \(time)"
        } else {
            formatter.dateFormat = "dd/MM HH:mm"
            return formatter.string(from: date)
        }
    }

    /// Collects current connections with bytes data and geo info.
    nonisolated private static func collectData() async -> [ConnectionSnapshot] {
        // 1. Get connections from lsof (+c 0 = no name truncation)
        let lsofResult = ShellExecutor.shell("lsof +c 0 -i -n -P 2>/dev/null | grep ESTABLISHED")
        let lsofLines = lsofResult.output.components(separatedBy: "\n").filter { !$0.isEmpty }

        // 2. Get bytes from nettop
        let nettopResult = ShellExecutor.shell("nettop -L 1 -x -P -k time,interface,state,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch 2>/dev/null")
        var bytesMap: [String: (bytesIn: Int64, bytesOut: Int64)] = [:]
        for line in nettopResult.output.components(separatedBy: "\n").dropFirst() {
            let parts = line.split(separator: ",").map(String.init)
            guard parts.count >= 3 else { continue }
            let processKey = parts[0]  // e.g. "Slack Helper.9198"
            let bytesIn = Int64(parts[1]) ?? 0
            let bytesOut = Int64(parts[2]) ?? 0
            bytesMap[processKey] = (bytesIn, bytesOut)
        }

        // 3. Parse lsof connections
        struct RawConnection {
            let processName: String
            let pid: Int
            let remoteIP: String
            let remotePort: String
        }

        var rawConnections: [RawConnection] = []
        let localPrefixes = ["192.168.", "10.", "172.16.", "172.17.", "127.0.0.1", "fe80:", "::1"]

        for line in lsofLines {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 9 else { continue }

            let processName = parts[0].replacingOccurrences(of: "\\x20", with: " ")
            let pid = Int(parts[1]) ?? 0
            let namePart = parts.dropFirst(8).joined(separator: " ")
                .replacingOccurrences(of: "(ESTABLISHED)", with: "")
                .trimmingCharacters(in: .whitespaces)

            guard namePart.contains("->") else { continue }
            let sides = namePart.split(separator: "->").map(String.init)
            guard sides.count == 2 else { continue }

            let remote = sides[1].trimmingCharacters(in: .whitespaces)
            let (remoteIP, remotePort) = parseAddressPort(remote)

            // Skip local connections
            if localPrefixes.contains(where: { remoteIP.hasPrefix($0) }) { continue }
            if remoteIP == "*" || remoteIP.isEmpty { continue }

            rawConnections.append(RawConnection(
                processName: processName, pid: pid,
                remoteIP: remoteIP, remotePort: remotePort
            ))
        }

        // 4. Resolve real process names via PID (fixes "2.1.49" → "claude")
        let uniquePIDs = Set(rawConnections.map(\.pid))
        var pidNameCache: [Int: String] = [:]
        for pid in uniquePIDs {
            let result = ShellExecutor.run("/bin/ps", arguments: ["-p", String(pid), "-o", "comm="])
            let fullPath = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !fullPath.isEmpty {
                pidNameCache[pid] = URL(fileURLWithPath: fullPath).lastPathComponent
            }
        }

        // 5. Resolve geo for unique IPs via GeoIPService (URLSession + cache + rate limiting)
        let uniqueIPs = Array(Set(rawConnections.map(\.remoteIP)))
        let geoResults = await GeoIPService.shared.resolve(ips: uniqueIPs)

        // 6. Resolve hostnames via reverse DNS
        var hostnameCache: [String: String] = [:]
        for ip in uniqueIPs {
            let result = ShellExecutor.run("/usr/bin/host", arguments: ["-W", "2", ip], timeout: .network)
            if !result.timedOut && result.exitCode == 0, result.output.contains("domain name pointer") {
                let parts = result.output.components(separatedBy: "domain name pointer ")
                if parts.count > 1 {
                    var hostname = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                    if hostname.hasSuffix(".") { hostname.removeLast() }
                    hostnameCache[ip] = hostname
                }
            }
        }

        // 7. Resolve parent process chain for each unique PID
        struct ParentInfo {
            let name: String
            let path: String
            let signature: String
            let chain: String
        }
        var parentCache: [Int: ParentInfo] = [:]
        for pid in uniquePIDs {
            let resolvedName = pidNameCache[pid] ?? ""
            let info = resolveParent(pid: pid, processName: resolvedName)
            parentCache[pid] = ParentInfo(name: info.name, path: info.path, signature: info.signature, chain: info.chain)
        }

        // 8. Detect dylib injection for network-active processes
        var injectionCache: [Int: String] = [:]
        for pid in uniquePIDs {
            injectionCache[pid] = detectInjection(pid: pid)
        }

        // 9. Build snapshots
        return rawConnections.map { conn in
            let resolvedName = pidNameCache[conn.pid] ?? conn.processName
            let nettopKey = "\(resolvedName).\(conn.pid)"
            let bytes = bytesMap[nettopKey]
                ?? bytesMap["\(conn.processName).\(conn.pid)"]
                ?? bytesMap.first(where: { $0.key.hasPrefix(String(resolvedName.prefix(14))) })?.value
                ?? (bytesIn: Int64(0), bytesOut: Int64(0))
            let geo = geoResults[conn.remoteIP] ?? (country: "Unknown", countryCode: "?", org: "")
            let parent = parentCache[conn.pid] ?? ParentInfo(name: "", path: "", signature: "", chain: "")
            let injection = injectionCache[conn.pid] ?? ""

            return ConnectionSnapshot(
                processName: resolvedName,
                pid: conn.pid,
                remoteIP: conn.remoteIP,
                remotePort: conn.remotePort,
                country: geo.country,
                countryCode: geo.countryCode,
                organization: geo.org,
                bytesIn: bytes.bytesIn,
                bytesOut: bytes.bytesOut,
                hostname: hostnameCache[conn.remoteIP] ?? "",
                parentName: parent.name,
                parentPath: parent.path,
                parentSignature: parent.signature,
                injectionRisk: injection,
                parentChain: parent.chain
            )
        }
    }

    /// Walk the parent process chain (max 5 hops) until we find a signed process or reach launchd (PID 1).
    /// Falls back to detecting the .app bundle from the process's own executable path.
    /// Returns the signed parent info plus the full chain string for display.
    nonisolated private static func resolveParent(pid: Int, processName: String) -> (name: String, path: String, signature: String, chain: String) {
        var chainHops: [(name: String, pid: Int)] = []

        // Strategy 1: Walk the PPID chain looking for a signed parent
        var currentPID = pid
        for _ in 0..<5 {
            let ppidResult = ShellExecutor.run("/bin/ps", arguments: ["-p", String(currentPID), "-o", "ppid="])
            let ppidStr = ppidResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let ppid = Int(ppidStr), ppid > 1 else { break }

            let commResult = ShellExecutor.run("/bin/ps", arguments: ["-p", String(ppid), "-o", "comm="])
            let parentPath = commResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !parentPath.isEmpty else { break }

            let parentName = URL(fileURLWithPath: parentPath).lastPathComponent
            chainHops.append((name: parentName, pid: ppid))

            let verifyResult = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", parentPath])
            if verifyResult.exitCode == 0 {
                let authority = extractAuthority(path: parentPath)
                let chain = buildChainString(processName: processName, pid: pid, hops: chainHops, authority: authority)
                return (name: parentName, path: parentPath, signature: authority, chain: chain)
            }

            currentPID = ppid
        }

        // Strategy 2: Find the .app bundle containing this process's binary
        let procPath = ShellExecutor.run("/bin/ps", arguments: ["-p", String(pid), "-o", "comm="]).output
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if !procPath.isEmpty, let appBundle = findAppBundle(in: procPath) {
            let appName = URL(fileURLWithPath: appBundle).deletingPathExtension().lastPathComponent
            let verifyResult = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", appBundle])
            if verifyResult.exitCode == 0 {
                let authority = extractAuthority(path: appBundle)
                let chain = "\(processName.isEmpty ? "?" : processName) (\(pid)) → \(appName) [\(authority)]"
                return (name: appName, path: appBundle, signature: authority, chain: chain)
            }
        }

        // No signed parent found — return partial chain if we have hops
        if !chainHops.isEmpty {
            let chain = buildChainString(processName: processName, pid: pid, hops: chainHops, authority: "unsigned")
            return (name: "", path: "", signature: "", chain: chain)
        }

        return (name: "", path: "", signature: "", chain: "")
    }

    /// Build a readable chain string: "process (PID) → parent (PID) → ... → signedApp [Authority]"
    nonisolated private static func buildChainString(processName: String, pid: Int, hops: [(name: String, pid: Int)], authority: String) -> String {
        var parts = ["\(processName.isEmpty ? "?" : processName) (\(pid))"]
        for (i, hop) in hops.enumerated() {
            if i == hops.count - 1 {
                parts.append("\(hop.name) [\(authority)]")
            } else {
                parts.append("\(hop.name) (\(hop.pid))")
            }
        }
        return parts.joined(separator: " → ")
    }

    /// Extract the first Authority= line from codesign output.
    nonisolated private static func extractAuthority(path: String) -> String {
        let infoResult = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", path])
        let infoText = infoResult.output + "\n" + infoResult.error
        if let line = infoText.components(separatedBy: "\n").first(where: { $0.hasPrefix("Authority=") }),
           let range = line.range(of: "Authority=") {
            return String(line[range.upperBound...])
        }
        return ""
    }

    /// Find the outermost .app bundle in a file path.
    /// "/Applications/Chrome.app/Contents/Frameworks/Helper.app/.../Helper" → "/Applications/Chrome.app"
    nonisolated private static func findAppBundle(in path: String) -> String? {
        let components = path.components(separatedBy: "/")
        for (i, component) in components.enumerated() where component.hasSuffix(".app") {
            let bundlePath = components[0...i].joined(separator: "/")
            if FileManager.default.fileExists(atPath: bundlePath) {
                return bundlePath
            }
        }
        return nil
    }

    /// Check a process for signs of dylib injection.
    nonisolated private static func detectInjection(pid: Int) -> String {
        var risks: [String] = []

        // Check 1: DYLD_INSERT_LIBRARIES
        // ps environ= may be blocked by hardened runtime — that's fine (means protected)
        let dyldResult = ShellExecutor.shell("/bin/ps eww -p \(pid) 2>/dev/null | tr '\\0' '\\n' | grep DYLD_INSERT_LIBRARIES")
        if dyldResult.exitCode == 0 && !dyldResult.output.isEmpty {
            let libs = dyldResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            risks.append("DYLD_INSERT_LIBRARIES: \(libs)")
        }

        // Check 2: Unsigned dylibs loaded into signed processes
        let pidPath = ShellExecutor.run("/bin/ps", arguments: ["-p", String(pid), "-o", "comm="]).output
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pidPath.isEmpty else { return risks.joined(separator: "; ") }

        let isSigned = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", pidPath]).exitCode == 0
        if isSigned {
            let vmmapResult = ShellExecutor.shell("/usr/bin/vmmap \(pid) 2>/dev/null | grep '\\.dylib'")
            if vmmapResult.exitCode == 0 {
                let trustedPrefixes = ["/usr/lib/", "/System/", "/Library/Apple/", "/opt/homebrew/"]
                var checkedPaths = Set<String>()

                for line in vmmapResult.output.components(separatedBy: "\n") {
                    guard let slashRange = line.range(of: "/") else { continue }
                    var dylibPath = String(line[slashRange.lowerBound...])
                        .trimmingCharacters(in: .whitespaces)
                    if let dylibEnd = dylibPath.range(of: ".dylib") {
                        dylibPath = String(dylibPath[..<dylibEnd.upperBound])
                            .trimmingCharacters(in: .whitespaces)
                    }
                    guard !dylibPath.isEmpty, !checkedPaths.contains(dylibPath) else { continue }
                    checkedPaths.insert(dylibPath)

                    if trustedPrefixes.contains(where: { dylibPath.hasPrefix($0) }) { continue }

                    let dylibVerify = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", dylibPath])
                    if dylibVerify.exitCode != 0 {
                        risks.append("Unsigned dylib: \(dylibPath)")
                    }
                }
            }
        }

        return risks.joined(separator: "; ")
    }

    nonisolated private static func parseAddressPort(_ input: String) -> (String, String) {
        let str = input.trimmingCharacters(in: .whitespaces)
        if str.contains("[") {
            if let bracketEnd = str.range(of: "]:") {
                return (String(str[str.index(after: str.startIndex)..<bracketEnd.lowerBound]),
                        String(str[bracketEnd.upperBound...]))
            }
            return (str, "")
        }
        if let lastColon = str.lastIndex(of: ":") {
            return (String(str[..<lastColon]), String(str[str.index(after: lastColon)...]))
        }
        return (str, "")
    }
}
