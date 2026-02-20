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

        // 7. Build snapshots
        return rawConnections.map { conn in
            let resolvedName = pidNameCache[conn.pid] ?? conn.processName
            let nettopKey = "\(resolvedName).\(conn.pid)"
            let bytes = bytesMap[nettopKey]
                ?? bytesMap["\(conn.processName).\(conn.pid)"]
                ?? bytesMap.first(where: { $0.key.hasPrefix(String(resolvedName.prefix(14))) })?.value
                ?? (bytesIn: Int64(0), bytesOut: Int64(0))
            let geo = geoResults[conn.remoteIP] ?? (country: "Unknown", countryCode: "?", org: "")

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
                hostname: hostnameCache[conn.remoteIP] ?? ""
            )
        }
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
