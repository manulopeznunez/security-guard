import Foundation
import SQLite3
import os.log

final class DatabaseManager: Sendable {
    static let shared = DatabaseManager()

    private let dbPath: String

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = appSupport.appendingPathComponent("MacSecurityGuard", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        dbPath = dir.appendingPathComponent("history.db").path
        Self.verifyDirectoryPermissions(dir)
        createTables()
    }

    /// Verifies the database directory has restrictive permissions (0700) and resets if tampered.
    private static func verifyDirectoryPermissions(_ dir: URL) {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: dir.path),
              let perms = attrs[.posixPermissions] as? Int else { return }
        if perms != 0o700 {
            AuditLogger.security.critical(
                "Database directory permissions changed from 0700 to \(String(perms, radix: 8), privacy: .public). Resetting."
            )
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        }
    }

    // MARK: - Database Setup

    private func createTables() {
        let db = open()
        defer { close(db) }

        let createConnectionsSQL = """
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            process_name TEXT NOT NULL,
            pid INTEGER NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port TEXT NOT NULL,
            country TEXT DEFAULT '',
            country_code TEXT DEFAULT '',
            organization TEXT DEFAULT '',
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            hostname TEXT DEFAULT '',
            process_path TEXT DEFAULT ''
        );
        """

        let createIndexSQL = """
        CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp);
        CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(remote_ip);
        CREATE INDEX IF NOT EXISTS idx_connections_process ON connections(process_name);
        """

        execute(db: db, sql: createConnectionsSQL)
        for sql in createIndexSQL.components(separatedBy: ";") where !sql.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            execute(db: db, sql: sql)
        }

        // Migration: add hostname column if missing (for existing databases)
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN hostname TEXT DEFAULT '';")
        // ^ silently fails if column already exists — that's fine

        // Migration: parent process tracking columns
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN parent_name TEXT DEFAULT '';")
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN parent_path TEXT DEFAULT '';")
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN parent_signature TEXT DEFAULT '';")

        // Migration: dylib injection risk column
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN injection_risk TEXT DEFAULT '';")

        // Migration: full parent process chain
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN parent_chain TEXT DEFAULT '';")

        // Migration: comprehensive process trace
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN process_trace TEXT DEFAULT '';")

        // Migration: full executable path for process identification
        execute(db: db, sql: "ALTER TABLE connections ADD COLUMN process_path TEXT DEFAULT '';")

        // Migration: clear false-positive injection_risk data from vmmap-based detection.
        // System dylibs (/usr/lib/, /System/) are SSV-protected but were incorrectly flagged.
        execute(db: db, sql: "UPDATE connections SET injection_risk = '' WHERE injection_risk LIKE '%/usr/lib/%' OR injection_risk LIKE '%/System/%' OR injection_risk LIKE '%SM=COW%';")

        // Security scores history
        let createScoresSQL = """
        CREATE TABLE IF NOT EXISTS security_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            enabled_count INTEGER NOT NULL,
            total_count INTEGER NOT NULL,
            score REAL NOT NULL,
            details TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_scores_timestamp ON security_scores(timestamp);
        """
        for sql in createScoresSQL.components(separatedBy: ";") where !sql.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            execute(db: db, sql: sql)
        }

        // Listening ports history (attack surface monitoring)
        let createListeningSQL = """
        CREATE TABLE IF NOT EXISTS listening_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            process_name TEXT NOT NULL,
            pid INTEGER NOT NULL,
            local_port TEXT NOT NULL,
            local_address TEXT DEFAULT '',
            process_path TEXT DEFAULT '',
            parent_signature TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_listening_timestamp ON listening_ports(timestamp);
        CREATE INDEX IF NOT EXISTS idx_listening_port ON listening_ports(local_port);
        """
        for sql in createListeningSQL.components(separatedBy: ";") where !sql.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            execute(db: db, sql: sql)
        }

        // Approval audit trail
        let createApprovalHistorySQL = """
        CREATE TABLE IF NOT EXISTS approval_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            category TEXT NOT NULL,
            item_id TEXT NOT NULL,
            action TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_approval_history_timestamp ON approval_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_approval_history_category ON approval_history(category);
        """
        for sql in createApprovalHistorySQL.components(separatedBy: ";") where !sql.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            execute(db: db, sql: sql)
        }
    }

    // MARK: - Insert

    func insertSnapshot(connections: [ConnectionSnapshot]) {
        AuditLogger.database.info("Inserting \(connections.count) connection snapshots")
        let db = open()
        defer { close(db) }

        let sql = """
        INSERT INTO connections (process_name, pid, remote_ip, remote_port, country, country_code, organization, bytes_in, bytes_out, hostname, parent_name, parent_path, parent_signature, injection_risk, parent_chain, process_trace, process_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        // Use a transaction for performance
        execute(db: db, sql: "BEGIN TRANSACTION;")

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            execute(db: db, sql: "ROLLBACK;")
            return
        }

        for conn in connections {
            sqlite3_bind_text(stmt, 1, (conn.processName as NSString).utf8String, -1, nil)
            sqlite3_bind_int(stmt, 2, Int32(conn.pid))
            sqlite3_bind_text(stmt, 3, (conn.remoteIP as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 4, (conn.remotePort as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 5, (conn.country as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 6, (conn.countryCode as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 7, (conn.organization as NSString).utf8String, -1, nil)
            sqlite3_bind_int64(stmt, 8, Int64(conn.bytesIn))
            sqlite3_bind_int64(stmt, 9, Int64(conn.bytesOut))
            sqlite3_bind_text(stmt, 10, (conn.hostname as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 11, (conn.parentName as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 12, (conn.parentPath as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 13, (conn.parentSignature as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 14, (conn.injectionRisk as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 15, (conn.parentChain as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 16, (conn.processTrace as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 17, (conn.processPath as NSString).utf8String, -1, nil)
            sqlite3_step(stmt)
            sqlite3_reset(stmt)
        }

        sqlite3_finalize(stmt)
        execute(db: db, sql: "COMMIT;")
    }

    // MARK: - Queries

    /// Top IPs by connection count in the last N days.
    func topIPs(days: Int, limit: Int = 30) -> [IPSummary] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT remote_ip, country, country_code, organization,
               COUNT(*) as times_seen,
               COUNT(DISTINCT process_name) as app_count,
               GROUP_CONCAT(DISTINCT process_name) as app_names,
               SUM(bytes_in) as total_in,
               SUM(bytes_out) as total_out,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen,
               MAX(hostname) as hostname
        FROM connections
        WHERE timestamp >= datetime('now', 'localtime', ?1)
        GROUP BY remote_ip
        ORDER BY times_seen DESC
        LIMIT ?2;
        """

        var results: [IPSummary] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, Int32(limit))

        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(IPSummary(
                remoteIP: String(cString: sqlite3_column_text(stmt, 0)),
                country: String(cString: sqlite3_column_text(stmt, 1)),
                countryCode: String(cString: sqlite3_column_text(stmt, 2)),
                organization: String(cString: sqlite3_column_text(stmt, 3)),
                timesSeen: Int(sqlite3_column_int(stmt, 4)),
                appCount: Int(sqlite3_column_int(stmt, 5)),
                appNames: String(cString: sqlite3_column_text(stmt, 6)),
                totalBytesIn: Int64(sqlite3_column_int64(stmt, 7)),
                totalBytesOut: Int64(sqlite3_column_int64(stmt, 8)),
                firstSeen: String(cString: sqlite3_column_text(stmt, 9)),
                lastSeen: String(cString: sqlite3_column_text(stmt, 10)),
                hostname: sqlite3_column_text(stmt, 11).map { String(cString: $0) } ?? ""
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    /// Top apps by data transferred in the last N days.
    func topApps(days: Int, limit: Int = 20) -> [AppSummary] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT process_name,
               COUNT(*) as times_seen,
               COUNT(DISTINCT remote_ip) as unique_ips,
               COUNT(DISTINCT country) as unique_countries,
               SUM(bytes_in) as total_in,
               SUM(bytes_out) as total_out,
               MAX(parent_name) as parent_name,
               MAX(parent_signature) as parent_signature,
               MAX(injection_risk) as injection_risk,
               MAX(parent_chain) as parent_chain,
               MAX(process_trace) as process_trace,
               MAX(process_path) as process_path
        FROM connections
        WHERE timestamp >= datetime('now', 'localtime', ?1)
        GROUP BY process_name
        ORDER BY (total_in + total_out) DESC
        LIMIT ?2;
        """

        var results: [AppSummary] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, Int32(limit))

        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(AppSummary(
                processName: String(cString: sqlite3_column_text(stmt, 0)),
                timesSeen: Int(sqlite3_column_int(stmt, 1)),
                uniqueIPs: Int(sqlite3_column_int(stmt, 2)),
                uniqueCountries: Int(sqlite3_column_int(stmt, 3)),
                totalBytesIn: Int64(sqlite3_column_int64(stmt, 4)),
                totalBytesOut: Int64(sqlite3_column_int64(stmt, 5)),
                parentName: sqlite3_column_text(stmt, 6).map { String(cString: $0) } ?? "",
                parentSignature: sqlite3_column_text(stmt, 7).map { String(cString: $0) } ?? "",
                injectionRisk: sqlite3_column_text(stmt, 8).map { String(cString: $0) } ?? "",
                parentChain: sqlite3_column_text(stmt, 9).map { String(cString: $0) } ?? "",
                processTrace: sqlite3_column_text(stmt, 10).map { String(cString: $0) } ?? "",
                processPath: sqlite3_column_text(stmt, 11).map { String(cString: $0) } ?? ""
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    /// Connections to a specific IP in the last N days.
    func connectionsForIP(_ ip: String, days: Int) -> [ConnectionRecord] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT timestamp, process_name, pid, remote_port, bytes_in, bytes_out
        FROM connections
        WHERE remote_ip = ?1 AND timestamp >= datetime('now', 'localtime', ?2)
        ORDER BY timestamp DESC
        LIMIT 200;
        """

        var results: [ConnectionRecord] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        sqlite3_bind_text(stmt, 1, (ip as NSString).utf8String, -1, nil)
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 2, (daysParam as NSString).utf8String, -1, nil)

        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(ConnectionRecord(
                timestamp: String(cString: sqlite3_column_text(stmt, 0)),
                processName: String(cString: sqlite3_column_text(stmt, 1)),
                pid: Int(sqlite3_column_int(stmt, 2)),
                remotePort: String(cString: sqlite3_column_text(stmt, 3)),
                bytesIn: Int64(sqlite3_column_int64(stmt, 4)),
                bytesOut: Int64(sqlite3_column_int64(stmt, 5))
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    /// Countries summary for the last N days.
    func topCountries(days: Int) -> [CountrySummary] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT country, country_code,
               COUNT(*) as times_seen,
               COUNT(DISTINCT remote_ip) as unique_ips,
               COUNT(DISTINCT process_name) as app_count,
               SUM(bytes_in) as total_in,
               SUM(bytes_out) as total_out
        FROM connections
        WHERE timestamp >= datetime('now', 'localtime', ?1)
          AND country != '' AND country != 'Local' AND country != 'Unknown'
        GROUP BY country
        ORDER BY times_seen DESC;
        """

        var results: [CountrySummary] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)

        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(CountrySummary(
                country: String(cString: sqlite3_column_text(stmt, 0)),
                countryCode: String(cString: sqlite3_column_text(stmt, 1)),
                timesSeen: Int(sqlite3_column_int(stmt, 2)),
                uniqueIPs: Int(sqlite3_column_int(stmt, 3)),
                appCount: Int(sqlite3_column_int(stmt, 4)),
                totalBytesIn: Int64(sqlite3_column_int64(stmt, 5)),
                totalBytesOut: Int64(sqlite3_column_int64(stmt, 6))
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    /// Total database stats.
    func totalStats() -> (records: Int, oldestRecord: String, dbSizeKB: Int64) {
        let db = open()
        defer { close(db) }

        var records = 0
        var oldest = "N/A"
        var stmt: OpaquePointer?

        if sqlite3_prepare_v2(db, "SELECT COUNT(*), MIN(timestamp) FROM connections;", -1, &stmt, nil) == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                records = Int(sqlite3_column_int(stmt, 0))
                if let text = sqlite3_column_text(stmt, 1) {
                    oldest = String(cString: text)
                }
            }
        }
        sqlite3_finalize(stmt)

        let fileSize = (try? FileManager.default.attributesOfItem(atPath: dbPath)[.size] as? Int64) ?? 0

        return (records, oldest, fileSize / 1024)
    }

    /// Purge old records.
    func purgeOlderThan(days: Int) {
        AuditLogger.database.info("Purging records older than \(days) days")
        let db = open()
        defer { close(db) }

        let sql = "DELETE FROM connections WHERE timestamp < datetime('now', 'localtime', ?1);"
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
            let daysParam = "-\(days) days"
            sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
            sqlite3_step(stmt)
        }
        sqlite3_finalize(stmt)
        execute(db: db, sql: "VACUUM;")
    }

    // MARK: - Listening Ports

    func insertListeningPorts(_ ports: [ListeningPortSnapshot]) {
        guard !ports.isEmpty else { return }
        AuditLogger.database.info("Inserting \(ports.count) listening port snapshots")
        let db = open()
        defer { close(db) }

        let sql = """
        INSERT INTO listening_ports (process_name, pid, local_port, local_address, process_path, parent_signature)
        VALUES (?, ?, ?, ?, ?, ?);
        """

        execute(db: db, sql: "BEGIN TRANSACTION;")

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            execute(db: db, sql: "ROLLBACK;")
            return
        }

        for port in ports {
            sqlite3_bind_text(stmt, 1, (port.processName as NSString).utf8String, -1, nil)
            sqlite3_bind_int(stmt, 2, Int32(port.pid))
            sqlite3_bind_text(stmt, 3, (port.localPort as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 4, (port.localAddress as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 5, (port.processPath as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 6, (port.parentSignature as NSString).utf8String, -1, nil)
            sqlite3_step(stmt)
            sqlite3_reset(stmt)
        }

        sqlite3_finalize(stmt)
        execute(db: db, sql: "COMMIT;")
    }

    /// Top listening ports by frequency in the last N days, grouped by port+process.
    func topListeningPorts(days: Int, limit: Int = 50) -> [ListeningPortSummary] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT local_port, local_address, process_name, process_path, parent_signature,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen,
               COUNT(*) as times_seen
        FROM listening_ports
        WHERE timestamp >= datetime('now', 'localtime', ?1)
        GROUP BY local_port, process_name
        ORDER BY times_seen DESC
        LIMIT ?2;
        """

        var results: [ListeningPortSummary] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, Int32(limit))

        while sqlite3_step(stmt) == SQLITE_ROW {
            let port = String(cString: sqlite3_column_text(stmt, 0))
            let address = String(cString: sqlite3_column_text(stmt, 1))
            let process = String(cString: sqlite3_column_text(stmt, 2))
            let path = sqlite3_column_text(stmt, 3).map { String(cString: $0) } ?? ""
            let signature = sqlite3_column_text(stmt, 4).map { String(cString: $0) } ?? ""
            let firstSeen = String(cString: sqlite3_column_text(stmt, 5))
            let lastSeen = String(cString: sqlite3_column_text(stmt, 6))
            let timesSeen = Int(sqlite3_column_int(stmt, 7))

            let (risk, reason) = Self.classifyPortRisk(port: port, processName: process, signature: signature)

            results.append(ListeningPortSummary(
                localPort: port,
                localAddress: address,
                processName: process,
                processPath: path,
                parentSignature: signature,
                firstSeen: firstSeen,
                lastSeen: lastSeen,
                timesSeen: timesSeen,
                isCurrentlyOpen: false,
                risk: risk,
                riskReason: reason
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    /// Purge old listening port records.
    func purgeOldListeningPorts(days: Int) {
        AuditLogger.database.info("Purging listening port records older than \(days) days")
        let db = open()
        defer { close(db) }

        let sql = "DELETE FROM listening_ports WHERE timestamp < datetime('now', 'localtime', ?1);"
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
            let daysParam = "-\(days) days"
            sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
            sqlite3_step(stmt)
        }
        sqlite3_finalize(stmt)
    }

    // MARK: - Approval Audit Trail

    func insertApprovalEvent(category: String, itemID: String, action: String) {
        let db = open()
        defer { close(db) }

        let sql = "INSERT INTO approval_history (category, item_id, action) VALUES (?, ?, ?);"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        sqlite3_bind_text(stmt, 1, (category as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (itemID as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 3, (action as NSString).utf8String, -1, nil)
        sqlite3_step(stmt)
        sqlite3_finalize(stmt)
    }

    func approvalHistory(days: Int = 30, category: String? = nil) -> [ApprovalEvent] {
        let db = open()
        defer { close(db) }

        let sql: String
        if category != nil {
            sql = """
            SELECT timestamp, category, item_id, action
            FROM approval_history
            WHERE timestamp >= datetime('now', 'localtime', ?1)
              AND category = ?2
            ORDER BY timestamp DESC
            LIMIT 500;
            """
        } else {
            sql = """
            SELECT timestamp, category, item_id, action
            FROM approval_history
            WHERE timestamp >= datetime('now', 'localtime', ?1)
            ORDER BY timestamp DESC
            LIMIT 500;
            """
        }

        var results: [ApprovalEvent] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)
        if let category {
            sqlite3_bind_text(stmt, 2, (category as NSString).utf8String, -1, nil)
        }

        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(ApprovalEvent(
                timestamp: String(cString: sqlite3_column_text(stmt, 0)),
                category: String(cString: sqlite3_column_text(stmt, 1)),
                itemID: String(cString: sqlite3_column_text(stmt, 2)),
                action: String(cString: sqlite3_column_text(stmt, 3))
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    // MARK: - Port Risk Classification

    private static let dangerousPorts: Set<String> = ["22", "5900", "5988", "3283", "548", "445"]
    private static let devPorts: Set<String> = [
        "3000", "3001", "4200", "5000", "5173", "5432", "3306", "6379", "27017",
        "8080", "8443", "8000", "8888", "9090", "9200", "11211", "15672", "2375"
    ]

    static func classifyPortRisk(port: String, processName: String, signature: String) -> (PortRisk, String) {
        if dangerousPorts.contains(port) {
            return (.dangerous, "High-risk service port (\(port))")
        }
        if signature.isEmpty || signature == "unsigned" {
            return (.dangerous, "Unsigned process listening on port \(port)")
        }
        if devPorts.contains(port) {
            return (.warning, "Development/database port (\(port))")
        }
        return (.safe, "Signed process on standard port")
    }

    // MARK: - Security Scores

    func insertScore(enabled: Int, total: Int, details: String) {
        let db = open()
        defer { close(db) }

        let sql = "INSERT INTO security_scores (enabled_count, total_count, score, details) VALUES (?, ?, ?, ?);"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        sqlite3_bind_int(stmt, 1, Int32(enabled))
        sqlite3_bind_int(stmt, 2, Int32(total))
        sqlite3_bind_double(stmt, 3, total > 0 ? Double(enabled) / Double(total) : 0)
        sqlite3_bind_text(stmt, 4, (details as NSString).utf8String, -1, nil)
        sqlite3_step(stmt)
        sqlite3_finalize(stmt)
    }

    func scoreHistory(days: Int = 30) -> [ScoreSnapshot] {
        let db = open()
        defer { close(db) }

        let sql = """
        SELECT id, timestamp, enabled_count, total_count, score, details
        FROM security_scores
        WHERE timestamp >= datetime('now', 'localtime', ?1)
        ORDER BY timestamp DESC;
        """

        var results: [ScoreSnapshot] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        let daysParam = "-\(days) days"
        sqlite3_bind_text(stmt, 1, (daysParam as NSString).utf8String, -1, nil)

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        while sqlite3_step(stmt) == SQLITE_ROW {
            let tsString = String(cString: sqlite3_column_text(stmt, 1))
            results.append(ScoreSnapshot(
                id: Int(sqlite3_column_int(stmt, 0)),
                timestamp: formatter.date(from: tsString) ?? Date(),
                enabledCount: Int(sqlite3_column_int(stmt, 2)),
                totalCount: Int(sqlite3_column_int(stmt, 3)),
                score: sqlite3_column_double(stmt, 4),
                details: String(cString: sqlite3_column_text(stmt, 5))
            ))
        }
        sqlite3_finalize(stmt)
        return results
    }

    func lastScanDate() -> Date? {
        let db = open()
        defer { close(db) }

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT MAX(timestamp) FROM security_scores;", -1, &stmt, nil) == SQLITE_OK else { return nil }

        var result: Date?
        if sqlite3_step(stmt) == SQLITE_ROW, let text = sqlite3_column_text(stmt, 0) {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            result = formatter.date(from: String(cString: text))
        }
        sqlite3_finalize(stmt)
        return result
    }

    // MARK: - SQLite Helpers

    private func open() -> OpaquePointer? {
        var db: OpaquePointer?
        let result = sqlite3_open(dbPath, &db)
        if result != SQLITE_OK {
            AuditLogger.database.error("Failed to open database: code \(result)")
        }
        // Enable WAL mode for better concurrent read/write performance
        execute(db: db, sql: "PRAGMA journal_mode=WAL;")
        // Prevent other processes from reading the DB while open
        execute(db: db, sql: "PRAGMA locking_mode=EXCLUSIVE;")
        // Zero-fill deleted content instead of leaving it recoverable on disk
        execute(db: db, sql: "PRAGMA secure_delete=ON;")
        return db
    }

    private func close(_ db: OpaquePointer?) {
        sqlite3_close(db)
    }

    @discardableResult
    private func execute(db: OpaquePointer?, sql: String) -> Bool {
        let success = sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK
        if !success {
            AuditLogger.database.error("SQL failed: \(sql.prefix(100), privacy: .public)")
        }
        return success
    }
}

// MARK: - Data Types

struct ConnectionSnapshot: Sendable {
    let processName: String
    let pid: Int
    let remoteIP: String
    let remotePort: String
    let country: String
    let countryCode: String
    let organization: String
    let bytesIn: Int64
    let bytesOut: Int64
    let hostname: String
    let parentName: String
    let parentPath: String
    let parentSignature: String
    let injectionRisk: String
    let parentChain: String
    let processTrace: String
    let processPath: String
}

struct IPSummary: Identifiable, Sendable {
    let id = UUID()
    let remoteIP: String
    let country: String
    let countryCode: String
    let organization: String
    let timesSeen: Int
    let appCount: Int
    let appNames: String
    let totalBytesIn: Int64
    let totalBytesOut: Int64
    let firstSeen: String
    let lastSeen: String
    let hostname: String
}

struct AppSummary: Identifiable, Sendable {
    let id = UUID()
    let processName: String
    let timesSeen: Int
    let uniqueIPs: Int
    let uniqueCountries: Int
    let totalBytesIn: Int64
    let totalBytesOut: Int64
    var isSigned: Bool = false
    var signatureAuthority: String = ""
    var parentName: String = ""
    var parentSignature: String = ""
    var injectionRisk: String = ""
    var parentChain: String = ""
    var processTrace: String = ""
    var processPath: String = ""
}

struct ConnectionRecord: Identifiable, Sendable {
    let id = UUID()
    let timestamp: String
    let processName: String
    let pid: Int
    let remotePort: String
    let bytesIn: Int64
    let bytesOut: Int64
}

struct CountrySummary: Identifiable, Sendable {
    let id = UUID()
    let country: String
    let countryCode: String
    let timesSeen: Int
    let uniqueIPs: Int
    let appCount: Int
    let totalBytesIn: Int64
    let totalBytesOut: Int64
}

struct ScoreSnapshot: Identifiable, Sendable {
    let id: Int
    let timestamp: Date
    let enabledCount: Int
    let totalCount: Int
    let score: Double
    let details: String
}

struct ApprovalEvent: Identifiable, Sendable {
    let id = UUID()
    let timestamp: String
    let category: String
    let itemID: String
    let action: String
}
