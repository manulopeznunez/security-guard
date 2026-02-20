import Foundation
import os.log

// MARK: - Public Types

struct CVERecord: Sendable, Identifiable, Codable {
    let id: String
    let aliases: [String]
    let summary: String
    let severity: CVESeverity
    let fixedVersion: String?

    var displayID: String {
        aliases.first(where: { $0.hasPrefix("CVE-") }) ?? id
    }
}

enum CVESeverity: Int, Comparable, Sendable, Codable {
    case unknown = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    static func < (lhs: CVESeverity, rhs: CVESeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .unknown: "Unknown"
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        case .critical: "Critical"
        }
    }

    /// Parse from a CVSS 3.x base score (0.0-10.0)
    static func from(cvssScore: Double) -> CVESeverity {
        switch cvssScore {
        case ..<0.1: .unknown
        case 0.1..<4.0: .low
        case 4.0..<7.0: .medium
        case 7.0..<9.0: .high
        default: .critical
        }
    }

    /// Extract base score from a CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
    /// Falls back to parsing known metric values if no explicit score is embedded.
    static func from(cvssVector: String) -> CVESeverity {
        // Try to extract a numeric score if present at the end
        // Some vectors include "/score:X.X" but most don't — we estimate from AV/AC/PR/UI/S/C/I/A
        let components = cvssVector.components(separatedBy: "/")

        // Simple heuristic based on Attack Vector and Impact metrics
        let hasNetworkVector = components.contains("AV:N")
        let hasLowComplexity = components.contains("AC:L")
        let hasHighConfidentiality = components.contains("C:H")
        let hasHighIntegrity = components.contains("I:H")
        let hasHighAvailability = components.contains("A:H")
        let hasNoPriv = components.contains("PR:N")
        let hasNoInteraction = components.contains("UI:N")

        let highImpactCount = [hasHighConfidentiality, hasHighIntegrity, hasHighAvailability]
            .filter { $0 }.count

        if hasNetworkVector && hasLowComplexity && hasNoPriv && hasNoInteraction && highImpactCount >= 2 {
            return .critical
        } else if hasNetworkVector && highImpactCount >= 1 {
            return .high
        } else if hasNetworkVector || highImpactCount >= 1 {
            return .medium
        } else {
            return .low
        }
    }
}

// MARK: - Package Mapping

struct OSVPackageMapping: Sendable {
    let repoURL: String
    let tagFormats: [TagFormat]

    /// Build tag strings to try for a given version, in order of priority.
    func tagCandidates(for version: String) -> [String] {
        tagFormats.map { $0.apply(version: version) }
    }
}

enum TagFormat: Sendable {
    case prefixed(String)
    case prefixedV
    case plain
    case custom(@Sendable (String) -> String)

    func apply(version: String) -> String {
        switch self {
        case .prefixed(let prefix): "\(prefix)\(version)"
        case .prefixedV: "v\(version)"
        case .plain: version
        case .custom(let transform): transform(version)
        }
    }
}

// MARK: - CVEService Actor

actor CVEService {
    static let shared = CVEService()

    // MARK: - Configuration

    private let endpoint = URL(string: "https://api.osv.dev/v1/query")!
    private let cacheTTL: TimeInterval = 86400  // 24 hours
    private let maxConcurrent = 5

    // MARK: - State

    private var cache: [String: CachedCVEResult] = [:]
    private var backoffUntil: Date = .distantPast
    private var consecutiveFailures = 0

    // MARK: - URLSession (no cert pinning — OSV.dev is a public free API)

    private let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        config.waitsForConnectivity = false
        return URLSession(configuration: config)
    }()

    // MARK: - Cache

    private struct CachedCVEResult {
        let records: [CVERecord]
        let cachedAt: Date
        var isExpired: Bool { Date().timeIntervalSince(cachedAt) > 86400 }
    }

    // MARK: - Public API

    /// Look up known vulnerabilities for a list of Homebrew packages.
    /// Returns a dictionary mapping package name → [CVERecord].
    /// Packages without an OSV mapping are silently skipped.
    func lookup(packages: [(name: String, version: String)]) async -> [String: [CVERecord]] {
        var results: [String: [CVERecord]] = [:]
        var uncached: [(name: String, version: String)] = []

        // 1. Check cache
        for pkg in packages {
            if let cached = cache[pkg.name], !cached.isExpired {
                results[pkg.name] = cached.records
            } else {
                uncached.append(pkg)
            }
        }

        guard !uncached.isEmpty else { return results }

        // 2. Check backoff
        if Date() < backoffUntil {
            AuditLogger.network.warning("CVEService: in backoff period, returning cached-only results")
            return results
        }

        // 3. Filter to packages with a known mapping
        let mapped = uncached.compactMap { pkg -> (String, String, OSVPackageMapping)? in
            guard let mapping = Self.osvMappings[pkg.name] else { return nil }
            return (pkg.name, pkg.version, mapping)
        }

        AuditLogger.network.info(
            "CVEService: \(packages.count) requested, \(results.count) cached, \(mapped.count) to query"
        )

        // 4. Query in parallel with concurrency cap
        for batchStart in stride(from: 0, to: mapped.count, by: maxConcurrent) {
            let batchEnd = min(batchStart + maxConcurrent, mapped.count)
            let batch = Array(mapped[batchStart..<batchEnd])

            await withTaskGroup(of: (String, [CVERecord]).self) { group in
                for (name, version, mapping) in batch {
                    group.addTask {
                        let records = await self.querySinglePackage(
                            name: name, version: version, mapping: mapping
                        )
                        return (name, records)
                    }
                }
                for await (name, records) in group {
                    results[name] = records
                    cache[name] = CachedCVEResult(records: records, cachedAt: Date())
                }
            }
        }

        return results
    }

    // MARK: - Single Package Query

    private func querySinglePackage(
        name: String, version: String, mapping: OSVPackageMapping
    ) async -> [CVERecord] {
        let candidates = mapping.tagCandidates(for: version)

        for tag in candidates {
            do {
                let records = try await fetchFromOSV(repoURL: mapping.repoURL, versionTag: tag)
                consecutiveFailures = 0
                if !records.isEmpty {
                    AuditLogger.network.info(
                        "CVEService: \(name) \(tag) → \(records.count) vulnerabilities"
                    )
                    return records
                }
                // Empty result — try next tag format
            } catch {
                consecutiveFailures += 1
                let backoffSeconds = min(pow(2.0, Double(consecutiveFailures)) * 5, 300)
                backoffUntil = Date().addingTimeInterval(backoffSeconds)
                AuditLogger.network.error(
                    "CVEService: query failed for \(name): \(error.localizedDescription, privacy: .public). Backing off \(Int(backoffSeconds))s"
                )
                return []  // Stop trying on network error
            }
        }

        return []  // No results from any tag format
    }

    // MARK: - Network

    private func fetchFromOSV(repoURL: String, versionTag: String) async throws -> [CVERecord] {
        let body: [String: Any] = [
            "package": [
                "name": repoURL,
                "ecosystem": "GIT",
            ],
            "version": versionTag,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: body)

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        if httpResponse.statusCode == 429 {
            consecutiveFailures += 1
            let retryAfter = Double(httpResponse.value(forHTTPHeaderField: "Retry-After") ?? "60") ?? 60
            backoffUntil = Date().addingTimeInterval(retryAfter)
            throw URLError(.networkConnectionLost)
        }

        guard httpResponse.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }

        let osvResponse = try JSONDecoder().decode(OSVResponse.self, from: data)
        return parseVulnerabilities(osvResponse.vulns ?? [])
    }

    // MARK: - Parsing

    private func parseVulnerabilities(_ vulns: [OSVVulnerability]) -> [CVERecord] {
        vulns.map { vuln in
            let severity = parseSeverity(vuln.severity)
            let fixedVersion = parseFixedVersion(vuln.affected)

            return CVERecord(
                id: vuln.id,
                aliases: vuln.aliases ?? [],
                summary: vuln.summary ?? "No description available",
                severity: severity,
                fixedVersion: fixedVersion
            )
        }
    }

    private func parseSeverity(_ severityEntries: [OSVSeverity]?) -> CVESeverity {
        guard let entries = severityEntries else { return .unknown }

        for entry in entries {
            if entry.type == "CVSS_V3" || entry.type == "CVSS_V4" {
                return CVESeverity.from(cvssVector: entry.score)
            }
        }
        return .unknown
    }

    private func parseFixedVersion(_ affected: [OSVAffected]?) -> String? {
        guard let affected = affected else { return nil }
        for entry in affected {
            guard let ranges = entry.ranges else { continue }
            for range in ranges {
                guard let events = range.events else { continue }
                for event in events {
                    if let fixed = event.fixed, !fixed.isEmpty {
                        return fixed
                    }
                }
            }
        }
        return nil
    }

    // MARK: - OSV Mappings

    /// Mapping from Homebrew package names to OSV GIT ecosystem repo URLs and tag formats.
    /// Covers the security-critical packages. Non-mapped packages are skipped during lookup.
    static let osvMappings: [String: OSVPackageMapping] = [
        // Cryptography
        "openssl": OSVPackageMapping(
            repoURL: "https://github.com/openssl/openssl.git",
            tagFormats: [.prefixed("openssl-"), .prefixedV, .plain]
        ),
        "openssl@3": OSVPackageMapping(
            repoURL: "https://github.com/openssl/openssl.git",
            tagFormats: [.prefixed("openssl-"), .prefixedV, .plain]
        ),
        "openssl@1.1": OSVPackageMapping(
            repoURL: "https://github.com/openssl/openssl.git",
            tagFormats: [.prefixed("OpenSSL_"), .prefixed("openssl-")]
        ),
        "gnutls": OSVPackageMapping(
            repoURL: "https://gitlab.com/gnutls/gnutls.git",
            tagFormats: [.plain, .prefixedV]
        ),
        "libressl": OSVPackageMapping(
            repoURL: "https://github.com/libressl/portable.git",
            tagFormats: [.prefixedV, .plain]
        ),

        // Network tools
        "curl": OSVPackageMapping(
            repoURL: "https://github.com/curl/curl.git",
            tagFormats: [
                .custom { "curl-\($0.replacingOccurrences(of: ".", with: "_"))" },
                .prefixedV,
            ]
        ),
        "wget": OSVPackageMapping(
            repoURL: "https://git.savannah.gnu.org/git/wget.git",
            tagFormats: [.prefixedV, .plain]
        ),

        // Version control
        "git": OSVPackageMapping(
            repoURL: "https://github.com/git/git.git",
            tagFormats: [.prefixedV, .plain]
        ),
        "git-lfs": OSVPackageMapping(
            repoURL: "https://github.com/git-lfs/git-lfs.git",
            tagFormats: [.prefixedV]
        ),

        // SSH/Security
        "openssh": OSVPackageMapping(
            repoURL: "https://github.com/openssh/openssh-portable.git",
            tagFormats: [
                .custom { "V_\($0.replacingOccurrences(of: ".", with: "_"))" },
                .prefixedV,
            ]
        ),
        "ssh-copy-id": OSVPackageMapping(
            repoURL: "https://github.com/openssh/openssh-portable.git",
            tagFormats: [
                .custom { "V_\($0.replacingOccurrences(of: ".", with: "_"))" },
                .prefixedV,
            ]
        ),
        "gnupg": OSVPackageMapping(
            repoURL: "https://github.com/gpg/gnupg.git",
            tagFormats: [.prefixed("gnupg-"), .prefixedV]
        ),
        "gpg": OSVPackageMapping(
            repoURL: "https://github.com/gpg/gnupg.git",
            tagFormats: [.prefixed("gnupg-"), .prefixedV]
        ),

        // Language runtimes
        "python": OSVPackageMapping(
            repoURL: "https://github.com/python/cpython.git",
            tagFormats: [.prefixedV, .plain]
        ),
        "python@3.12": OSVPackageMapping(
            repoURL: "https://github.com/python/cpython.git",
            tagFormats: [.prefixedV, .plain]
        ),
        "python@3.13": OSVPackageMapping(
            repoURL: "https://github.com/python/cpython.git",
            tagFormats: [.prefixedV, .plain]
        ),
        "python@3.14": OSVPackageMapping(
            repoURL: "https://github.com/python/cpython.git",
            tagFormats: [.prefixedV, .plain]
        ),
        "node": OSVPackageMapping(
            repoURL: "https://github.com/nodejs/node.git",
            tagFormats: [.prefixedV]
        ),
        "go": OSVPackageMapping(
            repoURL: "https://github.com/golang/go.git",
            tagFormats: [.prefixed("go"), .prefixedV]
        ),
        "ruby": OSVPackageMapping(
            repoURL: "https://github.com/ruby/ruby.git",
            tagFormats: [
                .prefixedV,
                .custom { "v\($0.replacingOccurrences(of: ".", with: "_"))" },
            ]
        ),

        // Servers
        "nginx": OSVPackageMapping(
            repoURL: "https://github.com/nginx/nginx.git",
            tagFormats: [.prefixed("release-"), .plain]
        ),
        "httpd": OSVPackageMapping(
            repoURL: "https://github.com/apache/httpd.git",
            tagFormats: [.plain, .prefixedV]
        ),

        // Databases
        "postgresql": OSVPackageMapping(
            repoURL: "https://github.com/postgres/postgres.git",
            tagFormats: [
                .custom { "REL_\($0.replacingOccurrences(of: ".", with: "_"))" },
                .prefixedV,
            ]
        ),
        "mysql": OSVPackageMapping(
            repoURL: "https://github.com/mysql/mysql-server.git",
            tagFormats: [.prefixed("mysql-"), .plain]
        ),
        "redis": OSVPackageMapping(
            repoURL: "https://github.com/redis/redis.git",
            tagFormats: [.plain, .prefixedV]
        ),
    ]
}

// MARK: - OSV API Codable Types

private struct OSVResponse: Decodable {
    let vulns: [OSVVulnerability]?
}

private struct OSVVulnerability: Decodable {
    let id: String
    let summary: String?
    let aliases: [String]?
    let severity: [OSVSeverity]?
    let affected: [OSVAffected]?
}

private struct OSVSeverity: Decodable {
    let type: String
    let score: String
}

private struct OSVAffected: Decodable {
    let ranges: [OSVRange]?
}

private struct OSVRange: Decodable {
    let type: String?
    let events: [OSVEvent]?
}

private struct OSVEvent: Decodable {
    let introduced: String?
    let fixed: String?
}
