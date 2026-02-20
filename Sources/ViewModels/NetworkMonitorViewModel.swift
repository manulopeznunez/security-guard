import Foundation

@Observable
@MainActor
final class NetworkMonitorViewModel {
    var connections: [NetworkConnection] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Listing connections..."

        let raw = await Self.getConnections()
        connections = raw

        progress = "Verifying code signatures..."
        let signed = await Self.verifySignatures(for: raw)
        connections = signed

        progress = "Resolving \(Set(signed.compactMap { $0.isLocal ? nil : $0.remoteAddress }).count) IPs..."

        // Resolve geo info for unique non-local IPs
        let resolved = await Self.resolveGeo(for: signed)
        connections = resolved
        progress = "Done. \(resolved.count) connections."
        isScanning = false
        ScanDateTracker.record(.networkMonitor)
        let unsignedCount = resolved.filter { !$0.isSigned }.count
        DatabaseManager.shared.insertScanHistory(
            scanner: "networkMonitor", total: resolved.count, flagged: unsignedCount,
            summary: "\(resolved.count) connections, \(unsignedCount) unsigned"
        )
    }

    nonisolated static func getConnections() async -> [NetworkConnection] {
        // +c 0 = no name truncation
        let result = ShellExecutor.shell("lsof +c 0 -i -n -P 2>/dev/null | grep -E 'ESTABLISHED|LISTEN'")
        let lines = result.output.components(separatedBy: "\n").filter { !$0.isEmpty }

        var connections: [NetworkConnection] = []
        var pidNameCache: [Int: String] = [:]

        for line in lines {
            // lsof output format:
            // COMMAND   PID USER  FD TYPE  DEVICE SIZE/OFF NODE NAME
            // Slack     9198 user  25u IPv4 0xe52  0t0 TCP 192.168.0.11:55289->176.34.164.201:443 (ESTABLISHED)
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 9 else { continue }

            let lsofName = parts[0].replacingOccurrences(of: "\\x20", with: " ")
            let pid = Int(parts[1]) ?? 0

            // Resolve real name via ps (fixes "2.1.49" → "claude")
            if pidNameCache[pid] == nil {
                let psResult = ShellExecutor.run("/bin/ps", arguments: ["-p", String(pid), "-o", "comm="])
                let fullPath = psResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
                pidNameCache[pid] = fullPath.isEmpty ? lsofName : URL(fileURLWithPath: fullPath).lastPathComponent
            }
            let processName = pidNameCache[pid] ?? lsofName

            // The connection info is in the last parts
            // Find the TCP/UDP entry with ->
            let namePart = parts.dropFirst(8).joined(separator: " ")
            let state: String
            if namePart.contains("(ESTABLISHED)") {
                state = "ESTABLISHED"
            } else if namePart.contains("(LISTEN)") {
                state = "LISTEN"
            } else {
                state = "OTHER"
            }

            // Parse: 192.168.0.11:55289->176.34.164.201:443
            let cleanName = namePart
                .replacingOccurrences(of: "(ESTABLISHED)", with: "")
                .replacingOccurrences(of: "(LISTEN)", with: "")
                .trimmingCharacters(in: .whitespaces)

            if cleanName.contains("->") {
                // Outgoing connection
                let sides = cleanName.split(separator: "->").map(String.init)
                guard sides.count == 2 else { continue }

                let local = parseAddressPort(sides[0])
                let remote = parseAddressPort(sides[1])

                let isLocal = isLocalAddress(remote.address)

                connections.append(NetworkConnection(
                    processName: processName,
                    pid: pid,
                    localAddress: local.address,
                    localPort: local.port,
                    remoteAddress: remote.address,
                    remotePort: remote.port,
                    state: state,
                    country: isLocal ? "Local" : "...",
                    countryCode: isLocal ? "LAN" : "",
                    organization: isLocal ? "Local Network" : "",
                    hostname: "",
                    isLocal: isLocal,
                    isSigned: false,
                    signatureAuthority: ""
                ))
            } else if state == "LISTEN" {
                let local = parseAddressPort(cleanName)
                connections.append(NetworkConnection(
                    processName: processName,
                    pid: pid,
                    localAddress: local.address,
                    localPort: local.port,
                    remoteAddress: "*",
                    remotePort: "*",
                    state: state,
                    country: "Local",
                    countryCode: "LAN",
                    organization: "Listening",
                    hostname: "",
                    isLocal: true,
                    isSigned: false,
                    signatureAuthority: ""
                ))
            }
        }

        return connections
    }

    nonisolated static func resolveGeo(for connections: [NetworkConnection]) async -> [NetworkConnection] {
        var updated = connections

        // Collect unique non-local IPs
        let uniqueIPs = Array(Set(
            connections.compactMap { $0.isLocal ? nil : $0.remoteAddress }
        ))

        // Use GeoIPService (URLSession + cache + rate limiting + cert pinning)
        let geoResults = await GeoIPService.shared.resolve(ips: uniqueIPs)

        // Resolve hostnames via reverse DNS
        var hostnameCache: [String: String] = [:]
        for ip in uniqueIPs {
            let dnsResult = ShellExecutor.run("/usr/bin/host", arguments: ["-W", "2", ip], timeout: .network)
            if !dnsResult.timedOut && dnsResult.exitCode == 0,
               dnsResult.output.contains("domain name pointer") {
                let dnsParts = dnsResult.output.components(separatedBy: "domain name pointer ")
                if dnsParts.count > 1 {
                    var hostname = dnsParts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                    if hostname.hasSuffix(".") { hostname.removeLast() }
                    hostnameCache[ip] = hostname
                }
            }
        }

        // Apply geo info and hostnames to connections
        for i in updated.indices where !updated[i].isLocal {
            if let geo = geoResults[updated[i].remoteAddress] {
                updated[i].country = geo.country
                updated[i].countryCode = geo.countryCode
                updated[i].organization = geo.org
            } else {
                updated[i].country = "Unknown"
                updated[i].countryCode = "?"
                updated[i].organization = ""
            }
            updated[i].hostname = hostnameCache[updated[i].remoteAddress] ?? ""
        }

        return updated
    }

    nonisolated static func verifySignatures(for connections: [NetworkConnection]) async -> [NetworkConnection] {
        var updated = connections
        var cache: [Int: (valid: Bool, authority: String)] = [:]

        for i in updated.indices {
            let pid = updated[i].pid
            if cache[pid] == nil {
                // Verify signature validity
                let verify = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", String(pid)])
                let isValid = verify.exitCode == 0

                // Extract first Authority line
                var authority = "Unknown"
                let info = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", String(pid)])
                let infoText = info.output + "\n" + info.error
                if let line = infoText.components(separatedBy: "\n").first(where: { $0.hasPrefix("Authority=") }),
                   let range = line.range(of: "Authority=") {
                    authority = String(line[range.upperBound...])
                }

                if !isValid {
                    authority = verify.error.trimmingCharacters(in: .whitespacesAndNewlines)
                    if authority.isEmpty { authority = "Unsigned / Invalid" }
                }

                cache[pid] = (isValid, authority)
            }

            let result = cache[pid]!
            updated[i].isSigned = result.valid
            updated[i].signatureAuthority = result.authority
        }

        return updated
    }

    // MARK: - Helpers

    nonisolated static func parseAddressPort(_ input: String) -> (address: String, port: String) {
        // Handle IPv6: [fe80::1]:443 or IPv4: 192.168.0.11:443
        let str = input.trimmingCharacters(in: .whitespaces)

        if str.contains("[") {
            // IPv6
            if let bracketEnd = str.range(of: "]:") {
                let address = String(str[str.index(after: str.startIndex)..<bracketEnd.lowerBound])
                let port = String(str[bracketEnd.upperBound...])
                return (address, port)
            }
            return (str, "")
        }

        // IPv4: split on last colon
        if let lastColon = str.lastIndex(of: ":") {
            let address = String(str[..<lastColon])
            let port = String(str[str.index(after: lastColon)...])
            return (address, port)
        }

        return (str, "")
    }

    nonisolated static func isLocalAddress(_ address: String) -> Bool {
        address.hasPrefix("192.168.") ||
        address.hasPrefix("10.") ||
        address.hasPrefix("172.16.") || address.hasPrefix("172.17.") ||
        address.hasPrefix("172.18.") || address.hasPrefix("172.19.") ||
        address.hasPrefix("172.2") || address.hasPrefix("172.3") ||
        address == "127.0.0.1" ||
        address == "localhost" ||
        address == "*" ||
        address.hasPrefix("fe80:") ||
        address == "::1"
    }

    /// Maps country codes to flag emojis.
    nonisolated static func flag(for countryCode: String) -> String {
        guard countryCode.count == 2 else { return "" }
        let base: UInt32 = 127397
        let scalars = countryCode.uppercased().unicodeScalars.compactMap {
            UnicodeScalar(base + $0.value)
        }
        return scalars.map(String.init).joined()
    }
}
