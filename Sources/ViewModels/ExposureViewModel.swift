import Foundation

@Observable
@MainActor
final class ExposureViewModel {
    var entries: [ExposureCheckEntry] = []
    var isScanning = false
    var progress = ""

    func entriesForSection(_ section: ExposureSection) -> [ExposureCheckEntry] {
        entries.filter { $0.section == section }
    }

    func scan() async {
        isScanning = true
        progress = "Scanning system exposure..."
        let results = await Task.detached { Self.performScan() }.value
        entries = results
        progress = "Found \(results.count) items"
        isScanning = false

        let flagged = results.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.exposure, flaggedIDs: flagged)
        Self.saveCachedResult(results)
        ScanDateTracker.record(.exposure)
        DatabaseManager.shared.insertScanHistory(
            scanner: "exposure", total: results.count, flagged: flagged.count,
            summary: "\(results.count) checks, \(flagged.count) flagged"
        )
    }

    func loadCached() {
        if let cached = Self.loadCachedResult() { entries = cached }
    }

    // MARK: - Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("exposure-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: [ExposureCheckEntry]) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> [ExposureCheckEntry]? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode([ExposureCheckEntry].self, from: data)
    }

    // MARK: - Scan

    nonisolated static func performScan() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []
        results.append(contentsOf: scanWiFi())
        results.append(contentsOf: scanBluetooth())
        results.append(contentsOf: scanSharing())
        results.append(contentsOf: scanDNS())
        results.append(contentsOf: scanKernelExtensions())
        results.append(contentsOf: scanSystemExtensions())
        return results
    }

    // MARK: - Wi-Fi

    nonisolated private static func scanWiFi() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        let profiler = ShellExecutor.run("/usr/sbin/system_profiler", arguments: ["SPAirPortDataType", "-detailLevel", "basic"])
        let output = profiler.output

        // Check current network security
        if let secRange = output.range(of: "Security:") {
            let secLine = output[secRange.lowerBound...].prefix(100)
            let secType = String(secLine).components(separatedBy: ":").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "Unknown"

            let risk: ProcessRisk
            let reason: String
            if secType.contains("WPA3") {
                risk = .safe; reason = "Using WPA3 — strongest available"
            } else if secType.contains("WPA2") {
                risk = .safe; reason = "Using WPA2 Personal — adequate security"
            } else if secType.contains("WEP") {
                risk = .suspicious; reason = "WEP is broken — trivially crackable"
            } else if secType.lowercased().contains("open") || secType.lowercased().contains("none") {
                risk = .suspicious; reason = "Open network — no encryption"
            } else {
                risk = .warning; reason = "Security type: \(secType)"
            }

            results.append(ExposureCheckEntry(
                section: .wifi, name: "Current Network Security",
                detail: secType, risk: risk, riskReason: reason,
                remediation: risk == .safe ? "No action needed" : "Connect to a WPA2/WPA3 protected network"
            ))
        }

        // Check saved networks
        let saved = ShellExecutor.run("/usr/sbin/networksetup", arguments: ["-listpreferredwirelessnetworks", "en0"])
        let networks = saved.output.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.contains("Preferred networks") }

        if !networks.isEmpty {
            results.append(ExposureCheckEntry(
                section: .wifi, name: "Saved Networks",
                detail: "\(networks.count) saved networks",
                risk: networks.count > 20 ? .warning : .safe,
                riskReason: networks.count > 20 ? "Many saved networks — clean up unused ones" : "\(networks.count) networks saved",
                remediation: "Remove networks you no longer use from System Settings > Wi-Fi > Advanced"
            ))
        }

        return results
    }

    // MARK: - Bluetooth

    nonisolated private static func scanBluetooth() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        let profiler = ShellExecutor.run("/usr/sbin/system_profiler", arguments: ["SPBluetoothDataType", "-detailLevel", "basic"])
        let output = profiler.output

        // Check if Bluetooth is on
        let btOn = output.contains("State: On") || output.contains("Bluetooth Power: On")

        if btOn {
            // Check discoverable mode
            let discoverable = output.contains("Discoverable: Yes")

            results.append(ExposureCheckEntry(
                section: .bluetooth, name: "Bluetooth Status",
                detail: discoverable ? "On, Discoverable" : "On",
                risk: discoverable ? .warning : .safe,
                riskReason: discoverable ? "Bluetooth is discoverable — visible to nearby devices" : "Bluetooth on but not discoverable",
                remediation: discoverable ? "Disable discoverability when not pairing" : "No action needed"
            ))

            // Count connected devices
            let deviceMatches = output.components(separatedBy: "Connected: Yes").count - 1
            if deviceMatches > 0 {
                results.append(ExposureCheckEntry(
                    section: .bluetooth, name: "Connected Devices",
                    detail: "\(deviceMatches) device(s) connected",
                    risk: .safe, riskReason: "Active Bluetooth connections",
                    remediation: "Review connected devices in System Settings > Bluetooth"
                ))
            }
        } else {
            results.append(ExposureCheckEntry(
                section: .bluetooth, name: "Bluetooth Status",
                detail: "Off", risk: .safe, riskReason: "Bluetooth is disabled — minimal attack surface",
                remediation: "No action needed"
            ))
        }

        return results
    }

    // MARK: - Sharing

    nonisolated private static func scanSharing() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        // AirDrop
        let airdrop = ShellExecutor.run("/usr/bin/defaults", arguments: ["read", "com.apple.sharingd", "DiscoverableMode"])
        let airdropMode = airdrop.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let airdropRisk: ProcessRisk
        let airdropDetail: String
        switch airdropMode {
        case "Everyone":
            airdropRisk = .suspicious; airdropDetail = "Everyone — accepts files from strangers"
        case "Contacts Only":
            airdropRisk = .safe; airdropDetail = "Contacts Only"
        case "Off", "":
            airdropRisk = .safe; airdropDetail = "Off"
        default:
            airdropRisk = .warning; airdropDetail = airdropMode
        }
        results.append(ExposureCheckEntry(
            section: .sharing, name: "AirDrop",
            detail: airdropDetail, risk: airdropRisk,
            riskReason: airdropRisk == .suspicious ? "AirDrop accepts files from anyone nearby" : "AirDrop configured safely",
            remediation: "Set AirDrop to 'Contacts Only' or 'Off' in Control Center"
        ))

        // Screen Sharing
        let screenSharing = ShellExecutor.shell("launchctl list 2>/dev/null | grep screensharing")
        let screenSharingOn = !screenSharing.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        results.append(ExposureCheckEntry(
            section: .sharing, name: "Screen Sharing",
            detail: screenSharingOn ? "Enabled" : "Disabled",
            risk: screenSharingOn ? .warning : .safe,
            riskReason: screenSharingOn ? "Screen Sharing allows remote desktop access" : "Screen Sharing is off",
            remediation: "Disable in System Settings > General > Sharing"
        ))

        // File Sharing (SMB)
        let smb = ShellExecutor.shell("launchctl list 2>/dev/null | grep smbd")
        let smbOn = !smb.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        results.append(ExposureCheckEntry(
            section: .sharing, name: "File Sharing (SMB)",
            detail: smbOn ? "Enabled" : "Disabled",
            risk: smbOn ? .warning : .safe,
            riskReason: smbOn ? "File Sharing exposes folders on the network" : "File Sharing is off",
            remediation: "Disable in System Settings > General > Sharing"
        ))

        // Remote Management (ARD)
        let ard = ShellExecutor.shell("launchctl list 2>/dev/null | grep ARDAgent")
        let ardOn = !ard.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        results.append(ExposureCheckEntry(
            section: .sharing, name: "Remote Management",
            detail: ardOn ? "Enabled" : "Disabled",
            risk: ardOn ? .suspicious : .safe,
            riskReason: ardOn ? "Remote Management gives full admin control remotely" : "Remote Management is off",
            remediation: "Disable in System Settings > General > Sharing"
        ))

        return results
    }

    // MARK: - DNS

    nonisolated private static func scanDNS() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        let dns = ShellExecutor.run("/usr/sbin/scutil", arguments: ["--dns"])
        let output = dns.output

        // Extract nameservers
        var nameservers: [String] = []
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("nameserver[") {
                if let ip = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces) {
                    if !nameservers.contains(ip) { nameservers.append(ip) }
                }
            }
        }

        let knownSecureDNS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
        let isSecure = nameservers.contains { knownSecureDNS.contains($0) }
        let hasDoH = output.contains("https://") || output.contains("DNS over HTTPS") || output.contains("DNS over TLS")

        let risk: ProcessRisk
        let detail: String
        let reason: String
        if hasDoH {
            risk = .safe; detail = "Encrypted DNS (DoH/DoT)"; reason = "DNS queries are encrypted"
        } else if isSecure {
            risk = .safe; detail = nameservers.joined(separator: ", "); reason = "Using known secure DNS provider"
        } else if nameservers.isEmpty {
            risk = .warning; detail = "No DNS configured"; reason = "DNS configuration could not be read"
        } else {
            risk = .warning; detail = nameservers.joined(separator: ", "); reason = "Using ISP/default DNS — queries are unencrypted"
        }

        results.append(ExposureCheckEntry(
            section: .dns, name: "DNS Configuration",
            detail: detail, risk: risk, riskReason: reason,
            remediation: risk == .safe ? "No action needed" : "Consider using 1.1.1.1 or 8.8.8.8 in System Settings > Wi-Fi > DNS"
        ))

        return results
    }

    // MARK: - Kernel Extensions

    nonisolated private static func scanKernelExtensions() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        let kexts = ShellExecutor.run("/usr/bin/kmutil", arguments: ["showloaded", "--list-only"])
        let output = kexts.output

        var thirdPartyCount = 0
        var thirdPartyNames: [String] = []

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            // Apple kexts start with com.apple
            if !trimmed.contains("com.apple") && trimmed.contains(".") {
                thirdPartyCount += 1
                // Extract bundle ID
                let parts = trimmed.components(separatedBy: .whitespaces)
                if let bundleId = parts.last {
                    thirdPartyNames.append(bundleId)
                }
            }
        }

        if thirdPartyCount > 0 {
            results.append(ExposureCheckEntry(
                section: .kernelExtensions, name: "Third-Party Kernel Extensions",
                detail: "\(thirdPartyCount) non-Apple kext(s): \(thirdPartyNames.prefix(5).joined(separator: ", "))",
                risk: .warning, riskReason: "Third-party kernel extensions run with full system privileges",
                remediation: "Review if these kexts are needed. macOS is moving to System Extensions."
            ))
        } else {
            results.append(ExposureCheckEntry(
                section: .kernelExtensions, name: "Kernel Extensions",
                detail: "No third-party kexts loaded",
                risk: .safe, riskReason: "Only Apple kernel extensions are loaded",
                remediation: "No action needed"
            ))
        }

        return results
    }

    // MARK: - System Extensions

    nonisolated private static func scanSystemExtensions() -> [ExposureCheckEntry] {
        var results: [ExposureCheckEntry] = []

        let sysext = ShellExecutor.run("/usr/bin/systemextensionsctl", arguments: ["list"])
        let output = sysext.output

        var extensions: [(name: String, teamID: String, state: String)] = []
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Lines look like: "--- com.apple.security-systemextension    com.developer.app.Extension    teamID    [activated enabled]"
            if trimmed.contains("[") && trimmed.contains("]") {
                let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                if parts.count >= 3 {
                    let bundleId = parts.count > 2 ? parts[2] : parts[1]
                    let teamID = parts.count > 3 ? parts[3] : ""
                    let state = trimmed.components(separatedBy: "[").last?.replacingOccurrences(of: "]", with: "") ?? ""
                    if !bundleId.hasPrefix("---") {
                        extensions.append((name: bundleId, teamID: teamID, state: state))
                    }
                }
            }
        }

        if extensions.isEmpty {
            results.append(ExposureCheckEntry(
                section: .systemExtensions, name: "System Extensions",
                detail: "No system extensions installed",
                risk: .safe, riskReason: "No third-party system extensions",
                remediation: "No action needed"
            ))
        } else {
            for ext in extensions {
                let isNetwork = ext.name.lowercased().contains("network") || ext.name.lowercased().contains("vpn") || ext.name.lowercased().contains("firewall")
                let isSecurity = ext.name.lowercased().contains("security") || ext.name.lowercased().contains("endpoint")

                results.append(ExposureCheckEntry(
                    section: .systemExtensions, name: ext.name,
                    detail: "Team: \(ext.teamID) — \(ext.state)",
                    risk: .safe,
                    riskReason: isNetwork ? "Network system extension" : (isSecurity ? "Security system extension" : "System extension"),
                    remediation: "Verify this is from a trusted vendor"
                ))
            }
        }

        return results
    }
}
