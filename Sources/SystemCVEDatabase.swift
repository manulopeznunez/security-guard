import Foundation

// MARK: - System CVE Model

/// A known vulnerability in a macOS system service.
struct SystemCVE: Sendable, Identifiable {
    let id: String
    let severity: CVESeverity
    let summary: String
    let fixedInVersion: String
    let wormable: Bool
}

// MARK: - System CVE Database

enum SystemCVEDatabase {

    // MARK: - Service Fingerprinting

    /// Maps "processName:port" → known macOS service name.
    private static let serviceFingerprints: [String: String] = [
        // AirPlay Receiver
        "ControlCenter:5000": "AirPlay Receiver",
        "ControlCenter:7000": "AirPlay Receiver",
        "AirPlayXPCHelper:7000": "AirPlay Receiver",

        // Screen Sharing / VNC
        "screensharingd:5900": "Screen Sharing (VNC)",

        // Remote Desktop
        "ARDAgent:3283": "Apple Remote Desktop",

        // File Sharing
        "smbd:445": "SMB File Sharing",
        "AppleFileServer:548": "AFP File Sharing",

        // SSH
        "sshd:22": "Remote Login (SSH)",

        // Xcode / Instruments
        "remoted:62078": "Apple Remote Services (Xcode)",
    ]

    /// Look up the known service name for a (processName, port) pair.
    static func identifyService(processName: String, port: String) -> String? {
        let key = "\(processName):\(port)"
        if let match = serviceFingerprints[key] {
            return match
        }
        // Fallback: match by process name only (for ports that vary)
        for (fingerprint, serviceName) in serviceFingerprints {
            if fingerprint.hasPrefix("\(processName):") {
                return serviceName
            }
        }
        return nil
    }

    // MARK: - CVE Database

    /// Known CVEs for macOS system services, keyed by service name.
    private static let cveDatabase: [String: [SystemCVE]] = [
        "AirPlay Receiver": [
            SystemCVE(
                id: "CVE-2025-24252",
                severity: .critical,
                summary: "Wormable zero-click RCE via AirPlay (AirBorne)",
                fixedInVersion: "15.4",
                wormable: true
            ),
            SystemCVE(
                id: "CVE-2025-24206",
                severity: .high,
                summary: "AirPlay authentication bypass (AirBorne)",
                fixedInVersion: "15.4",
                wormable: false
            ),
            SystemCVE(
                id: "CVE-2025-24271",
                severity: .high,
                summary: "AirPlay ACL bypass allows sending commands without pairing",
                fixedInVersion: "15.4",
                wormable: false
            ),
        ],
        "Screen Sharing (VNC)": [
            SystemCVE(
                id: "CVE-2024-44171",
                severity: .medium,
                summary: "Screen sharing session may persist after lock screen",
                fixedInVersion: "14.7",
                wormable: false
            ),
        ],
        "Remote Login (SSH)": [
            SystemCVE(
                id: "CVE-2024-6387",
                severity: .high,
                summary: "regreSSHion: Signal handler race in OpenSSH (theoretical RCE)",
                fixedInVersion: "14.5",
                wormable: false
            ),
        ],
    ]

    /// Returns unpatched CVEs for a service on the given OS version.
    static func vulnerabilities(for service: String, osVersion: String) -> [SystemCVE] {
        guard let cves = cveDatabase[service] else { return [] }
        return cves.filter { cve in
            compareVersions(osVersion, isLessThan: cve.fixedInVersion)
        }
    }

    // MARK: - Version Comparison

    /// Returns true if `version` is strictly less than `target`.
    /// Compares dot-separated integer components (e.g. "15.1" < "15.4").
    static func compareVersions(_ version: String, isLessThan target: String) -> Bool {
        let v1 = version.split(separator: ".").compactMap { Int($0) }
        let v2 = target.split(separator: ".").compactMap { Int($0) }
        let maxLen = max(v1.count, v2.count)
        for i in 0..<maxLen {
            let a = i < v1.count ? v1[i] : 0
            let b = i < v2.count ? v2[i] : 0
            if a < b { return true }
            if a > b { return false }
        }
        return false
    }

    // MARK: - OS Patch Level

    /// Minimum patched macOS version per major release.
    static let minimumSafeVersions: [String: String] = [
        "15": "15.4",
        "14": "14.7.5",
        "13": "13.7.5",
    ]

    /// Check if the given macOS version is up to date.
    static func checkOSPatchLevel(_ currentVersion: String) -> (isSafe: Bool, minimumRequired: String?) {
        let major = String(currentVersion.split(separator: ".").first ?? "")
        guard let minimum = minimumSafeVersions[major] else {
            return (true, nil)
        }
        let safe = !compareVersions(currentVersion, isLessThan: minimum)
        return (safe, minimum)
    }
}
