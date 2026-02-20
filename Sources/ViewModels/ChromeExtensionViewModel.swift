import Foundation

@Observable
@MainActor
final class ChromeExtensionViewModel {
    var extensions: [ChromeExtensionEntry] = []
    var isScanning = false
    var progress = ""

    func scan() async {
        isScanning = true
        progress = "Scanning Chrome profiles..."
        let results = Self.performScan()
        extensions = results
        progress = "Found \(results.count) extensions."
        isScanning = false

        // Cache flagged items for Security Status
        let flagged = results.filter { $0.risk == .high }.map(\.extensionId)
        ApprovalManager.saveFlagged(.chromeExtension, ids: flagged)
    }

    nonisolated static func performScan() -> [ChromeExtensionEntry] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let chromeBase = "\(home)/Library/Application Support/Google/Chrome"

        guard FileManager.default.fileExists(atPath: chromeBase) else { return [] }

        // Find all profiles
        var profiles: [(name: String, path: String, prefsPath: String)] = []
        if let contents = try? FileManager.default.contentsOfDirectory(atPath: chromeBase) {
            for item in contents {
                let extPath = "\(chromeBase)/\(item)/Extensions"
                let prefsPath = "\(chromeBase)/\(item)/Preferences"
                if FileManager.default.fileExists(atPath: extPath) {
                    profiles.append((name: item, path: extPath, prefsPath: prefsPath))
                }
            }
        }

        // Read profile display names from Local State
        let profileDisplayNames = loadProfileDisplayNames(chromeBase: chromeBase)

        var results: [ChromeExtensionEntry] = []

        for profile in profiles {
            // Load Chrome Preferences to get extension metadata
            let prefsData = loadPrefsExtensions(at: profile.prefsPath)

            guard let extensionDirs = try? FileManager.default.contentsOfDirectory(atPath: profile.path) else { continue }

            for extId in extensionDirs {
                let extPath = "\(profile.path)/\(extId)"
                // Each extension has version subfolders
                guard let versions = try? FileManager.default.contentsOfDirectory(atPath: extPath) else { continue }
                // Use the latest version (last alphabetically)
                guard let latestVersion = versions.sorted().last else { continue }

                let manifestPath = "\(extPath)/\(latestVersion)/manifest.json"
                guard let data = FileManager.default.contents(atPath: manifestPath),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                let name = json["name"] as? String ?? "Unknown"
                // Skip Chrome built-in components (names starting with __)
                if name.hasPrefix("__") { continue }

                let version = json["version"] as? String ?? "?"
                let description = json["description"] as? String ?? ""
                let permissions = json["permissions"] as? [String] ?? []
                let hostPermissions = json["host_permissions"] as? [String] ?? []
                let author = json["author"] as? String ?? ""
                let homepageURL = json["homepage_url"] as? String ?? ""

                // Check update_url in manifest — Web Store extensions have this
                let updateURL = json["update_url"] as? String ?? ""
                let hasWebStoreUpdateURL = updateURL.contains("google.com/service/update2/crx")

                // Check Chrome Preferences for this extension
                let prefsMeta = prefsData[extId]
                let fromWebStore = prefsMeta?.fromWebStore ?? false
                let location = prefsMeta?.location ?? -1

                // Determine source
                let isFromWebStore = fromWebStore || hasWebStoreUpdateURL
                let source: String
                switch location {
                case 1: source = "Chrome Web Store"
                case 5: source = "External (Policy)"
                case 10: source = "Built-in"
                default:
                    source = isFromWebStore ? "Chrome Web Store" : "Sideloaded"
                }

                // Also check content_scripts matches for broad access
                var contentScriptMatches: [String] = []
                if let contentScripts = json["content_scripts"] as? [[String: Any]] {
                    for script in contentScripts {
                        if let matches = script["matches"] as? [String] {
                            contentScriptMatches.append(contentsOf: matches)
                        }
                    }
                }

                let (risk, reasons) = assessRisk(
                    permissions: permissions,
                    hostPermissions: hostPermissions,
                    contentScriptMatches: contentScriptMatches
                )

                let displayName = profileDisplayNames[profile.name] ?? profile.name

                results.append(ChromeExtensionEntry(
                    name: name,
                    extensionId: extId,
                    version: version,
                    description: description,
                    permissions: permissions,
                    hostPermissions: hostPermissions,
                    profile: profile.name,
                    risk: risk,
                    riskReasons: reasons,
                    isFromWebStore: isFromWebStore,
                    source: source,
                    author: author,
                    homepageURL: homepageURL,
                    profileDisplayName: displayName
                ))
            }
        }

        return results.sorted { lhs, rhs in
            // Sort: unverified high first, then verified high, then medium, then low
            if lhs.risk != rhs.risk { return lhs.risk > rhs.risk }
            if lhs.isFromWebStore != rhs.isFromWebStore { return !lhs.isFromWebStore }
            return lhs.name < rhs.name
        }
    }

    // MARK: - Chrome Profile Display Names

    nonisolated private static func loadProfileDisplayNames(chromeBase: String) -> [String: String] {
        let localStatePath = "\(chromeBase)/Local State"
        guard let data = FileManager.default.contents(atPath: localStatePath),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = json["profile"] as? [String: Any],
              let infoCache = profile["info_cache"] as? [String: Any] else {
            return [:]
        }

        var result: [String: String] = [:]
        for (dirName, value) in infoCache {
            guard let profileDict = value as? [String: Any] else { continue }
            // Prefer gaia_name (Google account name), fall back to name (profile display name)
            let gaiaName = profileDict["gaia_name"] as? String ?? ""
            let name = profileDict["name"] as? String ?? ""
            let displayName = gaiaName.isEmpty ? name : gaiaName
            if !displayName.isEmpty {
                result[dirName] = displayName
            }
        }
        return result
    }

    // MARK: - Chrome Preferences Reader

    private struct ExtPrefsMetadata {
        let fromWebStore: Bool
        let location: Int
    }

    nonisolated private static func loadPrefsExtensions(at path: String) -> [String: ExtPrefsMetadata] {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let extensions = json["extensions"] as? [String: Any],
              let settings = extensions["settings"] as? [String: Any] else {
            return [:]
        }

        var result: [String: ExtPrefsMetadata] = [:]
        for (extId, value) in settings {
            guard let extDict = value as? [String: Any] else { continue }
            let fromWebStore = extDict["from_webstore"] as? Bool ?? false
            let location = extDict["location"] as? Int ?? -1
            result[extId] = ExtPrefsMetadata(fromWebStore: fromWebStore, location: location)
        }
        return result
    }

    nonisolated static func assessRisk(
        permissions: [String],
        hostPermissions: [String],
        contentScriptMatches: [String]
    ) -> (ExtensionRisk, [String]) {
        var reasons: [String] = []
        var maxRisk = ExtensionRisk.low

        let allPerms = permissions + hostPermissions

        // HIGH risk permissions
        let highRiskPerms: [(perm: String, reason: String)] = [
            ("<all_urls>", "Access to ALL websites"),
            ("*://*/*", "Access to ALL websites"),
            ("debugger", "Can debug/inspect other tabs"),
            ("webRequestBlocking", "Can block/modify network requests"),
            ("nativeMessaging", "Can communicate with local programs"),
            ("proxy", "Can change proxy settings"),
        ]

        for check in highRiskPerms {
            if allPerms.contains(check.perm) || contentScriptMatches.contains(check.perm) {
                reasons.append(check.reason)
                maxRisk = .high
            }
        }

        // MEDIUM risk permissions
        let mediumRiskPerms: [(perm: String, reason: String)] = [
            ("webRequest", "Can see all network requests"),
            ("cookies", "Can read/write cookies"),
            ("tabs", "Can see all open tabs"),
            ("history", "Can read browsing history"),
            ("bookmarks", "Can read/modify bookmarks"),
            ("clipboardRead", "Can read clipboard"),
            ("clipboardWrite", "Can write to clipboard"),
            ("downloads", "Can manage downloads"),
            ("management", "Can manage other extensions"),
            ("webNavigation", "Can track page navigation"),
            ("declarativeNetRequestWithHostAccess", "Can modify network requests"),
        ]

        for check in mediumRiskPerms {
            if allPerms.contains(check.perm) {
                reasons.append(check.reason)
                if maxRisk < .medium { maxRisk = .medium }
            }
        }

        // Check for broad content script matches
        for match in contentScriptMatches {
            if match.contains("<all_urls>") || match == "*://*/*" || match == "http://*/*" || match == "https://*/*" {
                if !reasons.contains("Access to ALL websites") {
                    reasons.append("Content scripts on ALL pages")
                    maxRisk = .high
                }
            }
        }

        if reasons.isEmpty {
            reasons.append("Limited permissions")
        }

        return (maxRisk, reasons)
    }
}
