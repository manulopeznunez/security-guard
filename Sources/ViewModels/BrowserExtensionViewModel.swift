import Foundation

@Observable
@MainActor
final class BrowserExtensionViewModel {
    var extensions: [BrowserExtensionEntry] = []
    var isScanning = false
    var progress = ""
    var selectedBrowser: BrowserType?

    var filteredExtensions: [BrowserExtensionEntry] {
        guard let browser = selectedBrowser else { return extensions }
        return extensions.filter { $0.browser == browser }
    }

    var availableBrowsers: [BrowserType] {
        let found = Set(extensions.map(\.browser))
        return BrowserType.allCases.filter { found.contains($0) }
    }

    func scan() async {
        isScanning = true
        progress = "Scanning browser extensions..."
        let results = await Task.detached { Self.performScan() }.value
        extensions = results
        let chromeCount = results.filter { $0.browser == .chrome }.count
        let safariCount = results.filter { $0.browser == .safari }.count
        let firefoxCount = results.filter { $0.browser == .firefox }.count
        progress = "Found \(results.count) extensions (Chrome: \(chromeCount), Safari: \(safariCount), Firefox: \(firefoxCount))"
        isScanning = false

        let flagged = results.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.browserExtension, flaggedIDs: flagged)
        Self.saveCachedResult(results)
        ScanDateTracker.record(.browserExtensions)
        DatabaseManager.shared.insertScanHistory(
            scanner: "browserExtensions", total: results.count, flagged: flagged.count,
            summary: "\(results.count) extensions, \(flagged.count) high risk"
        )
    }

    func loadCached() {
        if let cached = Self.loadCachedResult() { extensions = cached }
    }

    // MARK: - JSON Cache

    nonisolated private static var cacheURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacSecurityGuard", isDirectory: true)
            .appendingPathComponent("browser-extensions-cache.json")
    }

    nonisolated private static func saveCachedResult(_ result: [BrowserExtensionEntry]) {
        guard let data = try? JSONEncoder().encode(result) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    nonisolated static func loadCachedResult() -> [BrowserExtensionEntry]? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode([BrowserExtensionEntry].self, from: data)
    }

    // MARK: - Combined Scan

    nonisolated static func performScan() -> [BrowserExtensionEntry] {
        var results: [BrowserExtensionEntry] = []
        results.append(contentsOf: scanChrome())
        results.append(contentsOf: scanSafari())
        results.append(contentsOf: scanFirefox())
        return results.sorted { lhs, rhs in
            if lhs.risk != rhs.risk { return lhs.risk > rhs.risk }
            if lhs.isFromStore != rhs.isFromStore { return !lhs.isFromStore }
            return lhs.name < rhs.name
        }
    }

    // MARK: - Chrome Scanner

    nonisolated private static func scanChrome() -> [BrowserExtensionEntry] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let chromeBase = "\(home)/Library/Application Support/Google/Chrome"
        guard FileManager.default.fileExists(atPath: chromeBase) else { return [] }

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

        let profileDisplayNames = loadChromeProfileDisplayNames(chromeBase: chromeBase)
        var results: [BrowserExtensionEntry] = []

        for profile in profiles {
            let prefsData = loadChromePrefsExtensions(at: profile.prefsPath)
            guard let extensionDirs = try? FileManager.default.contentsOfDirectory(atPath: profile.path) else { continue }

            for extId in extensionDirs {
                let extPath = "\(profile.path)/\(extId)"
                guard let versions = try? FileManager.default.contentsOfDirectory(atPath: extPath),
                      let latestVersion = versions.sorted().last else { continue }

                let manifestPath = "\(extPath)/\(latestVersion)/manifest.json"
                guard let data = FileManager.default.contents(atPath: manifestPath),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                let name = json["name"] as? String ?? "Unknown"
                if name.hasPrefix("__") { continue }

                let version = json["version"] as? String ?? "?"
                let description = json["description"] as? String ?? ""
                let permissions = json["permissions"] as? [String] ?? []
                let hostPermissions = json["host_permissions"] as? [String] ?? []
                let author = json["author"] as? String ?? ""
                let homepageURL = json["homepage_url"] as? String ?? ""

                let updateURL = json["update_url"] as? String ?? ""
                let hasWebStoreUpdateURL = updateURL.contains("google.com/service/update2/crx")
                let prefsMeta = prefsData[extId]
                let fromWebStore = prefsMeta?.fromWebStore ?? false
                let location = prefsMeta?.location ?? -1
                let isFromWebStore = fromWebStore || hasWebStoreUpdateURL

                let source: String
                switch location {
                case 1: source = "Chrome Web Store"
                case 5: source = "External (Policy)"
                case 10: source = "Built-in"
                default: source = isFromWebStore ? "Chrome Web Store" : "Sideloaded"
                }

                var contentScriptMatches: [String] = []
                if let contentScripts = json["content_scripts"] as? [[String: Any]] {
                    for script in contentScripts {
                        if let matches = script["matches"] as? [String] {
                            contentScriptMatches.append(contentsOf: matches)
                        }
                    }
                }

                let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
                    permissions: permissions,
                    hostPermissions: hostPermissions,
                    contentScriptMatches: contentScriptMatches
                )

                let displayName = profileDisplayNames[profile.name] ?? profile.name

                results.append(BrowserExtensionEntry(
                    name: name, extensionId: extId, version: version,
                    description: description, permissions: permissions,
                    hostPermissions: hostPermissions, profile: profile.name,
                    risk: risk, riskReasons: reasons, isFromStore: isFromWebStore,
                    source: source, author: author, homepageURL: homepageURL,
                    profileDisplayName: displayName, browser: .chrome
                ))
            }
        }
        return results
    }

    // MARK: - Safari Scanner

    nonisolated private static func scanSafari() -> [BrowserExtensionEntry] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var results: [BrowserExtensionEntry] = []

        // Try reading Safari extension preferences
        let prefsResult = ShellExecutor.run("/usr/bin/defaults", arguments: ["read", "com.apple.Safari", "ManagedPlugInPolicies"])
        let extensionsResult = ShellExecutor.run("/usr/bin/defaults", arguments: ["read", "com.apple.Safari", "ExtensionsEnabled"])

        // Scan App Extensions via pluginkit
        let pluginResult = ShellExecutor.run("/usr/bin/pluginkit", arguments: ["-mDvvv", "-p", "com.apple.Safari.web-extension"])
        if !pluginResult.output.isEmpty {
            let blocks = pluginResult.output.components(separatedBy: "\n\n")
            for block in blocks where !block.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let lines = block.components(separatedBy: "\n")
                var bundleId = ""
                var displayName = ""
                var version = ""
                var path = ""

                for line in lines {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.contains("(") && trimmed.contains(")") && bundleId.isEmpty {
                        // First line often: "  com.developer.app.Extension(1.0)"
                        let parts = trimmed.components(separatedBy: "(")
                        bundleId = parts[0].trimmingCharacters(in: .whitespaces)
                        if parts.count > 1 {
                            version = parts[1].replacingOccurrences(of: ")", with: "")
                        }
                    }
                    if trimmed.hasPrefix("Path = ") {
                        path = String(trimmed.dropFirst("Path = ".count))
                    }
                    if trimmed.hasPrefix("Display Name = ") {
                        displayName = String(trimmed.dropFirst("Display Name = ".count))
                    }
                }

                if bundleId.isEmpty { continue }
                if displayName.isEmpty { displayName = bundleId.components(separatedBy: ".").last ?? bundleId }

                // Safari extensions from App Store are generally trusted
                let isFromStore = path.contains("/Applications/") || path.contains("AppStore")
                let risk: ExtensionRisk = isFromStore ? .low : .medium
                let reasons = isFromStore ? ["App Store distributed"] : ["Non-App Store extension"]

                results.append(BrowserExtensionEntry(
                    name: displayName, extensionId: bundleId, version: version,
                    description: "", permissions: [], hostPermissions: [],
                    profile: "Default", risk: risk, riskReasons: reasons,
                    isFromStore: isFromStore, source: isFromStore ? "App Store" : "Developer",
                    author: "", homepageURL: "", profileDisplayName: "Safari",
                    browser: .safari
                ))
            }
        }

        return results
    }

    // MARK: - Firefox Scanner

    nonisolated private static func scanFirefox() -> [BrowserExtensionEntry] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let firefoxBase = "\(home)/.mozilla/firefox"
        guard FileManager.default.fileExists(atPath: firefoxBase) else { return [] }

        var results: [BrowserExtensionEntry] = []

        // Find profiles
        guard let profileDirs = try? FileManager.default.contentsOfDirectory(atPath: firefoxBase) else { return [] }

        for profileDir in profileDirs {
            let profilePath = "\(firefoxBase)/\(profileDir)"
            let extensionsJsonPath = "\(profilePath)/extensions.json"

            guard FileManager.default.fileExists(atPath: extensionsJsonPath),
                  let data = FileManager.default.contents(atPath: extensionsJsonPath),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let addons = json["addons"] as? [[String: Any]] else { continue }

            for addon in addons {
                let addonType = addon["type"] as? String ?? ""
                // Only scan actual extensions, not themes/langpacks/etc
                guard addonType == "extension" else { continue }

                let addonId = addon["id"] as? String ?? ""
                let name = addon["defaultLocale"] as? [String: Any]
                let localeName = name?["name"] as? String ?? (addon["name"] as? String ?? "Unknown")
                let localeDesc = name?["description"] as? String ?? (addon["description"] as? String ?? "")
                let version = addon["version"] as? String ?? "?"
                let creator = addon["defaultLocale"] as? [String: Any]
                let authorName = creator?["creator"] as? String ?? ""
                let homepageURL = addon["homepageURL"] as? String ?? ""
                let active = addon["active"] as? Bool ?? false
                let isBuiltin = addon["isBuiltin"] as? Bool ?? false
                let isSystem = addon["isSystem"] as? Bool ?? false
                let sourceURI = addon["sourceURI"] as? String ?? ""

                if isBuiltin || isSystem { continue }
                if addonId.isEmpty { continue }

                let isFromStore = sourceURI.contains("addons.mozilla.org")

                // Parse permissions from addon data
                var permissions: [String] = []
                if let userPerms = addon["userPermissions"] as? [String: Any],
                   let perms = userPerms["permissions"] as? [String] {
                    permissions = perms
                }
                var hostPermissions: [String] = []
                if let userPerms = addon["userPermissions"] as? [String: Any],
                   let origins = userPerms["origins"] as? [String] {
                    hostPermissions = origins
                }

                let (risk, reasons) = ChromeExtensionViewModel.assessRisk(
                    permissions: permissions,
                    hostPermissions: hostPermissions,
                    contentScriptMatches: []
                )

                results.append(BrowserExtensionEntry(
                    name: localeName, extensionId: addonId, version: version,
                    description: localeDesc, permissions: permissions,
                    hostPermissions: hostPermissions, profile: profileDir,
                    risk: risk, riskReasons: reasons, isFromStore: isFromStore,
                    source: isFromStore ? "Mozilla Add-ons" : "Sideloaded",
                    author: authorName, homepageURL: homepageURL,
                    profileDisplayName: profileDir, browser: .firefox
                ))
            }
        }

        return results
    }

    // MARK: - Chrome Helpers

    private struct ChromeExtPrefsMetadata {
        let fromWebStore: Bool
        let location: Int
    }

    nonisolated private static func loadChromeProfileDisplayNames(chromeBase: String) -> [String: String] {
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
            let gaiaName = profileDict["gaia_name"] as? String ?? ""
            let name = profileDict["name"] as? String ?? ""
            let displayName = gaiaName.isEmpty ? name : gaiaName
            if !displayName.isEmpty { result[dirName] = displayName }
        }
        return result
    }

    nonisolated private static func loadChromePrefsExtensions(at path: String) -> [String: ChromeExtPrefsMetadata] {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let extensions = json["extensions"] as? [String: Any],
              let settings = extensions["settings"] as? [String: Any] else {
            return [:]
        }
        var result: [String: ChromeExtPrefsMetadata] = [:]
        for (extId, value) in settings {
            guard let extDict = value as? [String: Any] else { continue }
            let fromWebStore = extDict["from_webstore"] as? Bool ?? false
            let location = extDict["location"] as? Int ?? -1
            result[extId] = ChromeExtPrefsMetadata(fromWebStore: fromWebStore, location: location)
        }
        return result
    }
}
