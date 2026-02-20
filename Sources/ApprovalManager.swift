import Foundation

/// Centralized approval and quarantine system for items flagged across all scanners.
/// Items without valid signatures require manual user review.
/// Three states: pending (default), approved (safe), quarantined (dangerous).
/// Persisted in UserDefaults across sessions.
enum ApprovalManager {
    /// Posted whenever approval state changes (scan results, approve, quarantine, revoke).
    /// UI observes this to refresh tab alert badges.
    static let stateDidChangeNotification = Notification.Name("ApprovalManagerStateDidChange")

    private static func notifyChange() {
        NotificationCenter.default.post(name: stateDidChangeNotification, object: nil)
    }
    enum Category: String {
        case process = "process"
        case persistence = "persistence"
        case appSignature = "app"
        case chromeExtension = "extension"
        case knockknock = "knockknock"
        case networkMonitor = "network"
        case homebrew = "homebrew"
        case attackSurface = "surface"
        case tccPermission = "tcc"
        case configGuard = "config"
        case sudoConfig = "sudo"
        case usersGroups = "users"
        case browserExtension = "browserExt"
        case exposure = "exposure"
        case devDeps = "devdeps"
        case breachCheck = "breach"
    }

    // MARK: - Approval storage

    private static let key = "ApprovedSecurityItems"

    private static var store: Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
    }

    private static func save(_ store: Set<String>) {
        UserDefaults.standard.set(Array(store), forKey: key)
    }

    static func isApproved(_ category: Category, id: String) -> Bool {
        store.contains("\(category.rawValue):\(id)")
    }

    /// Approve an item. Auto-revokes quarantine (mutually exclusive states).
    static func approve(_ category: Category, id: String) {
        // Remove quarantine if present (mutually exclusive)
        var q = quarantineStore
        if q.remove("\(category.rawValue):\(id)") != nil {
            saveQuarantine(q)
        }

        var s = store
        s.insert("\(category.rawValue):\(id)")
        save(s)
        DatabaseManager.shared.insertApprovalEvent(
            category: category.rawValue, itemID: id, action: "approved"
        )
        notifyChange()
    }

    static func revoke(_ category: Category, id: String) {
        var s = store
        s.remove("\(category.rawValue):\(id)")
        save(s)
        DatabaseManager.shared.insertApprovalEvent(
            category: category.rawValue, itemID: id, action: "revoked"
        )
        notifyChange()
    }

    // MARK: - Quarantine storage

    private static let quarantineKey = "QuarantinedSecurityItems"

    private static var quarantineStore: Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: quarantineKey) ?? [])
    }

    private static func saveQuarantine(_ store: Set<String>) {
        UserDefaults.standard.set(Array(store), forKey: quarantineKey)
    }

    static func isQuarantined(_ category: Category, id: String) -> Bool {
        quarantineStore.contains("\(category.rawValue):\(id)")
    }

    /// Quarantine an item. Auto-revokes approval (mutually exclusive states).
    static func quarantine(_ category: Category, id: String) {
        // Remove approval if present (mutually exclusive)
        var s = store
        if s.remove("\(category.rawValue):\(id)") != nil {
            save(s)
        }

        var q = quarantineStore
        q.insert("\(category.rawValue):\(id)")
        saveQuarantine(q)
        DatabaseManager.shared.insertApprovalEvent(
            category: category.rawValue, itemID: id, action: "quarantined"
        )
        notifyChange()
    }

    static func unquarantine(_ category: Category, id: String) {
        var q = quarantineStore
        q.remove("\(category.rawValue):\(id)")
        saveQuarantine(q)
        DatabaseManager.shared.insertApprovalEvent(
            category: category.rawValue, itemID: id, action: "unquarantined"
        )
        notifyChange()
    }

    static func quarantinedCount(for category: Category) -> Int {
        flaggedIDs(for: category).filter { isQuarantined(category, id: $0) }.count
    }

    /// Returns all quarantined entries across all categories as "category:id" strings.
    static func allQuarantinedEntries() -> Set<String> {
        quarantineStore
    }

    // MARK: - Flagged items cache

    /// Each scanner saves its flagged item IDs after scanning.
    /// Security Status reads this cache instead of re-scanning.
    private static let flaggedKey = "FlaggedSecurityItems"

    static func saveFlagged(_ category: Category, ids: [String]) {
        var all = allFlagged()
        all[category.rawValue] = ids
        UserDefaults.standard.set(all, forKey: flaggedKey)
    }

    static func flaggedIDs(for category: Category) -> [String] {
        allFlagged()[category.rawValue] ?? []
    }

    /// Items that are neither approved nor quarantined (still need triage).
    static func pendingCount(for category: Category) -> Int {
        flaggedIDs(for: category).filter {
            !isApproved(category, id: $0) && !isQuarantined(category, id: $0)
        }.count
    }

    static func hasBeenScanned(_ category: Category) -> Bool {
        allFlagged()[category.rawValue] != nil
    }

    private static func allFlagged() -> [String: [String]] {
        UserDefaults.standard.dictionary(forKey: flaggedKey) as? [String: [String]] ?? [:]
    }

    // MARK: - Unified post-scan handler

    /// Saves flagged items, checks quarantine reappearances, and prunes orphaned entries.
    /// All scanners should call this after scanning instead of saveFlagged() directly.
    static func recordScanResults(_ category: Category, flaggedIDs: [String]) {
        saveFlagged(category, ids: flaggedIDs)

        for id in flaggedIDs where isQuarantined(category, id: id) {
            NotificationService.sendQuarantineReappearanceAlert(
                categoryRawValue: category.rawValue,
                itemID: id
            )
        }

        pruneOrphanedEntries(category, currentIDs: Set(flaggedIDs))
        notifyChange()
    }

    /// Remove approval and quarantine entries for a category whose IDs
    /// are no longer in the current flagged list.
    private static func pruneOrphanedEntries(_ category: Category, currentIDs: Set<String>) {
        let prefix = "\(category.rawValue):"

        var approvals = store
        let orphanedApprovals = approvals.filter { entry in
            entry.hasPrefix(prefix) && !currentIDs.contains(String(entry.dropFirst(prefix.count)))
        }
        if !orphanedApprovals.isEmpty {
            approvals.subtract(orphanedApprovals)
            save(approvals)
            for entry in orphanedApprovals {
                let itemID = String(entry.dropFirst(prefix.count))
                DatabaseManager.shared.insertApprovalEvent(
                    category: category.rawValue, itemID: itemID, action: "approval_pruned"
                )
            }
        }

        var quarantines = quarantineStore
        let orphanedQuarantines = quarantines.filter { entry in
            entry.hasPrefix(prefix) && !currentIDs.contains(String(entry.dropFirst(prefix.count)))
        }
        if !orphanedQuarantines.isEmpty {
            quarantines.subtract(orphanedQuarantines)
            saveQuarantine(quarantines)
            for entry in orphanedQuarantines {
                let itemID = String(entry.dropFirst(prefix.count))
                DatabaseManager.shared.insertApprovalEvent(
                    category: category.rawValue, itemID: itemID, action: "quarantine_pruned"
                )
            }
        }
    }

    // MARK: - Approval Date Queries

    /// Returns when an item was last approved or quarantined, with the action name.
    static func lastActionDate(_ category: Category, id: String) -> (action: String, date: Date)? {
        DatabaseManager.shared.lastActionDate(category: category.rawValue, itemID: id)
    }

    /// Items approved more than N days ago — candidates for rotation/re-review.
    static func staleApprovals(for category: Category, days: Int = 90) -> [ApprovalEvent] {
        DatabaseManager.shared.staleApprovals(category: category.rawValue, olderThanDays: days)
    }

    // MARK: - Migration

    /// Migrate old Chrome extension approvals to the new system.
    static func migrateOldChromeApprovals() {
        let oldKey = "ApprovedExtensionIDs"
        guard let oldIDs = UserDefaults.standard.stringArray(forKey: oldKey), !oldIDs.isEmpty else { return }
        var s = store
        for id in oldIDs {
            s.insert("\(Category.chromeExtension.rawValue):\(id)")
        }
        save(s)
        UserDefaults.standard.removeObject(forKey: oldKey)
    }
}
