import Foundation

/// Centralized approval system for items flagged across all scanners.
/// Items without valid signatures require manual user approval.
/// Persisted in UserDefaults across sessions.
enum ApprovalManager {
    enum Category: String {
        case process = "process"
        case persistence = "persistence"
        case appSignature = "app"
        case chromeExtension = "extension"
    }

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

    static func approve(_ category: Category, id: String) {
        var s = store
        s.insert("\(category.rawValue):\(id)")
        save(s)
    }

    static func revoke(_ category: Category, id: String) {
        var s = store
        s.remove("\(category.rawValue):\(id)")
        save(s)
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

    static func pendingCount(for category: Category) -> Int {
        flaggedIDs(for: category).filter { !isApproved(category, id: $0) }.count
    }

    static func hasBeenScanned(_ category: Category) -> Bool {
        allFlagged()[category.rawValue] != nil
    }

    private static func allFlagged() -> [String: [String]] {
        UserDefaults.standard.dictionary(forKey: flaggedKey) as? [String: [String]] ?? [:]
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
