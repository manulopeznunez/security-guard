import Foundation

/// Tracks per-scanner last scan dates using UserDefaults.
/// Used to display "Last scan: Today 14:32" or "20/02/2026 14:32" (red if stale) in all tab headers.
enum ScanDateTracker {
    enum Scanner: String, CaseIterable {
        case processes
        case persistence
        case knockknock
        case homebrew
        case appSignatures
        case chromeExtensions
        case networkMonitor
        case attackSurface
        case configGuard
        case permissions
        case browserExtensions
        case exposure
        case devDeps
        case breachCheck
    }

    private static let prefix = "LastScanDate_"

    /// Record the current time as the last scan date for a scanner.
    static func record(_ scanner: Scanner) {
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: prefix + scanner.rawValue)
    }

    /// Returns the last scan date for a scanner, or nil if never scanned.
    static func lastDate(for scanner: Scanner) -> Date? {
        let ts = UserDefaults.standard.double(forKey: prefix + scanner.rawValue)
        return ts > 0 ? Date(timeIntervalSince1970: ts) : nil
    }

    /// True if the last scan date is NOT today (or never scanned).
    static func isStale(for scanner: Scanner) -> Bool {
        guard let date = lastDate(for: scanner) else { return true }
        return !Calendar.current.isDateInToday(date)
    }

    /// Formatted string for display: "Today 14:32" or "20/02/2026 14:32".
    /// Returns nil if never scanned.
    static func formattedDate(for scanner: Scanner) -> String? {
        guard let date = lastDate(for: scanner) else { return nil }
        let formatter = DateFormatter()
        if Calendar.current.isDateInToday(date) {
            formatter.dateFormat = "'Today' HH:mm"
        } else {
            formatter.dateFormat = "dd/MM/yyyy HH:mm"
        }
        return formatter.string(from: date)
    }
}
