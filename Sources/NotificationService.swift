import Foundation
import UserNotifications

/// Sends macOS notifications when quarantined items reappear.
/// Anti-spam: suppresses duplicate alerts within a 1-hour window.
@MainActor
enum NotificationService {
    private static var notifiedRecently: [String: Date] = [:]
    private static let suppressionInterval: TimeInterval = 3600  // 1 hour

    /// Request notification permissions. Call once at app launch.
    nonisolated static func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { granted, error in
            if let error {
                AuditLogger.security.error("Notification permission error: \(error.localizedDescription)")
            }
            AuditLogger.security.info("Notification permission granted: \(granted)")
        }
    }

    /// Fire an alert for a quarantined item that has reappeared.
    /// Can be called from any context — dispatches to MainActor for state access.
    nonisolated static func sendQuarantineReappearanceAlert(
        categoryRawValue: String,
        itemID: String
    ) {
        let cacheKey = "\(categoryRawValue):\(itemID)"

        let content = UNMutableNotificationContent()
        content.title = "Quarantined Item Reappeared"
        content.subtitle = itemID
        content.body = "A previously quarantined \(categoryRawValue) item has been detected again. This may indicate a persistent threat."
        content.sound = .default
        content.interruptionLevel = .timeSensitive

        Task { @MainActor in
            // Anti-spam: skip if notified recently
            cleanExpiredEntries()
            if let lastNotified = notifiedRecently[cacheKey],
               Date().timeIntervalSince(lastNotified) < suppressionInterval {
                return
            }
            notifiedRecently[cacheKey] = Date()

            let identifier = "quarantine-\(cacheKey.hashValue)"
            let request = UNNotificationRequest(
                identifier: identifier,
                content: content,
                trigger: nil  // Deliver immediately
            )

            UNUserNotificationCenter.current().add(request) { error in
                if let error {
                    AuditLogger.security.error("Failed to send notification: \(error.localizedDescription)")
                } else {
                    AuditLogger.audit.info("Critical alert: quarantined \(categoryRawValue):\(itemID) reappeared")
                }
            }
        }
    }

    private static func cleanExpiredEntries() {
        let now = Date()
        notifiedRecently = notifiedRecently.filter { now.timeIntervalSince($0.value) < suppressionInterval }
    }
}
