import Foundation

@Observable
@MainActor
final class BreachCheckViewModel {
    var emailAccounts: [EmailAccount] = []
    var breachResults: [BreachResult] = []
    var isScanning = false
    var progress = ""
    var apiKeyConfigured = false
    var newEmailInput = ""

    func scan() async {
        isScanning = true
        progress = "Discovering email accounts..."

        // Check API key
        apiKeyConfigured = Self.getAPIKey() != nil

        // Discover + load manual emails
        var discovered = Self.discoverEmails()
        let manual = Self.loadManualEmails()
        for m in manual where !discovered.contains(where: { $0.email == m.email }) {
            discovered.append(m)
        }
        emailAccounts = discovered

        guard apiKeyConfigured, let apiKey = Self.getAPIKey() else {
            progress = "API key not configured — set up HIBP key to scan"
            isScanning = false
            return
        }

        // Check each email with rate limiting
        var allBreaches: [BreachResult] = []
        for i in 0..<emailAccounts.count {
            progress = "Checking \(i + 1)/\(emailAccounts.count): \(emailAccounts[i].email)..."
            let breaches = await Self.checkEmail(emailAccounts[i].email, apiKey: apiKey)
            emailAccounts[i].breachCount = breaches.count
            emailAccounts[i].lastChecked = Date()
            allBreaches.append(contentsOf: breaches)
        }

        breachResults = allBreaches.sorted { $0.risk.rawValue > $1.risk.rawValue }
        progress = "Found \(allBreaches.count) breaches across \(emailAccounts.count) accounts"
        isScanning = false

        let flagged = allBreaches.filter(\.needsReview).map(\.approvalID)
        ApprovalManager.recordScanResults(.breachCheck, flaggedIDs: flagged)
        ScanDateTracker.record(.breachCheck)
        DatabaseManager.shared.insertScanHistory(
            scanner: "breachCheck", total: emailAccounts.count, flagged: allBreaches.count,
            summary: "\(emailAccounts.count) emails, \(allBreaches.count) breaches"
        )
    }

    func addManualEmail(_ email: String) {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard trimmed.contains("@"), !emailAccounts.contains(where: { $0.email == trimmed }) else { return }
        let account = EmailAccount(email: trimmed, source: "Manual")
        emailAccounts.append(account)
        Self.saveManualEmail(trimmed)
    }

    func removeManualEmail(_ email: String) {
        emailAccounts.removeAll { $0.email == email && $0.source == "Manual" }
        Self.deleteManualEmail(email)
    }

    // MARK: - API Key (Keychain)

    nonisolated static func getAPIKey() -> String? {
        let result = ShellExecutor.run("/usr/bin/security", arguments: [
            "find-generic-password", "-s", "MacSecurityGuard-HIBP", "-w"
        ])
        let key = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        return key.isEmpty || result.exitCode != 0 ? nil : key
    }

    nonisolated static func setAPIKey(_ key: String) {
        // Delete existing first
        _ = ShellExecutor.run("/usr/bin/security", arguments: [
            "delete-generic-password", "-s", "MacSecurityGuard-HIBP"
        ])
        _ = ShellExecutor.run("/usr/bin/security", arguments: [
            "add-generic-password", "-s", "MacSecurityGuard-HIBP",
            "-a", "hibp-api-key", "-w", key
        ])
    }

    // MARK: - Manual Emails (UserDefaults)

    nonisolated(unsafe) private static let manualEmailsKey = "ManualBreachCheckEmails"

    nonisolated private static func loadManualEmails() -> [EmailAccount] {
        let emails = UserDefaults.standard.stringArray(forKey: manualEmailsKey) ?? []
        return emails.map { EmailAccount(email: $0, source: "Manual") }
    }

    nonisolated private static func saveManualEmail(_ email: String) {
        var emails = UserDefaults.standard.stringArray(forKey: manualEmailsKey) ?? []
        if !emails.contains(email) { emails.append(email) }
        UserDefaults.standard.set(emails, forKey: manualEmailsKey)
    }

    nonisolated private static func deleteManualEmail(_ email: String) {
        var emails = UserDefaults.standard.stringArray(forKey: manualEmailsKey) ?? []
        emails.removeAll { $0 == email }
        UserDefaults.standard.set(emails, forKey: manualEmailsKey)
    }

    // MARK: - Email Discovery

    nonisolated static func discoverEmails() -> [EmailAccount] {
        var emails: [EmailAccount] = []
        var seen = Set<String>()

        // Apple ID
        let appleid = ShellExecutor.run("/usr/bin/defaults", arguments: ["read", "MobileMeAccounts", "Accounts"])
        for line in appleid.output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("AccountID") {
                if let email = trimmed.components(separatedBy: "=").last?
                    .trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\";")),
                   email.contains("@"), !seen.contains(email) {
                    seen.insert(email)
                    emails.append(EmailAccount(email: email, source: "Apple ID"))
                }
            }
        }

        // Mail.app
        let mail = ShellExecutor.run("/usr/bin/defaults", arguments: ["read", "com.apple.mail", "MailAccounts"])
        let emailRegex = try? NSRegularExpression(pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        if let regex = emailRegex {
            let matches = regex.matches(in: mail.output, range: NSRange(mail.output.startIndex..., in: mail.output))
            for match in matches {
                if let range = Range(match.range, in: mail.output) {
                    let email = String(mail.output[range]).lowercased()
                    if !seen.contains(email) {
                        seen.insert(email)
                        emails.append(EmailAccount(email: email, source: "Mail.app"))
                    }
                }
            }
        }

        // Keychain — parse "acct" fields that look like emails
        let keychain = ShellExecutor.shell("security dump-keychain login.keychain 2>/dev/null | grep '\"acct\"'")
        if let regex = emailRegex {
            let matches = regex.matches(in: keychain.output, range: NSRange(keychain.output.startIndex..., in: keychain.output))
            for match in matches {
                if let range = Range(match.range, in: keychain.output) {
                    let email = String(keychain.output[range]).lowercased()
                    if !seen.contains(email) {
                        seen.insert(email)
                        emails.append(EmailAccount(email: email, source: "Keychain"))
                    }
                }
            }
        }

        return emails
    }

    // MARK: - HIBP API

    nonisolated private static func checkEmail(_ email: String, apiKey: String) async -> [BreachResult] {
        // Rate limiting: 1.5s between requests
        try? await Task.sleep(for: .seconds(1.5))

        let encodedEmail = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? email
        let url = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encodedEmail)?truncateResponse=false"

        let result = await Task.detached {
            ShellExecutor.run("/usr/bin/curl", arguments: [
                "-s", "-w", "\n%{http_code}",
                "-H", "hibp-api-key: \(apiKey)",
                "-H", "user-agent: MacSecurityGuard/1.0",
                url
            ], timeout: .network)
        }.value

        let lines = result.output.components(separatedBy: "\n")
        guard let httpCode = lines.last, httpCode == "200" else { return [] }
        let jsonBody = lines.dropLast().joined(separator: "\n")

        guard let data = jsonBody.data(using: .utf8),
              let breaches = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return []
        }

        return breaches.compactMap { breach in
            let dataClasses = breach["DataClasses"] as? [String] ?? []
            return BreachResult(
                email: email,
                breachName: breach["Name"] as? String ?? "",
                breachTitle: breach["Title"] as? String ?? "",
                breachDomain: breach["Domain"] as? String ?? "",
                breachDate: breach["BreachDate"] as? String ?? "",
                pwnCount: breach["PwnCount"] as? Int ?? 0,
                dataClasses: dataClasses,
                isVerified: breach["IsVerified"] as? Bool ?? false,
                isSensitive: breach["IsSensitive"] as? Bool ?? false,
                breachDescription: breach["Description"] as? String ?? ""
            )
        }
    }
}
