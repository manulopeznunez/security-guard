import Foundation

@Observable
@MainActor
final class NetworkHistoryViewModel {
    var topIPs: [IPSummary] = []
    var topApps: [AppSummary] = []
    var topCountries: [CountrySummary] = []
    var totalRecords = 0
    var oldestRecord = "N/A"
    var dbSizeKB: Int64 = 0
    var selectedDays = 7
    var isLoading = false

    func refresh() async {
        isLoading = true
        let days = selectedDays
        let ips = await Task.detached { DatabaseManager.shared.topIPs(days: days) }.value
        let apps = await Task.detached { DatabaseManager.shared.topApps(days: days) }.value
        let countries = await Task.detached { DatabaseManager.shared.topCountries(days: days) }.value
        let stats = await Task.detached { DatabaseManager.shared.totalStats() }.value

        // Verify code signatures for each app
        let signedApps = await Task.detached { NetworkHistoryViewModel.verifyAppSignatures(apps) }.value

        topIPs = ips
        topApps = signedApps
        topCountries = countries
        totalRecords = stats.records
        oldestRecord = stats.oldestRecord
        dbSizeKB = stats.dbSizeKB
        isLoading = false
    }

    nonisolated private static func verifyAppSignatures(_ apps: [AppSummary]) -> [AppSummary] {
        var updated = apps
        for i in updated.indices {
            let name = updated[i].processName
            // Try to find a running process with this name and verify by PID
            let psResult = ShellExecutor.run("/usr/bin/pgrep", arguments: ["-x", name])
            let pids = psResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
                .components(separatedBy: "\n").compactMap { Int($0) }

            if let pid = pids.first {
                let verify = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", String(pid)])
                updated[i].isSigned = verify.exitCode == 0

                let info = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", String(pid)])
                let infoText = info.output + "\n" + info.error
                if let line = infoText.components(separatedBy: "\n").first(where: { $0.hasPrefix("Authority=") }),
                   let range = line.range(of: "Authority=") {
                    updated[i].signatureAuthority = String(line[range.upperBound...])
                }
            } else {
                // Not running — try /Applications/<name>.app
                let appPath = "/Applications/\(name).app"
                if FileManager.default.fileExists(atPath: appPath) {
                    let verify = ShellExecutor.run("/usr/bin/codesign", arguments: ["-v", appPath])
                    updated[i].isSigned = verify.exitCode == 0

                    let info = ShellExecutor.run("/usr/bin/codesign", arguments: ["-dvvv", appPath])
                    let infoText = info.output + "\n" + info.error
                    if let line = infoText.components(separatedBy: "\n").first(where: { $0.hasPrefix("Authority=") }),
                       let range = line.range(of: "Authority=") {
                        updated[i].signatureAuthority = String(line[range.upperBound...])
                    }
                }
            }
        }
        return updated
    }

    func purgeOld() async {
        await Task.detached { DatabaseManager.shared.purgeOlderThan(days: 90) }.value
        await refresh()
    }
}
