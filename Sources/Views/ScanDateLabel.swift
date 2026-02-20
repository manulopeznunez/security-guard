import SwiftUI

/// Reusable label that displays the last scan date for a scanner.
/// Shows in gray if scanned today, RED if scanned on a previous day.
struct ScanDateLabel: View {
    let scanner: ScanDateTracker.Scanner

    var body: some View {
        if let text = ScanDateTracker.formattedDate(for: scanner) {
            let stale = ScanDateTracker.isStale(for: scanner)
            HStack(spacing: 3) {
                Image(systemName: "clock")
                    .font(.system(size: 9))
                Text(text)
                    .font(.caption)
            }
            .foregroundStyle(stale ? .red : .secondary)
            .help(stale ? "Last scan is outdated — run a new scan" : "Last scan time")
        }
    }
}
