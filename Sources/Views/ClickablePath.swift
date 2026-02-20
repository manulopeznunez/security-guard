import SwiftUI
import AppKit

/// A text view that displays a file path and opens/reveals it on click.
/// Expands `~` to the user's home directory.
/// Shows a pointer cursor on hover and underlines the path.
struct ClickablePath: View {
    let path: String
    var font: Font = .system(.caption, design: .monospaced)

    var body: some View {
        Text(path)
            .font(font)
            .underline(isHovering, color: .accentColor)
            .onHover { hovering in
                isHovering = hovering
                if hovering {
                    NSCursor.pointingHand.push()
                } else {
                    NSCursor.pop()
                }
            }
            .onTapGesture {
                revealInFinder()
            }
            .help("Click to reveal in Finder")
    }

    @State private var isHovering = false

    private func revealInFinder() {
        let expanded = path.replacingOccurrences(of: "~", with: NSHomeDirectory())
        let url = URL(fileURLWithPath: expanded)
        if FileManager.default.fileExists(atPath: expanded) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            // If file doesn't exist, try opening the parent directory
            let parent = url.deletingLastPathComponent()
            if FileManager.default.fileExists(atPath: parent.path) {
                NSWorkspace.shared.open(parent)
            }
        }
    }
}
