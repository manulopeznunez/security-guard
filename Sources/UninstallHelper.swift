import AppKit

enum UninstallHelper {

    /// Shows a confirmation alert and, if confirmed, moves the .app bundle to the Trash.
    /// First tries NSWorkspace.recycle; if that fails (e.g. root-owned apps like Fing),
    /// falls back to an admin shell command that moves the app to Trash with elevated privileges.
    /// If the app bundle no longer exists, offers to reveal the containing folder in Finder.
    @MainActor
    static func uninstallApp(name: String, path: String) {
        // If the app bundle doesn't exist, offer to reveal the parent folder
        if !FileManager.default.fileExists(atPath: path) {
            let alert = NSAlert()
            alert.messageText = "\(name) not found"
            alert.informativeText = "The app bundle no longer exists at:\n\(path)\n\nThe persistence entry (plist) may still be present. Open the containing folder to remove it manually?"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open Folder")
            alert.addButton(withTitle: "Cancel")

            if alert.runModal() == .alertFirstButtonReturn {
                let folder = URL(fileURLWithPath: path).deletingLastPathComponent()
                NSWorkspace.shared.open(folder)
            }
            return
        }

        let alert = NSAlert()
        alert.messageText = "Uninstall \(name)?"
        alert.informativeText = "This will move \"\(name)\" to the Trash. macOS may ask for your password and offer to remove associated data."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Move to Trash")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else { return }

        let fileURL = URL(fileURLWithPath: path)
        NSWorkspace.shared.recycle([fileURL]) { _, error in
            if let error {
                DispatchQueue.main.async {
                    Self.adminTrash(name: name, path: path, originalError: error)
                }
            }
        }
    }

    /// Reveals the plist source folder in Finder so the user can remove entries manually.
    @MainActor
    static func revealInFinder(source: String) {
        let home = NSHomeDirectory()
        let path: String
        switch source {
        case "~/Library/LaunchAgents":
            path = "\(home)/Library/LaunchAgents"
        default:
            path = source
        }
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Claude Code Investigation

    /// Investigate a persistence entry with Claude Code.
    static func investigateWithClaude(item: PersistenceEntry) {
        let home = NSHomeDirectory()
        let plistPath: String
        if item.source == "~/Library/LaunchAgents" {
            plistPath = "\(home)/Library/LaunchAgents/\(item.label).plist"
        } else if item.source.hasPrefix("/") {
            plistPath = "\(item.source)/\(item.label).plist"
        } else {
            plistPath = item.executablePath
        }

        let prompt = """
        Investigate this macOS persistence entry and give me a clear security recommendation.

        ENTRY DETAILS:
        - Plist: \(plistPath)
        - Label: \(item.label)
        - Executable: \(item.executablePath)
        - Source directory: \(item.source)
        - Code signature: \(item.signatureAuthority.isEmpty ? "NONE" : item.signatureAuthority)

        INVESTIGATION STEPS:
        1. Read the plist file and analyze its contents
        2. Check if the binary exists and inspect it
        3. Search the web for the label and executable to identify what it is
        4. Determine if this is from a legitimate, known application

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / REMOVE
        - WHAT IS IT: Brief explanation of what this persistence entry does
        - WHY THIS VERDICT: Clear reasoning for your recommendation
        - CONSEQUENCES OF REMOVING: What breaks or stops working if deleted
        - CONSEQUENCES OF APPROVING: What risks you accept by keeping it
        - RECOMMENDED ACTION: Specific steps to take
        """

        launchClaude(with: prompt)
    }

    /// Investigate an app signature with Claude Code.
    static func investigateAppWithClaude(app: AppSignatureEntry) {
        let prompt = """
        Investigate this macOS application and give me a clear security recommendation.

        APP DETAILS:
        - Name: \(app.appName)
        - Path: \(app.appPath)
        - Code signature: \(app.authority.isEmpty ? "NONE" : app.authority)
        - Signature valid: \(app.isValid ? "YES" : "NO")
        - Details: \(app.details)

        INVESTIGATION STEPS:
        1. Check the app bundle at the path above (codesign -dvvv, contents, Info.plist)
        2. Search the web for this app to determine if it is legitimate
        3. Check if the signature issue indicates tampering or just an unsigned app
        4. Look for any known malware or adware with this name

        RESPONSE FORMAT:
        - VERDICT: SAFE / SUSPICIOUS / REMOVE
        - WHAT IS IT: Brief explanation of what this app does
        - WHY THIS VERDICT: Clear reasoning for your recommendation
        - CONSEQUENCES OF REMOVING: What breaks or stops working if you uninstall it
        - CONSEQUENCES OF APPROVING: What risks you accept by keeping it
        - RECOMMENDED ACTION: Specific steps to take
        """

        launchClaude(with: prompt)
    }

    /// Launches Claude Code in an interactive Terminal session with the given prompt.
    private static func launchClaude(with prompt: String) {
        let scriptFile = NSTemporaryDirectory() + "claude_investigate.sh"
        let escapedPrompt = prompt.replacingOccurrences(of: "\"", with: "\\\"")
        let shellScript = """
        #!/bin/bash
        CLAUDE="$HOME/.local/bin/claude"
        if [ ! -x "$CLAUDE" ]; then
            CLAUDE=$(which claude 2>/dev/null)
        fi
        if [ -z "$CLAUDE" ]; then
            echo "Error: claude not found. Install it with: npm install -g @anthropic-ai/claude-code"
            read -p "Press Enter to close..."
            exit 1
        fi
        exec "$CLAUDE" "\(escapedPrompt)"
        """
        try? shellScript.write(toFile: scriptFile, atomically: true, encoding: .utf8)
        _ = ShellExecutor.shell("chmod +x '\(scriptFile)'")

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = [
            "-e", "tell application \"Terminal\" to activate",
            "-e", "tell application \"Terminal\" to do script \"bash '\(scriptFile)'\"",
        ]
        try? task.run()
    }

    /// Fallback: move to Trash using `do shell script` with administrator privileges.
    @MainActor
    private static func adminTrash(name: String, path: String, originalError: Error) {
        let escaped = path.replacingOccurrences(of: "'", with: "'\\''")
        let trashPath = NSHomeDirectory() + "/.Trash/" + URL(fileURLWithPath: path).lastPathComponent
        let trashEscaped = trashPath.replacingOccurrences(of: "'", with: "'\\''")

        let script = "do shell script \"mv '\(escaped)' '\(trashEscaped)'\" with administrator privileges"

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", script]
        let errPipe = Pipe()
        task.standardError = errPipe

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus != 0 {
                let stderr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                // User cancelled the password dialog
                if stderr.contains("-128") { return }

                // Offer to open the folder as last resort
                let errAlert = NSAlert()
                errAlert.messageText = "Could not uninstall \(name)"
                errAlert.informativeText = (stderr.isEmpty ? originalError.localizedDescription : stderr)
                    + "\n\nYou can open the containing folder to remove it manually."
                errAlert.alertStyle = .critical
                errAlert.addButton(withTitle: "Open Folder")
                errAlert.addButton(withTitle: "Close")
                if errAlert.runModal() == .alertFirstButtonReturn {
                    let folder = URL(fileURLWithPath: path).deletingLastPathComponent()
                    NSWorkspace.shared.open(folder)
                }
            }
        } catch {
            let errAlert = NSAlert()
            errAlert.messageText = "Could not uninstall \(name)"
            errAlert.informativeText = originalError.localizedDescription
            errAlert.alertStyle = .critical
            errAlert.runModal()
        }
    }
}
