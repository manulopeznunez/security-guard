import Foundation
import os.log

struct ShellExecutor: Sendable {

    struct Result: Sendable {
        let output: String
        let error: String
        let exitCode: Int32
        let timedOut: Bool
    }

    enum Timeout: Sendable {
        case local       // 10s — ps, codesign, pgrep, plutil, etc.
        case network     // 30s — curl, host, DNS lookups
        case install     // 120s — brew install
        case scan        // 180s — KnockKnock, deep system scans
        case none        // No timeout (avoid using)

        var seconds: Double {
            switch self {
            case .local:   return 10
            case .network: return 30
            case .install: return 120
            case .scan:    return 180
            case .none:    return .infinity
            }
        }
    }

    /// Runs a command directly by executable path with arguments.
    /// Safe from shell injection. Includes configurable timeout.
    static func run(
        _ command: String,
        arguments: [String] = [],
        workingDirectory: String? = nil,
        timeout: Timeout = .local
    ) -> Result {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments
        if let dir = workingDirectory {
            process.currentDirectoryURL = URL(fileURLWithPath: dir)
        }
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let commandName = URL(fileURLWithPath: command).lastPathComponent

        do {
            try process.run()
        } catch {
            AuditLogger.shell.error(
                "Failed to launch \(commandName, privacy: .public): \(error.localizedDescription, privacy: .public)"
            )
            return Result(output: "", error: error.localizedDescription, exitCode: -1, timedOut: false)
        }

        // Read stdout and stderr concurrently BEFORE waitUntilExit
        // to prevent pipe buffer deadlock (64KB limit).
        let outHandle = stdoutPipe.fileHandleForReading
        let errHandle = stderrPipe.fileHandleForReading

        nonisolated(unsafe) var outputData = Data()
        nonisolated(unsafe) var errorData = Data()

        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outputData = outHandle.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errorData = errHandle.readDataToEndOfFile()
            group.leave()
        }

        // Timeout mechanism: terminate process if it exceeds the limit
        nonisolated(unsafe) var timedOut = false
        if timeout != .none {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout.seconds) {
                if process.isRunning {
                    timedOut = true
                    process.terminate()
                    // Grace period, then force kill
                    DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
                        if process.isRunning { process.interrupt() }
                    }
                }
            }
        }

        group.wait()
        process.waitUntilExit()

        let output = String(data: outputData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let errorOutput = String(data: errorData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        if timedOut {
            AuditLogger.shell.warning(
                "TIMEOUT: \(commandName, privacy: .public) killed after \(timeout.seconds, privacy: .public)s"
            )
        }

        return Result(
            output: output,
            error: timedOut ? "Command timed out after \(Int(timeout.seconds))s" : errorOutput,
            exitCode: timedOut ? -2 : process.terminationStatus,
            timedOut: timedOut
        )
    }

    /// Runs a command via /bin/sh -c for commands with pipes/redirects.
    static func shell(_ command: String, timeout: Timeout = .local) -> Result {
        run("/bin/sh", arguments: ["-c", command], timeout: timeout)
    }
}
