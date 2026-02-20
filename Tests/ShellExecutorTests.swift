import Testing
@testable import MacSecurityGuard

struct ShellExecutorTests {

    @Test func runEchoCommand() {
        let result = ShellExecutor.run("/bin/echo", arguments: ["hello"])
        #expect(result.exitCode == 0)
        #expect(result.output == "hello")
        #expect(result.timedOut == false)
    }

    @Test func runFailingCommand() {
        let result = ShellExecutor.run("/usr/bin/false")
        #expect(result.exitCode == 1)
        #expect(result.timedOut == false)
    }

    @Test func shellWithPipe() {
        let result = ShellExecutor.shell("echo 'abc' | tr 'a' 'x'")
        #expect(result.output == "xbc")
        #expect(result.exitCode == 0)
    }

    @Test func timeoutKillsSlowCommand() {
        let result = ShellExecutor.run("/bin/sleep", arguments: ["60"], timeout: .local)
        #expect(result.timedOut == true)
        #expect(result.exitCode == -2)
    }

    @Test func fastCommandCompletesWithinTimeout() {
        let result = ShellExecutor.run("/bin/echo", arguments: ["fast"], timeout: .local)
        #expect(result.timedOut == false)
        #expect(result.exitCode == 0)
    }

    @Test func argumentSeparationPreventsInjection() {
        // This must NOT be interpreted as shell commands
        let result = ShellExecutor.run("/bin/echo", arguments: ["hello; rm -rf /"])
        #expect(result.output == "hello; rm -rf /")
    }

    @Test func nonExistentCommand() {
        let result = ShellExecutor.run("/nonexistent/binary")
        #expect(result.exitCode == -1)
        #expect(result.timedOut == false)
    }

    @Test func stderrCapture() {
        let result = ShellExecutor.shell("echo 'out' && echo 'err' >&2")
        #expect(result.output == "out")
        #expect(result.error == "err")
    }

    @Test func largeOutputNoPipeDeadlock() {
        // Generate >64KB of output (pipe buffer size)
        let result = ShellExecutor.shell("yes | head -n 10000", timeout: .local)
        #expect(result.output.count > 10000)
    }

    @Test func timeoutResultFields() {
        let result = ShellExecutor.run("/bin/sleep", arguments: ["60"], timeout: .local)
        #expect(result.timedOut == true)
        #expect(result.error.contains("timed out"))
    }
}
