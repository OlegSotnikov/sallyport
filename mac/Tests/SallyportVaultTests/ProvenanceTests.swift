import Darwin
import Foundation
import Testing
@testable import SallyportVault

@Suite("Provenance — darwin kernel facts")
struct SessionProvenanceTests {

    // Our own (pid, start time) is alive; the same pid with a different start
    // time is NOT (that would be a recycled pid = a different process); a dead
    // pid is not alive.
    @Test("alive() has exact-process semantics (pid + start time)")
    func aliveExactProcess() throws {
        let selfPID = Int(getpid())
        let prov = Provenance.chain(pid: selfPID)
        let started = try #require(prov.chain.first, "chain must capture our own process").startedAt
        try #require(started != 0, "chain must capture our own start time")

        #expect(Provenance.alive(pid: selfPID, startedAt: started),
                "our own exact process must be alive")
        #expect(!Provenance.alive(pid: selfPID, startedAt: started + 1),
                "same pid with a different start time must NOT be alive (pid reuse)")
        #expect(!Provenance.alive(pid: 0, startedAt: started), "zero pid must never be alive")
        #expect(!Provenance.alive(pid: selfPID, startedAt: 0), "zero start must never be alive")

        // A finished child: its pid must be dead with ANY start time once reaped.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try p.run()
        let childPID = Int(p.processIdentifier)
        p.waitUntilExit()
        #expect(!Provenance.alive(pid: childPID, startedAt: started),
                "an exited child must not be alive")
    }

    @Test("chain() captures self: name, exe path, start time, ppid")
    func chainOfSelf() throws {
        let selfPID = Int(getpid())
        let prov = Provenance.chain(pid: selfPID)
        let first = try #require(prov.chain.first)
        #expect(first.pid == selfPID)
        #expect(!first.name.isEmpty, "p_comm must yield a process name")
        #expect(!first.path.isEmpty, "kern.procargs2 must yield our own exe path")
        #expect(first.startedAt != 0, "p_starttime must be captured")
        #expect(first.ppid == Int(getppid()))
        // The test runner is not the sp/sallyportd shim, so it IS the origin.
        #expect(prov.origin.pid == selfPID)
        #expect(prov.origin.startedAt == first.startedAt)
        #expect(prov.origin.path == first.path)
        #expect(!prov.intact, "capture never claims intact; the app recomputes it")
    }

    @Test("chain() of a nonexistent pid is empty, not an error")
    func chainOfGonePID() {
        let prov = Provenance.chain(pid: 0)
        #expect(prov.chain.isEmpty)
        #expect(prov.origin.pid == 0)
    }

    @Test("originHop skips the sp/sallyportd shim to the real agent")
    func originHopSkipsShim() {
        let shim = Hop(pid: 10, name: "sp", path: "/usr/local/bin/sp", ppid: 20, startedAt: 1)
        let agent = Hop(pid: 20, name: "claude", path: "/usr/local/bin/claude", ppid: 1, startedAt: 2)

        // The name-trust branch exists only for a team-less (ad-hoc) runner; under
        // CLT's Apple-signed swiftpm-testing-helper ourTeam() is real, so the shim
        // check demands a LIVE team signature these dead fixture pids can't have.
        if Provenance.ourTeam() == nil {
            #expect(Provenance.originHop([shim, agent])?.pid == 20)

            // `sp` recognized by exe basename even when the comm name drifted
            // (dev / unsigned: no team to pin the live signature to, so name-based).
            let spByPath = Hop(pid: 11, name: "worker", path: "/opt/sp", ppid: 20, startedAt: 1)
            #expect(Provenance.originHop([spByPath, agent])?.pid == 20)
        }

        // The obsolete `sallyportd` exemption is GONE (#7): a process by that
        // name is a real origin, not silently skipped.
        let notShim = Hop(pid: 12, name: "sallyportd", path: "/opt/sallyportd", ppid: 20, startedAt: 1)
        #expect(Provenance.originHop([notShim, agent])?.pid == 12)

        // Everything ours → fall back to hops[0]; empty → nil.
        #expect(Provenance.originHop([shim])?.pid == 10)
        #expect(Provenance.originHop([]) == nil)
    }

    @Test("appName derives the .app bundle display name")
    func appNameParsing() {
        #expect(Provenance.appName(fromPath: "/Applications/Claude.app/Contents/MacOS/Claude")
                == "Claude")
        #expect(Provenance.appName(fromPath: "/usr/local/bin/claude").isEmpty)
        #expect(Provenance.appName(fromPath: "").isEmpty)
    }

    @Test("displayName prefers the .app name, then the exe basename, over the kernel comm")
    func displayNamePrefersRealName() {
        // The exact bug: Claude Code's comm is its VERSION. The path basename is
        // the name a human recognizes and must win.
        #expect(Provenance.displayName(path: "/Users/os/.local/bin/claude", comm: "2.1.207") == "claude")
        // A GUI app: the BUNDLE name ("iTerm") beats both the exe basename
        // ("iTerm2") and the truncated comm ("iTermServer-3.6.").
        #expect(Provenance.displayName(path: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
                                       comm: "iTermServer-3.6.") == "iTerm")
        // No path (process already gone): fall back to the comm.
        #expect(Provenance.displayName(path: "", comm: "zsh") == "zsh")
    }

    // The SecStaticCode-based port of `codesign --verify --strict` +
    // "Authority=" extraction.
    @Test("codesign: an Apple binary is valid with an authority; junk is not")
    func codesignVerdicts() throws {
        let (valid, authority) = Provenance.codesign(path: "/bin/ls")
        #expect(valid, "/bin/ls must verify against the Apple anchor")
        #expect(!authority.isEmpty, "the leaf authority (Software Signing) must be extracted")

        // The (path, mtime) cache returns the same verdict.
        let again = Provenance.codesign(path: "/bin/ls")
        #expect(again.valid == valid)
        #expect(again.authority == authority)

        #expect(Provenance.codesign(path: "").valid == false)
        #expect(Provenance.codesign(path: "/nonexistent/not-a-binary").valid == false)

        // An unsigned plain file: not validly signed, no authority.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("sallyport-unsigned-\(UUID().uuidString)")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let junk = Provenance.codesign(path: tmp.path)
        #expect(junk.valid == false)
        #expect(junk.authority.isEmpty)
    }

    // getsockopt(LOCAL_PEERPID) on a socketpair we own reports our own pid on
    // the peer end (also pins the locally-spelled SOL_LOCAL/LOCAL_PEERPID values).
    @Test("peerPID reads the unix-socket peer via LOCAL_PEERPID")
    func peerPIDOnSocketpair() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer {
            _ = Darwin.close(fds[0])
            _ = Darwin.close(fds[1])
        }
        #expect(Provenance.peerPID(fromFD: fds[0]) == Int(getpid()))
        #expect(Provenance.peerPID(fromFD: -1) == 0, "failure is best-effort zero")
    }

    // Pins the LOCAL_PEERTOKEN value and the audit_token_t PID slot (val[5]):
    // both are spelled locally, so this must agree with the kernel on the
    // platform actually running the suite.
    @Test("peerIdentity pins pid, start time, and audit token via LOCAL_PEERTOKEN")
    func peerIdentityOnSocketpair() throws {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer {
            _ = Darwin.close(fds[0])
            _ = Darwin.close(fds[1])
        }
        let identity = try #require(Provenance.peerIdentity(fromFD: fds[0]))
        #expect(identity.pid == Int(getpid()))
        #expect(identity.startedAt > 0)
        #expect(Provenance.alive(pid: identity.pid, startedAt: identity.startedAt),
                "the captured start time must match the kernel's for this instance")
        let token = try #require(identity.auditToken, "modern Darwin must supply the token")
        #expect(token.count == MemoryLayout<audit_token_t>.size)

        // The token must drive code-signing guest lookup for this process.
        #expect(Provenance.liveCodeSatisfies(pid: identity.pid, auditToken: token,
                                             requirement: "anchor apple generic")
                == Provenance.liveCodeSatisfies(pid: identity.pid,
                                                requirement: "anchor apple generic"),
                "token-keyed and pid-keyed lookups must agree for a live process")

        #expect(Provenance.peerIdentity(fromFD: -1) == nil, "failure must be fail-closed")
    }

    @Test("cwd is captured from the kernel and fails to empty")
    func cwdCapture() {
        let own = Provenance.cwdPath(pid: Int(getpid()))
        #expect(own == FileManager.default.currentDirectoryPath)
        #expect(Provenance.cwdPath(pid: -1).isEmpty)
        #expect(Provenance.cwdPath(pid: 0).isEmpty)

        let prov = Provenance.chain(pid: Int(getpid()))
        #expect(prov.origin.cwd == own, "the origin must carry its working directory")
    }

    @Test("live signing information uses a real SecStaticCode and fails closed")
    func liveStaticCodeConversion() throws {
        #expect(SSHSpawner.liveCDHash(pid: -1) == nil)

        let selfHop = try #require(Provenance.chain(pid: Int(getpid())).chain.first)
        let diskHash = SSHSpawner.expectedCDHash(path: selfHop.path)
        let liveHash = SSHSpawner.liveCDHash(pid: getpid())
        if let diskHash {
            #expect(liveHash == diskHash,
                    "dynamic-to-static conversion must describe the executable actually running")
        }

        // Ad-hoc builds legitimately have no team id; the security property is
        // that inspection is total and never reinterprets SecCode memory as a
        // different CoreFoundation type.
        _ = SSHSpawner.ownTeamIdentifier()
    }
}
