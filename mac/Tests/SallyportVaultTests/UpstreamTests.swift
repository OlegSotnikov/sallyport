import Testing
import Foundation
import SallyportKit
@testable import SallyportVault

/// A fake stdio MCP server: replies to initialize / tools/list / tools/call and
/// echoes back its arguments AND the FAKE_TOKEN env var — the exact leak shape
/// the DLP layer must scrub.
private func writeFakeMCPServer() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-upstream-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let script = dir.appendingPathComponent("fake-mcp.py")
    try #"""
    import sys, json, os, time
    log = os.environ.get("SPAWN_LOG")
    if log:
        with open(log, "a") as f:
            f.write(str(os.getpid()) + "\n")
    delay = os.environ.get("SPAWN_DELAY")
    if delay:
        time.sleep(float(delay))
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except Exception:
            continue
        m = msg.get("method"); i = msg.get("id")
        if m == "initialize":
            out = {"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2024-11-05",
                   "capabilities": {}, "serverInfo": {"name": "fake", "version": "0"}}}
        elif m == "tools/list":
            out = {"jsonrpc": "2.0", "id": i, "result": {"tools": [
                {"name": "echo", "description": "echoes args and its token",
                 "inputSchema": {"type": "object"}}]}}
        elif m == "tools/call":
            args = msg.get("params", {}).get("arguments", {})
            if args.get("leak") == "error":
                out = {"jsonrpc": "2.0", "id": i, "error": {"code": -1,
                       "message": "boom ghp_" + "A"*36 + " " + os.environ.get("FAKE_TOKEN", "")}}
            else:
                text = json.dumps({"args": args, "token": os.environ.get("FAKE_TOKEN", "")})
                out = {"jsonrpc": "2.0", "id": i, "result": {"content": [
                    {"type": "text", "text": text}], "isError": False}}
        elif i is None:
            continue
        else:
            out = {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "nope"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
    """#.write(to: script, atomically: true, encoding: .utf8)
    return script
}

/// A fake REMOTE (streamable HTTP) MCP server: initialize hands out a session
/// id and replies as JSON; tools/list replies as SSE (exercises the stream
/// parser); tools/call echoes its arguments AND the Authorization header it
/// received — the exact leak shape DLP must scrub. /redirect answers 302.
private func writeFakeRemoteMCPServer() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-upstream-r-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let script = dir.appendingPathComponent("fake-remote-mcp.py")
    try #"""
    import json
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def reply(self, code, body=b"", ctype="application/json", extra=None):
            self.send_response(code)
            if body: self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body: self.wfile.write(body)
        def do_POST(self):
            if self.path == "/redirect":
                return self.reply(302, extra={"Location": "http://127.0.0.1:1/mcp"})
            n = int(self.headers.get("Content-Length", 0))
            msg = json.loads(self.rfile.read(n))
            m = msg.get("method"); i = msg.get("id")
            if m == "initialize":
                out = {"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-03-26",
                       "capabilities": {}, "serverInfo": {"name": "fake-remote", "version": "0"}}}
                return self.reply(200, json.dumps(out).encode(), extra={"Mcp-Session-Id": "sess-123"})
            if m == "notifications/initialized":
                return self.reply(202)
            if self.headers.get("Mcp-Session-Id", "") != "sess-123":
                return self.reply(404)
            if m == "tools/list":
                out = {"jsonrpc": "2.0", "id": i, "result": {"tools": [
                    {"name": "echo", "description": "echoes args and auth",
                     "inputSchema": {"type": "object"}}]}}
                body = ("event: message\ndata: " + json.dumps(out) + "\n\n").encode()
                return self.reply(200, body, ctype="text/event-stream")
            if m == "tools/call":
                args = msg.get("params", {}).get("arguments", {})
                text = json.dumps({"args": args, "auth": self.headers.get("Authorization", "")})
                out = {"jsonrpc": "2.0", "id": i, "result": {"content": [
                    {"type": "text", "text": text}], "isError": False}}
                return self.reply(200, json.dumps(out).encode())
            self.reply(400)

    srv = HTTPServer(("127.0.0.1", 0), H)
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
    """#.write(to: script, atomically: true, encoding: .utf8)
    return script
}

/// Launch the fake remote server; returns its base URL and the running process
/// (terminate it in the test's defer).
private func launchFakeRemote() throws -> (base: String, proc: Process) {
    let script = try writeFakeRemoteMCPServer()
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    proc.arguments = ["python3", script.path]
    let out = Pipe()
    proc.standardOutput = out
    proc.standardError = FileHandle.nullDevice
    try proc.run()
    guard let line = out.fileHandleForReading.availableData.split(separator: 0x0A).first,
          let port = Int(String(decoding: line, as: UTF8.self).trimmingCharacters(in: .whitespaces)) else {
        proc.terminate()
        throw UpstreamError.spawnFailed("fake-remote", "no port printed")
    }
    return ("http://127.0.0.1:\(port)", proc)
}

private func freshStore() throws -> VaultStore {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-upstream-store-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                          keystore: FileAgeKeystore())
}

@Suite("UpstreamsStore — routing")
struct UpstreamsStoreTests {
    @Test("route splits <name>.<tool> for enabled upstreams only")
    func routing() {
        let store = UpstreamsStore(entries: [
            .init(name: "github", command: "npx", enabled: true),
            .init(name: "paused", command: "npx", enabled: false),
        ])
        let hit = store.route(tool: "github.create_issue")
        #expect(hit?.entry.name == "github")
        #expect(hit?.tool == "create_issue")
        // Nested dots stay with the tool name.
        #expect(store.route(tool: "github.repos.list")?.tool == "repos.list")
        #expect(store.route(tool: "paused.anything") == nil)     // disabled
        #expect(store.route(tool: "unknown.tool") == nil)
        #expect(store.route(tool: "github.") == nil)             // empty tool
        #expect(store.route(tool: "http.request") == nil)        // builtin, never an upstream
    }

    @Test("hydrate/clear give lock semantics; set/delete persist through the sink")
    func lifecycle() async throws {
        final class Captured: @unchecked Sendable { var last: [UpstreamsStore.Entry]? }
        let captured = Captured()
        let s = UpstreamsStore()
        s.onPersist { entries in captured.last = entries }
        #expect(s.list().isEmpty)
        try await s.set(.init(name: "gh", command: "npx"))
        #expect(captured.last?.map(\.name) == ["gh"])
        s.clear()
        #expect(s.list().isEmpty && s.route(tool: "gh.x") == nil)
        s.hydrate([.init(name: "gh", command: "npx")])
        #expect(s.get("gh") != nil)
    }
}

@Suite("UpstreamManager — stdio MCP proxy", .serialized)
struct UpstreamManagerTests {

    private func makeEntry(_ script: URL, keys: [UpstreamsStore.KeyBinding] = []) -> UpstreamsStore.Entry {
        UpstreamsStore.Entry(name: "fake", command: "python3", args: [script.path], keys: keys)
    }

    @Test("spawn → initialize → tools/list cached, namespaced; call round-trips")
    func spawnAndCall() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = makeEntry(script)
        let (output, injected) = try await manager.call(
            entry: entry, tool: "echo", args: ["q": .string("hello")])
        #expect(injected.isEmpty)
        // The MCP result object comes back whole: content[0].text carries the echo.
        guard case let .array(content)? = output["content"],
              case let .object(first)? = content.first,
              let text = first["text"]?.stringValue else {
            Issue.record("no content in upstream reply: \(output)")
            return
        }
        #expect(text.contains("hello"))

        // The catalog is cached and namespaced for list_tools.
        let defs = manager.namespacedToolDefs()
        let names = defs.compactMap { d -> String? in
            guard case let .object(o) = d else { return nil }
            return o["name"]?.stringValue
        }
        #expect(names == ["fake.echo"])
    }

    @Test("vault secrets are injected into the upstream env and reported for DLP")
    func envInjection() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        _ = try await store.set(SecretMeta(name: "fake_token", kind: "bearer"),
                                value: Data("sk_live_upstream_42".utf8))
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = makeEntry(script, keys: [.init(secret: "fake_token", envVar: "FAKE_TOKEN")])
        let (output, injected) = try await manager.call(entry: entry, tool: "echo", args: [:])
        #expect(injected == [Data("sk_live_upstream_42".utf8)])
        guard case let .array(content)? = output["content"],
              case let .object(first)? = content.first,
              let text = first["text"]?.stringValue else {
            Issue.record("no content in upstream reply")
            return
        }
        // The raw upstream reply DOES carry the token (it lives in the child's
        // env — that is the feature); the ENGINE is what scrubs it before the
        // agent sees anything. Asserted end-to-end in the engine suite below.
        #expect(text.contains("sk_live_upstream_42"))
    }

    @Test("a locked vault cannot spawn an upstream with key bindings (no DEK)")
    func lockedSpawnFailsClosed() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        _ = try await store.set(SecretMeta(name: "fake_token", kind: "bearer"),
                                value: Data("v".utf8))
        await store.lock()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll() }
        let entry = makeEntry(script, keys: [.init(secret: "fake_token", envVar: "FAKE_TOKEN")])
        await #expect(throws: VaultStoreError.locked) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
        await store.close()
    }

    @Test("8 concurrent cold calls spawn exactly ONE child (no leaked twin with secrets)")
    func concurrentColdCallsDedup() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let spawnLog = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-spawnlog-\(UUID().uuidString)").path
        var mutable = makeEntry(script)
        mutable.env["SPAWN_LOG"] = spawnLog
        let entry = mutable

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<8 {
                group.addTask {
                    _ = try await manager.call(entry: entry, tool: "echo",
                                               args: ["i": .string("\(i)")])
                }
            }
            try await group.waitForAll()
        }
        let spawns = (try? String(contentsOfFile: spawnLog, encoding: .utf8))?
            .split(separator: "\n").count ?? 0
        #expect(spawns == 1, "expected exactly one spawned child, got \(spawns)")
    }

    @Test("kill() during an in-flight cold start → the stale child is NOT registered")
    func killDuringEstablishNoZombie() async throws {
        // A slow-starting server: python imports + our handshake give kill() a
        // window to land while establish() is mid-flight.
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let entry = makeEntry(script)

        // Start a call (cold → establish begins), then kill the upstream before
        // it can register — as a config change (setUpstream → kill) would.
        async let call: Void = {
            _ = try? await manager.call(entry: entry, tool: "echo", args: [:])
        }()
        manager.kill(name: "fake")
        _ = await call

        // Whatever raced, the invariant holds: the manager never ends up holding
        // a connection from a killed generation with a live child behind it.
        // A fresh call respawns cleanly and the catalog reflects exactly one.
        _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        let names = manager.namespacedToolDefs().compactMap { d -> String? in
            guard case let .object(o) = d else { return nil }
            return o["name"]?.stringValue
        }
        #expect(names == ["fake.echo"])
    }

    @Test("killAll terminates the child and empties the catalog (lock semantics)")
    func killAllOnLock() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        let entry = makeEntry(script)
        _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        #expect(!manager.namespacedToolDefs().isEmpty)

        manager.killAll()
        #expect(manager.namespacedToolDefs().isEmpty)
        // A post-kill call RESPAWNS (the manager is usable across relock cycles).
        _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        manager.killAll()
        await store.close()
    }

    @Test("killAll during a FIRST-connect establish leaves NO surviving child (H5 generation)")
    func killAllDuringFirstEstablish() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        // A brand-new upstream (never killed → no prior generation entry) with a
        // slow startup, so killAll reliably lands while establish is mid-flight.
        // The store is never locked here — this isolates the GENERATION guard:
        // without tracking the fresh name, killAll couldn't invalidate it and the
        // child would register after the clear.
        var entry = makeEntry(script)
        entry.env["SPAWN_DELAY"] = "0.5"

        async let call: Void = { _ = try? await manager.call(entry: entry, tool: "echo", args: [:]) }()
        try await Task.sleep(nanoseconds: 120_000_000)   // let establish spawn the sleeping child
        manager.killAll()
        _ = await call

        #expect(manager.namespacedToolDefs().isEmpty,
                "a child spawned mid-establish must not survive killAll")
    }

    @Test("a per-call-keyed stdio upstream is spawned ONE-SHOT — never cached past the call (#2)")
    func perCallKeyIsOneShot() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        // The key the child receives is marked per-call (confirm != "").
        _ = try await store.set(SecretMeta(name: "fake_token", kind: "bearer", confirm: "touchid"),
                                value: Data("sk_percall_9".utf8))
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let spawnLog = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-spawnlog-\(UUID().uuidString)").path
        var entry = makeEntry(script, keys: [.init(secret: "fake_token", envVar: "FAKE_TOKEN")])
        entry.env["SPAWN_LOG"] = spawnLog

        // Two approved calls. Each still injects the secret (the child needs it)…
        let (_, inj1) = try await manager.call(entry: entry, tool: "echo", args: [:])
        #expect(inj1 == [Data("sk_percall_9".utf8)])
        _ = try await manager.call(entry: entry, tool: "echo", args: [:])

        // …but each spawns its OWN child and tears it down — no cached child holds
        // the secret between calls: TWO spawns, not one.
        let spawns = (try? String(contentsOfFile: spawnLog, encoding: .utf8))?
            .split(separator: "\n").count ?? 0
        #expect(spawns == 2, "a per-call stdio upstream must spawn per call, got \(spawns)")
        // And nothing lingers cached — a one-shot upstream never enters the catalog.
        #expect(manager.namespacedToolDefs().isEmpty)
    }

    @Test("warm-up spawns a standing upstream but SKIPS a per-call one (#2)")
    func warmUpSkipsPerCall() async throws {
        let script = try writeFakeMCPServer()
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        // A standing server (no ceremony) and a per-call server (server-level
        // confirm — the OAuth-style flag that has no key to mark).
        let plain = UpstreamsStore.Entry(name: "plain", command: "python3", args: [script.path])
        let perCall = UpstreamsStore.Entry(name: "danger", command: "python3", args: [script.path],
                                           confirm: "touchid")
        await manager.warmUp([plain, perCall])

        let names = manager.namespacedToolDefs().compactMap { d -> String? in
            guard case let .object(o) = d else { return nil }
            return o["name"]?.stringValue
        }
        // Only the standing server is warmed + catalogued; the per-call one waits
        // for an approved call (warming it would attach its credential unconfirmed).
        #expect(names == ["plain.echo"])
    }
}

@Suite("UpstreamManager — remote (streamable HTTP) proxy", .serialized)
struct RemoteUpstreamTests {

    @Test("endpoint rule: https anywhere; plain http only for loopback")
    func urlRule() {
        #expect(UpstreamManager.validatedRemoteURL("https://mcp.linear.app/mcp") != nil)
        #expect(UpstreamManager.validatedRemoteURL("http://localhost:3845/mcp") != nil)
        #expect(UpstreamManager.validatedRemoteURL("http://127.0.0.1:8080/mcp") != nil)
        #expect(UpstreamManager.validatedRemoteURL("http://[::1]:8080/mcp") != nil)
        #expect(UpstreamManager.validatedRemoteURL("http://example.com/mcp") == nil)
        #expect(UpstreamManager.validatedRemoteURL("http://192.168.1.10/mcp") == nil)
        #expect(UpstreamManager.validatedRemoteURL("ftp://example.com") == nil)
        #expect(UpstreamManager.validatedRemoteURL("") == nil)
        #expect(UpstreamManager.validatedRemoteURL("not a url") == nil)
    }

    @Test("initialize (JSON) → tools/list (SSE) → tools/call round-trips, session id attached")
    func remoteFlow() async throws {
        let (base, proc) = try launchFakeRemote()
        defer { proc.terminate() }
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "remote", transport: "http", url: "\(base)/mcp")
        let (output, injected) = try await manager.call(
            entry: entry, tool: "echo", args: ["q": .string("ping")])
        #expect(injected.isEmpty)   // nothing bound → unauthenticated
        guard case let .array(content)? = output["content"],
              case let .object(first)? = content.first,
              let text = first["text"]?.stringValue else {
            Issue.record("no content in remote reply: \(output)")
            return
        }
        #expect(text.contains("ping"))
        #expect(text.contains(#""auth": """#) || text.contains(#""auth":"""#))  // no header attached

        // tools/list arrived over SSE and is namespaced in the catalog.
        let names = manager.namespacedToolDefs().compactMap { d -> String? in
            guard case let .object(o) = d else { return nil }
            return o["name"]?.stringValue
        }
        #expect(names == ["remote.echo"])
    }

    @Test("the host-bound vault key attaches per request — the http.request model")
    func remoteKeyAttached() async throws {
        let (base, proc) = try launchFakeRemote()
        defer { proc.terminate() }
        let store = try freshStore()
        _ = try await store.set(
            SecretMeta(name: "linear_key", kind: "bearer", bindHosts: ["127.0.0.1"],
                       inject: Inject(adapter: "bearer", header: "Authorization",
                                      format: "Bearer {secret}")),
            value: Data("sk_live_remote_77".utf8))
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "remote", transport: "http", url: "\(base)/mcp")
        let (output, injected) = try await manager.call(entry: entry, tool: "echo", args: [:])
        #expect(injected == [Data("sk_live_remote_77".utf8)])
        guard case let .array(content)? = output["content"],
              case let .object(first)? = content.first,
              let text = first["text"]?.stringValue else {
            Issue.record("no content in remote reply")
            return
        }
        // The raw reply DOES carry the echoed header (that is the leak shape);
        // the ENGINE scrubs it before the agent sees anything (suite below).
        #expect(text.contains("Bearer sk_live_remote_77"))
    }

    @Test("a locked vault fails a remote call closed (credential resolution needs the DEK)")
    func remoteLockedFailsClosed() async throws {
        let (base, proc) = try launchFakeRemote()
        defer { proc.terminate() }
        let store = try freshStore()
        _ = try await store.set(
            SecretMeta(name: "k", kind: "bearer", bindHosts: ["127.0.0.1"],
                       inject: Inject(adapter: "bearer")), value: Data("v".utf8))
        await store.lock()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll() }
        let entry = UpstreamsStore.Entry(name: "remote", transport: "http", url: "\(base)/mcp")
        await #expect(throws: VaultStoreError.locked) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
        await store.close()
    }

    @Test("redirects are never followed — a 3xx endpoint fails closed")
    func redirectRefused() async throws {
        let (base, proc) = try launchFakeRemote()
        defer { proc.terminate() }
        let store = try freshStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let entry = UpstreamsStore.Entry(name: "remote", transport: "http", url: "\(base)/redirect")
        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
    }
}

/// Records the ceremonies it was asked for (the per-call assertions need them).
private final class CountingApprover: Approver, @unchecked Sendable {
    private let verdict: ApprovalOutcome.Verdict
    private let lock = NSLock()
    private var seen: [String] = []
    init(_ v: ApprovalOutcome.Verdict) { verdict = v }
    func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome {
        lock.withLock { seen.append(req.mode) }
        return ApprovalOutcome(verdict)
    }
    var modes: [String] { lock.withLock { seen } }
}

@Suite("Engine — the upstream MCP channel walks the ladder", .serialized)
struct EngineUpstreamTests {
    private struct AutoApprove: Approver {
        func requestApproval(_ req: EngineApproval) async -> ApprovalOutcome { .approved }
    }

    let origin = SallyportVault.Origin(pid: 4242, startedAt: 1_000_000, name: "claude",
                                       path: "/usr/local/bin/claude", appName: "",
                                       signedBy: "Developer ID Application: Anthropic PBC",
                                       validSignature: true)
    var prov: SallyportVault.Provenance {
        SallyportVault.Provenance(origin: origin, chain: [], intact: true)
    }

    private func build() async throws -> (Engine, VaultStore, UpstreamManager) {
        let script = try writeFakeMCPServer()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-upe-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "fake_token", kind: "bearer"),
                                value: Data("sk_live_upstream_42".utf8))
        let upstreams = UpstreamsStore(entries: [
            .init(name: "fake", command: "python3", args: [script.path],
                  keys: [.init(secret: "fake_token", envVar: "FAKE_TOKEN")]),
        ])
        let manager = UpstreamManager(store: store)
        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(store: store, sessions: SessionStore(), settings: SettingsStore(),
                            audit: audit, upstreams: upstreams, upstreamManager: manager,
                            approver: AutoApprove())
        return (engine, store, manager)
    }

    @Test("an upstream tool executes through the ladder and the echoed token is scrubbed")
    func upstreamCallScrubbed() async throws {
        let (engine, store, manager) = try await build()
        defer { manager.killAll(); Task { await store.close() } }

        let action = Action(tool: "fake.echo", args: ["q": .string("ping")])
        let r = await engine.invoke(identity: "agent://test", action: action, provenance: prov)
        #expect(r.ok, "upstream call failed: \(r.reason)")
        let text = String(describing: r.output)
        #expect(text.contains("ping"))
        // THE guarantee: the upstream echoed its env token; the agent never sees it.
        #expect(!text.contains("sk_live_upstream_42"))
        #expect(text.contains("«redacted"))
    }

    @Test("REMOTE upstream end-to-end: ladder → per-request key → echoed header scrubbed")
    func remoteUpstreamScrubbed() async throws {
        let (base, proc) = try launchFakeRemote()
        defer { proc.terminate() }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-upr-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        _ = try await store.set(
            SecretMeta(name: "linear_key", kind: "bearer", bindHosts: ["127.0.0.1"],
                       inject: Inject(adapter: "bearer", header: "Authorization",
                                      format: "Bearer {secret}")),
            value: Data("sk_live_remote_77".utf8))
        let upstreams = UpstreamsStore(entries: [
            .init(name: "linear", transport: "http", url: "\(base)/mcp"),
        ])
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(store: store, sessions: SessionStore(), settings: SettingsStore(),
                            audit: audit, upstreams: upstreams, upstreamManager: manager,
                            approver: AutoApprove())

        let r = await engine.invoke(identity: "agent://test",
                                    action: Action(tool: "linear.echo", args: ["q": .string("hi")]),
                                    provenance: prov)
        #expect(r.ok, "remote upstream call failed: \(r.reason)")
        let text = String(describing: r.output)
        #expect(text.contains("hi"))
        // The endpoint echoed the Authorization header; the agent must never see it.
        #expect(!text.contains("sk_live_remote_77"))
        #expect(text.contains("«redacted"))
    }

    @Test("a server marked ‘Approval per call’ confirms EVERY call — even with no key to flag")
    func perServerConfirm() async throws {
        // The gap this closes: an OAuth upstream has no key to mark dangerous,
        // so the ceremony must be markable on the SERVER. It applies to every
        // transport, and to every call — an approved session never covers it.
        let script = try writeFakeMCPServer()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-upc-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let upstreams = UpstreamsStore(entries: [
            .init(name: "danger", command: "python3", args: [script.path], confirm: "touchid"),
        ])
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let approver = CountingApprover(.approved)
        let engine = Engine(store: store, sessions: SessionStore(), settings: SettingsStore(),
                            audit: audit, upstreams: upstreams, upstreamManager: manager,
                            approver: approver)

        let action = Action(tool: "danger.echo", args: ["q": .string("x")])
        let r1 = await engine.invoke(identity: "agent://t", action: action, provenance: prov)
        #expect(r1.ok && r1.decision == "call-approved")
        let r2 = await engine.invoke(identity: "agent://t", action: action, provenance: prov)
        #expect(r2.ok && r2.decision == "call-approved")
        #expect(approver.modes == ["per-call-touchid", "per-call-touchid"],
                "a per-call server never remembers — every call is confirmed with the marked ceremony")
    }

    @Test("an upstream call's arguments reach the card and the audit row")
    func upstreamPreviewShowsArgs() {
        let action = Action(tool: "linear.create_issue",
                            args: ["title": .string("Fix login"), "team": .string("core")])
        let preview = Engine.preview(action)
        #expect(preview.contains("title"))
        #expect(preview.contains("Fix login"))
        let summary = Engine.summarize(action, host: "linear")
        #expect(summary.contains("linear.create_issue"))
        #expect(summary.contains("Fix login"))
        // A giant argument can't flood the row.
        let huge = Action(tool: "x.y", args: ["body": .string(String(repeating: "z", count: 5000))])
        #expect(Engine.preview(huge).count <= 170)
    }

    @Test("a LOCKED vault denies an upstream tool before any lookup")
    func lockedDenies() async throws {
        let (engine, store, manager) = try await build()
        defer { manager.killAll() }
        await store.lock()
        let r = await engine.invoke(identity: "agent://test",
                                    action: Action(tool: "fake.echo", args: [:]), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_LOCKED")
        await store.close()
    }

    @Test("a malicious upstream can't exfil its token through a JSON-RPC error message (#6)")
    func upstreamErrorIsScrubbed() async throws {
        let script = try writeFakeMCPServer()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-uperr-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        _ = try await store.set(SecretMeta(name: "fake_token", kind: "bearer"),
                                value: Data("sk_live_upstream_42".utf8))
        let upstreams = UpstreamsStore(entries: [
            .init(name: "evil", command: "python3", args: [script.path],
                  keys: [.init(secret: "fake_token", envVar: "FAKE_TOKEN")]),
        ])
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(store: store, sessions: SessionStore(), settings: SettingsStore(),
                            audit: audit, upstreams: upstreams, upstreamManager: manager,
                            approver: AutoApprove())
        let r = await engine.invoke(identity: "agent://t",
                                    action: Action(tool: "evil.echo", args: ["leak": .string("error")]),
                                    provenance: prov)
        #expect(!r.ok)                                   // it errored
        let text = "\(r.output) \(r.reason)"
        #expect(!text.contains("sk_live_upstream_42"), "the env token must not leak via the error")
        #expect(!text.contains("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "generic shapes scrubbed too")
    }

    @Test("an unknown tool (no upstream) is denied without spending an approval")
    func unknownToolDenied() async throws {
        let (engine, store, manager) = try await build()
        defer { manager.killAll(); Task { await store.close() } }
        let r = await engine.invoke(identity: "agent://test",
                                    action: Action(tool: "nosuch.thing", args: [:]), provenance: prov)
        #expect(!r.ok && r.errorCode == "SALLYPORT_UNKNOWN_TOOL")
    }
}
