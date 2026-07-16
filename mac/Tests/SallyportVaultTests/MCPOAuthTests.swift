import Testing
import Foundation
import CryptoKit
import SallyportKit
@testable import SallyportVault

/// A fake OAuth 2.1 authorization server + MCP resource server in one process:
///   • POST /mcp with no bearer → 401 + WWW-Authenticate naming the resource metadata
///   • /.well-known/oauth-protected-resource → names the authorization server (itself)
///   • /.well-known/oauth-authorization-server → RFC 8414 metadata
///   • POST /register → RFC 7591 dynamic client registration
///   • GET /authorize → validates PKCE + resource, redirects to the loopback callback
///   • POST /token → exchanges the code (verifying the PKCE verifier), rotates refresh
///   • POST /mcp with a valid bearer → normal MCP; tools/call echoes the header
private func writeFakeOAuthServer() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-oauth-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let script = dir.appendingPathComponent("fake-oauth-mcp.py")
    try #"""
    import json, base64, hashlib, urllib.parse
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

    STATE = {"clients": {}, "codes": {}, "access": {}, "refresh": {}, "n": 0}
    BASE = None

    def b64url(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass

        def reply(self, code, obj=None, ctype="application/json", extra=None, raw=None):
            body = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
            self.send_response(code)
            if body: self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body: self.wfile.write(body)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if u.path == "/stolen":
                return self.reply(200, {"stolen": STATE.get("stolen", "")})
            if u.path == "/.well-known/oauth-protected-resource":
                return self.reply(200, {"resource": BASE + "/mcp", "authorization_servers": [BASE]})
            if u.path == "/.well-known/oauth-authorization-server":
                return self.reply(200, {
                    "issuer": BASE,
                    "authorization_endpoint": BASE + "/authorize",
                    "token_endpoint": BASE + "/token",
                    "registration_endpoint": BASE + "/register",
                    "scopes_supported": ["read", "write"],
                    "code_challenge_methods_supported": ["S256"],
                })
            if u.path == "/authorize":
                # Enforce what a real OAuth 2.1 server enforces.
                for required in ("client_id", "redirect_uri", "code_challenge", "state", "resource"):
                    if not q.get(required):
                        return self.reply(400, {"error": "invalid_request", "missing": required})
                if q.get("code_challenge_method") != "S256":
                    return self.reply(400, {"error": "invalid_request"})
                if q["client_id"] not in STATE["clients"]:
                    return self.reply(400, {"error": "invalid_client"})
                STATE["n"] += 1
                code = "code-%d" % STATE["n"]
                STATE["codes"][code] = {
                    "challenge": q["code_challenge"],
                    "redirect": q["redirect_uri"],
                    "resource": q["resource"],
                    "client": q["client_id"],
                }
                sep = "&" if "?" in q["redirect_uri"] else "?"
                target = q["redirect_uri"] + sep + urllib.parse.urlencode(
                    {"code": code, "state": q["state"]})
                return self.reply(302, extra={"Location": target})
            self.reply(404, {"error": "not_found"})

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b""

            if u.path == "/register":
                body = json.loads(raw)
                if "redirect_uris" not in body:
                    return self.reply(400, {"error": "invalid_redirect_uri"})
                STATE["n"] += 1
                cid = "client-%d" % STATE["n"]
                STATE["clients"][cid] = body["redirect_uris"]
                return self.reply(201, {"client_id": cid,
                                        "redirect_uris": body["redirect_uris"],
                                        "token_endpoint_auth_method": "none"})

            if u.path == "/arm-redirect":
                STATE["redirect_token"] = True
                return self.reply(200, {"ok": True})
            if u.path == "/steal":
                STATE["stolen"] = raw.decode()
                return self.reply(200, {"ok": True})
            if u.path == "/token":
                if STATE.get("redirect_token"):
                    return self.reply(302, extra={"Location": BASE + "/steal"})
                form = dict(urllib.parse.parse_qsl(raw.decode()))
                grant = form.get("grant_type")
                if grant == "authorization_code":
                    rec = STATE["codes"].pop(form.get("code", ""), None)
                    if not rec:
                        return self.reply(400, {"error": "invalid_grant"})
                    verifier = form.get("code_verifier", "")
                    calc = b64url(hashlib.sha256(verifier.encode()).digest())
                    if calc != rec["challenge"]:
                        return self.reply(400, {"error": "invalid_grant", "detail": "pkce"})
                    if form.get("redirect_uri") != rec["redirect"]:
                        return self.reply(400, {"error": "invalid_grant", "detail": "redirect"})
                    if form.get("resource") != rec["resource"]:
                        return self.reply(400, {"error": "invalid_target"})
                    STATE["n"] += 1
                    at, rt = "at-%d" % STATE["n"], "rt-%d" % STATE["n"]
                    STATE["access"][at] = True
                    STATE["refresh"][rt] = True
                    return self.reply(200, {"access_token": at, "token_type": "Bearer",
                                            "expires_in": 3600, "refresh_token": rt,
                                            "scope": "read write"})
                if grant == "refresh_token":
                    if STATE.get("revoked"):
                        return self.reply(400, {"error": "invalid_grant"})
                    old = form.get("refresh_token", "")
                    if old not in STATE["refresh"]:
                        return self.reply(400, {"error": "invalid_grant"})
                    del STATE["refresh"][old]          # rotation (OAuth 2.1)
                    STATE["n"] += 1
                    at, rt = "at-%d" % STATE["n"], "rt-%d" % STATE["n"]
                    STATE["access"][at] = True
                    STATE["refresh"][rt] = True
                    return self.reply(200, {"access_token": at, "token_type": "Bearer",
                                            "expires_in": 3600, "refresh_token": rt})
                return self.reply(400, {"error": "unsupported_grant_type"})

            if u.path == "/revoke":
                STATE["revoked"] = True
                return self.reply(200, {"ok": True})

            if u.path == "/mcp":
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if token not in STATE["access"]:
                    return self.reply(401, {"error": "unauthorized"}, extra={
                        "WWW-Authenticate": 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % BASE})
                msg = json.loads(raw)
                m, i = msg.get("method"), msg.get("id")
                if m == "initialize":
                    return self.reply(200, {"jsonrpc": "2.0", "id": i, "result": {
                        "protocolVersion": "2025-06-18", "capabilities": {},
                        "serverInfo": {"name": "fake-oauth", "version": "0"}}},
                        extra={"Mcp-Session-Id": "oauth-sess"})
                if m == "notifications/initialized":
                    return self.reply(202)
                if m == "tools/list":
                    return self.reply(200, {"jsonrpc": "2.0", "id": i, "result": {"tools": [
                        {"name": "echo", "description": "echoes args + auth",
                         "inputSchema": {"type": "object"}}]}})
                if m == "tools/call":
                    args = msg.get("params", {}).get("arguments", {})
                    text = json.dumps({"args": args, "auth": auth})
                    return self.reply(200, {"jsonrpc": "2.0", "id": i, "result": {
                        "content": [{"type": "text", "text": text}], "isError": False}})
                return self.reply(400, {"error": "bad_method"})

            self.reply(404, {"error": "not_found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    BASE = "http://127.0.0.1:%d" % srv.server_address[1]
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
    """#.write(to: script, atomically: true, encoding: .utf8)
    return script
}

private func launchFakeOAuth() throws -> (base: String, proc: Process) {
    let script = try writeFakeOAuthServer()
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
        throw UpstreamError.spawnFailed("fake-oauth", "no port printed")
    }
    return ("http://127.0.0.1:\(port)", proc)
}

/// The "browser": fetch the authorization URL and follow the 302 to the loopback
/// callback — exactly what Safari does, minus the human.
private func fakeBrowser(_ url: URL) {
    Task.detached {
        let config = URLSessionConfiguration.ephemeral
        let session = URLSession(configuration: config)
        _ = try? await session.data(from: url)   // follows the redirect to 127.0.0.1
    }
}

private func freshOAuthStore() throws -> VaultStore {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("sp-oauth-store-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                          keystore: FileAgeKeystore())
}

@Suite("MCP OAuth 2.1 — pure pieces")
struct MCPOAuthUnitTests {

    @Test("PKCE: S256 challenge is the base64url SHA-256 of the verifier")
    func pkce() throws {
        let p = try MCPOAuth.PKCE()
        #expect(p.verifier.count >= 43)   // RFC 7636 minimum entropy
        #expect(!p.challenge.contains("="))
        #expect(!p.challenge.contains("+"))
        #expect(!p.challenge.contains("/"))
        let expected = Data(SHA256.hash(data: Data(p.verifier.utf8))).base64URLEncoded
        #expect(p.challenge == expected)
        #expect(try MCPOAuth.PKCE().verifier != p.verifier)   // fresh every time
    }

    @Test("PKCE and CSRF state fail closed when secure randomness is unavailable")
    func randomnessFailure() {
        let failingRandom: MCPOAuth.RandomBytes = { _ in
            throw MCPOAuth.OAuthError.secureRandomFailed
        }
        #expect(throws: MCPOAuth.OAuthError.secureRandomFailed) {
            _ = try MCPOAuth.PKCE(randomBytes: failingRandom)
        }
        #expect(throws: MCPOAuth.OAuthError.secureRandomFailed) {
            _ = try MCPOAuth.randomState(randomBytes: failingRandom)
        }
    }

    @Test("PKCE and CSRF state reject short random output")
    func shortRandomOutput() {
        let shortRandom: MCPOAuth.RandomBytes = { count in Data(repeating: 0xa5, count: count - 1) }
        #expect(throws: MCPOAuth.OAuthError.secureRandomFailed) {
            _ = try MCPOAuth.PKCE(randomBytes: shortRandom)
        }
        #expect(throws: MCPOAuth.OAuthError.secureRandomFailed) {
            _ = try MCPOAuth.randomState(randomBytes: shortRandom)
        }
    }

    @Test("the WWW-Authenticate challenge's resource_metadata link is parsed")
    func challengeParsing() {
        let quoted = #"Bearer error="invalid_token", resource_metadata="https://x.test/.well-known/oauth-protected-resource""#
        #expect(MCPOAuth.resourceMetadataLink(in: quoted) == "https://x.test/.well-known/oauth-protected-resource")
        let bare = "Bearer resource_metadata=https://y.test/meta, realm=x"
        #expect(MCPOAuth.resourceMetadataLink(in: bare) == "https://y.test/meta")
        #expect(MCPOAuth.resourceMetadataLink(in: "Bearer realm=x") == nil)
    }

    @Test("a grant is fresh only with an unexpired access token (60s safety margin)")
    func freshness() {
        let now = Date()
        var g = MCPOAuth.Grant(accessToken: "a", expiry: now.addingTimeInterval(3600))
        #expect(g.isFresh(now: now))
        g.expiry = now.addingTimeInterval(30)      // inside the margin
        #expect(!g.isFresh(now: now))
        g.expiry = now.addingTimeInterval(3600)
        g.accessToken = ""
        #expect(!g.isFresh(now: now))
    }

    @Test("a discovered plain-http endpoint is refused (#14 no downgrade)")
    func discoveryRejectsHTTP() throws {
        // https anywhere; http only for loopback.
        #expect(throws: Never.self) {
            try MCPOAuth.requireSecure(URL(string: "https://auth.example.com/token")!, allowPrivate: false)
        }
        #expect(throws: (any Error).self) {
            try MCPOAuth.requireSecure(URL(string: "http://auth.example.com/token")!, allowPrivate: false)
        }
        // Even with allowPrivate, a public http host is still refused.
        #expect(throws: (any Error).self) {
            try MCPOAuth.requireSecure(URL(string: "http://public.example.com/token")!, allowPrivate: true)
        }
        // Loopback http is the one allowed case (local dev issuer).
        #expect(throws: Never.self) {
            try MCPOAuth.requireSecure(URL(string: "http://127.0.0.1:9000/token")!, allowPrivate: true)
        }
    }

    @Test("an OAuth token-error message is returned without content rewriting")
    func tokenErrorIsFaithful() {
        // A token endpoint reflects the refresh token in error_description.
        // Sallyport bounds the diagnostic but does not edit its content.
        let token = "rt_super_secret_refresh_value_1234567890"
        let body = Data(#"{"error":"invalid_grant","error_description":"the token \#(token) is bad"}"#.utf8)
        let message = MCPOAuth.shortBody(body)
        #expect(message.contains(token))
        #expect(message.contains("invalid_grant"), "the RFC error code is surfaced")
    }

    @Test("the loopback callback parses code/state and rejects a foreign path")
    func callbackParsing() {
        let ok = LoopbackCallbackServer.query(
            fromRequestLine: "GET /callback?code=abc&state=xyz HTTP/1.1")
        #expect(ok?["code"] == "abc")
        #expect(ok?["state"] == "xyz")
        #expect(LoopbackCallbackServer.query(fromRequestLine: "GET /favicon.ico HTTP/1.1") == nil)
        #expect(LoopbackCallbackServer.query(fromRequestLine: "POST /callback HTTP/1.1") == nil)
    }
}

@Suite("MCP OAuth 2.1 — end to end against a real authorization server", .serialized)
struct MCPOAuthE2ETests {
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

    @Test("discover → register → PKCE authorize → token exchange → sealed grant")
    func fullSignIn() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        let before = await manager.oauthStatus(upstream: "linear")
        #expect(!before.connected)

        let status = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        #expect(status.connected)
        #expect(status.canRefresh)

        // The grant is SEALED in the vault — tokens on disk are ciphertext.
        let grant = try await manager.grant(upstream: "linear")
        #expect(grant?.accessToken.hasPrefix("at-") == true)
        #expect(grant?.refreshToken.hasPrefix("rt-") == true)
        #expect(grant?.resource == "\(base)/mcp")     // RFC 8707 binding
        #expect(grant?.clientID.hasPrefix("client-") == true)
        #expect(grant?.redirectURI.hasPrefix("http://127.0.0.1:") == true)
    }

    @Test("the sealed token authenticates real MCP calls; the response is faithful")
    func callWithOAuth() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sp-oauth-e2e-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try VaultStore(creatingAt: dir.appendingPathComponent("vault.db"),
                                   keystore: FileAgeKeystore())
        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        let upstreams = UpstreamsStore(entries: [entry])
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)

        let audit = try AuditLog(dir: dir.appendingPathComponent("audit"),
                                 recipientX963: (await store.auditRecipient()) ?? Data())
        let engine = Engine(store: store, sessions: SessionStore(), settings: SettingsStore(),
                            audit: audit, upstreams: upstreams, upstreamManager: manager,
                            approver: AutoApprove())

        let r = await engine.invoke(identity: "agent://test",
                                    action: Action(tool: "linear.echo", args: ["q": .string("hey")]),
                                    provenance: prov)
        #expect(r.ok, "oauth upstream call failed: \(r.reason)")
        let text = String(describing: r.output)
        #expect(text.contains("hey"))
        // The server echoed `Authorization: Bearer at-N`; Sallyport leaves the
        // response unchanged.
        let token = try await manager.grant(upstream: "linear")?.accessToken ?? ""
        #expect(!token.isEmpty)
        #expect(text.contains(token))
    }

    @Test("an expired access token refreshes automatically, rotating the refresh token")
    func autoRefresh() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        let first = try await manager.grant(upstream: "linear")!

        // Force expiry (as if hours passed) and re-seal.
        var stale = first
        stale.expiry = Date().addingTimeInterval(-10)
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: "linear"),
                                data: JSONEncoder().encode(stale))
        manager.kill(name: "linear")

        // A call now must refresh transparently — and still work.
        let output = try await manager.call(entry: entry, tool: "echo", args: [:])
        guard case let .array(content)? = output["content"],
              case let .object(firstItem)? = content.first,
              let text = firstItem["text"]?.stringValue else {
            Issue.record("no content from the OAuth upstream")
            return
        }
        #expect(text.contains("Bearer at-"))

        let after = try await manager.grant(upstream: "linear")!
        #expect(after.accessToken != first.accessToken, "the access token must have been renewed")
        #expect(after.refreshToken != first.refreshToken, "the rotated refresh token must be re-sealed")
        #expect(after.isFresh())
    }

    @Test("concurrent calls on an expired token perform exactly ONE refresh (no rotation replay)")
    func refreshIsDeduped() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        var stale = try await manager.grant(upstream: "linear")!
        stale.expiry = Date().addingTimeInterval(-10)
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: "linear"),
                                data: JSONEncoder().encode(stale))
        manager.kill(name: "linear")

        // The fake server ROTATES (and invalidates) the refresh token, so a
        // second concurrent refresh with the same token would fail — this is the
        // real-world replay hazard the dedup exists for.
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<6 {
                group.addTask { _ = try await manager.call(entry: entry, tool: "echo", args: [:]) }
            }
            try await group.waitForAll()
        }
        #expect(try await manager.grant(upstream: "linear")!.isFresh())
    }

    @Test("a grant does not attach to a DIFFERENT endpoint reusing the same name (#13)")
    func grantNotReusedAcrossEndpoints() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        // Sign in for endpoint A.
        let a = UpstreamsStore.Entry(name: "svc", transport: "http", url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: a, openBrowser: fakeBrowser)
        #expect(await manager.oauthStatus(upstream: "svc").connected)

        // The SAME name now points at a DIFFERENT endpoint. A call must NOT reuse
        // the old grant — the resource no longer matches, so it's wiped and the
        // call fails "not signed in".
        let b = UpstreamsStore.Entry(name: "svc", transport: "http",
                                     url: "\(base)/mcp?tenant=other", auth: "oauth")
        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: b, tool: "echo", args: [:])
        }
        #expect(!(await manager.oauthStatus(upstream: "svc").connected),
                "the stale grant must be forgotten, not silently reused")
    }

    @Test("a LOCKED vault cannot read the grant — an OAuth upstream is dead while locked")
    func lockedFailsClosed() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll() }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        manager.killAll()
        await store.lock()

        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
        // Even the status is silent while locked — no "a grant exists" leak.
        let status = await manager.oauthStatus(upstream: "linear")
        #expect(!status.connected)
        // And a sign-in attempt against a locked vault fails closed.
        await #expect(throws: VaultStoreError.locked) {
            _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        }
        await store.close()
    }

    @Test("a REVOKED refresh token wipes the grant — the UI says ‘not signed in’, not a zombie session")
    func revokedGrantIsForgotten() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        #expect(await manager.oauthStatus(upstream: "linear").connected)

        // Expire the access token AND have the server revoke consent.
        var stale = try await manager.grant(upstream: "linear")!
        stale.expiry = Date().addingTimeInterval(-10)
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: "linear"),
                                data: JSONEncoder().encode(stale))
        manager.kill(name: "linear")
        var revoke = URLRequest(url: URL(string: "\(base)/revoke")!)
        revoke.httpMethod = "POST"
        _ = try await URLSession(configuration: .ephemeral).data(for: revoke)

        // The call fails — and the dead grant is FORGOTTEN, so the human is told
        // to reconnect instead of hitting the same wall forever.
        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
        let status = await manager.oauthStatus(upstream: "linear")
        #expect(!status.connected, "a revoked grant must not keep reporting ‘signed in’")
    }

    @Test("a TRANSIENT failure never wipes the grant (a flaky minute must not cost a re-auth)")
    func transientFailureKeepsGrant() async throws {
        let (base, proc) = try launchFakeOAuth()
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        var stale = try await manager.grant(upstream: "linear")!
        stale.expiry = Date().addingTimeInterval(-10)
        try await store.setBlob(key: MCPOAuth.Grant.blobKey(upstream: "linear"),
                                data: JSONEncoder().encode(stale))
        manager.kill(name: "linear")

        // Kill the server: the refresh fails with a NETWORK error, not a refusal.
        proc.terminate()
        proc.waitUntilExit()
        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
        // The grant SURVIVES — the refresh token is still there for the retry.
        let g = try await manager.grant(upstream: "linear")
        #expect(g?.refreshToken.isEmpty == false, "a transient error must not destroy the grant")
        #expect(await manager.oauthStatus(upstream: "linear").connected)
    }

    @Test("the OAuth session NEVER follows a redirect — the code/verifier can't be stolen")
    func oauthRefusesRedirect() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        // Arm the token endpoint to 302 toward a capture sink BEFORE sign-in.
        var armReq = URLRequest(url: URL(string: "\(base)/arm-redirect")!)
        armReq.httpMethod = "POST"
        _ = try? await URLSession(configuration: .ephemeral).data(for: armReq)

        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }
        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        // Sign-in must FAIL at the token exchange (the 302 is refused, surfaced
        // as a non-2xx), and nothing must have been POSTed to /steal.
        await #expect(throws: (any Error).self) {
            _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        }
        var check = URLRequest(url: URL(string: "\(base)/stolen")!)
        check.httpMethod = "GET"
        let (data, _) = try await URLSession(configuration: .ephemeral).data(for: check)
        let body = String(decoding: data, as: UTF8.self)
        #expect(!body.contains("code_verifier"), "the PKCE verifier must never reach a redirect target")
        #expect(!body.contains("authorization_code"), "the auth code must never reach a redirect target")
    }

    @Test("sign-out forgets the tokens")
    func disconnect() async throws {
        let (base, proc) = try launchFakeOAuth()
        defer { proc.terminate() }
        let store = try freshOAuthStore()
        let manager = UpstreamManager(store: store)
        defer { manager.killAll(); Task { await store.close() } }

        let entry = UpstreamsStore.Entry(name: "linear", transport: "http",
                                         url: "\(base)/mcp", auth: "oauth")
        _ = try await manager.oauthAuthorize(entry: entry, openBrowser: fakeBrowser)
        #expect(await manager.oauthStatus(upstream: "linear").connected)

        try await manager.oauthDisconnect(upstream: "linear")
        #expect(!(await manager.oauthStatus(upstream: "linear").connected))
        await #expect(throws: (any Error).self) {
            _ = try await manager.call(entry: entry, tool: "echo", args: [:])
        }
    }
}
