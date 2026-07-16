import Testing
import Foundation
import SallyportKit
@testable import SallyportVault

// MARK: - Test scaffolding (the Swift httptest)

/// A tiny NSLock box so mock handlers and hit counters are Sendable.
final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withLock<R>(_ body: (inout Value) -> R) -> R {
        lock.lock(); defer { lock.unlock() }
        return body(&value)
    }
    var current: Value { withLock { $0 } }
}

/// An in-process URLProtocol stub standing in for Go's httptest servers: the
/// handler sees every request (with its drained body) and scripts the reply —
/// including redirects, which flow through the executor's real RedirectPolicy
/// delegate exactly like live CFNetwork redirects.
final class MockHTTP: URLProtocol {
    enum Reply {
        case respond(status: Int, headers: [String: String], body: String)
        case redirect(to: String, status: Int)
        case fail(URLError.Code)
        case stall
    }

    static let handler = Locked<(@Sendable (URLRequest, Data) -> Reply)?>(nil)
    static let startCount = Locked(0)
    static let stopCount = Locked(0)

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() { Self.stopCount.withLock { $0 += 1 } }

    override func startLoading() {
        Self.startCount.withLock { $0 += 1 }
        guard let handler = MockHTTP.handler.current, let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        switch handler(request, Self.drainBody(request)) {
        case .fail(let code):
            client?.urlProtocol(self, didFailWithError: URLError(code))
        case .stall:
            return
        case .respond(let status, let headers, let body):
            let resp = HTTPURLResponse(url: url, statusCode: status,
                                       httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        case .redirect(let location, let status):
            let target = URL(string: location, relativeTo: url)!.absoluteURL
            let resp = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Location": target.absoluteString])!
            var newReq = URLRequest(url: target)
            newReq.httpMethod = request.httpMethod
            // Mimic URLSession's proposed redirect request: headers are carried
            // over — which is exactly why the executor must refuse cross-host hops.
            for (k, v) in request.allHTTPHeaderFields ?? [:] {
                newReq.setValue(v, forHTTPHeaderField: k)
            }
            client?.urlProtocol(self, wasRedirectedTo: newReq, redirectResponse: resp)
            // If the delegate refuses the redirect, this 3xx becomes the task's
            // final response (the "returned as data" path); if it follows, the
            // session cancels this load and these messages are dropped.
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data())
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    /// URLSession hands the protocol a body stream, not httpBody — slurp it.
    private static func drainBody(_ request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open(); defer { stream.close() }
        var data = Data()
        let bufSize = 4096
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { buf.deallocate() }
        while stream.hasBytesAvailable {
            let n = stream.read(buf, maxLength: bufSize)
            if n <= 0 { break }
            data.append(buf, count: n)
        }
        return data
    }
}

private let testToken = "cf_live_SECRET_do_not_leak"

private func bearerCred() -> Cred {
    Cred(name: "cf_token", kind: "bearer",
         inject: Inject(adapter: "bearer", header: "Authorization", format: "Bearer {secret}"),
         secret: Data(testToken.utf8))
}

/// Binds one host to one credential (Go's fakeResolver). Cred is a value type,
/// so every call hands the executor a fresh copy to consume and wipe.
private func binding(_ host: String, _ cred: Cred?) -> CredResolver {
    { h, _ in h == host ? cred : nil }
}

private func httpAction(url: String, method: String = "GET",
                        headers: [String: JSONValue]? = nil,
                        body: String? = nil, params: JSONValue? = nil) -> Action {
    var args: [String: JSONValue] = ["url": .string(url), "method": .string(method)]
    if let headers { args["headers"] = .object(headers) }
    if let body { args["body"] = .string(body) }
    if let params { args["params"] = params }
    return Action(tool: "http.request", args: args)
}

private func makeExecutor(classify: (@Sendable (IPAddr) -> IPClass)? = nil,
                          maxBody: Int = 0, timeout: TimeInterval = 5) -> HTTPExecutor {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.protocolClasses = [MockHTTP.self]
    var netGuard = NetGuard()
    if let classify { netGuard.classify = classify }
    return HTTPExecutor(configuration: cfg, timeout: timeout, maxBody: maxBody, netGuard: netGuard)
}

/// The Go tests' loopbackAsPublic: treats loopback as a routable public address
/// so a happy-path test can drive a 127.0.0.1 "server" as if it were a normal
/// internet destination. All other ranges keep the production classification.
private func loopbackAsPublic(_ ip: IPAddr) -> IPClass {
    ip.unmapped().isLoopback ? .publicRoutable : NetGuard.classifyIP(ip)
}

// MARK: - Executor behavior (ported from httpexec_test.go)

@Suite("HTTPExecutor — http.request egress", .serialized)
struct HTTPExecutorTests {

    @Test("injects the bound credential and returns the response")
    func injectsBoundCredential() async throws {
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.value(forHTTPHeaderField: "Authorization") == "Bearer \(testToken)" {
                return .respond(status: 200, headers: [:], body: #"{"authorized":true}"#)
            }
            return .respond(status: 401, headers: [:], body: #"{"authorized":false}"#)
        } }

        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                      resolve: binding("192.0.2.1", bearerCred()))
        #expect(out.output["status"] == .int(200))
        // The parsed `json` field is returned INSTEAD of a raw body — never both.
        #expect(out.output["json"] == .object(["authorized": .bool(true)]))
        #expect(out.output["body"] == nil)
        // This response did not echo the token, so it is naturally absent.
        #expect(!String(describing: out.output).contains(testToken))
        #expect(out.bytesOut == #"{"authorized":true}"#.utf8.count)
    }

    @Test("an oversized response body is capped DURING the read, never fully buffered (#14)")
    func responseBodyCapped() async throws {
        // A body far larger than the cap; the executor must not buffer it whole.
        let big = String(repeating: "x", count: 5000)
        MockHTTP.handler.withLock { $0 = { _, _ in .respond(status: 200, headers: [:], body: big) } }
        let e = makeExecutor(maxBody: 100)
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                      resolve: binding("192.0.2.1", nil))
        #expect(out.output["status"] == .int(200))
        let body = out.output["body"]?.stringValue ?? ""
        #expect(body.count == 100, "the body must be truncated to maxBody, got \(body.count)")
        #expect(out.bytesOut == 100)
    }

    @Test("a trickling or stalled endpoint is cancelled at the hard deadline")
    func hardDeadlineCancelsTransport() async {
        MockHTTP.startCount.withLock { $0 = 0 }
        MockHTTP.stopCount.withLock { $0 = 0 }
        MockHTTP.handler.withLock { $0 = { _, _ in .stall } }
        let e = makeExecutor(timeout: 0.05)
        let started = ContinuousClock.now
        await #expect(throws: HTTPExecError.timeout) {
            _ = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                    resolve: { _, _ in nil })
        }
        // Generous on purpose (100× the 0.05s deadline): this asserts "the
        // deadline fired instead of the 60s stall", and a tight ceiling turns
        // parallel-suite scheduling delays into flakes.
        #expect(ContinuousClock.now - started < .seconds(5))
        #expect(MockHTTP.startCount.current > 0, "the transport must start before the deadline")
        let cancellationDeadline = ContinuousClock.now + .milliseconds(500)
        while MockHTTP.stopCount.current == 0,
              ContinuousClock.now < cancellationDeadline {
            try? await Task.sleep(for: .milliseconds(5))
        }
        #expect(MockHTTP.stopCount.current > 0, "deadline must cancel the URLSession task")
    }

    @Test("CFNetwork's request timeout race is normalized to the hard-deadline error")
    func transportTimeoutIsNormalized() async {
        MockHTTP.handler.withLock { $0 = { _, _ in .fail(.timedOut) } }
        let e = makeExecutor(timeout: 5)

        await #expect(throws: HTTPExecError.timeout) {
            _ = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                    resolve: { _, _ in nil })
        }
    }

    @Test("non-timeout URLSession failures remain transport errors")
    func nonTimeoutTransportErrorIsPreserved() async {
        MockHTTP.handler.withLock { $0 = { _, _ in .fail(.networkConnectionLost) } }
        let e = makeExecutor(timeout: 5)

        do {
            _ = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                    resolve: { _, _ in nil })
            Issue.record("the transport failure must propagate")
        } catch let error as URLError {
            #expect(error.code == .networkConnectionLost)
        } catch {
            Issue.record("expected URLError.networkConnectionLost, got \(error)")
        }
    }

    @Test("a cross-host redirect is refused and never carries the credential")
    func crossHostRedirectDoesNotLeakCredential() async throws {
        let bHits = Locked(0)
        let bSawToken = Locked(false)
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.url?.host() == "198.51.100.7" {
                bHits.withLock { $0 += 1 }
                if req.value(forHTTPHeaderField: "Authorization") != nil {
                    bSawToken.withLock { $0 = true }
                }
                return .respond(status: 200, headers: [:], body: "B-body")
            }
            return .redirect(to: "http://198.51.100.7/steal", status: 302)
        } }

        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                      resolve: binding("192.0.2.1", bearerCred()))
        #expect(bHits.current == 0, "cross-host redirect was followed")
        #expect(!bSawToken.current, "credential leaked to cross-host redirect target")
        #expect(out.output["status"] == .int(302), "expected the 302 returned as data")
        #expect(out.output["cross_host_redirect_refused"] == .bool(true))
    }

    @Test("a credentialed request does NOT follow even a same-host redirect (#18 path-binding)")
    func credentialedRequestRefusesRedirect() async throws {
        // A key bound to /start must never ride a 302 to /final with the
        // credential attached: the binding was for /start, and the hop could
        // reach a path the operator never authorized. The 3xx is returned as
        // data and the credential never reaches /final.
        let finalAuth = Locked("")
        MockHTTP.handler.withLock { $0 = { req, _ in
            switch req.url?.path {
            case "/start":
                return .redirect(to: "/final", status: 302)
            default:
                finalAuth.withLock { $0 = req.value(forHTTPHeaderField: "Authorization") ?? "" }
                return .respond(status: 200, headers: [:], body: "ok")
            }
        } }

        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/start"),
                                      resolve: binding("192.0.2.1", bearerCred()))
        #expect(out.output["status"] == .int(302), "the redirect must be returned as data, not followed")
        #expect(finalAuth.current == "", "the credential must NOT reach the redirect target")
        #expect(out.output["final_url"] == .string("https://192.0.2.1/start"))
        #expect(out.output["cross_host_redirect_refused"] == .bool(true))
    }

    @Test("a SigV4 request refuses same-host redirects")
    func sigV4RequestRefusesRedirect() async throws {
        let finalHits = Locked(0)
        let startWasSigned = Locked(false)
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.url?.path == "/start" {
                if req.value(forHTTPHeaderField: "Authorization")?
                    .hasPrefix("AWS4-HMAC-SHA256 ") == true {
                    startWasSigned.withLock { $0 = true }
                }
                return .redirect(to: "/final", status: 302)
            }
            finalHits.withLock { $0 += 1 }
            return .respond(status: 200, headers: [:], body: "should-not-be-reached")
        } }

        let cred = Cred(name: "aws", kind: "aws-sigv4",
                        inject: Inject(adapter: "aws-sigv4",
                                       params: ["region": "us-east-1",
                                                "service": "execute-api"]),
                        secret: Data("AKID:SECRET".utf8))
        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/start"),
                                      resolve: binding("192.0.2.1", cred))

        #expect(startWasSigned.current, "the initial request must carry a SigV4 signature")
        #expect(finalHits.current == 0, "a signed request must not follow a redirect")
        #expect(out.output["status"] == .int(302))
        #expect(out.output["final_url"] == .string("https://192.0.2.1/start"))
        #expect(out.output["cross_host_redirect_refused"] == .bool(true))
    }

    @Test("self-signed TLS is accepted ONLY with the key's explicit opt-in")
    func insecureTLSOptIn() {
        // Opt-in + a server-trust challenge → accept the presented cert.
        // (SecTrust can't be fabricated in a unit test; nil trust must still
        // fall back to default handling even WITH the opt-in — fail closed.)
        let m = NSURLAuthenticationMethodServerTrust
        #expect(RedirectPolicy.trustDecision(method: m, allowInsecureTLS: false, trust: nil).0
                == .performDefaultHandling)
        #expect(RedirectPolicy.trustDecision(method: m, allowInsecureTLS: true, trust: nil).0
                == .performDefaultHandling)
        // A non-server-trust challenge (e.g. client cert ask) is never affected.
        #expect(RedirectPolicy.trustDecision(method: NSURLAuthenticationMethodHTTPBasic,
                                             allowInsecureTLS: true, trust: nil).0
                == .performDefaultHandling)
    }

    @Test("an UNCREDENTIALED same-host redirect is still followed")
    func uncredentialedRedirectFollows() async throws {
        MockHTTP.handler.withLock { $0 = { req, _ in
            switch req.url?.path {
            case "/start": return .redirect(to: "/final", status: 302)
            default: return .respond(status: 200, headers: [:], body: "ok")
            }
        } }
        let e = makeExecutor()
        // No binding → no credential → the same-host redirect is followed as before.
        let out = try await e.execute(httpAction(url: "http://192.0.2.1/start"),
                                      resolve: { _, _ in nil })
        #expect(out.output["status"] == .int(200), "an uncredentialed same-host redirect should follow")
        #expect(out.output["final_url"] == .string("http://192.0.2.1/final"))
    }

    @Test("no binding, no injection")
    func noBindingNoInjection() async throws {
        let sawAuth = Locked(false)
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.value(forHTTPHeaderField: "Authorization") != nil {
                sawAuth.withLock { $0 = true }
            }
            return .respond(status: 200, headers: [:], body: "ok")
        } }

        // Resolver bound to a DIFFERENT host → nothing injected here. 192.0.2.1
        // (TEST-NET-1) classifies public, so the unbound request is allowed.
        let e = makeExecutor()
        _ = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                resolve: binding("other.example", bearerCred()))
        #expect(!sawAuth.current, "injected a credential for an unbound host")
    }

    @Test("an https→http same-host redirect is refused (header adapter can't leak)")
    func schemeDowngradeRedirectDoesNotLeakHeaderCred() async throws {
        let headerSecret = "cfat_HEADER_SECRET_do_not_leak"
        let startSawHeader = Locked(false)
        let stealHits = Locked(0)
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.url?.path == "/start" {
                if req.value(forHTTPHeaderField: "X-Api-Key") == headerSecret {
                    startSawHeader.withLock { $0 = true }
                }
                // Redirect to the SAME host but over http:// (a scheme downgrade).
                return .redirect(to: "http://192.0.2.1/steal", status: 302)
            }
            stealHits.withLock { $0 += 1 }
            return .respond(status: 200, headers: [:], body: "should-not-be-reached")
        } }

        let cred = Cred(name: "api_key", kind: "header",
                        inject: Inject(adapter: "header", header: "X-Api-Key"),
                        secret: Data(headerSecret.utf8))
        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/start"),
                                      resolve: binding("192.0.2.1", cred))
        #expect(startSawHeader.current, "header credential not injected on the initial https request")
        #expect(out.output["status"] == .int(302),
                "scheme-downgrade redirect must be refused and returned as data")
        #expect(out.output["cross_host_redirect_refused"] == .bool(true))
        #expect(stealHits.current == 0, "credential-bearing request crossed the downgrade")
    }

    // MARK: Anti-SSRF network guard (docs/02 §6.2)

    @Test("metadata is blocked even when a credential is bound to it")
    func guardBlocksMetadataEvenWhenBound() async throws {
        let hits = Locked(0)
        MockHTTP.handler.withLock { $0 = { _, _ in
            hits.withLock { $0 += 1 }
            return .respond(status: 200, headers: [:], body: "should-not-be-reached")
        } }

        // Bind a credential to the metadata host to prove the metadata block
        // wins over the "bound ⇒ private allowed" carve-out.
        let e = makeExecutor()
        do {
            _ = try await e.execute(httpAction(url: "http://169.254.169.254/latest/meta-data/"),
                                    resolve: binding("169.254.169.254", bearerCred()))
            Issue.record("metadata request must be blocked")
        } catch let blocked as BlockedError {
            #expect(blocked.reason == "metadata")
            #expect(blocked.ip == "169.254.169.254")
            // The block leaks only the IP — never the URL path or headers.
            #expect(!blocked.description.contains("meta-data"))
        }
        #expect(hits.current == 0, "guard did not fail closed")
    }

    @Test("an unbound private destination is blocked before anything is sent")
    func guardBlocksUnboundPrivate() async throws {
        let hits = Locked(0)
        MockHTTP.handler.withLock { $0 = { _, _ in
            hits.withLock { $0 += 1 }
            return .respond(status: 200, headers: [:], body: "should-not-be-reached")
        } }

        // Resolver bound to a different host → this request is unbound. The
        // production classifier treats loopback as private.
        let e = makeExecutor()
        do {
            _ = try await e.execute(httpAction(url: "http://127.0.0.1:8099/"),
                                    resolve: binding("other.example", bearerCred()))
            Issue.record("unbound private dial must be blocked")
        } catch let blocked as BlockedError {
            #expect(blocked.reason == "private")
            #expect(blocked.ip == "127.0.0.1")
        }
        #expect(hits.current == 0, "guard did not fail closed")
    }

    @Test("the bound ⇒ private-allowed carve-out lets a bound loopback through")
    func guardAllowsBoundLoopback() async throws {
        MockHTTP.handler.withLock { $0 = { _, _ in
            .respond(status: 200, headers: [:], body: "ok")
        } }

        let e = makeExecutor()
        let out = try await e.execute(httpAction(url: "http://127.0.0.1:8099/"),
                                      resolve: binding("127.0.0.1", bearerCred()))
        #expect(out.output["status"] == .int(200))
    }

    @Test("a public destination is unaffected (injected classifier)")
    func guardAllowsPublicDestination() async throws {
        MockHTTP.handler.withLock { $0 = { _, _ in
            .respond(status: 200, headers: [:], body: "ok")
        } }

        // Unbound + loopback-as-public classifier, standing in for a real
        // routable IP — proves the guard does not interfere with normal dials.
        let e = makeExecutor(classify: loopbackAsPublic)
        let out = try await e.execute(httpAction(url: "http://127.0.0.1:8099/"),
                                      resolve: binding("other.example", bearerCred()))
        #expect(out.output["status"] == .int(200))
    }

    @Test("classifyIP mirrors guard.go")
    func classifier() {
        let metadata = ["169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254",
                        "::ffff:169.254.169.254", "224.0.0.1", "ff02::1"]
        let priv = ["127.0.0.1", "127.9.9.9", "::1", "10.0.0.1", "172.16.0.1",
                    "172.31.255.255", "192.168.1.1", "fc00::1", "fdab::1",
                    "0.0.0.0", "::", "255.255.255.255", "::ffff:10.0.0.1"]
        let pub = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "192.0.2.1", "2606:4700:4700::1111"]
        for s in metadata { #expect(NetGuard.classifyIP(IPAddr(s)!) == .metadata, "\(s)") }
        for s in priv { #expect(NetGuard.classifyIP(IPAddr(s)!) == .privateInternal, "\(s)") }
        for s in pub { #expect(NetGuard.classifyIP(IPAddr(s)!) == .publicRoutable, "\(s)") }
    }

    @Test("malformed raw IP lengths are total and always fail closed")
    func malformedRawIPLengths() {
        let malformed = [
            IPAddr(bytes: []),
            IPAddr(bytes: [127]),
            IPAddr(bytes: [169, 254]),
            IPAddr(bytes: Array(repeating: 1, count: 5)),
            IPAddr(bytes: Array(repeating: 1, count: 15)),
            IPAddr(bytes: Array(repeating: 1, count: 17)),
        ]
        let guardrail = NetGuard()
        for ip in malformed {
            #expect(NetGuard.classifyIP(ip) == .invalid)
            #expect(ip.description == "<invalid-ip>")
            #expect(guardrail.check(ip, bound: true)?.reason == "invalid")
            #expect(guardrail.check(ip, bound: false)?.reason == "invalid")
        }
    }

    // MARK: OAuth2 client-credentials (ported from TestOAuth2ClientCredentials)

    @Test("oauth2: exchanges the client secret for a token, injects and caches it")
    func oauth2ClientCredentials() async throws {
        let tokenHits = Locked(0)
        let seenAuth = Locked("")
        MockHTTP.handler.withLock { $0 = { req, body in
            switch req.url?.host() {
            case "192.0.2.10": // token endpoint
                tokenHits.withLock { $0 += 1 }
                let form = String(decoding: body, as: UTF8.self)
                guard form.contains("grant_type=client_credentials"),
                      form.contains("scope=repo"),
                      let auth = req.value(forHTTPHeaderField: "Authorization"),
                      auth.hasPrefix("Basic ")
                else { return .respond(status: 400, headers: [:], body: "") }
                return .respond(status: 200, headers: ["Content-Type": "application/json"],
                                body: #"{"access_token":"AT-123","token_type":"Bearer","expires_in":3600}"#)
            default: // resource API — echoes the token to verify faithful output
                seenAuth.withLock { $0 = req.value(forHTTPHeaderField: "Authorization") ?? "" }
                return .respond(status: 200, headers: [:], body: #"{"ok":true,"echo":"AT-123"}"#)
            }
        } }

        let cred = Cred(name: "svc_app", kind: "oauth2",
                        inject: Inject(adapter: "oauth2",
                                       params: ["tokenUrl": "https://192.0.2.10/token",
                                                "clientId": "cid", "scope": "repo"]),
                        secret: Data("super-client-secret".utf8))
        let e = makeExecutor()
        let resolve = binding("192.0.2.20", cred)

        let out = try await e.execute(httpAction(url: "https://192.0.2.20/api"), resolve: resolve)
        #expect(out.output["status"] == .int(200))
        #expect(seenAuth.current == "Bearer AT-123")
        #expect(out.output["json"] == .object(["ok": .bool(true), "echo": .string("AT-123")]),
                "the endpoint response must be returned without content rewriting")
        #expect(!String(describing: out.output).contains("super-client-secret"))

        // A second request reuses the cached token — no second token fetch.
        _ = try await e.execute(httpAction(url: "https://192.0.2.20/api"), resolve: resolve)
        #expect(tokenHits.current == 1, "token endpoint should be hit once (cached)")
    }

    // MARK: Request shaping

    @Test("params object is merged into the query string, URL-encoded")
    func paramsMergedIntoQuery() async throws {
        let seenURL = Locked("")
        MockHTTP.handler.withLock { $0 = { req, _ in
            seenURL.withLock { $0 = req.url?.absoluteString ?? "" }
            return .respond(status: 200, headers: [:], body: "ok")
        } }

        let e = makeExecutor()
        _ = try await e.execute(
            httpAction(url: "http://192.0.2.1/search?a=1",
                       params: .object(["q": .string("hello world"),
                                        "limit": .int(50),
                                        "safe": .bool(true)])),
            resolve: { _, _ in nil })
        #expect(seenURL.current == "http://192.0.2.1/search?a=1&limit=50&q=hello+world&safe=true")
    }

    @Test("withQueryParams: sorted, replacing, tolerant of non-objects and bad URLs")
    func withQueryParamsUnit() {
        // An overridden key replaces ALL its prior values (Go's q.Set).
        #expect(HTTPExecutor.withQueryParams("http://x/p?a=1&a=2",
                                             params: .object(["a": .string("3")])) == "http://x/p?a=3")
        // Non-object / empty / missing params leave the URL unchanged.
        #expect(HTTPExecutor.withQueryParams("http://x/p", params: .string("no")) == "http://x/p")
        #expect(HTTPExecutor.withQueryParams("http://x/p", params: .object([:])) == "http://x/p")
        #expect(HTTPExecutor.withQueryParams("http://x/p", params: nil) == "http://x/p")
        // A bad URL passes through for the executor to surface clearly.
        #expect(HTTPExecutor.withQueryParams("://bad url",
                                             params: .object(["a": .string("1")])) == "://bad url")
        // Scalar rendering: integral double → "50", not "50.000000".
        #expect(HTTPExecutor.paramToStr(.double(50.0)) == "50")
        #expect(HTTPExecutor.paramToStr(.double(2.5)) == "2.5")
    }

    @Test("agent-supplied Authorization headers are dropped")
    func agentAuthorizationDropped() async throws {
        let sawAuth = Locked(false)
        MockHTTP.handler.withLock { $0 = { req, _ in
            if req.value(forHTTPHeaderField: "Authorization") != nil {
                sawAuth.withLock { $0 = true }
            }
            return .respond(status: 200, headers: [:], body: "ok")
        } }

        let e = makeExecutor()
        _ = try await e.execute(
            httpAction(url: "https://192.0.2.1/",
                       headers: ["Authorization": .string("Bearer agent-forged"),
                                 "X-Custom": .string("kept")]),
            resolve: { _, _ in nil })
        #expect(!sawAuth.current, "the agent may not set auth headers — that's sallyport's job")
    }

    @Test("hostile methods and headers are rejected before CFNetwork sees them")
    func requestSyntaxBoundary() async {
        let hits = Locked(0)
        MockHTTP.handler.withLock { $0 = { _, _ in
            hits.withLock { $0 += 1 }
            return .respond(status: 200, headers: [:], body: "unexpected")
        } }
        let e = makeExecutor()

        await #expect(throws: HTTPExecError.unsupportedMethod) {
            _ = try await e.execute(httpAction(url: "https://192.0.2.1/", method: "GET\r\nX-Evil: 1"),
                                    resolve: { _, _ in nil })
        }
        let hostileHeaders: [[String: JSONValue]] = [
            ["X-Test\r\nInjected": .string("x")],
            ["X-Test": .string("ok\r\nInjected: yes")],
            [String(repeating: "A", count: 129): .string("x")],
            ["X-Test": .string(String(repeating: "x", count: 16 * 1024 + 1))],
        ]
        for headers in hostileHeaders {
            await #expect(throws: HTTPExecError.invalidHeaders) {
                _ = try await e.execute(httpAction(url: "https://192.0.2.1/", headers: headers),
                                        resolve: { _, _ in nil })
            }
        }
        #expect(hits.current == 0)
        #expect(HTTPExecutor.isSafeHeaderName("X-Request_ID"))
        #expect(!HTTPExecutor.isSafeHeaderName(""))
        #expect(!HTTPExecutor.isSafeHeaderValue("line\nfeed"))
    }

    @Test("URL userinfo and oversized URLs are rejected before credential resolution")
    func urlSyntaxBoundary() async {
        let e = makeExecutor()
        await #expect(throws: HTTPExecError.self) {
            _ = try await e.execute(httpAction(url: "https://user:pass@192.0.2.1/"),
                                    resolve: { _, _ in Issue.record("resolver must not run"); return nil })
        }
        let huge = "https://192.0.2.1/" + String(repeating: "a", count: 16 * 1024)
        await #expect(throws: HTTPExecError.self) {
            _ = try await e.execute(httpAction(url: huge), resolve: { _, _ in nil })
        }
    }

    @Test("maxBody caps the returned body and bytesOut")
    func maxBodyCap() async throws {
        MockHTTP.handler.withLock { $0 = { _, _ in
            .respond(status: 200, headers: [:], body: "0123456789")
        } }

        let e = makeExecutor(maxBody: 5)
        let out = try await e.execute(httpAction(url: "https://192.0.2.1/"),
                                      resolve: { _, _ in nil })
        #expect(out.output["body"] == .string("01234"))
        #expect(out.bytesOut == 5)
    }

    @Test("a credential is REFUSED over plain http; loopback http is allowed (#9)")
    func credentialRequiresHTTPS() async throws {
        MockHTTP.handler.withLock { $0 = { _, _ in .respond(status: 200, headers: [:], body: "ok") } }
        let e = makeExecutor()
        // Plain http + a bound credential to a public host → refused, secret unsent.
        await #expect(throws: HTTPExecError.self) {
            _ = try await e.execute(httpAction(url: "http://192.0.2.1/x"),
                                    resolve: binding("192.0.2.1", bearerCred()))
        }
        // An UNCREDENTIALED plain-http request is still fine.
        let out = try await e.execute(httpAction(url: "http://192.0.2.1/x"), resolve: { _, _ in nil })
        #expect(out.output["status"] == .int(200))
        // Loopback dev servers may use http with a credential.
        #expect(HTTPExecutor.isLoopbackHost("localhost"))
        #expect(HTTPExecutor.isLoopbackHost("127.0.0.1"))
        #expect(!HTTPExecutor.isLoopbackHost("192.0.2.1"))
    }

    @Test("CGNAT shared space 100.64/10 is internal, not public (#9)")
    func cgnatIsInternal() {
        #expect(IPAddr("100.64.0.1")!.isPrivate)
        #expect(IPAddr("100.127.255.254")!.isPrivate)
        #expect(!IPAddr("100.63.255.255")!.isPrivate)   // just below the range
        #expect(!IPAddr("100.128.0.0")!.isPrivate)      // just above
        #expect(!IPAddr("8.8.8.8")!.isPrivate)
    }

    @Test("non-http(s) schemes are refused")
    func unsupportedScheme() async throws {
        let e = makeExecutor()
        await #expect(throws: HTTPExecError.unsupportedScheme("ftp")) {
            _ = try await e.execute(httpAction(url: "ftp://192.0.2.1/file"),
                                    resolve: { _, _ in nil })
        }
    }
}
