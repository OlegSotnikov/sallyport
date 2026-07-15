import Testing
import Foundation
@testable import SallyportVault

/// Adapter tests (ported from sigv4_test.go + the inject cases of httpexec.go).
/// All network-free: the oauth2 wire behavior lives in HTTPExecutorTests.
@Suite("Injection adapters")
struct AdaptersTests {

    /// A cache no test here ever lets reach the network.
    private func dummyOAuth() -> OAuth2TokenCache {
        OAuth2TokenCache(session: URLSession(configuration: .ephemeral),
                         timeout: 1, netGuard: NetGuard())
    }

    private func cred(adapter: String, header: String = "", format: String = "",
                      params: [String: String] = [:], secret: String) -> Cred {
        Cred(name: "t", kind: adapter,
             inject: Inject(adapter: adapter, header: header, format: format, params: params),
             secret: Data(secret.utf8))
    }

    // MARK: AWS SigV4 (ported from sigv4_test.go)

    @Test("SigV4 matches AWS's official get-vanilla test vector byte-for-byte")
    func sigV4GetVanilla() throws {
        var req = URLRequest(url: URL(string: "https://example.amazonaws.com/")!)
        req.httpMethod = "GET"
        let now = ISO8601DateFormatter().date(from: "2015-08-30T12:36:00Z")!

        try Adapters.signAWSV4(&req, accessKeyID: "AKIDEXAMPLE",
                               secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                               region: "us-east-1", service: "service",
                               body: Data(), now: now)

        let want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
            + "SignedHeaders=host;x-amz-date, "
            + "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        #expect(req.value(forHTTPHeaderField: "Authorization") == want)
        #expect(req.value(forHTTPHeaderField: "X-Amz-Date") == "20150830T123600Z")
    }

    @Test("SigV4 payload-hash + canonical-query paths produce a well-formed signature")
    func sigV4PostWithBodyAndQuery() throws {
        var req = URLRequest(url: URL(string: "https://api.example.com/v1/things?b=2&a=1")!)
        req.httpMethod = "POST"
        let now = ISO8601DateFormatter().date(from: "2026-01-02T03:04:05Z")!
        try Adapters.signAWSV4(&req, accessKeyID: "AKID", secretKey: "SECRET",
                               region: "eu-west-1", service: "execute-api",
                               body: Data(#"{"hello":"world"}"#.utf8), now: now)
        let auth = try #require(req.value(forHTTPHeaderField: "Authorization"))
        for must in ["AWS4-HMAC-SHA256 ",
                     "Credential=AKID/20260102/eu-west-1/execute-api/aws4_request",
                     "SignedHeaders=host;x-amz-date",
                     "Signature="] {
            #expect(auth.contains(must), "authorization missing \(must)")
        }
    }

    @Test("SigV4 for S3 additionally signs the payload hash")
    func sigV4S3SignsContentHash() throws {
        var req = URLRequest(url: URL(string: "https://bucket.s3.amazonaws.com/key")!)
        req.httpMethod = "PUT"
        let now = ISO8601DateFormatter().date(from: "2026-01-02T03:04:05Z")!
        try Adapters.signAWSV4(&req, accessKeyID: "AKID", secretKey: "SECRET",
                               region: "us-east-1", service: "s3",
                               body: Data("payload".utf8), now: now)
        #expect(req.value(forHTTPHeaderField: "X-Amz-Content-Sha256") != nil,
                "s3 must set X-Amz-Content-Sha256")
        let auth = try #require(req.value(forHTTPHeaderField: "Authorization"))
        #expect(auth.contains("host;x-amz-content-sha256;x-amz-date"),
                "s3 must sign the content hash header")
    }

    @Test("SigV4 requires region and service")
    func sigV4RequiresRegionService() {
        #expect(throws: HTTPExecError.sigV4ParamsRequired) {
            var req = URLRequest(url: URL(string: "https://x.example/")!)
            try Adapters.signAWSV4(&req, accessKeyID: "AKID", secretKey: "SECRET",
                                   region: "", service: "service", body: Data(), now: Date())
        }
    }

    @Test("awsURIEncode: unreserved pass through, '/' preserved only for paths")
    func awsURIEncoding() {
        #expect(Adapters.awsURIEncode("a b/c~d", encodeSlash: false) == "a%20b/c~d")
        #expect(Adapters.awsURIEncode("a b/c~d", encodeSlash: true) == "a%20b%2Fc~d")
        // Go's url.QueryEscape port (used for params merge + the oauth2 form).
        #expect(queryEscape("a b+c") == "a+b%2Bc")
    }

    // MARK: Adapter dispatch (ported from httpexec.go inject)

    @Test("bearer: default Authorization header and {secret} format template")
    func bearerAdapter() async throws {
        var req = URLRequest(url: URL(string: "https://api.example.com/x")!)
        let injected = try await Adapters.inject(
            cred(adapter: "bearer", secret: "tok_123"),
            into: &req, body: Data(), oauth: dummyOAuth())
        #expect(req.value(forHTTPHeaderField: "Authorization") == "Bearer tok_123")
        #expect(injected == [Data("tok_123".utf8)])

        var req2 = URLRequest(url: URL(string: "https://api.example.com/x")!)
        _ = try await Adapters.inject(
            cred(adapter: "bearer", header: "X-Auth", format: "token {secret}", secret: "tok_123"),
            into: &req2, body: Data(), oauth: dummyOAuth())
        #expect(req2.value(forHTTPHeaderField: "X-Auth") == "token tok_123")
    }

    @Test("header: requires a header name, then injects verbatim")
    func headerAdapter() async throws {
        await #expect(throws: HTTPExecError.headerAdapterNeedsName) {
            var r = URLRequest(url: URL(string: "https://api.example.com/x")!)
            _ = try await Adapters.inject(cred(adapter: "header", secret: "k"),
                                          into: &r, body: Data(), oauth: dummyOAuth())
        }
        var req = URLRequest(url: URL(string: "https://api.example.com/x")!)
        let injected = try await Adapters.inject(
            cred(adapter: "header", header: "X-Api-Key", secret: "cfat_abc"),
            into: &req, body: Data(), oauth: dummyOAuth())
        #expect(req.value(forHTTPHeaderField: "X-Api-Key") == "cfat_abc")
        #expect(injected == [Data("cfat_abc".utf8)])
    }

    @Test("basic: RFC 7617 base64; BOTH raw and wire forms are captured for redaction")
    func basicAdapter() async throws {
        var req = URLRequest(url: URL(string: "https://api.example.com/x")!)
        let injected = try await Adapters.inject(
            cred(adapter: "basic", secret: "user:pass"),
            into: &req, body: Data(), oauth: dummyOAuth())
        #expect(req.value(forHTTPHeaderField: "Authorization") == "Basic dXNlcjpwYXNz")
        // The base64 wire form would evade an exact-match scrub of the raw secret.
        #expect(injected == [Data("user:pass".utf8), Data("dXNlcjpwYXNz".utf8)])
    }

    @Test("aws-sigv4: secret must be ACCESS_KEY_ID:SECRET_ACCESS_KEY; HMAC never echoes")
    func sigV4Adapter() async throws {
        for bad in ["no-colon", ":key-only", "id-only:"] {
            await #expect(throws: HTTPExecError.badSigV4Secret) {
                var r = URLRequest(url: URL(string: "https://s3.amazonaws.com/")!)
                _ = try await Adapters.inject(
                    cred(adapter: "aws-sigv4",
                         params: ["region": "us-east-1", "service": "s3"], secret: bad),
                    into: &r, body: Data(), oauth: dummyOAuth())
            }
        }
        var req = URLRequest(url: URL(string: "https://s3.amazonaws.com/bucket/key")!)
        req.httpMethod = "GET"
        let injected = try await Adapters.inject(
            cred(adapter: "aws-sigv4",
                 params: ["region": "us-east-1", "service": "s3"], secret: "AKID:SECRET"),
            into: &req, body: Data(), oauth: dummyOAuth())
        let auth = try #require(req.value(forHTTPHeaderField: "Authorization"))
        #expect(auth.hasPrefix("AWS4-HMAC-SHA256 "))
        // The signature is a keyed HMAC — the secret key never appears verbatim,
        // so there is nothing to capture for redaction.
        #expect(injected.isEmpty)
        #expect(!auth.contains("SECRET"))
    }

    @Test("unknown adapters are refused")
    func unknownAdapter() async throws {
        await #expect(throws: HTTPExecError.unknownAdapter("magic")) {
            var r = URLRequest(url: URL(string: "https://api.example.com/x")!)
            _ = try await Adapters.inject(cred(adapter: "magic", secret: "s"),
                                          into: &r, body: Data(), oauth: dummyOAuth())
        }
    }

    @Test("thrown adapter errors never contain the secret")
    func errorsNeverLeakSecret() async {
        let secret = "sk_live_LEAKY_SECRET_9000"
        do {
            var r = URLRequest(url: URL(string: "https://api.example.com/x")!)
            _ = try await Adapters.inject(cred(adapter: "magic", secret: secret),
                                          into: &r, body: Data(), oauth: dummyOAuth())
            Issue.record("expected a throw")
        } catch {
            #expect(!String(describing: error).contains(secret))
        }
        do {
            var r = URLRequest(url: URL(string: "https://s3.amazonaws.com/")!)
            _ = try await Adapters.inject(
                cred(adapter: "aws-sigv4", params: [:], secret: "\(secret):\(secret)"),
                into: &r, body: Data(), oauth: dummyOAuth())
            Issue.record("expected a throw")
        } catch {
            #expect(!String(describing: error).contains(secret))
        }
    }

    // MARK: OAuth2 cache (network-free paths; wire behavior in HTTPExecutorTests)

    @Test("oauth2: tokenUrl and clientId are required before any network is touched")
    func oauth2ParamsRequired() async throws {
        let cache = dummyOAuth()
        await #expect(throws: HTTPExecError.oauth2ParamsRequired) {
            _ = try await cache.token(tokenURL: "", clientID: "cid",
                                      clientSecret: "s", scope: "")
        }
        await #expect(throws: HTTPExecError.oauth2ParamsRequired) {
            _ = try await cache.token(tokenURL: "https://idp.example/token", clientID: "",
                                      clientSecret: "s", scope: "")
        }
    }

    @Test("oauth2 cache key: stable, secret-blind, and rotation-busting")
    func oauth2CacheKey() {
        let k = OAuth2TokenCache.cacheKey(tokenURL: "https://idp.example/token",
                                          clientID: "cid", clientSecret: "sec", scope: "repo")
        #expect(k == OAuth2TokenCache.cacheKey(tokenURL: "https://idp.example/token",
                                               clientID: "cid", clientSecret: "sec", scope: "repo"))
        #expect(k.count == 16)             // 8 bytes hex — a digest, not the secret
        #expect(!k.contains("sec"))
        // Rotating ANY component gets a fresh cache slot.
        #expect(k != OAuth2TokenCache.cacheKey(tokenURL: "https://idp.example/token",
                                               clientID: "cid", clientSecret: "ROTATED", scope: "repo"))
        #expect(k != OAuth2TokenCache.cacheKey(tokenURL: "https://idp.example/token2",
                                               clientID: "cid", clientSecret: "sec", scope: "repo"))
        #expect(k != OAuth2TokenCache.cacheKey(tokenURL: "https://idp.example/token",
                                               clientID: "cid", clientSecret: "sec", scope: ""))
    }
}
