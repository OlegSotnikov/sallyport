import Foundation
import CryptoKit

/// Credential-injection adapters for the HTTP executor.
enum Adapters {

    /// Attaches `cred` to `request` according to its adapter. `body` is the raw
    /// request payload (needed by signing adapters like aws-sigv4); the oauth2
    /// adapter performs a guarded token fetch through `oauth`.
    static func inject(_ cred: Cred, into request: inout URLRequest, body: Data,
                       oauth: OAuth2TokenCache) async throws {
        // HTTP credentials become header material or HMAC inputs rather than
        // request payloads. Bound their plaintext before String/base64 copies.
        guard cred.secret.count <= 64 * 1024 else { throw HTTPExecError.invalidHeaders }
        let secret = String(decoding: cred.secret, as: UTF8.self)
        switch cred.inject.adapter {
        case "bearer":
            let header = orDefault(cred.inject.header, "Authorization")
            var value = "Bearer " + secret
            if !cred.inject.format.isEmpty {
                value = cred.inject.format.replacingOccurrences(of: "{secret}", with: secret)
            }
            try setHeader(value, name: header, request: &request)

        case "header":
            guard !cred.inject.header.isEmpty else { throw HTTPExecError.headerAdapterNeedsName }
            var value = secret
            if !cred.inject.format.isEmpty {
                value = cred.inject.format.replacingOccurrences(of: "{secret}", with: secret)
            }
            try setHeader(value, name: cred.inject.header, request: &request)

        case "basic":
            // secret is "user:pass"; RFC 7617 base64.
            let header = orDefault(cred.inject.header, "Authorization")
            let enc = basicEncode(secret)
            try setHeader("Basic " + enc, name: header, request: &request)

        case "aws-sigv4":
            // secret is "ACCESS_KEY_ID:SECRET_ACCESS_KEY"; params carry region+service.
            guard let colon = secret.firstIndex(of: ":") else { throw HTTPExecError.badSigV4Secret }
            let id = String(secret[..<colon])
            let key = String(secret[secret.index(after: colon)...])
            guard !id.isEmpty, !key.isEmpty else { throw HTTPExecError.badSigV4Secret }
            try signAWSV4(&request, accessKeyID: id, secretKey: key,
                          region: cred.inject.params["region"] ?? "",
                          service: cred.inject.params["service"] ?? "",
                          body: body, now: Date())

        case "oauth2":
            let p = cred.inject.params
            let tok = try await oauth.token(tokenURL: p["tokenUrl"] ?? "",
                                            clientID: p["clientId"] ?? "",
                                            clientSecret: secret,
                                            scope: p["scope"] ?? "")
            let header = orDefault(cred.inject.header, "Authorization")
            try setHeader("Bearer " + tok, name: header, request: &request)

        default:
            throw HTTPExecError.unknownAdapter(cred.inject.adapter)
        }
    }

    private static func setHeader(_ value: String, name: String,
                                  request: inout URLRequest) throws {
        guard HTTPExecutor.isSafeHeaderName(name), HTTPExecutor.isSafeHeaderValue(value) else {
            throw HTTPExecError.invalidHeaders
        }
        request.setValue(value, forHTTPHeaderField: name)
    }

    // MARK: - AWS Signature Version 4

    /// Signs the request with AWS Signature Version 4. `now` is injectable for tests.
    static func signAWSV4(_ request: inout URLRequest, accessKeyID: String, secretKey: String,
                          region: String, service: String, body: Data, now: Date) throws {
        guard !region.isEmpty, !service.isEmpty else { throw HTTPExecError.sigV4ParamsRequired }
        guard let url = request.url else { throw HTTPExecError.badURL("") }
        let amzDate = Self.amzDate(now)
        let dateStamp = String(amzDate.prefix(8))

        let payloadHash = hexSHA256(body)

        let host = url.hostPort
        request.setValue(amzDate, forHTTPHeaderField: "X-Amz-Date")
        // S3 (and S3-compatible) require the payload hash as a signed header;
        // other services do not include it (matching the standard test vectors).
        let s3 = service == "s3"
        if s3 { request.setValue(payloadHash, forHTTPHeaderField: "X-Amz-Content-Sha256") }

        // Keep the signed header set minimal and deterministic.
        var signedNames = ["host", "x-amz-date"]
        if s3 { signedNames.append("x-amz-content-sha256") }
        signedNames.sort()
        var canonicalHeaders = ""
        for h in signedNames {
            let val: String
            switch h {
            case "host": val = host
            case "x-amz-date": val = amzDate
            case "x-amz-content-sha256": val = payloadHash
            default: val = ""
            }
            canonicalHeaders += h + ":" + val.trimmingCharacters(in: .whitespaces) + "\n"
        }
        let signedHeaders = signedNames.joined(separator: ";")

        let canonicalRequest = [
            (request.httpMethod ?? "GET").uppercased(),
            canonicalURI(url),
            canonicalQuery(url),
            canonicalHeaders,
            signedHeaders,
            payloadHash,
        ].joined(separator: "\n")

        let algorithm = "AWS4-HMAC-SHA256"
        let credentialScope = [dateStamp, region, service, "aws4_request"].joined(separator: "/")
        let stringToSign = [
            algorithm,
            amzDate,
            credentialScope,
            hexSHA256(Data(canonicalRequest.utf8)),
        ].joined(separator: "\n")

        let kDate = hmacSHA256(key: Data(("AWS4" + secretKey).utf8), dateStamp)
        let kRegion = hmacSHA256(key: kDate, region)
        let kService = hmacSHA256(key: kRegion, service)
        let kSigning = hmacSHA256(key: kService, "aws4_request")
        let signature = hexEncode(hmacSHA256(key: kSigning, stringToSign))

        let auth = "\(algorithm) Credential=\(accessKeyID)/\(credentialScope), "
            + "SignedHeaders=\(signedHeaders), Signature=\(signature)"
        request.setValue(auth, forHTTPHeaderField: "Authorization")
    }

    /// AWS canonical URI with encoded path segments and preserved slashes.
    static func canonicalURI(_ url: URL) -> String {
        let p = url.path(percentEncoded: false)
        return awsURIEncode(p.isEmpty ? "/" : p, encodeSlash: false)
    }

    /// AWS canonical query: keys sorted, values sorted per key, both re-encoded.
    static func canonicalQuery(_ url: URL) -> String {
        guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
              !items.isEmpty else { return "" }
        var q: [String: [String]] = [:]
        for item in items { q[item.name, default: []].append(item.value ?? "") }
        var parts: [String] = []
        for k in q.keys.sorted() {
            for v in q[k, default: []].sorted() {
                parts.append(awsURIEncode(k, encodeSlash: true) + "=" + awsURIEncode(v, encodeSlash: true))
            }
        }
        return parts.joined(separator: "&")
    }

    /// Percent-encodes per RFC 3986 the way SigV4 requires: unreserved
    /// characters pass through; everything else is encoded; '/' is preserved
    /// when `encodeSlash` is false (used for the path).
    static func awsURIEncode(_ s: String, encodeSlash: Bool) -> String {
        var out = ""
        for c in Array(s.utf8) {
            switch c {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"),
                 UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "~"):
                out.append(Character(UnicodeScalar(c)))
            case UInt8(ascii: "/") where !encodeSlash:
                out.append("/")
            default:
                out += String(format: "%%%02X", c)
            }
        }
        return out
    }

    /// "20060102T150405Z" in UTC (the SigV4 X-Amz-Date form).
    static func amzDate(_ now: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f.string(from: now)
    }

    static func hexSHA256(_ data: Data) -> String {
        hexEncode(Data(SHA256.hash(data: data)))
    }

    static func hmacSHA256(key: Data, _ message: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8),
                                             using: SymmetricKey(data: key)))
    }

    static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func basicEncode(_ userpass: String) -> String {
        Data(userpass.utf8).base64EncodedString()
    }

    static func orDefault(_ v: String, _ d: String) -> String { v.isEmpty ? d : v }
}

// MARK: - OAuth 2.0 client-credentials token cache

/// Caches OAuth 2.0 client-credentials tokens until shortly before expiry.
/// Concurrent cache misses may each fetch a valid token; the last result is stored.
actor OAuth2TokenCache {
    struct Token: Sendable {
        var accessToken: String
        var expiry: Date
    }

    private let transport: PinnedHTTPTransport
    private let timeout: TimeInterval
    private let netGuard: NetGuard
    private let now: @Sendable () -> Date
    private var tokens: [String: Token] = [:]

    init(transport: PinnedHTTPTransport, timeout: TimeInterval, netGuard: NetGuard,
         now: @escaping @Sendable () -> Date = { Date() }) {
        self.transport = transport
        self.timeout = timeout
        self.netGuard = netGuard
        self.now = now
    }

    /// Derives a stable cache key from the config + secret, so rotating any of
    /// them busts the cache without leaking the secret into the key.
    static func cacheKey(tokenURL: String, clientID: String, clientSecret: String,
                         scope: String) -> String {
        let material = "\(tokenURL)\u{0}\(clientID)\u{0}\(clientSecret)\u{0}\(scope)"
        let sum = SHA256.hash(data: Data(material.utf8))
        return sum.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// Returns a valid bearer token for the client-credentials config, fetching
    /// and caching one when the cache is empty or the cached token is near expiry.
    func token(tokenURL: String, clientID: String, clientSecret: String,
               scope: String) async throws -> String {
        guard !tokenURL.isEmpty, !clientID.isEmpty else {
            throw HTTPExecError.oauth2ParamsRequired
        }
        let key = Self.cacheKey(tokenURL: tokenURL, clientID: clientID,
                                clientSecret: clientSecret, scope: scope)
        if let t = tokens[key], now() < t.expiry { return t.accessToken }
        let tok = try await fetch(tokenURL: tokenURL, clientID: clientID,
                                  clientSecret: clientSecret, scope: scope)
        tokens[key] = tok
        return tok.accessToken
    }

    private func fetch(tokenURL: String, clientID: String, clientSecret: String,
                       scope: String) async throws -> Token {
        guard tokenURL.utf8.count <= 16 * 1024,
              let url = URL(string: tokenURL), url.user == nil, url.password == nil,
              let host = url.host(percentEncoded: false), !host.isEmpty else {
            throw HTTPExecError.oauth2BadTokenURL
        }
        // Require HTTPS, except for loopback development issuers.
        let isLoopback = host.lowercased() == "localhost" || IPAddr(host)?.unmapped().isLoopback == true
        guard url.scheme?.lowercased() == "https" || (url.scheme?.lowercased() == "http" && isLoopback) else {
            throw HTTPExecError.oauth2BadTokenURL
        }
        // Token requests use the network guard without a private-host binding.
        let destination = try netGuard.destination(for: url, bound: false)

        var form = "grant_type=client_credentials"
        if !scope.isEmpty { form += "&scope=" + queryEscape(scope) }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.httpBody = Data(form.utf8)
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        // RFC 6749 §2.3.1: client credentials in the Authorization header
        // (Basic), each form-urlencoded before concatenation per the spec.
        let userpass = queryEscape(clientID) + ":" + queryEscape(clientSecret)
        req.setValue("Basic " + Data(userpass.utf8).base64EncodedString(),
                     forHTTPHeaderField: "Authorization")

        // Reject cross-host redirects and HTTPS downgrades for token requests.
        // This request carries client credentials in a Basic header, so refuse
        // redirects and cap the response body.
        let policy = RedirectPolicy(origin: url.hostPort,
                                    originScheme: url.scheme?.lowercased() ?? "",
                                    hasCredential: true, maxBody: 1 << 20)
        let (raw, http) = try await transport.loadCapped(
            request: req, destination: destination, policy: policy,
            hardTimeout: timeout)
        guard http.statusCode == 200 else {
            throw HTTPExecError.oauth2TokenEndpointStatus(http.statusCode)
        }

        struct TokenResponse: Decodable {
            var accessToken: String?
            var tokenType: String?
            var expiresIn: Int?
            enum CodingKeys: String, CodingKey {
                case accessToken = "access_token"
                case tokenType = "token_type"
                case expiresIn = "expires_in"
            }
        }
        guard let parsed = try? JSONDecoder().decode(TokenResponse.self,
                                                     from: Data(raw.prefix(1 << 20))) else {
            throw HTTPExecError.oauth2ParseFailed
        }
        guard let accessToken = parsed.accessToken, !accessToken.isEmpty,
              HTTPExecutor.isSafeHeaderValue("Bearer " + accessToken) else {
            throw HTTPExecError.oauth2NoAccessToken
        }
        // Refresh a minute early; default to a short life when the server omits it.
        var life = TimeInterval(parsed.expiresIn ?? 0)
        if life <= 0 { life = 5 * 60 }
        if life > 90 { life -= 60 }
        return Token(accessToken: accessToken, expiry: now().addingTimeInterval(life))
    }
}
