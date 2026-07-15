import Foundation
import CryptoKit

/// OAuth 2.1 support for remote MCP servers. Implements protected-resource and
/// authorization-server discovery, dynamic client registration, PKCE, loopback
/// redirects, and resource indicators. Tokens and client credentials are sealed
/// under the vault DEK and unavailable while the vault is locked.
public enum MCPOAuth {

    // MARK: - Stored grant (sealed under the DEK)

    /// Everything Sallyport keeps about one authorized upstream. Nothing here
    /// ever leaves the vault: the agent sees tools, never a token.
    public struct Grant: Codable, Sendable, Equatable {
        public var issuer: String            // authorization server base
        public var authorizeEndpoint: String
        public var tokenEndpoint: String
        public var registrationEndpoint: String
        public var clientID: String
        public var clientSecret: String      // "" for a public client (PKCE only)
        public var redirectURI: String       // the loopback URI this client registered
        public var scopes: String
        public var resource: String          // RFC 8707 MCP endpoint
        public var accessToken: String
        public var refreshToken: String      // "" when the server issues none
        public var expiry: Date              // access-token expiry
        /// Optional account label for the UI.
        public var account: String

        public init(issuer: String = "", authorizeEndpoint: String = "", tokenEndpoint: String = "",
                    registrationEndpoint: String = "", clientID: String = "", clientSecret: String = "",
                    redirectURI: String = "", scopes: String = "", resource: String = "",
                    accessToken: String = "", refreshToken: String = "",
                    expiry: Date = .distantPast, account: String = "") {
            self.issuer = issuer; self.authorizeEndpoint = authorizeEndpoint
            self.tokenEndpoint = tokenEndpoint; self.registrationEndpoint = registrationEndpoint
            self.clientID = clientID; self.clientSecret = clientSecret
            self.redirectURI = redirectURI; self.scopes = scopes; self.resource = resource
            self.accessToken = accessToken; self.refreshToken = refreshToken
            self.expiry = expiry; self.account = account
        }

        /// The blob key this grant is sealed under.
        public static func blobKey(upstream: String) -> String { "oauth:\(upstream)" }

        /// Refresh a minute early so a call never races the expiry.
        public func isFresh(now: Date = Date()) -> Bool {
            !accessToken.isEmpty && now.addingTimeInterval(60) < expiry
        }
    }

    public enum OAuthError: Error, CustomStringConvertible, Sendable, Equatable {
        case discoveryFailed(String)
        case registrationFailed(String)
        case authorizationFailed(String)
        case tokenFailed(String)
        case noRefreshToken
        /// The server rejected the refresh permanently, so a new sign-in is required.
        case grantRevoked
        case notSignedIn(String)
        case cancelled

        public var description: String {
            switch self {
            case .discoveryFailed(let m): return "Could not discover sign-in configuration: \(m)"
            case .registrationFailed(let m): return "Authorization server rejected registration: \(m)"
            case .authorizationFailed(let m): return "Sign-in failed: \(m)"
            case .tokenFailed(let m): return "Token request failed: \(m)"
            case .noRefreshToken: return "No refresh token. Sign in again."
            case .grantRevoked: return "Sign-in was revoked. Connect again."
            case .notSignedIn(let u): return "\(u) is not signed in. Open MCP Servers and select Connect."
            case .cancelled: return "Sign-in was cancelled."
            }
        }
    }

    // MARK: - Discovery

    /// What the MCP endpoint's authorization server exposes.
    struct ServerMetadata: Sendable {
        var issuer: String
        var authorize: String
        var token: String
        var registration: String
        var scopesSupported: String
    }

    /// Whether OAuth endpoints may use private addresses. This is allowed only
    /// when the MCP endpoint itself is private; metadata addresses stay blocked.
    static func allowsPrivate(endpoint: URL) -> Bool {
        guard let host = endpoint.host?.lowercased() else { return false }
        if host == "localhost" { return true }
        guard let ip = IPAddr(host) else { return false }   // DNS names use public rules.
        return NetGuard.classifyIP(ip) == .privateInternal
    }

    static func discover(endpoint: URL, session: URLSession, netGuard: NetGuard,
                         timeout: TimeInterval) async throws -> ServerMetadata {
        let allowPrivate = allowsPrivate(endpoint: endpoint)
        // Ask the resource for its authorization server.
        var issuers: [URL] = []
        if let link = try? await protectedResourceMetadataURL(endpoint: endpoint, session: session,
                                                              netGuard: netGuard, timeout: timeout),
           let servers = try? await authorizationServers(from: link, session: session, netGuard: netGuard,
                                                         allowPrivate: allowPrivate, timeout: timeout) {
            issuers = servers
        }
        // Fall back to the endpoint origin.
        if issuers.isEmpty, let origin = originURL(of: endpoint) {
            issuers = [origin]
        }
        var lastError = "no authorization server found"
        for issuer in issuers {
            for candidate in metadataURLs(issuer: issuer) {
                do {
                    let meta = try await fetchServerMetadata(candidate, issuer: issuer, session: session,
                                                             netGuard: netGuard, allowPrivate: allowPrivate,
                                                             timeout: timeout)
                    return meta
                } catch {
                    lastError = "\(error)"
                }
            }
        }
        throw OAuthError.discoveryFailed(lastError)
    }

    /// The unauthenticated probe: an MCP server must answer 401 with a
    /// `WWW-Authenticate` naming its resource metadata (RFC 9728). We also
    /// accept the conventional well-known path when the header is absent.
    private static func protectedResourceMetadataURL(
        endpoint: URL, session: URLSession, netGuard: NetGuard, timeout: TimeInterval) async throws -> URL {
        try netGuard.validate(host: endpoint.host ?? "", bound: true)
        var probe = URLRequest(url: endpoint)
        probe.httpMethod = "POST"
        probe.timeoutInterval = timeout
        probe.setValue("application/json", forHTTPHeaderField: "Content-Type")
        probe.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
        probe.httpBody = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": ["protocolVersion": "2025-06-18", "capabilities": [:] as [String: Any],
                       "clientInfo": ["name": "sallyport", "version": "1.0"]],
        ])
        let (_, response) = try await Self.cappedData(probe, session: session)
        if let challenge = response.value(forHTTPHeaderField: "WWW-Authenticate"),
           let link = resourceMetadataLink(in: challenge), let url = URL(string: link) {
            return url
        }
        guard let origin = originURL(of: endpoint) else {
            throw OAuthError.discoveryFailed("bad endpoint URL")
        }
        return origin.appendingPathComponent(".well-known/oauth-protected-resource")
    }

    /// Extracts `resource_metadata` from a `WWW-Authenticate` challenge.
    static func resourceMetadataLink(in challenge: String) -> String? {
        guard let range = challenge.range(of: "resource_metadata=") else { return nil }
        let rest = challenge[range.upperBound...]
        if rest.hasPrefix("\"") {
            let body = rest.dropFirst()
            guard let end = body.firstIndex(of: "\"") else { return nil }
            return String(body[..<end])
        }
        let end = rest.firstIndex(of: ",") ?? rest.endIndex
        return String(rest[..<end]).trimmingCharacters(in: .whitespaces)
    }

    private static func authorizationServers(from metadataURL: URL, session: URLSession,
                                             netGuard: NetGuard, allowPrivate: Bool,
                                             timeout: TimeInterval) async throws -> [URL] {
        let json = try await getJSON(metadataURL, session: session, netGuard: netGuard,
                                     allowPrivate: allowPrivate, timeout: timeout)
        let servers = (json["authorization_servers"] as? [Any])?.compactMap { $0 as? String } ?? []
        return servers.compactMap { URL(string: $0) }
    }

    /// Returns RFC 8414 and OIDC metadata candidates for the issuer.
    private static func metadataURLs(issuer: URL) -> [URL] {
        var out: [URL] = []
        let path = issuer.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var base = URLComponents(url: issuer, resolvingAgainstBaseURL: false)
        base?.path = ""
        base?.query = nil
        base?.fragment = nil
        if let root = base?.url {
            if path.isEmpty {
                out.append(root.appendingPathComponent(".well-known/oauth-authorization-server"))
                out.append(root.appendingPathComponent(".well-known/openid-configuration"))
            } else {
                out.append(root.appendingPathComponent(".well-known/oauth-authorization-server/\(path)"))
                out.append(root.appendingPathComponent(".well-known/openid-configuration/\(path)"))
            }
        }
        out.append(issuer.appendingPathComponent(".well-known/oauth-authorization-server"))
        out.append(issuer.appendingPathComponent(".well-known/openid-configuration"))
        return out
    }

    private static func fetchServerMetadata(_ url: URL, issuer: URL, session: URLSession,
                                            netGuard: NetGuard, allowPrivate: Bool,
                                            timeout: TimeInterval) async throws -> ServerMetadata {
        let json = try await getJSON(url, session: session, netGuard: netGuard,
                                     allowPrivate: allowPrivate, timeout: timeout)
        guard let authorize = json["authorization_endpoint"] as? String,
              let token = json["token_endpoint"] as? String,
              !authorize.isEmpty, !token.isEmpty else {
            throw OAuthError.discoveryFailed("metadata has no authorization/token endpoint")
        }
        let scopes = (json["scopes_supported"] as? [Any])?.compactMap { $0 as? String } ?? []
        return ServerMetadata(
            issuer: (json["issuer"] as? String) ?? issuer.absoluteString,
            authorize: authorize,
            token: token,
            registration: (json["registration_endpoint"] as? String) ?? "",
            scopesSupported: scopes.joined(separator: " "))
    }

    // MARK: - Dynamic client registration (RFC 7591)

    /// Register Sallyport as a public native client for `redirectURI`.
    static func register(metadata: ServerMetadata, redirectURI: String, session: URLSession,
                         netGuard: NetGuard, allowPrivate: Bool,
                         timeout: TimeInterval) async throws -> (id: String, secret: String) {
        guard let url = URL(string: metadata.registration), !metadata.registration.isEmpty else {
            throw OAuthError.registrationFailed(
                "This server requires a pre-issued client; Sallyport cannot configure one yet.")
        }
        try requireSecure(url, allowPrivate: allowPrivate)
        try netGuard.validate(host: url.host ?? "", bound: allowPrivate)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "client_name": "Sallyport",
            "redirect_uris": [redirectURI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",   // public client + PKCE (OAuth 2.1)
            "application_type": "native",
        ])
        let (data, response) = try await Self.cappedData(req, session: session)
        guard (200..<300).contains(response.statusCode) else {
            throw OAuthError.registrationFailed("HTTP \(response.statusCode) \(shortBody(data))")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = json["client_id"] as? String, !id.isEmpty else {
            throw OAuthError.registrationFailed("no client_id in the reply")
        }
        return (id, (json["client_secret"] as? String) ?? "")
    }

    // MARK: - PKCE (RFC 7636)

    struct PKCE: Sendable {
        let verifier: String
        let challenge: String

        init() {
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            verifier = Data(bytes).base64URLEncoded
            challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded
        }
    }

    /// Build the browser URL for the authorization-code grant.
    static func authorizeURL(metadata: ServerMetadata, clientID: String, redirectURI: String,
                             scopes: String, resource: String, pkce: PKCE, state: String,
                             allowPrivate: Bool) throws -> URL {
        guard var comps = URLComponents(string: metadata.authorize), let authURL = comps.url else {
            throw OAuthError.authorizationFailed("bad authorization endpoint")
        }
        try requireSecure(authURL, allowPrivate: allowPrivate)
        var items = comps.queryItems ?? []
        items += [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            // Bind the token to this MCP endpoint with RFC 8707.
            URLQueryItem(name: "resource", value: resource),
        ]
        if !scopes.isEmpty { items.append(URLQueryItem(name: "scope", value: scopes)) }
        comps.queryItems = items
        guard let url = comps.url else {
            throw OAuthError.authorizationFailed("could not build the authorization URL")
        }
        return url
    }

    // MARK: - Token endpoint

    /// Exchange the authorization code for tokens (PKCE verifier proves it is us).
    static func exchange(code: String, metadata: ServerMetadata, clientID: String, clientSecret: String,
                         redirectURI: String, resource: String, verifier: String,
                         session: URLSession, netGuard: NetGuard, allowPrivate: Bool,
                         timeout: TimeInterval,
                         now: Date = Date()) async throws -> (access: String, refresh: String, expiry: Date, scopes: String) {
        var form = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectURI,
            "client_id": clientID,
            "code_verifier": verifier,
            "resource": resource,
        ]
        if !clientSecret.isEmpty { form["client_secret"] = clientSecret }
        return try await postToken(form, metadata: metadata, session: session, netGuard: netGuard,
                                   allowPrivate: allowPrivate, timeout: timeout, now: now)
    }

    /// Refreshes an access token and returns a rotated refresh token when supplied.
    static func refresh(grant: Grant, session: URLSession, netGuard: NetGuard,
                        timeout: TimeInterval,
                        now: Date = Date()) async throws -> (access: String, refresh: String, expiry: Date, scopes: String) {
        // The same rule as the interactive flow: private token endpoints are
        // allowed only for a private MCP endpoint (the grant remembers it).
        let allowPrivate = URL(string: grant.resource).map(allowsPrivate(endpoint:)) ?? false
        guard !grant.refreshToken.isEmpty else { throw OAuthError.noRefreshToken }
        var form = [
            "grant_type": "refresh_token",
            "refresh_token": grant.refreshToken,
            "client_id": grant.clientID,
            "resource": grant.resource,
        ]
        if !grant.clientSecret.isEmpty { form["client_secret"] = grant.clientSecret }
        let meta = ServerMetadata(issuer: grant.issuer, authorize: grant.authorizeEndpoint,
                                  token: grant.tokenEndpoint, registration: grant.registrationEndpoint,
                                  scopesSupported: grant.scopes)
        let fresh = try await postToken(form, metadata: meta, session: session, netGuard: netGuard,
                                        allowPrivate: allowPrivate, timeout: timeout, now: now)
        // A server that rotates gives a new refresh token; one that doesn't
        // expects the old one to keep working.
        return (fresh.access,
                fresh.refresh.isEmpty ? grant.refreshToken : fresh.refresh,
                fresh.expiry,
                fresh.scopes.isEmpty ? grant.scopes : fresh.scopes)
    }

    private static func postToken(_ form: [String: String], metadata: ServerMetadata,
                                  session: URLSession, netGuard: NetGuard, allowPrivate: Bool,
                                  timeout: TimeInterval,
                                  now: Date) async throws -> (access: String, refresh: String, expiry: Date, scopes: String) {
        guard let url = URL(string: metadata.token) else {
            throw OAuthError.tokenFailed("bad token endpoint")
        }
        try requireSecure(url, allowPrivate: allowPrivate)
        try netGuard.validate(host: url.host ?? "", bound: allowPrivate)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = Data(form.map { "\(formEscape($0.key))=\(formEscape($0.value))" }
            .joined(separator: "&").utf8)

        let (data, response) = try await Self.cappedData(req, session: session)
        let http = response
        guard (200..<300).contains(http.statusCode) else {
            // Treat 400 or 401 during refresh as a revoked grant. Network and
            // server failures remain transient.
            if form["grant_type"] == "refresh_token", (400...401).contains(http.statusCode) {
                throw OAuthError.grantRevoked
            }
            // Redact credentials submitted in the token request.
            let submitted = ["refresh_token", "code", "code_verifier", "client_secret"]
                .compactMap { form[$0] }.filter { !$0.isEmpty }.map { Data($0.utf8) }
            throw OAuthError.tokenFailed("HTTP \(http.statusCode) \(shortBody(data, secrets: submitted))")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = json["access_token"] as? String, !access.isEmpty else {
            throw OAuthError.tokenFailed("no access_token in the reply")
        }
        var life = TimeInterval((json["expires_in"] as? Int) ?? 0)
        if life <= 0 { life = 3600 }
        return (access,
                (json["refresh_token"] as? String) ?? "",
                now.addingTimeInterval(life),
                (json["scope"] as? String) ?? "")
    }

    // MARK: - Helpers

    /// Maximum OAuth response body size. OAuth requests do not follow redirects.
    private static let maxOAuthBody = 1 << 20

    static func cappedData(_ request: URLRequest, session: URLSession) async throws -> (Data, HTTPURLResponse) {
        let policy = RedirectPolicy(origin: request.url?.hostPort ?? "",
                                    originScheme: request.url?.scheme?.lowercased() ?? "https",
                                    hasCredential: true, maxBody: maxOAuthBody)
        return try await policy.loadCapped(request: request, session: session,
                                           hardTimeout: request.timeoutInterval)
    }

    private static func getJSON(_ url: URL, session: URLSession, netGuard: NetGuard,
                                allowPrivate: Bool, timeout: TimeInterval) async throws -> [String: Any] {
        try requireSecure(url, allowPrivate: allowPrivate)
        try netGuard.validate(host: url.host ?? "", bound: allowPrivate)
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await Self.cappedData(req, session: session)
        guard (200..<300).contains(response.statusCode) else {
            throw OAuthError.discoveryFailed("HTTP \(response.statusCode) at \(url.path)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OAuthError.discoveryFailed("unparseable metadata at \(url.path)")
        }
        return json
    }

    /// Requires HTTPS except for loopback development endpoints.
    static func requireSecure(_ url: URL, allowPrivate: Bool) throws {
        switch url.scheme?.lowercased() {
        case "https":
            return
        case "http" where allowPrivate:
            let h = (url.host ?? "").lowercased()
            if h == "localhost" || IPAddr(h)?.unmapped().isLoopback == true { return }
            throw OAuthError.discoveryFailed("HTTPS is required for \(url.host ?? "?")")
        default:
            throw OAuthError.discoveryFailed("HTTPS is required for \(url.host ?? "?")")
        }
    }

    static func originURL(of url: URL) -> URL? {
        var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        comps?.path = ""
        comps?.query = nil
        comps?.fragment = nil
        return comps?.url
    }

    /// Returns redacted RFC 6749 `error` fields for a user-facing message.
    static func shortBody(_ data: Data, secrets: [Data] = []) -> String {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return "" }
        let code = (obj["error"] as? String) ?? ""
        let desc = (obj["error_description"] as? String) ?? ""
        let combined = [code, desc].filter { !$0.isEmpty }.joined(separator: ": ")
        guard !combined.isEmpty else { return "" }
        // Redact submitted values and generic patterns before truncating.
        var bytes = Data(combined.utf8)
        if !secrets.isEmpty { (bytes, _) = DLP.redactWith(bytes, secrets: secrets) }
        (bytes, _) = DLP.redact(bytes)
        return "- \(String(String(decoding: bytes, as: UTF8.self).prefix(200)))"
    }

    static func formEscape(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    static func randomState() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncoded
    }
}

extension Data {
    /// base64url without padding (RFC 7636 / 4648 §5).
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
