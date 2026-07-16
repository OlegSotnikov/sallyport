import Foundation
import SallyportKit   // JSONValue

/// Executes `http.request` calls. It resolves a credential by host and path,
/// injects it, and returns the response without content filtering. Requests
/// with credentials do not follow redirects; other requests follow only safe
/// same-origin redirects.

// MARK: - Errors

/// Structured HTTP executor error. Messages must not contain secret values.
public enum HTTPExecError: Error, Sendable, Hashable, CustomStringConvertible {
    case badURL(String)
    case unsupportedScheme(String)
    case notHTTPResponse
    case timeout
    case tooManyRedirects
    case unsupportedMethod
    case invalidHeaders
    case noAddresses(host: String)
    case dnsLookupFailed(host: String)
    case headerAdapterNeedsName
    case badSigV4Secret
    case sigV4ParamsRequired
    case unknownAdapter(String)
    case oauth2ParamsRequired
    case oauth2BadTokenURL
    case oauth2TokenEndpointStatus(Int)
    case oauth2NoAccessToken
    case oauth2ParseFailed
    case insecureCredentialTransport(String)

    public var description: String {
        switch self {
        case .badURL(let u): return "httpexec: bad url: \(u)"
        case .unsupportedScheme(let s): return "httpexec: unsupported scheme \"\(s)\""
        case .notHTTPResponse: return "httpexec: request failed: not an HTTP response"
        case .timeout: return "httpexec: request exceeded its hard deadline"
        case .tooManyRedirects: return "httpexec: stopped after 10 redirects"
        case .unsupportedMethod: return "httpexec: unsupported HTTP method"
        case .invalidHeaders: return "httpexec: invalid or excessive request headers"
        case .noAddresses(let h): return "httpexec: no addresses for host \(h)"
        case .dnsLookupFailed(let h): return "httpexec: lookup \(h): no such host"
        case .headerAdapterNeedsName: return "httpexec: header adapter needs a header name"
        case .badSigV4Secret:
            return "httpexec: aws-sigv4 secret must be ACCESS_KEY_ID:SECRET_ACCESS_KEY"
        case .sigV4ParamsRequired: return "aws-sigv4: params 'region' and 'service' are required"
        case .unknownAdapter(let a): return "httpexec: unknown inject adapter \"\(a)\""
        case .oauth2ParamsRequired: return "oauth2: params 'tokenUrl' and 'clientId' are required"
        case .oauth2BadTokenURL: return "oauth2: build token request: bad token url"
        case .oauth2TokenEndpointStatus(let s): return "oauth2: token endpoint returned \(s)"
        case .oauth2NoAccessToken: return "oauth2: token endpoint returned no access_token"
        case .oauth2ParseFailed: return "oauth2: parse token response"
        case .insecureCredentialTransport(let h):
            return "httpexec: HTTPS is required for credentials sent to \(h); loopback HTTP is allowed"
        }
    }
}

/// Network guard refusal containing only the destination IP and a coarse reason.
public struct BlockedError: Error, Sendable, Hashable, CustomStringConvertible {
    public let ip: String       // the resolved destination IP that was blocked
    public let reason: String   // "metadata" or "private"
    public var description: String {
        "SALLYPORT_BLOCKED: destination \(ip) is a blocked internal/metadata address"
    }
}

// MARK: - Executor

/// Performs authenticated HTTP calls on behalf of an agent, via `URLSession`.
public struct HTTPExecutor: ChannelExecutor {
    /// Per-request timeout.
    public let timeout: TimeInterval
    /// Response body cap in bytes.
    public let maxBody: Int

    let netGuard: NetGuard
    let transport: PinnedHTTPTransport
    let oauth: OAuth2TokenCache

    /// Builds an executor. `timeout` <= 0 means 30 s; `maxBody` <= 0 means 8 MiB.
    public init(configuration: URLSessionConfiguration = .ephemeral,
                timeout: TimeInterval = 30, maxBody: Int = 8 << 20) {
        self.init(configuration: configuration, timeout: timeout, maxBody: maxBody,
                  netGuard: NetGuard())
    }

    /// Internal initializer for tests that inject a network guard.
    init(configuration: URLSessionConfiguration, timeout: TimeInterval, maxBody: Int,
         netGuard: NetGuard) {
        // Do not retain cookies or cache state between calls.
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.timeout = timeout.isFinite && timeout > 0 ? min(timeout, 3_600) : 30
        self.maxBody = maxBody > 0 ? min(maxBody, 64 << 20) : 8 << 20
        self.netGuard = netGuard
        let transport = PinnedHTTPTransport(configuration: configuration)
        self.transport = transport
        // OAuth token requests use the same pinned transport and network guard.
        self.oauth = OAuth2TokenCache(transport: transport, timeout: self.timeout,
                                      netGuard: netGuard)
    }

    /// Executes an `http.request` action and returns either parsed `json` or a
    /// raw `body` string.
    public func execute(_ action: Action, resolve: CredResolver) async throws -> ExecOutput {
        // Merge `params` into the URL query string.
        let reqURL = Self.withQueryParams(Self.toStr(action.args["url"]),
                                          params: action.args["params"])
        guard reqURL.utf8.count <= 16 * 1024,
              let url = URL(string: reqURL), url.user == nil, url.password == nil else {
            throw HTTPExecError.badURL(reqURL.utf8.count <= 512 ? reqURL : "<url exceeds limit>")
        }
        let scheme = url.scheme?.lowercased() ?? ""
        guard scheme == "http" || scheme == "https" else {
            throw HTTPExecError.unsupportedScheme(url.scheme ?? "")
        }
        let originHost = url.host(percentEncoded: false) ?? ""
        // Redirect origin includes host and port; the scheme is checked separately.
        let origin = url.hostPort

        var method = Self.toStr(action.args["method"]).uppercased()
        if method.isEmpty { method = "GET" }
        guard ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].contains(method) else {
            throw HTTPExecError.unsupportedMethod
        }
        let bodyData = Data(Self.toStr(action.args["body"]).utf8)

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = timeout
        if !bodyData.isEmpty { request.httpBody = bodyData }
        let suppliedHeaders = Self.toStrMap(action.args["headers"])
        guard suppliedHeaders.count <= 100 else { throw HTTPExecError.invalidHeaders }
        let reservedHeaders: Set<String> = [
            "authorization", "proxy-authorization", "host", "content-length",
            "transfer-encoding", "connection",
        ]
        for (k, v) in suppliedHeaders {
            guard Self.isSafeHeaderName(k), Self.isSafeHeaderValue(v) else {
                throw HTTPExecError.invalidHeaders
            }
            // Authentication headers are set only by Sallyport.
            if reservedHeaders.contains(k.lowercased()) { continue }
            request.setValue(v, forHTTPHeaderField: k)
        }

        // Resolve the bound credential; `bound` gates the guard's private-range
        // carve-out below.
        var cred = try await resolve(originHost, url.path(percentEncoded: false))
        // Own and wipe the resolved vault bytes on every exit path. An explicit
        // wipe immediately after injection keeps the lifetime short; this defer
        // also covers destination validation and adapter failures.
        defer { cred?.secret.zeroize() }
        let allowInsecureTLS = cred?.insecureTLS ?? false

        // Validate the destination before adding or sending a credential. Bound
        // hosts may resolve to private ranges; metadata addresses remain blocked.
        let destination = try netGuard.destination(for: url, bound: cred != nil)

        // Credentials require HTTPS except for exact loopback development hosts.
        if cred != nil, scheme != "https", !Self.isLoopbackHost(originHost) {
            throw HTTPExecError.insecureCredentialTransport(originHost)
        }

        if let resolved = cred {
            try await Adapters.inject(resolved, into: &request, body: bodyData, oauth: oauth)
            cred?.secret.zeroize()
        }

        // Credentialed redirects are refused. A key can disable certificate
        // verification only for its bound host.
        let policy = RedirectPolicy(origin: origin, originScheme: scheme,
                                    hasCredential: cred != nil,
                                    allowInsecureTLS: allowInsecureTLS, maxBody: maxBody)
        let http: HTTPURLResponse
        let body: Data
        // Cap the response as it streams.
        (body, http) = try await transport.loadCapped(
            request: request, destination: destination, policy: policy,
            hardTimeout: timeout)
        if policy.tooManyRedirects {
            throw HTTPExecError.tooManyRedirects
        }
        var output: [String: JSONValue] = [
            "status": .int(http.statusCode),
            "final_url": .string((http.url ?? url).absoluteString),
            "cross_host_redirect_refused": .bool(policy.refused),
        ]
        // Return parsed JSON or the raw body, not both.
        if let parsed = Self.parseJSONBody(body) {
            output["json"] = parsed
        } else {
            output["body"] = .string(String(decoding: body, as: UTF8.self))
        }
        return ExecOutput(output: output, bytesOut: body.count)
    }

    // MARK: Args and body helpers

    /// Merges a `params` object into the URL query. Keys are sorted and supplied
    /// values replace existing values for the same key.
    static func withQueryParams(_ rawURL: String, params: JSONValue?) -> String {
        guard case .object(let pm)? = params, !pm.isEmpty else { return rawURL }
        // URLComponents accepts some malformed strings, so require a scheme.
        guard var comps = URLComponents(string: rawURL),
              let scheme = comps.scheme, !scheme.isEmpty else {
            return rawURL
        }
        var q: [String: [String]] = [:]
        for item in comps.queryItems ?? [] {
            q[item.name, default: []].append(item.value ?? "")
        }
        for (k, v) in pm { q[k] = [paramToStr(v)] }
        let encoded = q.keys.sorted().flatMap { k in
            q[k, default: []].map { queryEscape(k) + "=" + queryEscape($0) }
        }.joined(separator: "&")
        comps.percentEncodedQuery = encoded.isEmpty ? nil : encoded
        return comps.string ?? rawURL
    }

    /// Renders a JSON scalar as a query value without a fractional part for integers.
    static func paramToStr(_ v: JSONValue) -> String {
        switch v {
        case .string(let s): return s
        case .bool(let b): return b ? "true" : "false"
        case .int(let i): return String(i)
        case .double(let d):
            if let i = Int64(exactly: d) { return String(i) }
            return String(d)
        case .null: return "null"
        case .array, .object: return v.displayString
        }
    }

    /// Returns the body parsed as a JSON object/array when it is valid JSON, so
    /// `http.request` can hand the agent a structured `json` field instead of a
    /// double-encoded string. Returns nil for non-JSON bodies.
    static func parseJSONBody(_ body: Data) -> JSONValue? {
        var t = body[...]
        while let f = t.first, f == 0x20 || f == 0x09 || f == 0x0a || f == 0x0d {
            t = t.dropFirst()
        }
        guard let f = t.first, f == UInt8(ascii: "{") || f == UInt8(ascii: "[") else { return nil }
        return try? JSONDecoder().decode(JSONValue.self, from: Data(t))
    }

    private static func toStr(_ v: JSONValue?) -> String { v?.stringValue ?? "" }

    /// A host that is exactly loopback (localhost / 127.0.0.0/8 / ::1), where a
    /// plain-http credential is permitted for a local dev server.
    static func isLoopbackHost(_ host: String) -> Bool {
        if host.lowercased() == "localhost" { return true }
        return IPAddr(host)?.unmapped().isLoopback == true
    }

    private static func toStrMap(_ v: JSONValue?) -> [String: String] {
        guard case .object(let m)? = v else { return [:] }
        var out: [String: String] = [:]
        for (k, val) in m { out[k] = val.stringValue ?? "" }
        return out
    }

    /// RFC 9110 token syntax, with conservative size limits. Foundation's header
    /// APIs are not a validation boundary; CR/LF and reserved transport headers
    /// must be rejected before an agent-controlled value reaches CFNetwork.
    static func isSafeHeaderName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard (1...128).contains(bytes.count) else { return false }
        let punctuation = Set("!#$%&'*+-.^_`|~".utf8)
        return bytes.allSatisfy {
            (0x30...0x39).contains($0) || (0x41...0x5a).contains($0)
                || (0x61...0x7a).contains($0) || punctuation.contains($0)
        }
    }

    static func isSafeHeaderValue(_ value: String) -> Bool {
        guard value.utf8.count <= 16 * 1024 else { return false }
        return value.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7f }
    }
}

// MARK: - Redirect policy

/// Redirect and response-size delegate. Credentialed requests do not follow any
/// redirect. Other requests stay on the same host, port, and secure scheme.
final class RedirectPolicy: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let origin: String        // host[:port] of the original request
    private let originScheme: String  // "https" refuses any non-https hop
    /// Whether the request carries a credential and must not follow redirects.
    private let hasCredential: Bool
    /// The bound key's certificate-verification opt-out.
    private let allowInsecureTLS: Bool
    /// Maximum buffered response size. Zero disables the cap for redirect tests.
    private let maxBody: Int
    private let lock = NSLock()
    private var refusedCrossHost = false
    private var hops = 0
    private var exceededHops = false
    // Capped-load state (all under `lock`).
    private var buffer = Data()
    private var capturedResponse: HTTPURLResponse?
    private var overflowed = false
    private var finished = false
    private var cancelled = false
    private var continuation: CheckedContinuation<(Data, HTTPURLResponse), any Error>?
    private var activeTask: URLSessionDataTask?

    init(origin: String, originScheme: String, hasCredential: Bool,
         allowInsecureTLS: Bool = false, maxBody: Int = 0) {
        self.origin = origin
        self.originScheme = originScheme
        self.hasCredential = hasCredential
        self.allowInsecureTLS = allowInsecureTLS
        self.maxBody = maxBody
    }

    /// Runs the request and truncates the streamed body at `maxBody`.
    func loadCapped(request: URLRequest, session: URLSession,
                    hardTimeout: TimeInterval) async throws -> (Data, HTTPURLResponse) {
        let bounded = hardTimeout.isFinite && hardTimeout > 0 ? min(hardTimeout, 3_600) : 30
        let timeoutNanos = UInt64((bounded * 1_000_000_000).rounded(.up))
        return try await withThrowingTaskGroup(of: (Data, HTTPURLResponse).self) { group in
            defer { group.cancelAll() }
            group.addTask { try await self.startLoad(request: request, session: session) }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNanos)
                throw HTTPExecError.timeout
            }
            guard let first = try await group.next() else { throw HTTPExecError.notHTTPResponse }
            return first
        }
    }

    /// Starts a delegate-driven load and forwards task cancellation to CFNetwork.
    private func startLoad(request: URLRequest,
                           session: URLSession) async throws -> (Data, HTTPURLResponse) {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { cont in
                let task = session.dataTask(with: request)
                task.delegate = self
                let shouldStart = lock.withLock { () -> Bool in
                    guard !cancelled, !finished else { return false }
                    continuation = cont
                    activeTask = task
                    return true
                }
                if shouldStart {
                    task.resume()
                } else {
                    cont.resume(throwing: CancellationError())
                }
            }
        }, onCancel: { self.cancelLoad() })
    }

    private func cancelLoad() {
        let state: (URLSessionDataTask?, CheckedContinuation<(Data, HTTPURLResponse), any Error>?) =
            lock.withLock {
                cancelled = true
                guard !finished, let cont = continuation else {
                    return (activeTask, nil)
                }
                finished = true
                continuation = nil
                let task = activeTask
                activeTask = nil
                return (task, cont)
            }
        state.0?.cancel()
        state.1?.resume(throwing: CancellationError())
    }

    private func finish(_ result: Result<(Data, HTTPURLResponse), any Error>) {
        let cont: CheckedContinuation<(Data, HTTPURLResponse), any Error>? = lock.withLock {
            if finished { return nil }
            finished = true
            let c = continuation
            continuation = nil
            activeTask = nil
            return c
        }
        cont?.resume(with: result)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else {
            finish(.failure(HTTPExecError.notHTTPResponse))
            completionHandler(.cancel)
            return
        }
        lock.withLock { capturedResponse = http }
        // The data callback truncates the stream at `maxBody`.
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let stop: Bool = lock.withLock {
            guard maxBody > 0 else { buffer.append(data); return false }
            if buffer.count >= maxBody { return true }
            let room = maxBody - buffer.count
            if data.count <= room {
                buffer.append(data)
                return false
            }
            buffer.append(data.prefix(room))
            overflowed = true
            return true
        }
        if stop { dataTask.cancel() }   // didComplete resolves the truncated load.
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didCompleteWithError error: (any Error)?) {
        let (body, http, overflow): (Data, HTTPURLResponse?, Bool) = lock.withLock {
            (buffer, capturedResponse, overflowed)
        }
        // Cancellation caused by the body cap returns the truncated body.
        if let error, !overflow {
            // URLRequest.timeoutInterval and our explicit hard deadline share
            // the same bound. CFNetwork can win that race and report
            // URLError.timedOut first; expose one stable executor-level timeout
            // either way. Every other transport failure remains untouched.
            if let urlError = error as? URLError, urlError.code == .timedOut {
                finish(.failure(HTTPExecError.timeout))
            } else {
                finish(.failure(error))
            }
            return
        }
        guard let http else {
            finish(.failure(HTTPExecError.notHTTPResponse))
            return
        }
        finish(.success((body, http)))
    }

    /// Accepts server trust without validation only when the bound key opts out.
    static func trustDecision(method: String, allowInsecureTLS: Bool, trust: SecTrust?)
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard method == NSURLAuthenticationMethodServerTrust,
              allowInsecureTLS, let trust else {
            return (.performDefaultHandling, nil)
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let (disposition, credential) = Self.trustDecision(
            method: challenge.protectionSpace.authenticationMethod,
            allowInsecureTLS: allowInsecureTLS,
            trust: challenge.protectionSpace.serverTrust)
        completionHandler(disposition, credential)
    }

    /// True if a cross-host / scheme-downgrade redirect was refused.
    var refused: Bool {
        lock.lock(); defer { lock.unlock() }
        return refusedCrossHost
    }

    /// True if the same-origin redirect chain exceeded 10 hops.
    var tooManyRedirects: Bool {
        lock.lock(); defer { lock.unlock() }
        return exceededHops
    }

    /// True if the body reached `maxBody` and was truncated while streaming.
    var bodyOverflowed: Bool {
        lock.lock(); defer { lock.unlock() }
        return overflowed
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        let targetOrigin = request.url?.hostPort ?? ""
        let targetScheme = request.url?.scheme?.lowercased() ?? ""
        lock.lock()
        // A credential selected for one host and path must not cross a redirect.
        if hasCredential {
            refusedCrossHost = true
            lock.unlock()
            completionHandler(nil)
            return
        }
        if targetOrigin != origin || (originScheme == "https" && targetScheme != "https") {
            refusedCrossHost = true
            lock.unlock()
            completionHandler(nil) // return the redirect response as data
            return
        }
        hops += 1
        if hops >= 10 {
            exceededHops = true
            lock.unlock()
            completionHandler(nil)
            return
        }
        lock.unlock()
        // Follow an uncredentialed same-origin redirect without a downgrade.
        completionHandler(request)
    }
}

// MARK: - Network guard

/// Blocks cloud metadata and link-local addresses. Other private ranges require
/// a credential bound to the host. Public addresses are allowed. Each successful
/// lookup returns the complete validated snapshot that the transport must pin.
struct NetGuard: Sendable {
    /// Injectable address classifier for tests.
    var classify: @Sendable (IPAddr) -> IPClass = NetGuard.classifyIP
    /// Injectable DNS resolver. Defaults to `getaddrinfo`.
    var resolve: @Sendable (String) throws -> [IPAddr] = NetGuard.systemResolve

    /// The AWS IMDS-over-IPv6 endpoint. It lives inside fc00::/7 (which the
    /// private check also matches), so it is classified as metadata *before*
    /// the private check to keep it blocked even for a bound host.
    static let metadataIPv6 = IPAddr(bytes: [
        0xfd, 0x00, 0x0e, 0xc2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x54,
    ])

    /// Maps a resolved IP to its guard category.
    static func classifyIP(_ ip: IPAddr) -> IPClass {
        let ip = ip.unmapped() // collapse IPv4-mapped IPv6 (::ffff:169.254.169.254)
        guard ip.isWellFormed else { return .invalid }

        // Cloud metadata and link-local addresses are always blocked.
        if ip.isLinkLocalUnicast || ip.isLinkLocalMulticast { return .metadata }
        if ip == metadataIPv6 { return .metadata }

        // Other private addresses require a credential-bound host.
        if ip.isLoopback          // 127.0.0.0/8, ::1
            || ip.isPrivate       // RFC1918 (10/8, 172.16/12, 192.168/16) + ULA fc00::/7
            || ip.isUnspecified   // 0.0.0.0, ::
            || ip.isBroadcast {   // 255.255.255.255
            return .privateInternal
        }

        return .publicRoutable
    }

    /// Returns a BlockedError if dialing `ip` is refused, given whether this
    /// request is credential-bound. Metadata is blocked regardless of bound.
    func check(_ ip: IPAddr, bound: Bool) -> BlockedError? {
        switch classify(ip.unmapped()) {
        case .invalid:
            return BlockedError(ip: ip.unmapped().description, reason: "invalid")
        case .metadata:
            return BlockedError(ip: ip.unmapped().description, reason: "metadata")
        case .privateInternal:
            if bound { return nil } // The user explicitly bound a credential here.
            return BlockedError(ip: ip.unmapped().description, reason: "private")
        case .publicRoutable:
            return nil
        }
    }

    /// Resolves `host`, rejects the request if any address is blocked, and
    /// returns one de-duplicated snapshot for connection pinning.
    func validatedAddresses(host: String, bound: Bool) throws -> [IPAddr] {
        let addrs: [IPAddr]
        if let ip = IPAddr(host) {
            addrs = [ip]
        } else {
            addrs = try resolve(host)
        }
        guard !addrs.isEmpty else { throw HTTPExecError.noAddresses(host: host) }
        var snapshot: [IPAddr] = []
        var seen: Set<IPAddr> = []
        for ip in addrs {
            if let blocked = check(ip, bound: bound) { throw blocked }
            let normalized = ip.unmapped()
            if seen.insert(normalized).inserted { snapshot.append(normalized) }
        }
        guard !snapshot.isEmpty else { throw HTTPExecError.noAddresses(host: host) }
        return snapshot
    }

    /// Resolves and validates exactly once for one logical URL load.
    func destination(for url: URL, bound: Bool) throws -> PinnedDestination {
        guard let host = url.host(percentEncoded: false), !host.isEmpty else {
            throw HTTPExecError.badURL(url.absoluteString)
        }
        return try PinnedDestination(url: url,
                                     addresses: validatedAddresses(host: host, bound: bound))
    }

    /// Validation-only compatibility helper for call sites that do not yet dial.
    func validate(host: String, bound: Bool) throws {
        _ = try validatedAddresses(host: host, bound: bound)
    }

    /// getaddrinfo-backed resolver (both address families, TCP).
    static func systemResolve(_ host: String) throws -> [IPAddr] {
        let maxResolvedAddresses = 64
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else {
            throw HTTPExecError.dnsLookupFailed(host: host)
        }
        defer { freeaddrinfo(first) }
        var out: [IPAddr] = []
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let n = node {
            guard out.count < maxResolvedAddresses else {
                throw HTTPExecError.dnsLookupFailed(host: host)
            }
            if let sa = n.pointee.ai_addr {
                switch Int32(sa.pointee.sa_family) {
                case AF_INET where n.pointee.ai_addrlen >= socklen_t(MemoryLayout<sockaddr_in>.size):
                    let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    out.append(IPAddr(bytes: withUnsafeBytes(of: sin.sin_addr) { Array($0) }))
                case AF_INET6 where n.pointee.ai_addrlen >= socklen_t(MemoryLayout<sockaddr_in6>.size):
                    let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                    out.append(IPAddr(bytes: withUnsafeBytes(of: sin6.sin6_addr) { Array($0) }))
                default:
                    break
                }
            }
            node = n.pointee.ai_next
        }
        return out
    }
}

/// Categorizes a resolved destination IP for the guard.
enum IPClass: Sendable, Hashable {
    case invalid          // malformed resolver output; always blocked
    case publicRoutable   // routable internet address; always allowed
    case privateInternal  // loopback, RFC 1918, ULA; allowed when bound
    case metadata         // cloud metadata and link-local; always blocked
}

/// Raw IPv4 or IPv6 address used by the network guard.
struct IPAddr: Sendable, Hashable, CustomStringConvertible {
    let bytes: [UInt8]

    var isWellFormed: Bool { bytes.count == 4 || bytes.count == 16 }

    init(bytes: [UInt8]) { self.bytes = bytes }

    /// Parses a textual IPv4/IPv6 literal; nil when `s` is not an IP literal.
    init?(_ s: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            self.bytes = withUnsafeBytes(of: v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 {
            self.bytes = withUnsafeBytes(of: v6) { Array($0) }
            return
        }
        return nil
    }

    /// Collapses an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form.
    func unmapped() -> IPAddr {
        guard bytes.count == 16,
              bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff
        else { return self }
        return IPAddr(bytes: Array(bytes[12...]))
    }

    /// 169.254.0.0/16 (incl. the 169.254.169.254 metadata address) or fe80::/10.
    var isLinkLocalUnicast: Bool {
        if bytes.count == 4 { return bytes[0] == 169 && bytes[1] == 254 }
        guard bytes.count == 16 else { return false }
        return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
    }

    /// 224.0.0.0/24 or ff_2::/16.
    var isLinkLocalMulticast: Bool {
        if bytes.count == 4 { return bytes[0] == 224 && bytes[1] == 0 && bytes[2] == 0 }
        guard bytes.count == 16 else { return false }
        return bytes[0] == 0xff && (bytes[1] & 0x0f) == 0x02
    }

    /// 127.0.0.0/8 or ::1.
    var isLoopback: Bool {
        if bytes.count == 4 { return bytes[0] == 127 }
        guard bytes.count == 16 else { return false }
        return bytes[0..<15].allSatisfy { $0 == 0 } && bytes[15] == 1
    }

    /// RFC1918 (10/8, 172.16/12, 192.168/16), RFC 6598 CGNAT shared space
    /// (100.64.0.0/10 for carrier NAT and Tailscale), or ULA
    /// fc00::/7.
    var isPrivate: Bool {
        if bytes.count == 4 {
            return bytes[0] == 10
                || (bytes[0] == 172 && (bytes[1] & 0xf0) == 16)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 100 && (bytes[1] & 0xc0) == 64)   // 100.64.0.0/10
        }
        guard bytes.count == 16 else { return false }
        return (bytes[0] & 0xfe) == 0xfc
    }

    /// 0.0.0.0 or ::.
    var isUnspecified: Bool { isWellFormed && bytes.allSatisfy { $0 == 0 } }

    /// The IPv4 limited-broadcast address 255.255.255.255.
    var isBroadcast: Bool { bytes.count == 4 && bytes.allSatisfy { $0 == 255 } }

    var description: String {
        guard isWellFormed else { return "<invalid-ip>" }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if bytes.count == 4 {
            var a = in_addr()
            withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: bytes) }
            _ = inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count))
        } else {
            var a = in6_addr()
            withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: bytes) }
            _ = inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
        }
        return String(decoding: buf.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
                      as: UTF8.self)
    }
}

// MARK: - Shared small helpers

extension URL {
    /// URL host with an explicit port when present.
    var hostPort: String {
        guard let host = host(percentEncoded: false) else { return "" }
        guard let port else { return host }
        return "\(host):\(port)"
    }
}

extension Data {
    /// Attempts an in-place wipe. Copy-on-write data is wiped when uniquely referenced.
    mutating func zeroize() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = memset_s(base, raw.count, 0, raw.count)
        }
    }
}

/// Form-encodes UTF-8 bytes, using `+` for spaces and percent encoding otherwise.
func queryEscape(_ s: String) -> String {
    var out = ""
    for c in Array(s.utf8) {
        switch c {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"),
             UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "~"):
            out.append(Character(UnicodeScalar(c)))
        case UInt8(ascii: " "):
            out.append("+")
        default:
            out += String(format: "%%%02X", c)
        }
    }
    return out
}
