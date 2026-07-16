import Foundation
import CFNetwork
import Network
import Security

/// A DNS result that has already passed `NetGuard`. The address set is scoped to
/// one logical request; it is never cached or reused by a later request.
struct PinnedDestination: Sendable, Hashable {
    let host: String
    let port: UInt16
    let addresses: [IPAddr]

    init(url: URL, addresses: [IPAddr]) throws {
        guard let host = url.host(percentEncoded: false), !host.isEmpty else {
            throw HTTPExecError.badURL(url.absoluteString)
        }
        let rawPort: Int
        if let explicit = url.port {
            rawPort = explicit
        } else {
            switch url.scheme?.lowercased() {
            case "http": rawPort = 80
            case "https": rawPort = 443
            default: throw HTTPExecError.unsupportedScheme(url.scheme ?? "")
            }
        }
        guard (1...Int(UInt16.max)).contains(rawPort), !addresses.isEmpty else {
            throw HTTPExecError.badURL(url.absoluteString)
        }
        self.host = Self.canonicalHost(host)
        self.port = UInt16(rawPort)
        self.addresses = addresses
    }

    static func canonicalHost(_ host: String) -> String {
        var normalized = host.lowercased()
        while normalized.last == "." { normalized.removeLast() }
        return normalized
    }

    func allows(host candidate: String, port candidatePort: UInt16) -> Bool {
        candidatePort == port && Self.canonicalHost(candidate) == host
    }

    func allows(address: IPAddr, port candidatePort: UInt16) -> Bool {
        candidatePort == port && addresses.contains(address.unmapped())
    }

    /// The request and its pin must describe the same authority. This is
    /// rechecked at the transport boundary so a future caller cannot pair a
    /// credential-bearing request with some other host's shared-IP snapshot.
    func allows(url: URL) -> Bool {
        guard let candidate = try? PinnedDestination(url: url, addresses: addresses) else {
            return false
        }
        return candidate.host == host && candidate.port == port
    }
}

enum PinnedTransportError: Error, Sendable, Equatable, CustomStringConvertible {
    case unavailable
    case proxyAuthentication
    case destinationRefused
    case connectionFailed

    var description: String {
        switch self {
        case .unavailable: return "pinned transport is unavailable"
        case .proxyAuthentication: return "pinned transport authentication failed"
        case .destinationRefused: return "pinned transport refused an unvalidated destination"
        case .connectionFailed: return "no validated destination address was reachable"
        }
    }
}

/// Runs one URLSession load through an authenticated, loopback-only SOCKS5
/// tunnel. URLSession continues to see the original URL, so Host, TLS SNI,
/// certificate hostname validation, HTTP/2, and task-level trust handling are
/// unchanged. The tunnel itself can dial only the supplied numeric DNS snapshot.
final class PinnedHTTPTransport: @unchecked Sendable {
    typealias ProxyReadyHook = @Sendable (PinnedSOCKSProxy) -> Void

    private let configuration: URLSessionConfiguration
    private let proxyReadyHook: ProxyReadyHook
    private let lock = NSLock()
    private var active: [UUID: ActivePinnedLoad] = [:]
    private var closed = false

    init(configuration: URLSessionConfiguration = .ephemeral,
         proxyReadyHook: @escaping ProxyReadyHook = { _ in }) {
        self.configuration = configuration.copy() as! URLSessionConfiguration
        self.proxyReadyHook = proxyReadyHook
    }

    func loadCapped(request: URLRequest, destination: PinnedDestination,
                    policy: RedirectPolicy,
                    hardTimeout: TimeInterval) async throws -> (Data, HTTPURLResponse) {
        guard let requestURL = request.url, destination.allows(url: requestURL) else {
            throw PinnedTransportError.destinationRefused
        }
        let id = UUID()
        let load = ActivePinnedLoad()
        try lock.withLock {
            guard !closed else { throw PinnedTransportError.unavailable }
            active[id] = load
        }
        defer {
            _ = lock.withLock { active.removeValue(forKey: id) }
            load.cancel()
        }
        try Task.checkCancellation()

        let proxy = try await PinnedSOCKSProxy.start(destination: destination)
        try load.attach(proxy: proxy)
        proxyReadyHook(proxy)

        let config = configuration.copy() as! URLSessionConfiguration
        // Force even localhost, IP literals, and simple hostnames through the
        // request-scoped proxy. CFNetwork otherwise bypasses proxies for local
        // authorities before `allowFailover` is consulted.
        config.connectionProxyDictionary = [
            kCFNetworkProxiesSOCKSEnable as String: true,
            kCFNetworkProxiesSOCKSProxy as String: "127.0.0.1",
            kCFNetworkProxiesSOCKSPort as String: Int(proxy.port.rawValue),
            kCFNetworkProxiesExcludeSimpleHostnames as String: false,
            kCFNetworkProxiesExceptionsList as String: [],
        ]
        var proxyConfig = ProxyConfiguration(socksv5Proxy: .hostPort(
            host: .ipv4(IPv4Address("127.0.0.1")!), port: proxy.port))
        proxyConfig.applyCredential(username: proxy.username, password: proxy.password)
        proxyConfig.allowFailover = false
        proxyConfig.matchDomains = [destination.host]
        config.proxyConfigurations = [proxyConfig]

        let session = URLSession(configuration: config)
        try load.attach(session: session)
        return try await policy.loadCapped(request: request, session: session,
                                           hardTimeout: hardTimeout)
    }

    /// Permanently closes this owner-scoped transport. Active URLSession tasks,
    /// SOCKS tunnels, and raced outbound dials are cancelled synchronously;
    /// future loads fail before registration. Remote MCP uses this on vault
    /// lock/revocation to close the check-then-load race.
    func shutdown() {
        let loads: [ActivePinnedLoad] = lock.withLock {
            guard !closed else { return [] }
            closed = true
            let current = Array(active.values)
            active.removeAll()
            return current
        }
        for load in loads { load.cancel() }
    }

    /// Cancels current requests but leaves a shared transport reusable.
    func cancelActive() {
        let loads = lock.withLock { Array(active.values) }
        for load in loads { load.cancel() }
    }
}

private final class ActivePinnedLoad: @unchecked Sendable {
    private let lock = NSLock()
    private var proxy: PinnedSOCKSProxy?
    private var session: URLSession?
    private var cancelled = false

    func attach(proxy: PinnedSOCKSProxy) throws {
        let accepted = lock.withLock {
            guard !cancelled else { return false }
            self.proxy = proxy
            return true
        }
        guard accepted else {
            proxy.stop()
            throw CancellationError()
        }
        proxy.setStopHandler { [weak self] in self?.cancel() }
    }

    func attach(session: URLSession) throws {
        let accepted = lock.withLock {
            guard !cancelled else { return false }
            self.session = session
            return true
        }
        guard accepted else {
            session.invalidateAndCancel()
            throw CancellationError()
        }
    }

    func cancel() {
        let resources: (PinnedSOCKSProxy?, URLSession?) = lock.withLock {
            guard !cancelled else { return (nil, nil) }
            cancelled = true
            let resources = (proxy, session)
            proxy = nil
            session = nil
            return resources
        }
        resources.1?.invalidateAndCancel()
        resources.0?.setStopHandler(nil)
        resources.0?.stop()
    }
}

// MARK: - Capability-authenticated, destination-restricted SOCKS5 proxy

/// One request-scoped SOCKS5 listener. A random capability keeps other local
/// processes from racing URLSession for the ephemeral listener. Even an
/// authenticated client can request only the original host/port or an exact IP
/// member of the validated snapshot.
final class PinnedSOCKSProxy: @unchecked Sendable {
    private static let maxClients = 8
    private let destination: PinnedDestination
    let username: String
    let password: String
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.sallyport.pinned-socks")
    private let queueKey = DispatchSpecificKey<Bool>()
    private let lock = NSLock()
    private var clients: [ObjectIdentifier: SOCKSClient] = [:]
    private var stopHandler: (@Sendable () -> Void)?
    private var stopped = false

    var port: NWEndpoint.Port {
        listener.port! // available only after `start` returns from `.ready`
    }

    var activeClientCount: Int { lock.withLock { clients.count } }
    var isStopped: Bool { lock.withLock { stopped } }

    func setStopHandler(_ handler: (@Sendable () -> Void)?) {
        let invokeNow = lock.withLock { () -> Bool in
            guard !stopped else { return handler != nil }
            stopHandler = handler
            return false
        }
        if invokeNow { handler?() }
    }

    private init(destination: PinnedDestination) throws {
        self.destination = destination
        self.username = try Self.randomCapability()
        self.password = try Self.randomCapability()

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(
            host: .ipv4(IPv4Address("127.0.0.1")!), port: .any)
        self.listener = try NWListener(using: parameters)
        queue.setSpecific(key: queueKey, value: true)
    }

    static func start(destination: PinnedDestination) async throws -> PinnedSOCKSProxy {
        let proxy = try PinnedSOCKSProxy(destination: destination)
        try await proxy.startListening()
        return proxy
    }

    private func startListening() async throws {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                let resumed = LockedFlag()
                listener.stateUpdateHandler = { [weak self] state in
                    switch state {
                    case .ready:
                        if resumed.take() { continuation.resume() }
                    case .failed(let error):
                        if resumed.take() { continuation.resume(throwing: error) }
                        self?.stop()
                    case .cancelled:
                        if resumed.take() {
                            continuation.resume(throwing: PinnedTransportError.unavailable)
                        }
                    default:
                        break
                    }
                }
                listener.newConnectionHandler = { [weak self] connection in
                    self?.accept(connection)
                }
                listener.start(queue: queue)
            }
        }, onCancel: { self.stop() })
    }

    private func accept(_ connection: NWConnection) {
        let hasCapacity = lock.withLock { !stopped && clients.count < Self.maxClients }
        guard hasCapacity else { connection.cancel(); return }
        let client = SOCKSClient(connection: connection, destination: destination,
                                 username: username, password: password,
                                 queue: queue,
                                 authenticatedFailure: { [weak self] in self?.stop() }) {
            [weak self] id in
            _ = self?.lock.withLock { self?.clients.removeValue(forKey: id) }
        }
        lock.withLock {
            guard !stopped, clients.count < Self.maxClients else {
                connection.cancel()
                return
            }
            clients[ObjectIdentifier(client)] = client
            client.start()
        }
    }

    func stop() {
        let state: ([SOCKSClient], (@Sendable () -> Void)?) = lock.withLock {
            guard !stopped else { return ([], nil) }
            stopped = true
            let current = Array(clients.values)
            clients.removeAll()
            let handler = stopHandler
            stopHandler = nil
            return (current, handler)
        }
        // Cancel the owner URLSession before tearing down the proxy connection;
        // CFNetwork has otherwise been observed replaying directly despite
        // `allowFailover = false` for local/private destinations.
        state.1?()
        listener.cancel()
        let cancelClients = { for client in state.0 { client.stop() } }
        if DispatchQueue.getSpecific(key: queueKey) == true {
            cancelClients()
        } else {
            queue.sync(execute: cancelClients)
        }
    }

    private static func randomCapability() throws -> String {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, raw.count, base)
        }
        guard status == errSecSuccess else { throw PinnedTransportError.unavailable }
        return bytes.base64EncodedString()
    }
}

/// A one-shot boolean used to resume an async continuation exactly once from
/// Network.framework state callbacks.
private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var available = true
    func take() -> Bool {
        lock.withLock {
            guard available else { return false }
            available = false
            return true
        }
    }
}

final class SOCKSClient: @unchecked Sendable {
    private enum State {
        case greeting
        case authentication
        case request
        case dialing
        case tunnel
        case closed
    }

    private let connection: NWConnection
    private let destination: PinnedDestination
    private let username: Data
    private let password: Data
    private let queue: DispatchQueue
    private let authenticatedFailure: @Sendable () -> Void
    private let onClose: @Sendable (ObjectIdentifier) -> Void
    private var state: State = .greeting
    private var buffer = Data()
    private var outbound: NWConnection?
    private var race: PinnedDialRace?
    private var handshakeDeadline: DispatchWorkItem?
    private var closed = false

    init(connection: NWConnection, destination: PinnedDestination,
         username: String, password: String, queue: DispatchQueue,
         authenticatedFailure: @escaping @Sendable () -> Void,
         onClose: @escaping @Sendable (ObjectIdentifier) -> Void) {
        self.connection = connection
        self.destination = destination
        self.username = Data(username.utf8)
        self.password = Data(password.utf8)
        self.queue = queue
        self.authenticatedFailure = authenticatedFailure
        self.onClose = onClose
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.receiveHandshake()
            case .failed, .cancelled: self?.stop()
            default: break
            }
        }
        connection.start(queue: queue)
        // An unauthenticated local client cannot occupy one of the bounded
        // listener slots indefinitely.
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, self.state != .tunnel else { return }
            self.stop()
        }
        handshakeDeadline = deadline
        queue.asyncAfter(deadline: .now() + 2, execute: deadline)
    }

    func stop() {
        guard !closed else { return }
        closed = true
        state = .closed
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
        race?.cancel()
        race = nil
        connection.cancel()
        outbound?.cancel()
        outbound = nil
        onClose(ObjectIdentifier(self))
    }

    private func receiveHandshake() {
        guard !closed, state != .tunnel else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, complete, error in
            guard let self else { return }
            if let data { self.buffer.append(data) }
            // SOCKS greeting + username/password + CONNECT target is bounded by
            // the protocol's one-byte lengths; 1 KiB leaves ample headroom.
            if self.buffer.count > 1_024 { self.stop(); return }
            if error != nil || complete { self.stop(); return }
            self.processHandshake()
            if !self.closed, self.state != .dialing, self.state != .tunnel {
                self.receiveHandshake()
            }
        }
    }

    private func processHandshake() {
        var madeProgress = true
        while madeProgress, !closed {
            madeProgress = false
            switch state {
            case .greeting:
                guard buffer.count >= 2 else { return }
                let bytes = [UInt8](buffer)
                let count = Int(bytes[1])
                guard buffer.count >= 2 + count else { return }
                let version = bytes[0]
                let methods = bytes[2..<(2 + count)]
                buffer = Data(bytes.dropFirst(2 + count))
                guard version == 0x05, methods.contains(0x02) else {
                    send(Data([0x05, 0xff]), closeAfter: true)
                    return
                }
                state = .authentication
                send(Data([0x05, 0x02]))
                madeProgress = true

            case .authentication:
                guard buffer.count >= 2 else { return }
                let bytes = [UInt8](buffer)
                let userCount = Int(bytes[1])
                guard buffer.count >= 2 + userCount + 1 else { return }
                let passCount = Int(bytes[2 + userCount])
                let total = 3 + userCount + passCount
                guard buffer.count >= total else { return }
                let version = bytes[0]
                let suppliedUser = Data(bytes[2..<(2 + userCount)])
                let suppliedPass = Data(bytes[(3 + userCount)..<total])
                buffer = Data(bytes.dropFirst(total))
                guard version == 0x01,
                      Self.constantTimeEqual(suppliedUser, username),
                      Self.constantTimeEqual(suppliedPass, password) else {
                    send(Data([0x01, 0x01]), closeAfter: true)
                    return
                }
                state = .request
                send(Data([0x01, 0x00]))
                madeProgress = true

            case .request:
                guard let request = parseRequest() else { return }
                guard request.command == 0x01, request.port == destination.port,
                      request.allowed(by: destination) else {
                    authenticatedFailure()
                    return
                }
                state = .dialing
                dialValidatedAddresses()

            case .dialing, .tunnel, .closed:
                return
            }
        }
    }

    private struct Request {
        let command: UInt8
        let host: String?
        let address: IPAddr?
        let port: UInt16

        func allowed(by destination: PinnedDestination) -> Bool {
            if let host { return destination.allows(host: host, port: port) }
            if let address { return destination.allows(address: address, port: port) }
            return false
        }
    }

    private func parseRequest() -> Request? {
        guard buffer.count >= 4 else { return nil }
        let bytes = [UInt8](buffer)
        guard bytes[0] == 0x05, bytes[2] == 0 else {
            send(Self.reply(code: 0x01), closeAfter: true)
            return nil
        }
        let command = bytes[1]
        let addressEnd: Int
        let host: String?
        let address: IPAddr?
        switch bytes[3] {
        case 0x01:
            addressEnd = 8
            guard bytes.count >= addressEnd + 2 else { return nil }
            host = nil
            address = IPAddr(bytes: Array(bytes[4..<8])).unmapped()
        case 0x04:
            addressEnd = 20
            guard bytes.count >= addressEnd + 2 else { return nil }
            host = nil
            address = IPAddr(bytes: Array(bytes[4..<20])).unmapped()
        case 0x03:
            guard bytes.count >= 5 else { return nil }
            let count = Int(bytes[4])
            addressEnd = 5 + count
            guard count > 0, bytes.count >= addressEnd + 2,
                  let decoded = String(bytes: bytes[5..<addressEnd], encoding: .utf8) else {
                send(Self.reply(code: 0x08), closeAfter: true)
                return nil
            }
            host = decoded
            address = nil
        default:
            send(Self.reply(code: 0x08), closeAfter: true)
            return nil
        }
        let port = UInt16(bytes[addressEnd]) << 8 | UInt16(bytes[addressEnd + 1])
        buffer = Data(bytes.dropFirst(addressEnd + 2))
        return Request(command: command, host: host, address: address, port: port)
    }

    private func dialValidatedAddresses() {
        // The capability and destination are now authenticated. From here the
        // logical request timeout and per-address dial deadline govern; the
        // short unauthenticated-client timer must not kill valid failover.
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
        let race = PinnedDialRace(addresses: destination.addresses, port: destination.port,
                                  queue: queue) { [weak self] winner in
            guard let self, !self.closed else { winner?.cancel(); return }
            self.race = nil
            guard let winner else {
                // Do not let CFNetwork reinterpret a SOCKS refusal as permission
                // to replay directly. Failing the validated set kills the whole
                // request-scoped proxy, which cancels its owner URLSession.
                self.authenticatedFailure()
                return
            }
            self.outbound = winner
            self.state = .tunnel
            self.send(Self.reply(code: 0x00)) { [weak self] in
                self?.startTunnel()
            }
        }
        self.race = race
        race.start()
    }

    private func startTunnel() {
        guard let outbound, !closed else { stop(); return }
        if !buffer.isEmpty {
            let pending = buffer
            buffer.removeAll(keepingCapacity: false)
            outbound.send(content: pending, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if error != nil { self.stop(); return }
                self.relay(from: self.connection, to: outbound)
            })
        } else {
            relay(from: connection, to: outbound)
        }
        relay(from: outbound, to: connection)
    }

    private func relay(from source: NWConnection, to destination: NWConnection) {
        guard !closed else { return }
        source.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                destination.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    guard let self else { return }
                    if sendError != nil || complete || error != nil {
                        self.stop()
                    } else {
                        self.relay(from: source, to: destination)
                    }
                })
            } else if complete || error != nil {
                self.stop()
            } else {
                self.relay(from: source, to: destination)
            }
        }
    }

    private func send(_ data: Data, closeAfter: Bool = false,
                      completion: (@Sendable () -> Void)? = nil) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil || closeAfter {
                self.stop()
            } else {
                completion?()
            }
        })
    }

    private static func reply(code: UInt8) -> Data {
        // IPv4 0.0.0.0:0 is a valid, deliberately non-informative BND address.
        Data([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    }

    static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        let maxCount = max(lhs.count, rhs.count)
        var difference = UInt8(truncatingIfNeeded: lhs.count ^ rhs.count)
        for index in 0..<maxCount {
            let a = index < lhs.count ? lhs[lhs.startIndex + index] : 0
            let b = index < rhs.count ? rhs[rhs.startIndex + index] : 0
            difference |= a ^ b
        }
        return difference == 0
    }
}

/// Races every address in one validated A/AAAA snapshot. Only a numeric
/// `NWEndpoint.Host.ipv4/ipv6` is ever handed to Network.framework, so this path
/// cannot trigger another DNS lookup. The first ready connection wins and all
/// losers are cancelled before the winner is exposed.
struct PinnedDialScheduler: Sendable {
    static let maxConcurrent = 2

    private(set) var pending: [IPAddr]
    private(set) var active: Set<Int> = []
    private var nextTicket = 0

    init(addresses: [IPAddr]) {
        self.pending = PinnedDialRace.happyEyeballsOrder(addresses)
    }

    mutating func takeNext() -> (ticket: Int, address: IPAddr)? {
        guard active.count < Self.maxConcurrent, !pending.isEmpty else { return nil }
        let ticket = nextTicket
        nextTicket += 1
        active.insert(ticket)
        return (ticket, pending.removeFirst())
    }

    mutating func completed(ticket: Int) { active.remove(ticket) }
}

final class PinnedDialRace: @unchecked Sendable {
    static let stagger: DispatchTimeInterval = .milliseconds(250)
    static let attemptDeadline: DispatchTimeInterval = .seconds(5)

    private var scheduler: PinnedDialScheduler
    private let port: NWEndpoint.Port
    private let queue: DispatchQueue
    private let completion: @Sendable (NWConnection?) -> Void
    private var active: [Int: NWConnection] = [:]
    private var attemptDeadlines: [Int: DispatchWorkItem] = [:]
    private var staggerWork: DispatchWorkItem?
    private var finished = false

    init(addresses: [IPAddr], port: UInt16, queue: DispatchQueue,
         completion: @escaping @Sendable (NWConnection?) -> Void) {
        self.scheduler = PinnedDialScheduler(addresses: addresses)
        self.port = NWEndpoint.Port(rawValue: port)!
        self.queue = queue
        self.completion = completion
    }

    func start() {
        guard !scheduler.pending.isEmpty else { finish(winner: nil); return }
        startNext()
        scheduleStagger()
    }

    func cancel() { finish(winner: nil, notify: false) }

    private func finish(winner: NWConnection?, notify: Bool = true) {
        guard !finished else { return }
        finished = true
        staggerWork?.cancel()
        staggerWork = nil
        for deadline in attemptDeadlines.values { deadline.cancel() }
        attemptDeadlines.removeAll()
        for connection in active.values where connection !== winner { connection.cancel() }
        active = winner.map { [-1: $0] } ?? [:]
        if notify { completion(winner) }
    }

    private func startNext() {
        guard !finished else { return }
        while let next = scheduler.takeNext() {
            let ticket = next.ticket
            guard let host = Self.numericHost(next.address) else {
                scheduler.completed(ticket: ticket)
                continue
            }
            let connection = NWConnection(to: .hostPort(host: host, port: port), using: .tcp)
            active[ticket] = connection
            connection.stateUpdateHandler = { [weak self, weak connection] state in
                guard let self, let connection, !self.finished else { return }
                switch state {
                case .ready:
                    guard self.active[ticket] === connection else {
                        connection.cancel()
                        return
                    }
                    self.attemptDeadlines.removeValue(forKey: ticket)?.cancel()
                    self.finish(winner: connection)
                case .failed, .cancelled:
                    self.attemptFailed(ticket: ticket, connection: connection,
                                       cancelConnection: false)
                default:
                    break
                }
            }
            connection.start(queue: queue)
            let deadline = DispatchWorkItem { [weak self, weak connection] in
                guard let self, let connection else { return }
                self.attemptFailed(ticket: ticket, connection: connection,
                                   cancelConnection: true)
            }
            attemptDeadlines[ticket] = deadline
            queue.asyncAfter(deadline: .now() + Self.attemptDeadline, execute: deadline)
            return
        }
        if active.isEmpty { finish(winner: nil) }
    }

    private func attemptFailed(ticket: Int, connection: NWConnection,
                               cancelConnection: Bool) {
        guard !finished, active.removeValue(forKey: ticket) != nil else { return }
        attemptDeadlines.removeValue(forKey: ticket)?.cancel()
        scheduler.completed(ticket: ticket)
        if cancelConnection { connection.cancel() }
        // A fast failure or per-address timeout advances immediately; otherwise
        // the 250 ms stagger opens the second family/next address.
        startNext()
        if active.isEmpty, scheduler.pending.isEmpty {
            finish(winner: nil)
        } else {
            scheduleStagger()
        }
    }

    private func scheduleStagger() {
        guard !finished, !scheduler.pending.isEmpty,
              scheduler.active.count < PinnedDialScheduler.maxConcurrent,
              staggerWork == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.staggerWork = nil
            self.startNext()
            self.scheduleStagger()
        }
        staggerWork = work
        queue.asyncAfter(deadline: .now() + Self.stagger, execute: work)
    }

    /// Interleaves address families while preserving resolver order inside each
    /// family. The family of the resolver's first answer keeps first attempt.
    static func happyEyeballsOrder(_ addresses: [IPAddr]) -> [IPAddr] {
        guard let first = addresses.first else { return [] }
        var v4 = addresses.filter { $0.unmapped().bytes.count == 4 }
        var v6 = addresses.filter { $0.unmapped().bytes.count == 16 }
        var out: [IPAddr] = []
        let startsV4 = first.unmapped().bytes.count == 4
        while !v4.isEmpty || !v6.isEmpty {
            if startsV4 {
                if !v4.isEmpty { out.append(v4.removeFirst()) }
                if !v6.isEmpty { out.append(v6.removeFirst()) }
            } else {
                if !v6.isEmpty { out.append(v6.removeFirst()) }
                if !v4.isEmpty { out.append(v4.removeFirst()) }
            }
        }
        return out
    }

    private static func numericHost(_ address: IPAddr) -> NWEndpoint.Host? {
        let address = address.unmapped()
        if address.bytes.count == 4, let value = IPv4Address(Data(address.bytes)) {
            return .ipv4(value)
        }
        if address.bytes.count == 16, let value = IPv6Address(Data(address.bytes)) {
            return .ipv6(value)
        }
        return nil
    }
}
