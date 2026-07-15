import Foundation
import SallyportKit

/// Authorizes and executes agent actions.
/// Locked or quarantined vaults deny all actions before reading vault metadata.
/// Per-call requirements take precedence over session approval. Every action is
/// recorded before execution, and returned data is checked for secret values.
public actor Engine {
    private let store: VaultStore
    private let sessions: SessionStore
    private let settings: SettingsStore
    private let audit: AuditLog
    private let http: any ChannelExecutor
    private let ssh: SSHExecuting?
    private let upstreams: UpstreamsStore?
    private let upstreamManager: UpstreamManager?
    private let approver: Approver
    private let identity: String
    /// Optional agent allowlist used at the session gate.
    private let allowlist: Allowlist?
    /// Streams each recorded row to observers (the app's live feed). Set by the host.
    public var onActivity: (@Sendable (AuditEvent) -> Void)?
    /// Handles `sallyport.request_credential`.
    public var credentialPrompter: (any CredentialPrompter)?

    public init(store: VaultStore, sessions: SessionStore, settings: SettingsStore,
                audit: AuditLog, http: any ChannelExecutor = HTTPExecutor(), ssh: SSHExecuting? = nil,
                upstreams: UpstreamsStore? = nil, upstreamManager: UpstreamManager? = nil,
                approver: Approver, allowlist: Allowlist? = nil, identity: String = "agent://local") {
        self.store = store; self.sessions = sessions; self.settings = settings
        self.audit = audit; self.http = http; self.ssh = ssh
        self.upstreams = upstreams; self.upstreamManager = upstreamManager
        self.approver = approver; self.allowlist = allowlist; self.identity = identity
    }

    public func setActivitySink(_ sink: @escaping @Sendable (AuditEvent) -> Void) { onActivity = sink }
    /// Test hook for audit write failures.
    public func closeAuditForTesting() { try? audit.close() }
    public func setCredentialPrompter(_ prompter: any CredentialPrompter) { credentialPrompter = prompter }

    /// Authorizes and runs one action.
    public func invoke(identity rawIdentity: String, action: Action, provenance: Provenance) async -> InvokeResult {
        let id = rawIdentity.isEmpty ? identity : rawIdentity
        let channel = Engine.channel(for: action.tool)
        let origin = provenance.origin

        // Credential requests use the same vault and session gates.
        let isCredentialAsk = action.tool == "sallyport.request_credential"

        // Check vault state before reading any vault metadata.
        let phase = await store.phaseNow()
        if phase != .ready {
            let target: String
            switch action.tool {
            case "http.request": target = Engine.hostPath(action.args["url"]).0
            case "ssh.exec": target = action.args["host"]?.stringValue ?? ""
            default: target = ""
            }
            let (code, reason, rule): (String, String, String) = phase == .quarantined
                ? ("SALLYPORT_QUARANTINED", "Vault data changed. Accept the current state in Sallyport to continue.", "vault.quarantined")
                : ("SALLYPORT_LOCKED", "The vault is locked. Unlock it first.", "vault.locked")
            return await record(id, channel, action, target, "deny", rule, true,
                                origin: origin, chain: provenance.chain,
                                result: .denied(code, reason, rule: rule))
        }
        // Bind authorization to the current vault lifecycle.
        let startEpoch = await store.epoch()

        // Resolve the target and per-call approval requirement.
        var host = ""
        var confirm = ""
        var sshHost: HostRef?
        var upstream: (entry: UpstreamsStore.Entry, tool: String)?
        // Deny if the per-call approval setting cannot be read.
        do {
            switch action.tool {
            case "http.request":
                let (h, p) = Engine.hostPath(action.args["url"])
                host = h
                if let m = try await store.boundMeta(host: h, path: p) { confirm = m.confirm }
            case "ssh.exec":
                let ref = (action.args["host"]?.stringValue) ?? ""
                host = ref
                if let ss = ssh, let hr = ss.host(ref) {
                    sshHost = hr
                    host = hr.addr.isEmpty ? ref : hr.addr
                    if !hr.keyName.isEmpty, let m = try await store.meta(name: hr.keyName) { confirm = m.confirm }
                } else {
                    return await record(id, channel, action, ref, "deny", "ssh.unknown-host", true,
                                        origin: origin, chain: provenance.chain,
                                        result: .denied("SALLYPORT_UNKNOWN_HOST",
                                                        ref.isEmpty
                                                            ? "ssh.exec needs a `host` from the SSH Hosts inventory"
                                                            : "\(ref) is not configured in SSH Hosts. Add it in Sallyport and retry.",
                                                        rule: "ssh.unknown-host"))
                }
            case "sallyport.request_credential":
                break
            default:
                // Resolve the configured MCP server and its strongest requirement.
                if let u = upstreams, let route = u.route(tool: action.tool) {
                    upstream = route
                    host = route.entry.name
                    confirm = try await strictestConfirm(route.entry)
                } else {
                    return await record(id, channel, action, "", "deny", "tool.unknown", true,
                                        origin: origin, chain: provenance.chain,
                                        result: .denied("SALLYPORT_UNKNOWN_TOOL",
                                                        "\(action.tool) is not a built-in tool or an enabled MCP server tool.",
                                                        rule: "tool.unknown"))
                }
            }
        } catch {
            return await record(id, channel, action, host, "deny", "meta.unreadable", true,
                                origin: origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_UNAVAILABLE",
                                                "Could not read the bound key approval setting.",
                                                rule: "meta.unreadable"))
        }

        // Select the approval mode.
        let identifiable = sessions.identifiable(origin)
        let sessionOK = identifiable && sessions.approved(origin)
        let sessionAuthOn = settings.perSessionAuth()

        // Session approval requires an identifiable caller.
        if sessionAuthOn && !identifiable {
            return await record(id, channel, action, host, "deny", "session.unidentifiable", true,
                                origin: origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_UNIDENTIFIABLE",
                                                "Sallyport could not identify the calling process.",
                                                rule: "session.unidentifiable"))
        }

        let sessionReq = sessionAuthOn ? settings.sessionAuth() : ""   // "" | click | touchid
        var askMode = ""
        var rule = "session.observe"
        if sessionOK {
            // Per-call approval still applies to an approved session.
            if !confirm.isEmpty {
                askMode = confirm == "touchid" ? "per-call-touchid" : "per-call"
                rule = "key.per-call"
            } else {
                rule = "session.approved"
            }
        } else if !sessionAuthOn {
            // Observe mode skips only session approval.
            if !confirm.isEmpty {
                askMode = confirm == "touchid" ? "per-call-touchid" : "per-call"
                rule = "key.per-call"
            } else {
                rule = "session.observe"
            }
        } else {
            // The caller needs session approval.
            if !confirm.isEmpty {
                // Use the stronger session or per-call requirement.
                let s = Engine.strongest(sessionReq, confirm)
                askMode = s == "touchid" ? "per-call-touchid" : "per-call"
                rule = "key.per-call"
            } else if let entry = allowlist?.match(pid: origin.pid, startedAt: origin.startedAt, targetHost: host) {
                // Recheck allowlist identity on every call.
                rule = "session.allowlist:\(entry.label)"
            } else {
                askMode = sessionReq == "touchid" ? "session-touchid" : "session"
                rule = "session.gate"
            }
        }

        var decision = askMode.isEmpty ? (sessionOK ? "session-allow"
                                          : (rule.hasPrefix("session.allowlist") ? "allowlist-allow" : "allow"))
                                       : "allow"

        if !askMode.isEmpty {
            let req = EngineApproval(id: Engine.reqID(), mode: askMode, rule: rule,
                                     reason: Engine.reason(askMode), channel: channel, tool: action.tool,
                                     summary: Engine.summarize(action, host: host), host: host,
                                     origin: origin, chain: provenance.chain)
            switch await approver.requestApproval(req).verdict {
            case .approved:
                // Reject approval after a lock or unlock transition.
                if !(await store.lifecycleIsCurrent(startEpoch, phase: .ready)) {
                    return await record(id, channel, action, host, "deny", "vault.locked", true,
                                        origin: origin, chain: provenance.chain,
                                        result: .denied("SALLYPORT_LOCKED",
                                                        "The vault state changed before approval completed.", rule: "vault.locked"))
                }
                switch askMode {
                case "session", "session-touchid": decision = "session-approved"
                default: decision = "call-approved"
                }
            case .denied:
                return await record(id, channel, action, host, "ask→denied", rule, true, origin: origin, chain: provenance.chain,
                                    result: .denied("SALLYPORT_DENIED", "denied by approver", rule: rule))
            case .timedOut, .noApprover:
                return await record(id, channel, action, host, "ask→timeout", rule, true, origin: origin, chain: provenance.chain,
                                    result: InvokeResult(ok: false, errorCode: "SALLYPORT_ASK_TIMEOUT", reason: "no approval within timeout", rule: rule, decision: "ask"))
            }
        }

        // Record intent before changing state or executing the action.
        if !recordIntent(id, channel, action, host, decision, rule, origin: origin, chain: provenance.chain) {
            return .denied("SALLYPORT_UNAVAILABLE", "The audit journal is unavailable.",
                           rule: rule)
        }

        // Commit session state after the intent record.
        switch askMode {
        case "session", "session-touchid": sessions.approve(origin)
        case "per-call", "per-call-touchid": sessions.approveViaCall(origin)
        default: break
        }
        if rule == "session.observe", identifiable { sessions.observe(origin) }
        // Record allowlisted callers without creating standing approval.
        if rule.hasPrefix("session.allowlist") { sessions.observe(origin) }
        if identifiable { sessions.countCall(origin) }

        // Revoke a new session if the vault lifecycle changed during admission.
        if !(await store.lifecycleIsCurrent(startEpoch, phase: .ready)) {
            if let key = SessionStore.sessionKey(origin) { _ = sessions.revoke(key: key) }
            return await record(id, channel, action, host, "deny", "vault.locked", true,
                                origin: origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_LOCKED",
                                                "The vault state changed during admission.",
                                                rule: "vault.locked"))
        }

        // A credential request uses a separate prompt after session approval.
        if isCredentialAsk {
            return await handleCredentialRequest(id: id, action: action, provenance: provenance)
        }

        // Execute under the lifecycle captured at the vault gate.
        do {
            var out = try await execute(action, tool: action.tool, host: host,
                                        sshHost: sshHost, upstream: upstream)
            // Drop output if the vault lifecycle changed during execution.
            if !(await store.lifecycleIsCurrent(startEpoch, phase: .ready)) {
                Engine.zeroize(&out.injected)
                return await record(id, channel, action, host, "deny", "vault.locked", true,
                                    bytesOut: out.bytesOut, recording: out.recording,
                                    hostKeyFp: out.output["host_key_fingerprint"]?.stringValue ?? "",
                                    origin: origin, chain: provenance.chain,
                                    result: .denied("SALLYPORT_LOCKED",
                                                    "The vault locked while the call was running.",
                                                    rule: "vault.locked"))
            }
            // Redact exact injected values and generic credential patterns.
            let (scrubbed, redactions) = Engine.redactOutput(out.output, injected: out.injected)
            Engine.zeroize(&out.injected)
            var result = InvokeResult(ok: true, output: scrubbed, rule: rule, decision: decision)
            if !out.recording.isEmpty { result.output["recording"] = .string(out.recording) }
            return await record(id, channel, action, host, decision, rule, false,
                                bytesOut: out.bytesOut, dlpRedactions: redactions,
                                recording: out.recording,
                                hostKeyFp: out.output["host_key_fingerprint"]?.stringValue ?? "",
                                origin: origin, chain: provenance.chain, result: result)
        } catch let e as BlockedError {
            return await record(id, channel, action, host, decision, rule, true, origin: origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_BLOCKED", Engine.scrubError(e.description), rule: rule))
        } catch {
            // Redact generic credential patterns from returned errors.
            return await record(id, channel, action, host, decision, rule, true, origin: origin, chain: provenance.chain,
                                result: InvokeResult(ok: false, errorCode: "SALLYPORT_UPSTREAM_DOWN", reason: Engine.scrubError("\(error)"), rule: rule, decision: decision))
        }
    }

    // MARK: - Credential request

    private func handleCredentialRequest(id: String, action: Action, provenance: Provenance) async -> InvokeResult {
        // Sanitize agent-controlled fields before showing them in the app.
        let host = Engine.sanitizeHost(action.args["host"]?.stringValue ?? "")
        let purpose = String((action.args["purpose"]?.stringValue ?? "").prefix(300))
        guard !host.isEmpty, !purpose.isEmpty else {
            return await record(id, "mcp", action, host, "deny", "credential.request", true,
                                origin: provenance.origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_BAD_REQUEST",
                                                "request_credential needs a valid `host` and a `purpose`",
                                                rule: "credential.request"))
        }
        var hosts: [String] = []
        if case let .array(items)? = action.args["hosts"] {
            hosts = items.compactMap { $0.stringValue.map(Engine.sanitizeHost) }
                .filter { !$0.isEmpty }
        }
        hosts = Array(hosts.prefix(10))
        var scopes: [String] = []
        if case let .array(items)? = action.args["scopes"] {
            scopes = items.compactMap { $0.stringValue.map { String($0.prefix(60)) } }
        }
        scopes = Array(scopes.prefix(10))
        let kind = ["bearer", "basic", "header"].contains(action.args["kind"]?.stringValue ?? "")
            ? (action.args["kind"]?.stringValue ?? "bearer") : "bearer"
        let ask = CredentialAsk(
            id: Engine.reqID(), host: host, hosts: hosts, purpose: purpose,
            kind: kind,
            header: Engine.sanitizeHeaderName(action.args["header"]?.stringValue ?? ""),
            format: Engine.sanitizeInjectFormat(action.args["format"]?.stringValue ?? "", kind: kind),
            suggestedName: Engine.sanitizeName(action.args["name"]?.stringValue ?? ""),
            docsURL: Engine.sanitizeHTTPSURL(action.args["docs_url"]?.stringValue ?? ""),
            scopes: scopes, origin: provenance.origin, chain: provenance.chain)

        guard let prompter = credentialPrompter else {
            return await record(id, "mcp", action, host, "deny", "credential.request", true,
                                origin: provenance.origin, chain: provenance.chain,
                                result: .denied("SALLYPORT_NO_APPROVER", "Credential prompt unavailable.", rule: "credential.request"))
        }
        let answer = await prompter.requestCredential(ask)
        var output: [String: JSONValue] = ["provisioned": .bool(answer.provisioned)]
        if let name = answer.name, !name.isEmpty { output["name"] = .string(name) }
        output["message"] = .string(answer.provisioned
            ? "Credential added. Retry the request; Sallyport will inject it."
            : "Credential request declined for \(host).")
        let decision = answer.provisioned ? "credential-provisioned" : "credential-declined"
        return await record(id, "mcp", action, host, decision, "credential.request", !answer.provisioned,
                            origin: provenance.origin, chain: provenance.chain,
                            result: InvokeResult(ok: true, output: output,
                                                 rule: "credential.request", decision: decision))
    }

    // MARK: - Execute

    /// Returns the strongest approval requirement for an MCP server and its keys.
    private func strictestConfirm(_ entry: UpstreamsStore.Entry) async throws -> String {
        var flags: [String] = [entry.confirm]
        if entry.transport == UpstreamsStore.Entry.httpTransport {
            if entry.auth != UpstreamsStore.Entry.oauthAuth {
                let (h, p) = Engine.hostPath(.string(entry.url))
                flags.append(try await store.boundMeta(host: h, path: p)?.confirm ?? "")
            }
        } else {
            // Propagate key metadata read failures.
            for binding in entry.keys {
                flags.append(try await store.meta(name: binding.secret)?.confirm ?? "")
            }
        }
        if flags.contains("touchid") { return "touchid" }
        if flags.contains("click") { return "click" }
        return ""
    }

    private func execute(_ action: Action, tool: String, host: String,
                         sshHost: HostRef?, upstream: (entry: UpstreamsStore.Entry, tool: String)?) async throws -> ExecOutput {
        if let upstream {
            guard let manager = upstreamManager else {
                throw EngineError.notConfigured("the upstream MCP channel is unavailable")
            }
            let (output, injected) = try await manager.call(entry: upstream.entry,
                                                            tool: upstream.tool, args: action.args)
            return ExecOutput(output: output, injected: injected)
        }
        switch tool {
        case "http.request":
            // Inject only when both URL parsers resolve the same host.
            let (boundHost, _) = Engine.hostPath(action.args["url"])
            let cred = try await preResolveHTTP(action)
            let resolver: CredResolver = { execHost, _ in
                execHost.lowercased() == boundHost.lowercased() ? cred : nil
            }
            return try await http.execute(action, resolve: resolver)
        case "ssh.exec":
            // A missing executor means the SSH helper is unavailable.
            guard let ss = ssh, let hr = sshHost else {
                throw EngineError.notConfigured("the bundled sp-ssh helper is unavailable")
            }
            var keyPEM = hr.keyName.isEmpty ? Data() : (try? await store.secretValue(name: hr.keyName)) ?? Data()
            // Wipe the decrypted private key after the command.
            defer { if !keyPEM.isEmpty { keyPEM.resetBytes(in: 0..<keyPEM.count) } }
            // Clamp the timeout to the helper's supported range.
            let reqTimeout = min(max(Engine.intArg(action.args["timeout_s"]), 0), 3600)
            return try await ss.execute(host: hr, command: action.args["cmd"]?.stringValue ?? "",
                                        timeoutS: reqTimeout, keyPEM: keyPEM)
        default:
            throw EngineError.notConfigured("tool \(tool) not executable")
        }
    }

    private func preResolveHTTP(_ action: Action) async throws -> Cred? {
        let (h, p) = Engine.hostPath(action.args["url"])
        return try await store.resolve(host: h, path: p)
    }

    // MARK: - Audit + activity

    /// Returns a valid hostname or an empty string.
    static func sanitizeHost(_ raw: String) -> String {
        let h = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !h.isEmpty, h.count <= 253,
              h.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }),
              !h.hasPrefix("."), !h.hasSuffix("."), h.contains(".") else { return "" }
        return h
    }

    /// Returns a valid HTTP header name or an empty string.
    static func sanitizeHeaderName(_ raw: String) -> String {
        let h = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !h.isEmpty, h.count <= 64,
              h.allSatisfy({ $0.isLetter || $0.isNumber || "-_".contains($0) }) else { return "" }
        return h
    }

    /// Validates a bounded inject template containing one `{secret}` placeholder.
    static func sanitizeInjectFormat(_ raw: String, kind: String) -> String {
        let f = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !f.isEmpty, f.count <= 60,
              f.components(separatedBy: "{secret}").count == 2,
              !f.contains(where: { $0.isNewline || $0.asciiValue.map { $0 < 0x20 } ?? false })
        else {
            // Use a safe default for invalid input.
            return kind == "bearer" ? "Bearer {secret}" : "{secret}"
        }
        return f
    }

    /// Returns a normalized vault name of at most 40 characters.
    static func sanitizeName(_ raw: String) -> String {
        String(raw.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }.prefix(40))
    }

    /// Returns a bounded HTTPS URL or an empty string.
    static func sanitizeHTTPSURL(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.count <= 200, let u = URL(string: s), u.scheme == "https",
              let host = u.host, !host.isEmpty else { return "" }
        return s
    }

    /// Redacts exact secrets and generic credential patterns from tool output.
    static func redactOutput(_ output: [String: JSONValue], injected: [Data]) -> ([String: JSONValue], Int) {
        var total = 0
        // Scrub exact values before generic patterns.
        func scrubString(_ s: String) -> String {
            var data = Data(s.utf8)
            if !injected.isEmpty {
                let (r, n) = DLP.redactWith(data, secrets: injected)
                data = r; total += n
            }
            let (r2, n2) = DLP.redact(data)
            total += n2
            return String(decoding: r2, as: UTF8.self)
        }
        // Redact object keys and preserve values after a key collision.
        func scrub(_ v: JSONValue) -> JSONValue {
            switch v {
            case .string(let s): return .string(scrubString(s))
            case .array(let a): return .array(a.map(scrub))
            case .object(let o):
                var out: [String: JSONValue] = [:]
                for (k, val) in o {
                    var key = scrubString(k)
                    if out[key] != nil { key += "~\(out.count)" }
                    out[key] = scrub(val)
                }
                return .object(out)
            default: return v
            }
        }
        return (scrub(.object(output)).objectValue ?? output, total)
    }

    /// Redacts generic credential patterns from an error string.
    static func scrubError(_ text: String) -> String {
        let (out, _) = DLP.redact(Data(text.utf8))
        return String(decoding: out, as: UTF8.self)
    }

    /// Wipes injected secret copies.
    static func zeroize(_ secrets: inout [Data]) {
        for i in secrets.indices where !secrets[i].isEmpty {
            secrets[i].resetBytes(in: 0..<secrets[i].count)
        }
        secrets.removeAll()
    }

    /// Records intent before execution. This row is not sent to the live feed.
    private func recordIntent(_ identity: String, _ channel: String, _ action: Action, _ target: String,
                              _ decision: String, _ rule: String,
                              origin: Origin, chain: [Hop]) -> Bool {
        var ev = AuditEvent(identity: identity, channel: channel, tool: action.tool, target: target,
                            argsPreview: Engine.preview(action), decision: decision + ".start", rule: rule,
                            isError: false)
        ev.session = SessionStore.sessionKey(origin) ?? ""
        ev.origin = AuditEvent.Origin(name: origin.name, path: origin.path, app: origin.appName,
                                      pid: origin.pid, signed: origin.validSignature,
                                      signedBy: origin.signedBy, chain: chain.map { $0.name }.joined(separator: " → "))
        return (try? audit.append(ev)) != nil
    }

    @discardableResult
    private func record(_ identity: String, _ channel: String, _ action: Action, _ target: String,
                        _ decision: String, _ rule: String, _ isError: Bool,
                        bytesOut: Int = 0, dlpRedactions: Int = 0, recording: String = "",
                        hostKeyFp: String = "",
                        origin: Origin, chain: [Hop], result: InvokeResult) async -> InvokeResult {
        var ev = AuditEvent(identity: identity, channel: channel, tool: action.tool, target: target,
                            argsPreview: Engine.preview(action), decision: decision, rule: rule,
                            isError: isError, bytesOut: bytesOut, dlpRedactions: dlpRedactions,
                            recording: recording, hostKeyFp: hostKeyFp)
        ev.session = SessionStore.sessionKey(origin) ?? ""
        ev.origin = AuditEvent.Origin(name: origin.name, path: origin.path, app: origin.appName,
                                      pid: origin.pid, signed: origin.validSignature,
                                      signedBy: origin.signedBy, chain: chain.map { $0.name }.joined(separator: " → "))
        if let written = try? audit.append(ev) {
            onActivity?(written)
        } else if result.ok {
            // Do not return success when the completion row cannot be written.
            return InvokeResult(
                ok: false,
                errorCode: "SALLYPORT_UNAVAILABLE",
                reason: "The action may have completed, but its audit outcome could not be written. Do not retry automatically.",
                rule: rule,
                decision: decision)
        }
        return result
    }
}

public enum EngineError: Error, Sendable { case notConfigured(String) }
