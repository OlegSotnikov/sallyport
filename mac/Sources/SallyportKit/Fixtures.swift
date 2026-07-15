import Foundation

/// Shared preview, demo, and test data.
public enum Fixtures {

    // MARK: Process hops

    public static let hopClaudeCode = ProcessHop(
        pid: 4321, name: "claude", path: "/Applications/Claude.app/Contents/MacOS/claude",
        ppid: 4200, appName: "Claude Code", validSignature: true,
        signedBy: "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)")
    public static let hopNode = ProcessHop(
        pid: 4200, name: "node", path: "/usr/local/bin/node",
        ppid: 3990, appName: nil, validSignature: true)
    public static let hopZsh = ProcessHop(
        pid: 3990, name: "zsh", path: "/bin/zsh",
        ppid: 3001, appName: nil, validSignature: true)
    public static let hopTerminal = ProcessHop(
        pid: 3001, name: "Terminal", path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        ppid: 1, appName: "Terminal", validSignature: true)

    /// Fully signed process chain.
    public static let signedChain: [ProcessHop] = [hopClaudeCode, hopNode, hopZsh, hopTerminal]

    /// Process chain with an unsigned intermediate.
    public static let tamperedChain: [ProcessHop] = [
        hopClaudeCode,
        ProcessHop(pid: 4200, name: "node", path: "/tmp/.x/node", ppid: 3990,
                   appName: nil, validSignature: false),
        hopZsh, hopTerminal,
    ]

    public static let provenanceIntact = Provenance(
        origin: hopClaudeCode, chain: signedChain, intact: true)
    public static let provenanceTampered = Provenance(
        origin: hopClaudeCode, chain: tamperedChain, intact: false)

    // MARK: Approval requests

    /// SSH mutation fixture with a highlighted command verb.
    public static let sshRestartNginx = ApprovalRequest(
        id: "req-7f3a",
        action: ActionDescriptor(
            channel: "ssh",
            tool: "ssh.exec",
            summary: "systemctl restart nginx",
            host: "203.0.113.10",
            argsPreview: .object(["host": .string("web-prod-1"),
                                  "command": .string("systemctl restart nginx")]),
            bodyPreview: "systemctl restart nginx",
            dangerTokens: ["restart"]),
        why: WhyDescriptor(rule: "ssh-write-ask", reason: "class=write · session recorded"),
        provenance: provenanceIntact)

    /// HTTP mutation fixture with a highlighted method.
    public static let httpCloudflareDNS = ApprovalRequest(
        id: "req-9c02",
        action: ActionDescriptor(
            channel: "http",
            tool: "http.request",
            summary: "POST https://api.cloudflare.com/client/v4/zones/…/dns_records (mutating)",
            host: "api.cloudflare.com",
            argsPreview: .object(["method": .string("POST"),
                                  "path": .string("/client/v4/zones/abc/dns_records")]),
            bodyPreview: #"{"type":"A","name":"gse.kz","content":"1.2.3.4"}"#,
            dangerTokens: ["POST"]),
        why: WhyDescriptor(rule: "http-mutating", reason: "bound credential: cloudflare"),
        provenance: provenanceIntact)

    /// Session approval from a signed caller.
    public static let sessionClaude = ApprovalRequest(
        id: "req-sess1",
        action: ActionDescriptor(
            channel: "http", tool: "http.request",
            summary: "GET https://api.cloudflare.com/client/v4/zones",
            host: "api.cloudflare.com",
            argsPreview: .object(["method": .string("GET"),
                                  "path": .string("/client/v4/zones")]),
            dangerTokens: []),
        why: WhyDescriptor(rule: "http-get-bound", reason: "first call from this agent this session"),
        provenance: provenanceIntact,
        mode: "session")

    /// Session approval triggered by a credential request.
    public static let sessionCredential = ApprovalRequest(
        id: "req-cred1",
        action: ActionDescriptor(
            channel: "mcp", tool: "sallyport.request_credential",
            summary: "Add a key for api.cloudflare.com",
            host: "api.cloudflare.com",
            argsPreview: nil,
            dangerTokens: []),
        why: WhyDescriptor(rule: "session.gate",
                           reason: "Approve this agent for the current session."),
        provenance: provenanceIntact,
        mode: "session")

    /// Session approval from an unsigned executable.
    public static let sessionUnsigned = ApprovalRequest(
        id: "req-sess2",
        action: ActionDescriptor(
            channel: "http", tool: "http.request",
            summary: "GET https://api.stripe.com/v1/charges",
            host: "api.stripe.com",
            argsPreview: .object(["method": .string("GET")]),
            dangerTokens: []),
        why: WhyDescriptor(rule: "http-get-bound", reason: "first call from this agent this session"),
        provenance: Provenance(
            origin: ProcessHop(pid: 5150, name: "python3.13", path: "/tmp/.cache/run.py",
                               ppid: 5000, appName: nil, validSignature: false, signedBy: nil),
            chain: [
                ProcessHop(pid: 5150, name: "python3.13", path: "/tmp/.cache/run.py", ppid: 5000,
                           appName: nil, validSignature: false),
                hopZsh, hopTerminal,
            ],
            intact: false),
        mode: "session")

    /// Request with a modified process chain.
    public static let sshTampered = ApprovalRequest(
        id: "req-bad1",
        action: ActionDescriptor(
            channel: "ssh", tool: "ssh.exec", summary: "rm -rf /var/log/*",
            host: "203.0.113.20",
            bodyPreview: "rm -rf /var/log/*", dangerTokens: ["rm", "-rf"]),
        why: WhyDescriptor(rule: "ssh-write-ask", reason: "class=destructive · session recorded"),
        provenance: provenanceTampered)

    // MARK: Activity rows

    public static let activityRows: [ActivityRow] = [
        ActivityRow(ts: "2026-07-08T14:22:31Z", identity: "agent://mac.claude-code",
                    channel: "ssh", tool: "ssh.exec", argsPreview: "df -h /",
                    target: "203.0.113.10", decision: "allow", rule: "ssh-read-allow",
                    isError: false, bytesOut: 214, durationMs: 340),
        ActivityRow(ts: "2026-07-08T14:22:29Z", identity: "agent://mac.claude-code",
                    channel: "http", tool: "cloudflare.zones_list", argsPreview: "GET /zones",
                    target: "api.cloudflare.com", decision: "allow", rule: "http-get-bound",
                    isError: false, bytesOut: 88, durationMs: 88),
        ActivityRow(ts: "2026-07-08T14:21:55Z", identity: "agent://box.claude1",
                    channel: "http", tool: "cloudflare.dns_record_update", argsPreview: "PUT zone gse.kz",
                    target: "api.cloudflare.com", decision: "ask→approved", rule: "http-mutating",
                    isError: false, bytesOut: 512, durationMs: 12_000),
        ActivityRow(ts: "2026-07-08T14:20:10Z", identity: "agent://box.koder-ai",
                    channel: "http", tool: "http.request", argsPreview: "POST evil.tld",
                    target: "evil.tld", decision: "deny", rule: "egress-deny",
                    isError: true, bytesOut: 0, durationMs: 3),
    ]
}
