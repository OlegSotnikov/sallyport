import Foundation

/// Handler for `sallyport.request_credential`, which asks the user to add a key.
/// The agent receives only whether a credential was added and its vault name.
/// Missing, dismissed, or timed-out prompts return "not provisioned".
public protocol CredentialPrompter: Sendable {
    func requestCredential(_ ask: CredentialAsk) async -> CredentialAnswer
}

/// Requested credential fields. The user reviews the host bindings before saving.
public struct CredentialAsk: Sendable {
    public var id: String
    public var host: String
    public var hosts: [String]
    public var purpose: String
    public var kind: String            // suggested adapter: bearer|basic|header|…
    /// For kind=header: the header name the API expects (e.g. X-Api-Key).
    public var header: String
    /// How the value goes on the wire, `{secret}` being the placeholder.
    public var format: String
    public var suggestedName: String
    public var docsURL: String         // where to create the token
    public var scopes: [String]        // suggested permissions/zones
    public var origin: Origin
    public var chain: [Hop]

    public init(id: String, host: String, hosts: [String], purpose: String,
                kind: String = "bearer", header: String = "", format: String = "",
                suggestedName: String = "", docsURL: String = "",
                scopes: [String] = [], origin: Origin = Origin(), chain: [Hop] = []) {
        self.id = id; self.host = host
        self.hosts = hosts.isEmpty ? [host] : hosts
        self.purpose = purpose; self.kind = kind
        self.header = header; self.format = format
        self.suggestedName = suggestedName; self.docsURL = docsURL
        self.scopes = scopes; self.origin = origin; self.chain = chain
    }
}

/// Result of a credential request.
public struct CredentialAnswer: Sendable {
    public var provisioned: Bool
    public var name: String?
    public init(provisioned: Bool, name: String? = nil) {
        self.provisioned = provisioned; self.name = name
    }
    public static let declined = CredentialAnswer(provisioned: false)
}
