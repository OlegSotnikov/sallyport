import Foundation

/// A well-known service the user can start from when adding a key: pre-fills the
/// host binding, adapter kind, header/format, adapter params, and links to where
/// the token is created. Presets never contain secret values.
public struct ServicePreset: Sendable, Hashable, Identifiable {
    public let id: String            // stable slug, e.g. "cloudflare"
    public let label: String         // "Cloudflare"
    public let suggestedName: String // vault secret name seed, e.g. "cloudflare_token"
    public let kind: SecretKind
    public let bind: [String]        // host bindings (wildcards allowed)
    public let header: String?       // for kind=.header
    public let format: String?      // inject format when non-default
    public let params: [String: String] // adapter params seed (sigv4/oauth2)
    public let docsURL: String       // where to create the token

    public init(id: String, label: String, suggestedName: String, kind: SecretKind,
                bind: [String], header: String? = nil, format: String? = nil,
                params: [String: String] = [:], docsURL: String) {
        self.id = id
        self.label = label
        self.suggestedName = suggestedName
        self.kind = kind
        self.bind = bind
        self.header = header
        self.format = format
        self.params = params
        self.docsURL = docsURL
    }
}

public enum ServicePresets {
    /// Alphabetical catalog supported by the current authentication adapters.
    public static let all: [ServicePreset] = [
        ServicePreset(id: "anthropic", label: "Anthropic", suggestedName: "anthropic_key",
                      kind: .header, bind: ["api.anthropic.com"], header: "x-api-key",
                      docsURL: "https://console.anthropic.com/settings/keys"),
        ServicePreset(id: "aws", label: "AWS (SigV4)", suggestedName: "aws_key",
                      kind: .awsSigV4, bind: ["*.amazonaws.com"],
                      params: ["region": "us-east-1", "service": "execute-api"],
                      docsURL: "https://console.aws.amazon.com/iam/home#/security_credentials"),
        ServicePreset(id: "cloudflare", label: "Cloudflare", suggestedName: "cloudflare_token",
                      kind: .bearer, bind: ["api.cloudflare.com"],
                      docsURL: "https://dash.cloudflare.com/profile/api-tokens"),
        ServicePreset(id: "digitalocean", label: "DigitalOcean", suggestedName: "digitalocean_token",
                      kind: .bearer, bind: ["api.digitalocean.com"],
                      docsURL: "https://cloud.digitalocean.com/account/api/tokens"),
        ServicePreset(id: "github", label: "GitHub", suggestedName: "github_token",
                      kind: .bearer, bind: ["api.github.com"],
                      docsURL: "https://github.com/settings/tokens"),
        ServicePreset(id: "gitlab", label: "GitLab", suggestedName: "gitlab_token",
                      kind: .header, bind: ["gitlab.com"], header: "PRIVATE-TOKEN",
                      docsURL: "https://gitlab.com/-/user_settings/personal_access_tokens"),
        ServicePreset(id: "notion", label: "Notion", suggestedName: "notion_token",
                      kind: .bearer, bind: ["api.notion.com"],
                      docsURL: "https://www.notion.so/my-integrations"),
        ServicePreset(id: "openai", label: "OpenAI", suggestedName: "openai_key",
                      kind: .bearer, bind: ["api.openai.com"],
                      docsURL: "https://platform.openai.com/api-keys"),
        ServicePreset(id: "sendgrid", label: "SendGrid", suggestedName: "sendgrid_key",
                      kind: .bearer, bind: ["api.sendgrid.com"],
                      docsURL: "https://app.sendgrid.com/settings/api_keys"),
        ServicePreset(id: "slack", label: "Slack", suggestedName: "slack_token",
                      kind: .bearer, bind: ["slack.com"],
                      docsURL: "https://api.slack.com/apps"),
        ServicePreset(id: "stripe", label: "Stripe", suggestedName: "stripe_key",
                      kind: .bearer, bind: ["api.stripe.com"],
                      docsURL: "https://dashboard.stripe.com/apikeys"),
        ServicePreset(id: "twilio", label: "Twilio", suggestedName: "twilio_auth",
                      kind: .basic, bind: ["api.twilio.com"],
                      docsURL: "https://console.twilio.com"),
        ServicePreset(id: "vercel", label: "Vercel", suggestedName: "vercel_token",
                      kind: .bearer, bind: ["api.vercel.com"],
                      docsURL: "https://vercel.com/account/tokens"),
    ]
}
