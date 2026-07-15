import Foundation
import SallyportKit

/// Built-in MCP tool definitions with current host hints.
public enum MCPTools {
    public struct Hints: Sendable {
        public var httpHosts: [String]
        public var sshHosts: [String]
        public init(httpHosts: [String] = [], sshHosts: [String] = []) {
            self.httpHosts = httpHosts; self.sshHosts = sshHosts
        }
    }

    public static let builtinNames: Set<String> = ["http.request", "ssh.exec", "sallyport.request_credential"]

    public static func defs(_ h: Hints) -> [JSONValue] {
        let httpBound = h.httpHosts.isEmpty
            ? "No HTTP credentials are bound. Add one in Keys and APIs."
            : "Bound credential hosts: \(h.httpHosts.sorted().joined(separator: ", ")). Other hosts are unauthenticated."
        let httpDesc = "Send an HTTP request. Do not include credentials, tokens, or an Authorization header. Sallyport injects only a credential bound to the target host. \(httpBound) Credentials are not forwarded on cross-host or HTTPS-to-HTTP redirects. Cloud metadata is blocked. Private addresses require an explicit credential binding. Put query parameters in `params`. Returns `status`, `final_url`, and either `json` or `body`."
        let sshInv = h.sshHosts.isEmpty
            ? "No SSH hosts are configured."
            : "Configured SSH hosts: \(h.sshHosts.sorted().joined(separator: ", ")). Use the host name, not its address."
        let sshDesc = "Run a command on a configured SSH host. Do not include credentials; Sallyport handles authentication. \(sshInv) A new agent may require session approval, and a key may require approval for every call. Sessions are recorded. Returns `stdout`, `stderr`, and `exit_code`."

        func schema(_ props: [String: JSONValue], required: [String]) -> JSONValue {
            .object(["type": .string("object"), "properties": .object(props),
                     "required": .array(required.map { .string($0) })])
        }
        func s(_ desc: String) -> JSONValue { .object(["type": .string("string"), "description": .string(desc)]) }

        return [
            .object([
                "name": .string("http.request"), "description": .string(httpDesc),
                "inputSchema": schema([
                    "method": .object(["type": .string("string"), "enum": .array(["GET","POST","PUT","PATCH","DELETE","HEAD"].map { .string($0) })]),
                    "url": s("Full URL, for example https://api.<service>.com/v1/resource"),
                    "params": .object(["type": .string("object"), "description": .string("Query parameters")]),
                    "headers": .object(["type": .string("object"), "description": .string("Additional non-credential headers")]),
                    "body": s("Request body for POST, PUT, or PATCH"),
                ], required: ["method", "url"]),
            ]),
            .object([
                "name": .string("ssh.exec"), "description": .string(sshDesc),
                "inputSchema": schema([
                    "host": s("Configured host name"),
                    "cmd": s("Command to run"),
                    "timeout_s": .object(["type": .string("integer"), "description": .string("Optional timeout in seconds")]),
                ], required: ["host", "cmd"]),
            ]),
            .object([
                "name": .string("sallyport.request_credential"),
                "description": .string("Ask the user to add a credential. Set `hosts` to every domain that may receive it and include known metadata. Returns `provisioned`, optional `name`, and `message`, never the credential value."),
                "inputSchema": schema([
                    "host": s("Primary service host, for example api.<service>.com"),
                    "hosts": .object(["type": .string("array"), "items": .object(["type": .string("string")]), "description": .string("Every domain that may receive this credential")]),
                    "purpose": s("Reason the credential is needed; shown to the user"),
                    "kind": s("Optional kind: bearer, basic, or header"),
                    "header": s("Optional header name for kind=header, for example X-Api-Key"),
                    "format": s("Optional value format using {secret}, for example Bearer {secret}"),
                    "name": s("Optional vault name, for example cf_token"),
                    "docs_url": s("Optional provider page where the user can create the credential"),
                    "scopes": .object(["type": .string("array"), "items": .object(["type": .string("string")]), "description": .string("Optional permissions or scopes")]),
                ], required: ["host", "purpose"]),
            ]),
        ]
    }
}
