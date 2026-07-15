import Foundation
import SallyportCLI

// `sp mcp` forwards MCP JSON-RPC calls between stdio and the running Sallyport app.

let args = Array(CommandLine.arguments.dropFirst())

switch args.first {
case "mcp":
    MCPShim().run()
case "--version", "version":
    print("sp (Sallyport) 1.0")
default:
    FileHandle.standardError.write(Data("""
    Sallyport CLI
    Usage: sp mcp        run the stdio MCP shim (point your agent's .mcp.json here)

    """.utf8))
    exit(args.isEmpty ? 1 : 0)
}
