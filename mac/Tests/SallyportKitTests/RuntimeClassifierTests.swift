import Testing
@testable import SallyportKit

@Suite("Runtime classification — shells and interpreters")
struct RuntimeClassifierTests {
    @Test("shells and interpreters classify by basename, versions stripped")
    func classification() {
        #expect(RuntimeClassifier.classify(path: "/bin/zsh", name: "zsh") == .shell)
        #expect(RuntimeClassifier.classify(path: "/bin/bash", name: "bash") == .shell)
        #expect(RuntimeClassifier.classify(path: "", name: "sh") == .shell)

        #expect(RuntimeClassifier.classify(path: "/usr/local/bin/node", name: "node") == .interpreter)
        #expect(RuntimeClassifier.classify(path: "/opt/homebrew/bin/bun", name: "bun") == .interpreter)
        #expect(RuntimeClassifier.classify(path: "/usr/bin/python3.13", name: "python3.13") == .interpreter)
        #expect(RuntimeClassifier.classify(path: "", name: "python3") == .interpreter)
        #expect(RuntimeClassifier.classify(path: "/usr/bin/osascript", name: "osascript") == .interpreter)
        #expect(RuntimeClassifier.classify(path: "/opt/php8", name: "php8") == .interpreter)
    }

    @Test("real binaries and apps are not flagged")
    func binariesPass() {
        #expect(RuntimeClassifier.classify(
            path: "/Applications/Claude.app/Contents/MacOS/Claude", name: "Claude") == nil)
        #expect(RuntimeClassifier.classify(path: "/usr/bin/ssh", name: "ssh") == nil)
        #expect(RuntimeClassifier.classify(path: "/usr/local/bin/codex", name: "codex") == nil)
        #expect(RuntimeClassifier.classify(path: "", name: "") == nil)
        // The kernel name is a fallback, not an override: a signed binary whose
        // path basename is distinct must not be flagged by a coincidental name.
        #expect(RuntimeClassifier.classify(path: "/usr/local/bin/claude", name: "node") == nil)
    }
}
