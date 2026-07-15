import Foundation
import Testing
@testable import SallyportApp
@testable import SallyportKit

@Suite("Localized approval copy")
struct ApprovalCopyTests {
    private let english = Locale(identifier: "en")

    @Test("known engine reasons are localized; unknown reasons remain verbatim")
    func reasons() {
        #expect(ApprovalCopy.reason("Approve this agent for the current session.", locale: english)
                == "Approve this agent for the current session.")
        #expect(ApprovalCopy.reason("This action requires approval every time.", locale: english)
                == "This action requires approval every time.")
        #expect(ApprovalCopy.reason("class=write · session recorded", locale: english)
                == "Write action · session recorded")
        #expect(ApprovalCopy.reason("bound credential: cloudflare", locale: english)
                == "Bound credential: cloudflare")
        #expect(ApprovalCopy.reason("upstream policy: custom", locale: english)
                == "upstream policy: custom")
    }

    @Test("engine SSH framing is removed without changing the command")
    func sshSummary() {
        var request = Fixtures.sshRestartNginx
        request.action.summary = "$ systemctl restart nginx on 203.0.113.10"
        request.action.argsPreview = nil
        request.action.bodyPreview = nil

        #expect(ApprovalCopy.actionText(request.action, locale: english)
                == "systemctl restart nginx")
        #expect(ApprovalCopy.notificationSubtitle(for: request, locale: english)
                == "ssh.exec `systemctl restart nginx` on 203.0.113.10")
        #expect(ApprovalCopy.touchIDReason(for: request, locale: english)
                == "Approve: systemctl restart nginx on 203.0.113.10 (Claude Code)")
    }

    @Test("known HTTP and credential summary fragments are localized")
    func builtInSummaries() {
        let http = Fixtures.httpCloudflareDNS.action
        #expect(ApprovalCopy.actionText(http, locale: english)
                == "POST https://api.cloudflare.com/client/v4/zones/…/dns_records (changes data)")

        let credential = Fixtures.sessionCredential.action
        #expect(ApprovalCopy.actionText(credential, locale: english)
                == "Add a key for api.cloudflare.com")
    }

    @Test("unknown tool summaries remain verbatim")
    func unknownSummary() {
        let summary = "vendor.deploy: target=prod (mutating)"
        let action = ActionDescriptor(channel: "mcp", tool: "vendor.deploy", summary: summary)
        #expect(ApprovalCopy.actionText(action, locale: english) == summary)

        let partialSSH = ActionDescriptor(channel: "ssh", tool: "ssh.exec",
                                          summary: "$ caller-supplied text", host: "prod")
        #expect(ApprovalCopy.actionText(partialSSH, locale: english) == "$ caller-supplied text")

        let noArguments = ActionDescriptor(channel: "mcp", tool: "vendor.status",
                                           summary: "vendor.status: (no arguments)")
        #expect(ApprovalCopy.actionText(noArguments, locale: english)
                == "vendor.status: no arguments")
    }
}
