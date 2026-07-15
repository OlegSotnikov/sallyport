# Contributing to Sallyport

This repository contains one source snapshot per Sallyport release. Development
happens in a private working repository, and each release lands here as one
commit.

## Accepted reports

- **Bug reports and behavior questions:** open an [issue](../../issues). Include the app version
  from About and, when relevant, redacted card or journal contents.
- **Security findings:** do not open a public issue. Email **hello@sallyport.dev**.
  Reports are credited unless you request otherwise.
- **Documentation corrections and design critique:** open an issue. The trust model
  ([docs/14-trust-model.md](docs/14-trust-model.md)) is the source of truth for current behavior.

## Pull requests

Pull requests are not accepted in this mirror. Open an issue instead. If a
reported issue leads to a shipped change, the release notes will credit the
reporter.

If you want to propose a substantial change, open an issue describing it first. Anything that weakens
the absolute vault gate, adds a rules engine, or introduces a server mode is out of scope.

## Building and testing

| Component | Commands |
|---|---|
| Go helper (`core/`) | `cd core && go test -race ./...` |
| Mac app (`mac/`) | `cd mac && swift build && swift test`; signed bundle via `./build-app.sh` |

The [CLA](CLA.md) applies to any contribution we accept through other channels; you keep the copyright
to your work.
