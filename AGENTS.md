# AGENTS.md

Instructions for AI agents (and humans) working in this repo.

## Testing discipline

- Table-driven tests for all parsing and evaluation logic. One table row = one
  documented case, named after the RFC section or edge case it covers.
- Parsers must have fuzz targets (`FuzzXxx`) that run in CI (short smoke) and
  locally before merging parser changes.
- SPF conformance is validated against the open-spf.org RFC 7208 YAML test
  suite in `internal/spf/testdata/`. Do not hand-pick cases; run the suite.
- Run `go test ./...` and `go vet ./...` before any commit.

## Code

- Stdlib first. The only permitted external dependency is the DKIM library.
- New RFC behavior goes in with its test in the same change.
- DNS is always behind the `dnsres.Resolver` interface. No production code
  performs real DNS I/O in tests.

## Commits

- Small, honest commits. If a change was developed with an agent, the commit
  message says what was delegated and what was reviewed by hand.
- Never commit generated benchmark artifacts; benchmark numbers live in the
  README with the methodology next to them.
