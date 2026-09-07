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
- The pre-push hook (`.githooks/pre-push`) auto-runs `gofmt -w`, then gates
  pushes on vet/staticcheck/gosec/test. Enable it with
  `git config core.hooksPath .githooks`; keep its tool versions in sync with
  `.github/workflows/ci.yml`.

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

## Agent skills

### Issue tracker

Issues live in Linear, accessed via the Linear MCP server configured in
`.mcp.json`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `CONTEXT.md` glossary; ADRs go in `docs/adr/` when needed.
See `docs/agents/domain.md`.
