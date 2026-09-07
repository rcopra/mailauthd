# mailauthd

A Go service that answers one question about any email: **can this sender be
trusted?** Submit a raw RFC 5322 message, get back a verdict — SPF, DKIM, and
DMARC results with a final DMARC-derived disposition.

The point is not just the checks — it's the shape of the thing: a single Go
process with streaming parsing, bounded concurrency and explicit backpressure,
RFC-precise conformance testing, measured optimization (numbers below), and an
agentic development workflow that is documented, not hidden.

## Status

Work in progress. Milestones:

- [ ] **M1** — SPF end-to-end via CLI, open-spf.org RFC 7208 conformance suite, fuzzing
- [ ] **M2** — DKIM (via `go-msgauth`, wrapped — crypto correctness isn't the showcase, orchestration is) + DMARC evaluation + HTTP service
- [ ] **M3** — load generator, `/metrics`, Docker, CI, benchmark tables
- [ ] **M4** — writeup

Done so far: scaffolded and committed — domain vocabulary (`internal/verdict`),
DNS resolver seam (`internal/dnsres`), CLI and service stubs, CI, Dockerfile,
architecture diagram (`docs/diagrams/`).

## Two entry points, one core

- **`mailauthd`** — the HTTP service. Long-running, concurrent, backpressured.
- **`mailauth`** — the CLI. Same pipeline in-process: `mailauth < message.eml`,
  Verdict JSON on stdout. No network, no server — this is also the bench harness.

Both are thin front-ends over the same `internal/` packages; the HTTP layer is
a wrapper, not the product.

## API (planned)

```
POST /v1/verify
Content-Type: message/rfc822

<raw message bytes>
```

```json
{
  "disposition": "pass",
  "results": [
    {"check": "spf",   "outcome": "pass",  "reason": "..."},
    {"check": "dkim",  "outcome": "pass",  "reason": "..."},
    {"check": "dmarc", "outcome": "pass",  "reason": "..."}
  ]
}
```

No authentication in v1 — this is a demonstration service, not a public API.
Vocabulary (`Check`, `Result`, `Disposition`, `Verdict`) is defined in
`CONTEXT.md`.

## Intake

The checks are the novel part; intake is deliberately boring — *obtain a MIME
blob, POST it.* Surfaces, ranked by effort:

| Intake | Effort | Status |
|---|---|---|
| Files / corpus (CLI, fixtures, loadgen) | zero | in scope (M1/M3) |
| Webhook receivers (SendGrid Inbound Parse, Mailgun Routes → raw MIME POST) | ~1 day | future work |
| IMAP / POP3 poller (spam trap, `abuse@`, quarantine) | ~1–2 days | stretch goal |
| Maildir / mbox watcher (self-hosted box) | ~1–2 days | stretch goal |
| MTA content filter / milter (in-line scanning) | ~1 week+ | known future work |
| Custom MTA | weeks | explicitly not happening |

## Benchmarks

Methodology: synthetic 1k-message corpus, fixture DNS (deterministic),
concurrency sweep at 1/8/64.

| Concurrency | req/s | p50 | p99 |
|---|---|---|---|
| 1 | — | — | — |
| 8 | — | — | — |
| 64 | — | — | — |

Secondary: real DNS with vs. without TTL cache — cache hit rate and latency
delta. (Populated in M3.)

## Development

- `docs/` — local reference lessons (SPF, DKIM, DMARC, the Verdict model, the
  DNS seam, backpressure, fuzzing). Kept out of version control on purpose.
- `AGENTS.md` — testing discipline and commit rules; `docs/workflow.md` (local)
  — how the agentic workflow is split, honestly.
- Testing: table-driven, RFC conformance suites (open-spf.org), fuzz targets on
  all parsers. No production code touches real DNS in tests.
- Stdlib first; the only external dependency is the wrapped DKIM library.

## License

MIT.
