# mailauthd

A Go service that answers one question about any email: **can this sender be
trusted?** Submit a raw RFC 5322 message, get back a verdict — SPF, DKIM, and
DMARC results with a final DMARC-derived disposition.

Built as a demonstration of the things that matter when operating scan
pipelines: streaming parsing, bounded concurrency with explicit backpressure,
measured optimization (benchmarks below), RFC-precise conformance testing,
and an agentic development workflow that is documented, not hidden.

## Status

Work in progress. Milestones:

- [ ] **M1** — SPF end-to-end via CLI, open-spf.org RFC 7208 conformance suite, fuzzing
- [ ] **M2** — DKIM (via `go-msgauth`) + DMARC evaluation + HTTP service
- [ ] **M3** — load generator, `/metrics`, Docker, CI, benchmark tables
- [ ] **M4** — writeup

## API (planned)

```
POST /v1/verify
Content-Type: message/rfc822

<raw message bytes>
```

Response (planned shape — see `CONTEXT.md` for terms):

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

## License

MIT.
