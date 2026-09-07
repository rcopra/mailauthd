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

## Intake: how emails reach the verdict engine

The auth checks are the expensive, novel part. Intake is deliberately boring:
*obtain a MIME blob, POST it.* An email is just an RFC 5322 artifact — headers
plus body — so anything holding that blob is a caller. Realistic intake
surfaces, ranked by effort:

| Intake | Mechanism | Effort | Status |
|---|---|---|---|
| Files / corpus | CLI, test fixtures, load generator | zero (built in) | in scope (M1/M3) |
| Webhook receivers | Point a domain's MX at SendGrid Inbound Parse / Mailgun Routes; they POST raw MIME to `/v1/verify` — the production sample-collection pattern | ~1 day | future work |
| IMAP / POP3 poller | Worker fetches from a dedicated mailbox (spam trap, `abuse@`, quarantine) and POSTs each message | ~1–2 days | stretch goal |
| Maildir / mbox watcher | Watch a Maildir on a self-hosted box, POST new arrivals | ~1–2 days | stretch goal |
| MTA content filter / milter | Scanner sits in-line during SMTP delivery via Postfix `content_filter` or a milter adapter | ~1 week+ | out of scope, known future work |
| Custom MTA | Run SMTP yourself | weeks | explicitly not happening |

The two entry points already shipped share one core: `mailauthd` is the HTTP
service; the `mailauth` CLI runs the same pipeline in-process over stdin with
no network involved. Benchmarks run through the CLI for this reason — verdict
cost without socket noise.

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
