# CONTEXT.md

Glossary for mailauthd. Terms only — no implementation details.

## Message

The raw RFC 5322 email (headers + body) submitted for evaluation. A Message
is input; the service never mutates or relays it.

## Check

One of the three standard email authentication mechanisms evaluated against a
Message: **SPF** (RFC 7208), **DKIM** (RFC 6376), or **DMARC** (RFC 7489).
A Check is a named mechanism, not a result.

## Result

The outcome of running one Check against a Message: an outcome value
(e.g. pass, fail, softfail, permerror, none) plus a human-readable reason.
Every evaluated Check produces exactly one Result.

## Disposition

The message fate derived from DMARC policy evaluation given the SPF and DKIM
Results: `pass`, `quarantine`, `reject`, or `none`. The Disposition is the
service's final answer about the Message.

## Verdict

The full response for one Message: the Disposition plus the Results of every
evaluated Check. The Verdict is the unit the API returns and the CLI prints.
