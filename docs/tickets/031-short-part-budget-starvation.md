# 031 — One held short part can hold the whole short-part budget

Since the global bound of ADR 0011 D5 landed on 2026-09-12, one client-driven
upload holding one short part of `optimizations.multipart_short_part_buffer_size`
bytes (`67108864` # default) keeps every other upload in the process from holding
its last part: each is answered `503 SlowDown` until that one session ends, and
the session's owner decides when that is.

Before the change the same client could take the process down — the cap was per
session, so N sessions held N × 64 MB and the container went OOM — and the global
budget is strictly better for the process. What is new is the effect on **other
clients**, and it is recorded nowhere: section 4.2 of `SECURITY_ARCHITECTURE.md`
lists the ways clients on one proxy share a blast radius and this one is missing,
section 8 has no H- entry for it, and ADR 0011 describes the two answers without
their cross-client consequence.

Found 2026-09-12 in the review of the test-audit wave. This is the work.

## What happens

Read-proven, with the lines:

| Step | Where |
|---|---|
| A part of exactly the budget is accepted: the size guard is `>` and the read limit is `limit+1` | [segmented_session.go:495](../../internal/orchestration/segmented_session.go#L495), [parser.go:117](../../internal/proxy/request/parser.go#L117) |
| It reserves the whole budget | [segmented_session.go:208-219](../../internal/orchestration/segmented_session.go#L208-L219): `if m.shortPartHeld-held+want > budget { return false }` — with `shortPartHeld == budget`, every `want > 0` from every other session is refused, a one-byte last part included |
| The refused part is answered `503 SlowDown` | [upload.go:352](../../internal/proxy/handlers/multipart/upload.go#L352) |
| The hold ends only on Complete, Abort, the idle sweep or shutdown | `releaseSessionBudget`, every path |
| The idle sweep counts from the last part received (ADR 0028 D1), and `SealPart` touches the clock before it does anything else | [segmented_session.go:453](../../internal/orchestration/segmented_session.go#L453) |
| The same-number resend of the held part is accepted as an idempotent replace | [segmented_session.go:492-500](../../internal/orchestration/segmented_session.go#L492-L500): the `pendingNum != partNumber` guard lets it through, `reserveLocked` moves `held → want` |

So one resend of the held part every 59 minutes keeps the hold alive
indefinitely under the default `multipart_session_idle_timeout` of 3600 s.
Nothing bounds it but the holder's will.

**Who can do it:** any authenticated `s3_clients` credential, under an encrypting
provider. Under the exit provider there is no session and no hold. No
unauthenticated path reaches it.

**Who is hurt, and how much:** every other upload whose last part is held — which
is every upload whose last part covers no whole segment or is under 5 MiB, in
practice nearly all of them — and it is hurt at its last part, after everything
else has been transferred. The client's SDK retries the `503` with backoff and
gives up: aws-sdk-go-v2 v1.47.0's standard retryer stops at `DefaultMaxAttempts = 3`
(`aws/retry/standard.go`), and its upload manager v1.23.5 then **aborts the whole
multipart upload** unless `LeavePartsOnError` is set, which defaults to `false`
(`feature/s3/manager/upload.go:316`, `:873-875`). From the client's side the
whole transfer is lost, not the last part: the proxy keeps the session open
(ADR 0011 D5), but the SDK has already told the backend to drop it.

The same mechanism hurts one client on its own — several concurrent backups of
one Velero each parking a last part — but that is sizing, not security, and the
README already describes the key as what all open uploads hold together.

## Where it stands against the recorded decisions

- **`SECURITY_ARCHITECTURE.md` 4.2** already says: *"Every authenticated client
  can do everything any other authenticated client can do … share one blast
  radius. If tenant separation is required, run one proxy per tenant."* This is a
  new instance of that statement, not a new class. It has to be listed there
  either way.
- **ADR 0014 D7**: no rate limiting, no blocking; *"denial-of-service defence
  [is] the ingress's job."* A bound on what one identity may **hold** is not a
  rate limit — it bounds bytes parked in memory, not requests per second — and
  the ingress cannot apply it, because the ingress does not know which part is
  the last. **ADR 0014 D12** sets the bar for anything throttle-shaped all the
  same: the key lands with the code reading it and a test that proves it, in one
  change. Whatever is chosen meets that bar or stays out.
- **ADR 0011 D5** (implemented 2026-09-12) spells out `SlowDown` and
  `EntityTooLarge` and does not say that a shared budget is a lever one client
  has over another.

## The decision, and what each answer costs

**Is the shared budget the documented consequence of "no multi-tenancy", or does
the proxy bound what one identity may hold?**

**A — document it, no code.** Fits 4.2 and ADR 0014 D7 as they stand. The
operator's levers, and what each one does: a shorter
`multipart_session_idle_timeout` does nothing against a renewed hold; a larger
budget raises the price without removing it; one proxy per tenant removes it,
which is what 4.2 already prescribes. Cost: one H-12 entry, one bullet in 4.2, one
sentence in ADR 0011.

**B — a per-identity share of the global budget.** The identity is already at
hand: `middleware.ClientIdentity(ctx)`
([identity.go:22-25](../../internal/proxy/middleware/identity.go#L22-L25))
carries the access key id the authentication middleware set, and
`CreateMultipartUpload` can hand it to the session. Accounting is a second map in
the Manager keyed by access key id, checked beside the global one in
`reserveShortPart` under the same leaf mutex. The share is either a fixed divisor
or a new key, and under D12 it lands with the code and a test that proves it. The
refusal to a client that exceeds its own share stays `SlowDown`: its own other
uploads finishing make room. It stops one credential starving another; it does
not stop one credential using its whole share across N of its own sessions, which
is that client's own sizing. A per-**session** share instead is cheaper and
pointless — a client opens a second session. Cost: the identity plumbed into the
session, one map, one key or divisor in the configuration table of `CLAUDE.md`,
the README reference and the chart values, orchestration tests with two
identities, and one integration test with two `s3_clients` entries.

Recommendation: **A**, unless several clients on one proxy becomes a supported
deployment. 4.2 says today that it is not, and a control that only matters in an
unsupported deployment is a control nobody will size. A is the documentation debt
of a change that has already landed, and it closes this ticket in one commit. If
the answer is B, the 4.2 sentence about one proxy per tenant changes with it,
because B is the first mechanism that separates clients at all.

## Work

- [ ] Decide A or B
- [ ] `SECURITY_ARCHITECTURE.md` section 8: a new open `### H-12` after H-4, in
      the shape of the other entries — what it is, who can do it, what it costs
      the others, the levers and what each one does not do
- [ ] `SECURITY_ARCHITECTURE.md` section 4.2: one bullet beside the other
      shared-blast-radius items, pointing at H-12
- [ ] ADR 0011: one sentence in the status block or the consequences — a global
      budget is a shared budget, and holding it is a lever one client has over
      another. Under B, a new D beside D5 that states the share and its answers
- [ ] Under B only: identity into the session; per-identity accounting in
      `reserveShortPart` and `releaseShortPart`; the key or divisor in every
      place the configuration is documented; tests — identity A fills its share,
      A's next short part is `SlowDown`, B's short part is served; an integration
      test with two `s3_clients` entries against MinIO; the 4.2 sentence about one
      proxy per tenant rewritten to what B actually separates

## Done when

- [ ] The decision is in ADR 0011, and H-12 and the 4.2 bullet are on the branch
- [ ] Under B: `make test-unit`, `make test-unit-race` and `make test-integration`
      are green with the new tests in them
- [ ] `git grep 031` is empty outside this directory, and this file is deleted
