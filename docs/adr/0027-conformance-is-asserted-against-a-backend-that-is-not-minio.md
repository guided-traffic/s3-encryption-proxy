# ADR 0027: Conformance is asserted against a backend that is not MinIO, seeded once and bounded by a byte budget

## Status

**Accepted.** Date: 2026-09-11.

Implemented the same day: the suite, one script for every backend, the free
matrix in continuous integration and the scheduled paid matrix.

**First paid run, 2026-09-11.** The corpus seeded in one pass — 17 objects,
10,878,989 bytes of a 16,777,216 byte budget — and all seventeen assertions pass
against Wasabi. Three things the run found, in the order they matter:

- **No backend this project can reach implements `x-amz-expected-bucket-owner`.**
  Three were probed: MinIO, LocalStack 3.8 and Wasabi. All three accept a wrong
  bucket owner and succeed. It was the gap this suite was built partly to close,
  and it stays open — recorded against
  [ADR 0007](0007-forward-it-or-refuse-it.md) rather than worked around.
  The pattern has a cause worth writing down: the header checks an **AWS account
  id**, and an implementation with no AWS account model has nothing to check it
  against. LocalStack is the sharpest case, because it *does* model account ids
  and still does not enforce it. Only AWS S3 itself is likely to close this.
  A negative result, and the suite reporting it by name is the point of D2.
- **The three multipart permissions are a cost control, not a convenience.**
  The first runs were made with a credential that could neither list nor abort
  multipart uploads, and left three uploads open that nothing could see or
  remove. They carried no parts, so they cost nothing — but a seed that died
  halfway through its 5 MiB multipart would have left billed parts in exactly
  that state. The policy is written out in
  [docs/developer/testing.md](../developer/testing.md), and the suite carries an
  opt-in sweep — `--clean` — that aborts the uploads left under its own prefix,
  because a test's own cleanup can be the thing that fails.
- **D9 caught a defect in this ADR's own implementation.** The seed created the
  bucket unconditionally, which works on a throwaway stack and is denied by a
  correctly scoped paid credential. It now creates one only when `HeadBucket`
  says it is missing, and says so plainly when it may not.

## Context

MinIO is the only backend this project has ever tested against, and MinIO is not
S3. It implements most of the API and quietly ignores parts of it, which means a
whole class of proxy defect is invisible here: **a header the proxy drops and a
header the proxy forwards produce the same answer from a backend that does not
act on it.**

This is not hypothetical. `x-amz-expected-bucket-owner` was dropped on 63 of 64
backend calls, and the entire integration suite passed throughout, because MinIO
accepts a wrong bucket owner and succeeds anyway (probed 2026-09-11). The defect
was found by reading the code. Nothing in the test matrix could have found it,
and nothing in the test matrix can confirm the fix.

The obvious answer — test against a second, real implementation — carries a cost
this project has not had to think about before. The backend available for it
bills **every written byte for a minimum of ninety days**, and deleting the
object refunds nothing. Cost is therefore a design constraint on the test suite
itself, not an operational afterthought.

Three numbers shaped the decision:

- The stored format seals **64 KiB per segment**, and the segment size is a
  constant rather than a setting. Everything the segment chain does — boundaries,
  multi-segment reads, ranges that cross segments, the tail-first read — is
  reachable within a few hundred kilobytes.
- **A refused request writes nothing.** The checksum verifier holds the last
  payload byte back until the verdict is in, so every refusal the product has is
  free to assert.
- The only genuinely expensive surface is a real multi-part layout, because S3
  refuses a part below 5 MiB unless it is the object's last. Two paths need one
  each. That is the floor, and it is about 10 MiB.

For comparison, pointing the existing integration suites at such a backend would
write on the order of three gigabytes per run — the sum of their payload size
literals, excluding the performance package. Two orders of magnitude more, for
assertions that were written to prove the proxy against itself rather than
against a specification.

## Decision

**D1. There is one conformance suite and it is backend-agnostic.** It asserts
what S3 specifies, takes its endpoints from the environment, and has no branch on
which backend is behind the proxy. The same binary runs against the local stack
and against the paid backend.

**D2. The difference between the two runs is the finding.** An assertion that
passes against one backend and not the other is a backend deviation, and the
suite reports it by name rather than hiding it behind a skip. A test that cannot
prove its point against the backend it is running on says so in its output and
says what it did prove instead.

**D3. Every free backend runs in continuous integration on every change, and
they run in parallel — one runner per backend.** The paid ones are scheduled,
never triggered by a push or a pull request: a per-push trigger turns one careless
payload into a charge that scales with how busy the repository is, and a pull
request trigger would expose the credentials to a fork.

`fail-fast` is off in both matrices. When one backend disagrees, what the others
did is the interesting half, and cancelling them throws away the comparison this
suite exists to make.

**D3a. Two free backends, not one.** MinIO and LocalStack. Two is the smallest
number that can disagree, and they do not have the same blind spots: LocalStack
models AWS account ids and re-implements the API surface, MinIO does neither. A
single free backend would make the whole design a one-run suite with a paid
appendix.

**D3b. Each backend gets its own container, bucket and proxy port.** That is what
makes parallelism free rather than a source of flakes, and it holds on a
workstation as well as on a runner — `make test-conformance-parallel` is the same
arrangement CI uses.

**D4. The corpus is seeded once and then only read.** The seed is idempotent
against the plaintext length, so a second seeding run against a seeded bucket
writes nothing and the steady-state cost is zero. Everything that is not the seed
runs with a **zero byte budget** and fails on the first byte it tries to write.

**D5. The byte budget is code, not convention.** A write reserves against a
ceiling before it reaches the backend, and a run that exceeds it fails rather
than pays. The ceiling is a named constant in the suite: raising it is a diff
someone has to justify.

**D6. Every object in the corpus states what it unlocks.** Adding one is adding a
recurring charge, so the justification travels with the entry rather than with
the commit that introduced it.

**D7. An incomplete multipart upload is treated as a leak.** Its parts are stored
and billed until it is aborted, and it does not appear in an object listing, so
it accumulates invisibly. Every test that opens an upload aborts it, and the
suite asserts that none is left open.

**D8. The key encryption key of the paid run is a stable secret, not a generated
one.** A stored object names the fingerprint of the key that wrapped it, so a
fresh key each run would make the corpus unreadable and force a re-seed — the
repeated write this whole design exists to avoid. The key protects a throwaway
test bucket, which is what makes storing it acceptable.

**D9. The suite never creates or deletes the paid bucket.** The operator creates
it once. A suite that could delete it could delete the wrong one. It does create
one on a throwaway backend, and only after `HeadBucket` says none is there.

**D10. One script sets up every backend, and continuous integration invokes that
script rather than reimplementing it.** A runner and a workstation that arrange
the backend differently are two setups, and only one of them gets debugged. The
script is also what makes adding a backend a matrix entry instead of a new job.

**D11. A probe value must not collide with a backend's own defaults.** The
wrong-owner id is `999999999999` and not `000000000000`, because the latter is
LocalStack's default account id: there it would be the *correct* owner, and the
success would have been read as the header being ignored. A test that probes what
a backend enforces has to pick values no backend can accidentally accept.

## Consequences

- **The proxy is now asserted against a specification rather than against one
  implementation.** The class of defect that produced the bucket-owner gap is
  reachable by a test for the first time.
- **A second backend is a second thing that can break the build**, and some of
  those breaks will be the backend's fault rather than the proxy's. D2 is what
  keeps that useful: the suite is expected to report deviations, and a deviation
  is information rather than a failure to work around.
- **The paid run is weekly, so a regression it would catch can sit for a week.**
  That is accepted: the free run catches everything that does not depend on the
  backend's behaviour, which is most of it.
- **Cost is bounded but not zero.** The seed is about 10 MiB once. At the current
  rate that is a fraction of a cent, and the ceiling that matters is the one on
  accidents, not the one on the corpus.
- **A contributor can run the free suite and never think about any of this.**
  The paid targets are named for what they are and carry the warning in the
  Makefile.

## Alternatives Considered

- **Point the existing integration suites at the paid backend.** Rejected on
  cost — roughly three gigabytes a run — and on fit: those suites assert the
  proxy against itself, with fresh buckets and generous payloads, which is right
  for a free backend and wrong for a billed one.
- **A backend-specific suite, written for Wasabi.** Rejected. It would run only
  where it costs money, so it could break silently between scheduled runs, and
  the interesting comparison — this backend against that one — would not exist.
- **Mock the second backend.** Rejected outright: a mock encodes what we believe
  the service does, and the entire point is that our belief about MinIO was
  wrong. A mock would have confirmed the bug.
- **Delete the corpus after each run.** Rejected: it does not refund anything on
  a backend with a minimum storage duration, and it would force a re-seed — a
  repeated write — on every run. Deleting costs more than keeping.
- **Generate the key encryption key per run.** Rejected under D8: it makes the
  seed non-idempotent, which converts the one-off cost into a recurring one.
- **Run on every pull request with a small budget.** Rejected: the cost is not
  really the bytes, it is that credentials for a paid resource would be reachable
  from any branch, and a fork's pull request must never see them.

## Residual risks

- **The paid backend may not implement the thing being asserted either.** It is a
  second implementation, not the specification. Where both backends agree and
  both are wrong, this suite agrees with them.
- **The corpus is a fixed set of sizes.** It covers the boundaries that matter in
  the stored format, and it does not cover a size nobody thought of. Adding one
  is cheap in bytes and has to be justified in the entry.
- **Nothing enforces the budget outside the seed.** A future test that writes
  through the SDK directly bypasses the reservation; what catches it is the
  footprint ceiling and the assertion that refused requests stored nothing, both
  of which are after the fact rather than before it.
- **The schedule is a single point of cost.** A workflow edit that adds a push
  trigger would not be caught by anything here except review.

## References

- [ADR 0007](0007-forward-it-or-refuse-it.md) — D14 and the residual risk this
  suite exists to close
- [ADR 0012](0012-client-checksums-are-verified-never-forwarded.md) — why a
  refused upload stores nothing, which is what makes the refusal coverage free
- [ADR 0003](0003-objects-are-an-authenticated-segment-chain.md) — the 64 KiB
  segment, which is why the chain is cheap to exercise
- [ADR 0020](0020-performance-is-measured-before-and-after.md) — the other suite
  that is deliberately not a continuous-integration gate, for a different reason
