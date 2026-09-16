# ADR 0036: A response follows S3, deviates only so a client stays usable, and changing one is never a breaking change

## Status

**Accepted.** Date: 2026-09-16.

**In force from this date for every change; nothing in the tree moves for it.** It is a rule
about what a response is and what changing one means for a release, decided while designing
the cooperation of several proxy instances, where a table of corrected answers — a lost upload
table, a repeated completion of a finished upload, a store that failed over — was waiting on
the question whether each correction had to wait for a major. The owner's ruling that it does
not is this record.

**ADR 0018 D5 keeps its wording and gains a pointer here**, so that no reader takes the broad
reading from it: this record says what one of its three terms, "a client-visible answer",
means. The note in ADR 0007 that its D13 refusal "is a new client-visible refusal, so it lands
with 5.0.0" records what happened on 2026-09-09 under the broad reading, stays as history, and
carries the same pointer.

## Context

The proxy stands in front of S3 for any client (ADR 0006 D1), and a compatibility question is
answered against S3 semantics, never against what one client sends (ADR 0006 D2). Every response
is composed by the proxy and never echoes the backend (ADR 0008). The conformance suite asserts
what S3 specifies (ADR 0027 D1). So the shape of an answer is, by default, S3's shape.

The product already deviates from S3, deliberately and in several places, and every one of those
deviations exists for the same reason: an encrypting proxy cannot give the client what S3 gives
it, and the client has to keep working anyway. The entity tag carries a `-0` marker so that a
client that treats a thirty-two-hex tag as an MD5 stops comparing it to one (ADR 0032). A
checksum algorithm the proxy cannot compute over the plaintext answers `501 NotImplemented`
rather than a forwarded value that describes ciphertext (ADR 0012). Server-side copy answers
`422 NotSupportedWithEncryption` (ADR 0011). An object the proxy did not write answers
`403 InvalidObjectState`, on GET, HEAD and ranged GET alike (ADR 0001). Every size and every
listing describes the plaintext, which S3 never saw (ADR 0010). None of these serves the proxy;
each serves the client, either by keeping it working through the proxy or by making its next
step the right one.

What a client's next step is, is decided by the **class** of an answer more than by its code. A
permanent state answers 4xx, so an SDK stops; a transient failure answers 5xx, so an SDK retries.
The line runs through the cause, not the symptom: a wrapped key that fails its authentication
tag is permanent and therefore `403`; the same call failing because a key provider is unreachable
is transient and therefore 5xx. A wrong class makes an SDK retry a request that cannot succeed,
or file a corruption as a passing outage; a wrong code inside the right class is a lie in the
text, but the SDK does the right thing.

ADR 0018 D5 marks a commit as breaking when it "breaks stored data, an existing configuration or
a client-visible answer". Read broadly, every corrected status code is a major — and this
project's majors break the stored format by policy (ADR 0017), so a corrected code would wait
for a release that makes every existing object unreadable, and a client would go on receiving
the wrong answer for the life of a major line. The broad reading was applied once, when a new
refusal of a query string carrying `;` was held for 5.0.0. It blocked the design work on
2026-09-16 for a status code. It is retired here.

Why the broad reading is wrong in substance: a client depends on a request the proxy accepts
being honoured (ADR 0007 D1), on a success having S3's shape, and on a refusal being retried or
not according to its class. **No client depends on receiving the wrong answer.** No SDK is written
to require `404 NoSuchUpload` where the upload exists; no client is written to retry a `500` that
cannot succeed and then to rely on having retried. Correcting the answer changes what the SDK does
next toward what S3's own answer would have made it do, which is the correction working.

## Decision

**D1. A response of this proxy follows S3.** Status, error code, headers and body shape are, by
default, what S3 answers to that request. The conformance suite asserts that default, and a
difference between the proxy's answer and S3's that no record below explains is a defect.

**D2. The proxy deviates from S3 exactly where an encrypting proxy has to for the client's sake.**
A deviation is admissible when it keeps a client working through the proxy, or when it makes the
client's behaviour through the proxy better than S3's own answer would — a truthful failure
instead of a lie, a stop instead of retries that cannot succeed, a marker that stops a client from
comparing a tag to a digest it is not. A deviation that serves the proxy rather than the client —
that hides a limit, saves the proxy a request, or spares it a refusal it owes — is not admissible
under this rule. Every deviation is recorded in an ADR and documented as a limit in the
user-facing reference (ADR 0006 D2), and it is argued from S3 semantics for any client, never
from one observed client (ADR 0006 D3).

**D3. The deviation rule never overrides honesty.** A deviation may not turn a refusal into a
success for work not done (ADR 0007 D1), may not make a refusal say something untrue
(ADR 0007 D8), may not serve a byte the proxy has not verified (ADR 0001), and may not put an
answer in the wrong class: a permanent state of the object, the upload or the request is 4xx, a
transient failure is 5xx, because the class is what decides the client's next step.

**D4. Adjusting a response is a correction and never a breaking change.** Moving an answer toward
S3's, or away from it under D2, never carries the breaking marker and never waits for a major.
Under ADR 0018 D5 the term "a client-visible answer" means **the acceptance of a request and the
shape of a success**: what the proxy takes and honours, and what a successful answer carries.
The status code, the error code, the class and the wording of a refusal, and a header the proxy
adds to an answer, are not it. Stored data and configuration stay exactly what D5 protects.

**D5. A response change lands as a fix, with its test and its documentation in the same change.**
The test states the new answer and cites the record that decides it (ADR 0031 D6); the
user-facing reference states it; the release notes name it under fixes. A change that turns a
green end-to-end verdict red is not an adjustment under D2 — it has stopped a client from
working — and it is a defect until the verdict is green again (ADR 0019, ADR 0031).

## Consequences

**A client may see a different answer after a minor release.** That is the point of the record:
the answer it saw was wrong, and the corrected one makes its next step the right one. The
release notes name every changed answer, so an operator reading them learns what moved. Nobody
likes that a client which had hard-coded the wrong code breaks; whether any client has is not
verified, the three exercised clients are covered by their suites, and a fourth that has would
be a defect found through one client and fixed for every client (ADR 0006 D4).

**Reviewers lose one argument and keep two.** "This changes an answer, it needs a major" is gone.
"This changes what the proxy accepts" and "this changes the shape of a success" remain, and both
still carry the marker under ADR 0018 D5.

**The conformance suite asserts the deviation where a record decides one.** Under ADR 0031 D6 a
behaviour an ADR records is the target, so where D2 applies the suite asserts the proxy's answer
and cites the record, not S3's answer. Where no record applies, it asserts S3's, and a mismatch
is a finding.

**Every new deviation still costs a decision.** D2 does not license a deviation because it is
convenient; it licenses one that a record argues for the client. The argument has to be written
before the answer changes, which is ADR 0031's cost and is deliberate.

**The design of instance cooperation carries no major-gated item.** Every answer in its table —
`503 SlowDown` while the store fails over, `404 NoSuchUpload` for an upload the proxy has ended,
`403 InvalidObjectState` for an upload the backend has and the proxy cannot serve, `200` with the
entity tag for a repeated completion of a finished upload — lands as a fix.

## Alternatives Considered

**The broad reading of ADR 0018 D5: every changed answer is a major.** Rejected. A corrected
code would wait for a release that breaks the stored format (ADR 0017), so a client would keep
receiving a lie for a whole major line; and the rule would make the honest answer the expensive
one, which inverts what the release guard exists for.

**Rewrite ADR 0018 D5.** Rejected. D5 is the definition the release guard is built on and is
deliberately not softened; its three terms stay. The term is defined here, D5 points here, and
the guard is unchanged.

**No rule; decide per change.** Rejected. The same argument recurs on every response correction,
and it was answered differently on 2026-09-09 and on 2026-09-16 — which is what a missing rule
looks like.

**Never deviate from S3.** Rejected. An encrypting proxy cannot compute a content digest the
client can verify, cannot serve an object it did not write, cannot copy server-side, and cannot
report a size S3 never saw. The deviations are the product; the rule is where they are allowed.

**Treat a class change as breaking and a code change inside a class as a fix.** Rejected. It is
the class change that repairs client behaviour — a stop instead of three retries that cannot
succeed — and holding exactly that for a major keeps the harmful behaviour longest.

## Residual risks

* **Not verified: whether any client depends on a specific wrong answer.** rclone, s3cmd and
  Velero are exercised by their suites and would show it as a red verdict. Nothing is known about
  clients outside them.
* **D2 can be argued badly.** A deviation justified by one client's observed behaviour is what
  ADR 0006 D3 forbids; D2 says "the client" and means any client under S3 semantics. The review
  of the record that introduces a deviation is where that line is held.
* **The wording of a refusal is not decided here.** ADR 0008 owns the message per error code;
  this record only says that changing it is not a break.

## References

* [ADR 0018](0018-a-major-release-is-declared-by-a-label.md) — the release guard; this record
  states what its D5 means by "a client-visible answer" and changes nothing else in it
* [ADR 0007](0007-forward-it-or-refuse-it.md) — honour or refuse with a named error; a refusal
  says what is true; the one precedent of the broad reading, retired here
* [ADR 0006](0006-the-proxy-serves-any-s3-client.md) — compatibility argued from S3 semantics, and
  every deliberate deviation documented as a limit
* [ADR 0008](0008-every-response-describes-the-proxy.md) — every response is composed by the proxy
* [ADR 0027](0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md) — the suite
  that asserts S3's answer where no record deviates
* [ADR 0031](0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md) — a
  behaviour an ADR decides is itself the target
* [ADR 0032](0032-the-entity-tag-is-a-change-token-never-a-content-digest.md),
  [ADR 0012](0012-client-checksums-are-verified-never-forwarded.md),
  [ADR 0011](0011-the-proxy-owns-the-part-layout.md),
  [ADR 0001](0001-the-backend-is-hostile.md) — the deviations the product already makes for the
  client's sake
* [docs/developer/errors.md](../developer/errors.md) — the status-class rule D3 rests on
* [docs/operations/README.md](../operations/README.md) — the user-facing reference where every
  deviation is documented as a limit
