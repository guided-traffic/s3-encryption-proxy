# ADR 0009: The metadata prefix is the proxy's namespace

## Status

**Accepted.** Date: 2026-09-07.

Two rules, at different stages. The startup validation of
`encryption.metadata_key_prefix` is **implemented and released in 4.0.0** as a breaking
change: an empty or non-lowercase prefix is refused at startup instead of being accepted
and silently mis-handled. The immediate repair named below — a case-insensitive comparison on
every write path — is **implemented**: the comparison no longer depends on the spelling a
client chooses, and the none-provider write path, which had no comparison at all, now makes
one. Before that, a client key differing only in case survived, reached the backend and
collided with the proxy's own key there; four of ten uploads against a running proxy left
the object permanently undecryptable. The refusal of such keys with `InvalidArgument` is
**decided and specified, still not implemented.** It was scheduled for 5.0.0 and the 5.0.0
work landed without it, so it is outstanding work for that release. Until it ships the keys
are dropped silently, uniformly, on every path. The `Decision` section below is written in
the present tense for both rules.

**Amended 2026-09-09, implemented 2026-09-11:** D2's shape rule — at least four characters,
starting with a letter or a digit, ending in `-` — is what startup validates, and the refusal
states the three rules rather than printing the pattern alone. `s3-`, `-abc-`, `s3ep` and an
empty prefix are all refused; no shipped value is affected.

**Closed 2026-09-10: the namespace is exclusive on the read side.** The read path used to
accept the *unprefixed* keys `encrypted-dek`, `dek-algorithm` and `kek-fingerprint` behind the
prefixed ones, as backward compatibility for a format that is no longer readable anyway
(ADR 0017). Those names lay outside the prefix, so the filter of D6 and D7 did not touch them
and a client could set them through `x-amz-meta-*`. The fallback is gone: every accessor reads
the prefixed key and nothing else, so D1's exclusivity claim is now true rather than intended.
ADR 0001 records the same closure against its D5.

## Context

Everything the proxy needs in order to decrypt an object — which key encryption key wrapped
the data key, the wrapped data key itself, the algorithm identifiers — is stored in that
object's own S3 user metadata, under a configurable prefix, `s3ep-` by default. S3 user
metadata is a single flat map per object: the keys the client sends and the keys the proxy
writes land in the same place. The prefix is the only thing that separates them.

That made the prefix a load-bearing configuration value with no guard rails, and three
concrete failures followed.

**An empty prefix turned the proxy into a shredder.** With the prefix set to the empty
string, every writer stored the encryption keys unprefixed, while one reader kept looking
for the literal default and found nothing. The object was then classified as unencrypted
and its **ciphertext was served to the client as plaintext behind a `200 OK`**. Nothing in
the exchange said anything was wrong. The naive repair — making that reader honour the
empty prefix literally — is worse: an empty prefix matches every metadata key, so no key
would ever be passed through. Neither branch is correct, which is why the value itself is
refused.

**A non-lowercase prefix silently disabled decryption.** S3 lower-cases user metadata keys
in transit; the proxy's comparisons did not. A prefix with a capital in it therefore never
matched on the way back: objects were written encrypted and read back as pass-through, and
the encryption metadata — including the wrapped data key — was handed to the client instead
of being filtered out.

**A client could write into the namespace and make its own object undecryptable.** A client
that sends user metadata whose key falls inside the prefix writes into the same map the
proxy writes into. Two of the write paths dropped such keys; the single-part paths compared
case-sensitively against a lowercase prefix, so a key differing only in case passed through
and collided at the backend, where S3 lower-cases it. The result is a stored object the
proxy can no longer read: a denial-of-restore path that any client can trigger, with no
credential beyond the one it already has, and no error at upload time.

All three are instances of the same rule the product is built on: a control that exists
only in configuration or documentation is worse than no control, because it gets relied
upon. The prefix was documented as a namespace and enforced as nothing.

## Decision

- **D1.** The configured prefix (`encryption.metadata_key_prefix`, default `s3ep-`) is the
  proxy's exclusive namespace inside an object's user metadata. Every key the proxy writes
  carries it, and no key outside the proxy's own set may carry it.
- **D2** (amended 2026-09-09). The prefix is validated at startup: it must match
  `^[a-z0-9][a-z0-9-]{2,}-$` — lowercase letters, digits and dashes, starting with a letter
  or a digit, at least four characters long, and ending in `-`. The trailing dash puts the
  end of the namespace on a word boundary, so a prefix cannot capture a client key that
  merely begins with the same letters; the minimum length rules out two-letter namespaces
  such as `s3-`. Any other value is a startup error that names the configuration key and
  the rule. The proxy does not start. Until 5.0.0 the released rule is the weaker
  `^[a-z0-9-]+$`.
- **D3.** An invalid prefix is never normalised, lower-cased, trimmed or replaced by the
  default. A configuration that would have caused silent data exposure fails loudly instead
  of being quietly repaired.
- **D4.** No code path substitutes a literal prefix for the configured one. There is one
  prefix per deployment and it comes from configuration.
- **D5.** Every comparison against the prefix lower-cases the key first. S3 lower-cases user
  metadata keys in transit, so a case-sensitive comparison is a hole by construction, on the
  write side and on the read side alike.
- **D6.** A write whose user metadata carries a key inside the namespace is **refused**:
  `PUT` and `CreateMultipartUpload` answer `400 InvalidArgument` and name the offending key.
  The key is not stripped, not renamed, and not stored. One rule, applied identically on
  every write path — single `PUT`, the proxy's internal multipart path and the client-driven
  multipart path.
- **D7.** Every key inside the namespace is removed from every client-visible response —
  `GET`, `HEAD` and ranged `GET`. The namespace is invisible from outside the proxy, and the
  wrapped data key never reaches a client.
- **D8.** Which keys exist inside the namespace is part of the stored object format, not
  part of this decision. The key set changes when the format changes (ADR 0003).

## Consequences

- **A configuration that used to boot now refuses to.** An empty or capitalised prefix was
  accepted before 4.0.0; it is a startup failure now. That is a breaking change and was
  released as one. It is also the intended outcome: every deployment that was running one
  of those values was either serving ciphertext as plaintext or leaking its wrapped data
  keys to clients.
- **A client that legitimately uses metadata keys starting with the prefix breaks.** It gets
  `400 InvalidArgument` where it previously got `200 OK` and a silently dropped key. This is
  the accepted cost of the fail-loud stance: the client learns at upload time that its key
  was not stored, rather than discovering the loss on read, or never.
- **The refusal is the only honest option once responses are filtered.** Because the response
  filter is a prefix test, a client key stored inside the namespace would also be stripped
  from every response — the client would lose it twice: once to the collision, once to the
  filter. Storing it silently is not a middle ground.
- **A default prefix change is a stored-data break.** Objects written under one prefix are
  not readable under another, and the startup guard cannot see this: both values are valid
  in isolation. Changing the prefix of a deployment that holds data is a migration, not a
  configuration edit.
- **The rule constrains shape, length and separator** since 2026-09-09, and nothing else:
  no maximum length, no ban on repeated dashes. A deployment whose prefix is shorter than
  four characters or lacks the trailing dash stops starting after the upgrade to 5.0.0. No
  shipped value is affected: all four end in `-` and are five characters or longer. An
  operator with such a value renames it, which for a bucket that already holds objects is
  the stored-data migration of the previous point.
- **Three write paths that behave differently collapse onto one rule.** That removes a class
  of bug where a defect fixed on the single `PUT` path stays open on a multipart path — the
  case-sensitivity hole is exactly that bug — at the cost of one shared check every write
  with user metadata pays.

## Alternatives Considered

- **Strip a client key inside the namespace silently on every path, writing the proxy's own
  keys last.** Nothing breaks for the client, which is the whole appeal. It loses because
  the loss is silent: the client is told `200 OK` about metadata that was discarded. That is
  the same silent-drop-with-200 failure the product refuses elsewhere (ADR 0007), and it
  leaves the client with no way to notice.
- **Normalise an invalid prefix at startup** — lower-case it, or fall back to the default
  when it is empty. Rejected: a configuration that would have turned the proxy into a
  shredder must fail loudly, not be quietly repaired into something the operator did not
  write. It would also hide the operator's actual intent behind a value they never chose.
- **Warn on an invalid prefix and continue.** Rejected for the reason this decision exists at
  all: a warning in a log the operator does not read is a control that exists only in
  documentation.
- **Make the reader honour an empty prefix literally** instead of refusing the value.
  Rejected because it is arithmetically wrong: an empty prefix is a prefix of every key, so
  every client metadata key would be classified as the proxy's own and nothing would pass
  through. Neither honouring nor ignoring an empty prefix is correct, which is what makes it
  a configuration error rather than a code branch.
- **Leave the client-key collision to the storage format work**, on the grounds that a format
  where every stored byte is authenticated makes a collided object fail loudly rather than
  silently. Rejected: it would still be a client-triggerable way to make an object
  permanently unreadable, and the refusal is cheap and independent of the format.

## Residual risks

- **Settled 2026-09-09: a trailing separator and a minimum length are required (D2).**
  Matching stays a pure prefix test; the shape rule is what makes that test safe. A prefix
  can still be a poor namespace by choice — `abc-` passes — but it can no longer capture a
  client key by accident of spelling.
- **No maximum length is enforced.** An absurdly long but syntactically valid prefix passes
  startup validation and then fails at the backend with an opaque S3 error, at request time
  rather than at start time. Accepted; the failure is loud, just late and badly located.
- **Changing a valid prefix to another valid prefix is undetectable at startup**, and under
  the segment chain it is no longer a silent pass-through: an object whose metadata carries
  no key under the configured prefix is refused with `InvalidObjectState` (ADR 0003 D10).
  Settled there; this record only points at it. The startup guard still cannot tell a
  renamed prefix from a fresh deployment, so the rename stays a documented migration.
- **A prefix set in the wrong place in a deployment's values is not validated at all.** At
  least one shipped deployment template carries `metadata_key_prefix` inside a provider's
  own configuration block, where it is absorbed as free-form provider configuration and no
  validation sees it. The value in question happens to be valid, so nothing is broken today.
  Correcting the placement is a change to that template, not to this decision; until it
  lands, D2 does not cover a prefix set in the wrong place.
- **A second, unreachable validation routine with the opposite rule still exists**, one that
  explicitly treats an empty prefix as valid. It has no caller, so it changes no behaviour,
  but it now contradicts the live rule and is deleted with the rest of the dead configuration
  code.
- **Not verified: whether any real S3 client legitimately uses metadata keys beginning with
  `s3ep-`.** No survey was done. The refusal in D6 assumes the collision space is empty in
  practice; if it is not, an affected client sees a hard `400` rather than a degradation.
- **Not verified by measurement: the cost of the per-key check on the write path.** It is a
  lower-case comparison per user metadata key on requests that carry user metadata, expected
  to be irrelevant next to encryption, but it was not benchmarked (ADR 0020 is the standard
  it would have to meet if anyone claims otherwise).

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0002 — One data key per object, wrapped by a configured key encryption key
- ADR 0003 — Objects are stored as an authenticated segment chain (defines which keys live
  inside this namespace)
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0008 — Every response describes the proxy, never the backend
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0020 — Performance is measured before and after, never asserted
- [README.md](../../README.md) — the `encryption.metadata_key_prefix` reference and the
  operator-facing note on what an invalid prefix used to do
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — what is written into object
  metadata, what is never written, and what is filtered out of client responses
