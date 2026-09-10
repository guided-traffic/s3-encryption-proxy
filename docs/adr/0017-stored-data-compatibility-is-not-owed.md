# ADR 0017: Stored data compatibility is not owed; a major release may break the format

## Status

**Accepted.** Date: 2026-09-07.

**The break is made; what proves it to an operator is not.** On the 5.0.0 branch the format
change this rule pays for is implemented, and so is the refusal of objects the proxy did not
write in the current format: `GET`, `HEAD` and a ranged `GET` answer `InvalidObjectState` 403
rather than serving bytes the proxy cannot authenticate, and no setting lets them through.
Objects written by **3.x and by 4.0.x are equally unreadable** afterwards — 4.0.0 was cut
without any of this work, so the break is against both lines.

**D9 holds for the tree and not only for the format, 2026-09-10. The previous format's code is
deleted, not left unreachable.** Gone: the whole-object `aes-gcm` path, the streaming `aes-ctr`
path, the wrapping layer between them and the key providers, the separate integrity layer the
four `encryption.integrity_verification` modes selected, and the fallbacks that read stored
metadata under the unprefixed legacy names. `s3ep-aes-iv` and `s3ep-hmac` are neither written
nor read; beside the client's own metadata an object carries `s3ep-dek-algorithm`,
`s3ep-encrypted-dek`, `s3ep-kek-fingerprint` and `s3ep-kek-algorithm`. One reader ships, and
nothing a configuration file can say selects another. The Context below describes the tree as
it stood before that removal.

**The configuration removals of D7 are done, 2026-09-10** — in the loader, in the shipped
examples and in the production deployment values alike: `encryption.integrity_verification`
with its four modes `off`, `lax`, `strict` and `hybrid`, `optimizations.streaming_threshold`,
`optimizations.streaming_buffer_size`, `optimizations.enable_adaptive_buffering`,
`s3_backend.use_tls`, every `s3_security` key except `max_clock_skew_seconds`, the never-read
`encryption.algorithm` and `encryption.key_rotation_days`, and the legacy top-level backend
block — `target_endpoint`, `region`, `access_key_id`, `secret_key`, `use_tls`,
`skip_ssl_verification` — together with its migration into `s3_backend`. A file that still uses
that block does not start: it fails with `s3_backend.target_endpoint is required`. Every other
removed key is ignored in silence, which is what D7 says it will be.

**Amended 2026-09-10, both refusals D8 names are now built.**
`encryption.providers[].config.aes_key` is admitted only as base64 of exactly 32 bytes that are
neither all printable nor drawn from too few distinct values, and startup refuses anything else
naming the field. `optimizations.streaming_segment_size` is checked for its 5 MB to 5 GB range
**and for segment alignment**, so a value that is not a multiple of the segment size refuses the
start rather than failing every upload larger than one part. That check is ADR 0011 D7.

**Still outstanding:** the release itself. No 5.0.0 is tagged, so the release notes D5 asks for
do not exist yet; what exists is the upgrade section of the operator documentation and the
breaking-change footers of the commits that made the break. The upgrade rehearsal of D6 has not
been run. A break nobody is warned about is the failure mode this decision exists to prevent,
so neither is optional for the release.

The precondition this decision rests on was confirmed by the repository owner on
2026-09-06: no deployment is known to hold data at rest that must stay readable across the
change. The precondition is stated rather than assumed precisely because it can fail; the
fallback is in D2 and in Residual risks.

**Amended 2026-09-09:** there is no migration procedure (D3, D5). The operator uploads the
data again from its source; the product documents no way to get plaintext out of a bucket
the new release cannot read, because no known deployment holds one. The rehearsal of D6
proves the refusal and a fresh upload, not a migration.

## Context

The project rule is that no backward compatibility is owed. That is cheap for interfaces
and expensive in exactly one place: the bytes already lying in somebody's bucket.

The stored format shipped through 4.0.x cannot be repaired compatibly. It authenticates
whole objects, so a ranged read is checked against nothing; integrity is a separate stored
value, so removing one metadata key switches verification off; an object carrying no proxy
metadata at all is handed to the client as plaintext even under an encrypting provider; and
a re-uploaded multipart part would encrypt twice at the same keystream offset, latent today
only because such a retry blocks instead of overwriting. Fixing those is a different layout,
a different set of stored metadata keys, a different derivation for the key identifier and a
different wrapped-key encoding. There is no version of the fix that leaves
an old object readable by the code that reads a new one.

So the choice was never "break or do not break". It was **break, or ship two readers**. The
second reader is not free: it is the whole decrypt path the new format deletes, kept alive
next to its replacement, unable to gain any of the properties the new format exists for,
and scheduled for deletion later anyway — a second change on top of the first.

Two concrete failures shaped how the break is done.

**Guessing is what the current code does, and it is the defect.** Today an object without
proxy metadata is served as its stored bytes. A hostile backend can therefore choose which
reader the proxy uses by editing metadata. Any "read whatever fits" migration strategy is
that same failure with a friendlier name, which is why an unreadable object has to be a
refusal and not a best effort.

**A silent configuration is the same failure in the other half.** The configuration loader
ignores keys it does not know, so a configuration written for an earlier release keeps
loading after a key is removed and quietly loses whatever the key described. A key that is
accepted and does nothing is the control-that-exists-only-in-configuration failure this
project treats as worse than no control.

One more force is timing. Every additional format break costs the operator another full
re-upload of every object. That is what makes bundling non-negotiable: the changes that
break the format — the layout, the key identifier derivation, the authenticated wrap, the
key admission rules — are pulled forward into the same release rather than shipped after
it, even when each on its own would have been comfortable in a later minor.

## Decision

**D1.** No compatibility is owed for data at rest. A major release may change the stored
object layout, the stored metadata keys and their values, and the derivation of the key
identifier, with no migration path and no read path for what came before.

**D2.** The rule holds on a stated precondition: no deployment is known to hold data at
rest that must survive the change. The precondition is confirmed with the repository owner
per breaking release, not assumed. If it ever fails, the fallback is a **read-only** path
for the previous format — refusing semantics only, ranged reads served by full decryption,
writes in the new format from the first day, and the old path deleted once a documented
re-encryption pass has run. That fallback is a design, not a built feature, and nothing
else about this decision changes when it is used.

**D3** (amended 2026-09-09). There is no migration. The operator uploads the data again
through the new release **from its source**. The product ships no re-encryption job, no
in-place converter, no dual-format reader and no procedure for extracting plaintext from a
bucket the new release cannot read, at the format layer or at the key layer. An object the
new release refuses is deleted or left to expire.

**D4.** An object the current release did not write in the current format is refused, never
guessed at. Which objects are refused, on which verbs and with which S3 error, is ADR 0003;
what this decision adds is that the refusal is not negotiable at a format break and carries
no opt-out setting. It is what makes the break honest: the difference between an operator
seeing an error per object and a client silently receiving ciphertext or substituted bytes.

**D5.** The release that causes the incompatibility states it in its release notes: which
release lines' objects stop being readable, which stored metadata keys change or disappear,
which configuration keys are removed, which configuration values now refuse startup, and
the plain statement that there is no migration: objects the new release refuses are
uploaded again from their source; one proxy version runs at a time; and an object written
by the previous release during a mixed rollout is refused afterwards like any other
(amended 2026-09-09).

**D6.** The upgrade is rehearsed once before the release, on a running stack rather than on
paper: a stack of the previous release with objects in the backend, upgraded in place to
the new build, a read of an old object answering `InvalidObjectState` 403, a fresh upload
of the same content through the new proxy, and a read that matches the original by SHA-256. The result is
recorded with the release.

**D7.** The same rule applies to configuration. A removed key is removed — no alias, no
deprecation window, no shim, and no migration of a legacy block into its replacement. The
removal is announced in the release notes and nowhere else, because the loader has no way
to complain about a key that is no longer declared.

**D8.** Where a change makes an existing configuration *value* invalid rather than absent,
the proxy refuses to start and the error names the field. Silent fixups are not offered.
This is why the same release both drops `encryption.integrity_verification` and
`optimizations.streaming_threshold` without comment and refuses to start on an
`optimizations.streaming_segment_size` that is not a multiple of 65536 or an
`encryption.providers[].config.aes_key` that is not base64 of exactly 32 acceptable bytes.

**D9.** Backward-compatibility code is deleted, not carried. Legacy configuration blocks
and the fallbacks that read stored metadata under older key names go with the release that
breaks the format; the read path recognises one shape.

**D10.** Everything that forces the operator to act at upgrade time ships in one major
release, so one upgrade costs one migration. A change that would break the stored format a
second time is pulled into that release or waits for the next major; it never lands in a
minor.

## Consequences

- **Every stored object has to be written again.** For a bucket that is the only copy of
  the data, that means reading the objects out with the previous release *before* the
  upgrade, which is what the operator documentation now tells the operator to do. Nothing in
  the product does it: no job, no converter, and no read path for the old bytes to fall back
  on.
- **Writers are stopped for the length of the migration**, and while it runs the bucket
  holds both kinds of object: the migrated ones serve, the rest answer 403. For a backup
  bucket that means restores are unavailable until the object in question has been moved.
- **The failure is loud but late.** A client discovers the incompatibility one object at a
  time, as a 403 on read. That is the intended behaviour and it is still an outage.
- **A re-upload produces new objects.** Modification times, entity tags and version
  identifiers change, so a client that reconciles against them sees the entire bucket as
  changed. Not verified against any named client.
- **The old ciphertext does not disappear by itself.** On a versioned bucket the previous
  versions remain, unreadable, and pay storage until a lifecycle rule removes them; under a
  retention lock they cannot be removed at all. Reasoning about how these backends behave,
  not verified here.
- **There is no downgrade.** Once objects are written in the new format, returning to the
  previous release makes them unreadable in the other direction. Nothing in the product
  prevents that move or warns about it.
- **The fallback of D2 became a rebuild rather than a retention.** The old reader is deleted,
  not dormant, so if the precondition ever fails the read-only path has to be written again
  from a released version of it. That is the other side of D9 and it was chosen: a reader kept
  in the tree for the fallback is a reader whose defects ship in every deployment.
- **The fixes wait for the bundle.** Holding every breaking change for one major means the
  defects that motivated it — unverified ranged reads, a tamper that no setting refuses,
  the keystream re-use a re-uploaded part would cause — stay shipped until the major
  lands. That is the price of costing the operator one migration instead of three.
- **Configuration breaks in two different ways.** A removed key is silent; a value the proxy
  cannot work with is fatal at startup. An operator upgrading with a stale file may get a
  clean start and a changed behaviour, or a refusal, depending on which half of the change
  touched them. The legacy top-level backend block is the loud half: dropping its migration
  leaves `s3_backend.target_endpoint` unset and startup says so.
- **A carried-over `optimizations.streaming_segment_size` that is not a multiple of the segment
  size refuses the start**, naming the key and the required multiple, rather than starting and
  failing the first upload larger than one part. The startup check of ADR 0011 D7 is what makes
  D8's promise cover this key.
- **The rehearsal costs a full stack cycle** before the release, on top of the test suites.
  It is the only step that proves the release notes describe what actually happens.

## Alternatives Considered

**Keep a read-only path for the previous format until every object has been rewritten.**
The stated fallback of D2, and the honest option if the precondition fails. It lost while
the precondition holds: it means shipping and maintaining the entire old decrypt path — its
whole-object verification, its two-request ranged reads — next to the new one, in exactly
the code the new format deletes, and then deleting it in a later release anyway. Two
readers, two test matrices, and a deployment that "works" on the old path is a deployment
still running with the defects the change exists to remove.

**Keep both readers permanently: read old, write new.** The same cost with no exit. Every
later change to the read path would have to be made twice, forever, to serve data that the
project has no evidence anyone holds.

**Detect the format and read whatever fits.** Superficially the friendliest option. It is
the failure described in Context: the format is decided by metadata the backend can edit,
so the backend picks the reader. Rejected outright — refusal is the only answer that keeps
the threat model intact.

**Re-encrypt objects lazily on read.** No operator work, and the bucket converges by
itself. Rejected: it turns a read into a write the client never asked for, which is a
mutation of a versioned or locked object; it needs the old reader anyway, so it is the
two-reader option with extra failure modes; and it never terminates, so the old code can
never be deleted.

**Ship a migration tool with the release.** Attractive until you ask what is inside it: to
read the old objects it needs the old reader and the old key identifier derivation. It is
the read-only path in a different binary, with the additional problem that it holds
plaintext outside the proxy while it runs.

**A deprecation window for removed configuration keys** — accept them for one minor, warn,
then remove. Rejected: the loader silently accepts unknown keys anyway, so the warning
could only fire for keys still declared, and a declared key that does nothing is precisely
the dead-control failure this project refuses to ship.

**Ship the format change as a minor and describe the break in the notes.** Rejected: the
version number is the only signal an automated upgrade reads, and a release that makes
stored data unreadable is the definition of a major.

## Residual risks

- **"No production deployment" is not verified and cannot be, from inside this
  repository.** Releases are public and the chart is installable; the evidence is the
  repository owner's knowledge of the deployments he knows about. Every encrypting
  deployment holds a license issued by the vendor, which is the one record that could turn
  the assumption into a check — **it is not verified that the issued-license record was
  consulted**.
- **The fallback exists on paper only, and now starts further back.** No read-only path for
  the previous format has been built or tested, and since the old code is deleted rather than
  dormant, building one starts from a released version of it. If the precondition fails late,
  the fallback is a design that enters the schedule at the worst possible moment.
- **The rehearsal has not been run.** The refusal is exercised over the wire against an
  object whose proxy metadata was stripped in the backend, which is the same decision an old
  object meets; an object a 4.0.x proxy actually wrote — one carrying `aes-ctr` or `aes-gcm`
  in `s3ep-dek-algorithm` — has never been read through a 5.0.0 proxy. Until D6 runs, the
  upgrade is described but not performed.
- **Settled 2026-09-09: the plaintext comes from the source, or from nowhere.** There is no
  migration and no tool. With no known deployment holding data, the release notes say so
  plainly instead of describing steps nobody can follow. An operator who turns up with data
  only in the bucket has the two-proxy route — the previous release reads, the new one
  writes — and the product neither documents nor tests it.
- **Settled 2026-09-09: rolling upgrades are a release-notes line, not a mechanism.** Run one
  version at a time. Nothing in the product detects a mixed window; an object the previous
  release writes during one is refused afterwards, loudly, like any foreign object. Not
  examined further.
- **A stale configuration keeps loading.** Nothing checks that a deployment dropped the
  removed keys, and no telemetry reports it. The release notes are the only mechanism, and
  they only reach someone who reads them.
- **Switching the active provider to the pass-through type is not a migration route.** It
  does not make old objects readable; it hands the stored ciphertext to the client as if it
  were content. It stays available as a testing and end-of-life aid and nothing more.
- **The break the operator sees is wider than the stored format, and nothing checks that the
  notes list all of it.** The same release also removes metric series a dashboard from an
  earlier version charts, and every configuration key no code read. Those are written down,
  but in their own sections of the operator documentation rather than in its upgrade summary,
  and the release notes are assembled from them by hand.
- **Not verified: whether any supported client treats a full re-upload as data loss** —
  a client reconciling on entity tags or modification times would see the whole bucket
  change at once.

## References

- ADR 0001 — *The S3 backend is hostile, and only the proxy's own verification counts* —
  why an unreadable object is refused instead of guessed at.
- ADR 0002 — *One data key per object, wrapped by a configured key encryption key* — the
  key-layer form of the same rule: several key providers may be configured at once so
  objects survive a key rotation, and removing one makes its objects unreadable with
  re-upload as the only migration.
- ADR 0003 — *Objects are stored as an authenticated segment chain* — the format this break
  buys, and the refusal semantics D4 relies on.
- ADR 0004 — *One local key provider: 256 random bits, an authenticated wrap, no
  passphrases* — the key admission and wrap changes that ride the same major under D10.
- ADR 0013 — *A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start* — the general rule behind D7 and D8.
- ADR 0018 — *A major release is declared by a label, never discovered at merge
  deliberately* — how the major is declared, and why the current line carries none of this
  work.
- ADR 0019 — *Integration and end-to-end tests are the product; they are never skipped* —
  the suites that run alongside the rehearsal of D6.
- [README.md](../../README.md) — the operator-facing upgrade section: which release lines
  stop being readable, which configuration keys are gone, and the meaning of the refusal an
  old object answers with.
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the threat model rule that
  the stored format may change without a migration path, and key rotation as the same
  re-upload story one layer down.
