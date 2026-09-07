# ADR 0017: Stored data compatibility is not owed; a major release may break the format

## Status

**Accepted.** Date: 2026-09-07.

**Implemented today: none of the break.** The current release line is 4.0.x, and it stores
objects in the format 3.x stored them in. The rule itself is older than this record and is
already visible one layer down: removing a key provider from the configuration makes every
object written under it permanently unreadable, the product ships no re-encryption job, and
re-writing objects through the proxy is what the documentation already calls the migration.

**Decided and specified, not implemented:** the format change that this rule pays for, the
refusal of objects the proxy did not write in the current format, the removal of the
configuration keys that go with it, the release notes that state the incompatibility, and
the upgrade rehearsal that proves those notes. All of it lands together in **5.0.0**.
Objects written by **3.x and by 4.0.x are equally unreadable** afterwards — 4.0.0 was cut
without any of this work, so the break is against both lines.

The precondition this decision rests on was confirmed by the repository owner on
2026-09-06: no deployment is known to hold data at rest that must stay readable across the
change. The precondition is stated rather than assumed precisely because it can fail; the
fallback is in D2 and in Residual risks.

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

**D3.** The migration is that the operator uploads the objects again through the new
release. The product ships no re-encryption job, no in-place converter and no dual-format
reader, at the format layer or at the key layer.

**D4.** An object the current release did not write in the current format is refused, never
guessed at. Which objects are refused, on which verbs and with which S3 error, is ADR 0003;
what this decision adds is that the refusal is not negotiable at a format break and carries
no opt-out setting. It is what makes the break honest: the difference between an operator
seeing an error per object and a client silently receiving ciphertext or substituted bytes.

**D5.** The release that causes the incompatibility states it in its release notes: which
release lines' objects stop being readable, which stored metadata keys change or disappear,
which configuration keys are removed, which configuration values now refuse startup, and
numbered migration steps — stop writers, upgrade, re-upload, verify a sample by SHA-256,
resume.

**D6.** The upgrade is rehearsed once before the release, on a running stack rather than on
paper: a stack of the previous release with objects in the backend, upgraded in place to
the new build, a read of an old object answering `InvalidObjectState` 403, a re-upload
through the new proxy, and a read that matches the original by SHA-256. The result is
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
  upgrade. The migration steps as drafted say "stop writers, upgrade, re-upload" and do not
  name where the plaintext comes from. Nothing in the product does this for the operator.
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
- **The fixes wait for the bundle.** Holding every breaking change for one major means the
  defects that motivated it — unverified ranged reads, a tamper that no setting refuses,
  the keystream re-use a re-uploaded part would cause — stay shipped until the major
  lands. That is the price of costing the operator one migration instead of three.
- **Configuration breaks in two different ways.** A removed key is silent; an invalid value
  is fatal at startup. An operator upgrading with a stale file may get a clean start and a
  changed behaviour, or a refusal, depending on which half of the change touched them.
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
- **The fallback exists on paper only.** No read-only path for the previous format has been
  built or tested. If the precondition fails late, the fallback is a design that enters the
  schedule at the worst possible moment.
- **The rehearsal has not been run.** Until it has, the release notes describe an upgrade
  nobody has performed end to end, including the claim that an old object answers 403.
- **Open: where the plaintext for the re-upload comes from.** For an operator whose only
  copy is in the bucket, the documented steps are incomplete. Not settled, and no tool
  exists.
- **Open: rolling upgrades.** A deployment with more than one replica runs both releases at
  once during a rollout. The migration steps assume writers are stopped; nothing in the
  product enforces or detects that, and the behaviour of a bucket written by both releases
  during the window has not been examined.
- **A stale configuration keeps loading.** Nothing checks that a deployment dropped the
  removed keys, and no telemetry reports it. The release notes are the only mechanism, and
  they only reach someone who reads them.
- **Switching the active provider to the pass-through type is not a migration route.** It
  does not make old objects readable; it hands the stored ciphertext to the client as if it
  were content. It stays available as a testing and end-of-life aid and nothing more.
- **Which client-visible behaviour changes ride the same major is still being settled**
  item by item. The stored-format break itself is not in question; the surrounding set is,
  and until it closes the release-notes list is provisional.
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
- [README.md](../../README.md) — the operator-facing upgrade and migration procedure, and
  the meaning of the refusal an old object answers with.
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the threat model rule that
  the stored format may change without a migration path, and key rotation as the same
  re-upload story one layer down.
