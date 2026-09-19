# 040 — Managed buckets: a startup readability verdict, and a pass that moves a bucket onto the current KEK

Raised 2026-09-14 by the owner. **Planning only. Nothing in this file is
decided** — every fork under *Open questions* is settled in ticket refining, not
before. Everything under *What the tree looks like today* was verified against
the branch on 2026-09-14. Everything under *Measured* was **executed** against
the running demo stack that day, through the proxy and directly against MinIO;
it is not reasoned about. Claims that are S3 semantics rather than observation
are marked as such, and they are the ones to re-check first.

## What it is

Six things, and the first open question is whether they are one ticket:

1. **A managed-bucket list in the configuration.** One or more buckets the
   deployment declares as its own.
2. **A startup verdict per managed bucket.** Is it reachable, what may the proxy
   do in it, and can every object in it be read — encrypted (is the key that
   wraps its data key configured?) or plaintext (no key needed).
3. **A failure policy over that verdict**: `fail-on-bucket-missing`,
   `fail-on-missing-permissions`, `fail-on-file-not-readable`, and whatever else
   the mechanics turn out to require.
4. **A pass that moves a bucket onto the current key encryption key.** A
   plaintext object is read (its checksum verified), sealed under a fresh data
   key and written back over the original. An object whose data key is wrapped
   by a key that is no longer the active one is moved onto the current one.
5. **A readiness switch**: the proxy serves while the pass runs, or stays unready
   until it finishes.
6. **Progress for the init phase** — enough to estimate the remaining time, and
   no more than that.

## The decisions it collides with

This is the part that cannot be worked around by design. **Item 4 is forbidden
verbatim by three accepted ADRs**, and item 2 falsifies a fourth record's stated
consequence:

| Record | What it says | What collides |
|---|---|---|
| [ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md) D3, amended 2026-09-09 | "There is no migration … The product ships no re-encryption job, no in-place converter, no dual-format reader and no procedure for extracting plaintext from a bucket the new release cannot read, **at the format layer or at the key layer**." | The last clause was written to cover the key layer, which is exactly where item 4 lives. It cannot be argued as out of scope |
| [ADR 0002](../adr/0002-one-data-key-per-object.md) D7 | "Key rotation is a configuration procedure, not an operation … **There is no re-encryption job and no rotation call**; re-writing objects through the proxy is the migration." | Item 4 is that job |
| [ADR 0004](../adr/0004-one-local-key-provider.md) D12 | "The product exposes no key-rotation operation." Its `Status` records that `encryption.key_rotation_days` was deleted "so no configuration file hints at the rotation operation D12 says the product does not have" | A rotation-shaped configuration key walks straight back into a key the project deliberately removed |
| [ADR 0002](../adr/0002-one-data-key-per-object.md), *Consequences* | "**Removing a provider destroys data.** The bucket is not consulted at startup **and cannot be**: the proxy has no way to know which fingerprints are still referenced by stored objects." | Item 2 makes the word "cannot" untrue. This is a Consequence, not a numbered Decision, so it is the weakest of the four — but it is an accepted record asserting an impossibility the feature removes |
| [038](038-s3-encryption-operator.md), *What it must not break* | "**The stored format.** No operator action rewrites, migrates or re-encrypts an object" | If this ever becomes an operator capability, 038's own constraint has to be renegotiated |

There is one internal inconsistency worth quoting when the amendment is written:
**ADR 0017 D2 already assumes a "documented re-encryption pass" exists** in its
own fallback design, while D3 says the product ships none. And
[ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)'s *Alternatives* left the
door open in as many words: "a tool can still be added later for someone who
wants the bucket converted in place."

**Consequence for the work order.** Under
[ADR 0022](../adr/0022-tickets-are-work-lists-that-get-archived.md) D2 an ADR is
written in the session the decision is taken, not when the code lands. So the
amendments to ADR 0017 D3, ADR 0002 D7, ADR 0004 D12 and ADR 0002's startup
Consequence are **the first work item of item 4**, not its last.

**2026-09-17.** The owner asked that the copier of
[017](017-filename-encryption.md) be built as an extensible pass engine whose
interfaces later carry this ticket's item 4 (see 017, F11: enumeration, plan,
conditional transfer, verify, delete-source policy, report, configuration). The
engine and its rename operation may exist before the amendments above; the
rewrap operation may not. 017's F11 records what this ticket measured as
constraints on every operation of that engine.

## Prior art already in this directory

Three live tickets have worked parts of this, and a fourth rules itself out.
Adopting their vocabulary costs nothing; inventing a second one costs the project
a second language for the same three operations.

- **[025](025-tink-kms-hcvault.md) is the largest overlap.** It already carries
  the rewrap campaign, including a table that separates what item 4 conflates —
  *rotate in the KMS* (no bytes rewritten), *retire an old key version* (a rewrap
  campaign, the whole bucket rewritten server-side) and *move to a different key*
  (add a provider, switch the alias, no rewrite). It also states, at 025:61, the
  finding this ticket's *Measured* section confirms: "**A rewrap campaign is not
  a metadata edit.** … Cost scales with bytes, not with object count." And at
  025:63 it records why the campaign cannot run through the proxy: "The proxy has
  no copy primitive left to borrow … It must stay that way, or every
  authenticated client gets a metadata-rewrite primitive."
- **[017](017-filename-encryption.md) designed the tool surface** for a
  bucket-wide pass: `migrate`, `verify` ("proves a bucket is fully migrated") and
  `audit` ("lists undecryptable keys"), with a pre-flight that "refuses the whole
  migration by default" on a locked, held or archived object and an
  `--allow-partial` opt-in. Items 2 and 3 are `verify` and `audit` in another
  guise.
- **[033](033-out-of-band-recovery-path.md)** is the third record concluding
  "a separate tool, never the proxy", and its five open questions — where it
  lives, how consent is stated, whether it reads the configuration — are the same
  five. If both end up as subcommands, that is one decision taken once.
- **[036](036-high-availability.md)** has no overlap beyond the shared argument
  that a top-level block the proxy defines later breaks no existing operator
  file, so nothing has to be reserved in advance.

## What the tree looks like today

**Configuration.** `viper.Unmarshal` runs with `ErrorUnused = true`
([config.go:324-334](../../internal/config/config.go#L324)), so a key the struct
does not define refuses the start. That cuts both ways: the list cannot appear in
an example or the documentation before the field exists, and
[ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D10
makes removing it later a breaking change. There is exactly one hole in
`ErrorUnused` — `EncryptionProvider.Config` is a `mapstructure:",remain"` field,
so anything nested under a provider loses strict-key checking and needs its own
allowlist entry in `providerConfigKeys`. **There is no bucket-scoped
configuration anywhere today**; `git grep -ni bucket -- internal/config/` returns
three comments and nothing else. Per-entry defaults for a list cannot go in
`setDefaults` (viper defaults a key, not a list element) — they go in a
`resolve*` function after `${VAR}` expansion, the slot `resolveBackends` occupies
([config.go:449-470](../../internal/config/config.go#L449)). `${VAR}` expansion
covers a named field list only ([envexpand.go:45-102](../../internal/config/envexpand.go#L45)):
the four fields per `s3_backends` entry, two per `s3_clients` entry, and strings
under `encryption.providers[].config`. **A bucket name written as `${VAR}` would
reach the S3 client as literal text.**

**Startup.** Nothing in the process touches the network before `net.Listen`
([server.go:252](../../internal/proxy/server.go#L252)). Configuration loading
reads the licence and `os.Stat`s the TLS files and that is all. **A bucket probe
would be the first startup network call this product has ever made**, which is
what turns a backend blip from a per-request 5xx into a crash loop. The only slot
where a pre-flight can fail the process before serving is between
[main.go:128](../../cmd/s3-encryption-proxy/main.go#L128) and
[main.go:231](../../cmd/s3-encryption-proxy/main.go#L231).

**Health and the chart.** `/health` has exactly two states — healthy, and
`shutting_down` during drain
([health/handler.go](../../internal/proxy/handlers/health/handler.go)). The chart
points **liveness and readiness at the same path**
([values.yaml:134-149](../../deploy/helm/s3-encryption-proxy/values.yaml#L134)):
liveness `initialDelaySeconds: 30`, `periodSeconds: 10`, readiness
`initialDelaySeconds: 5`, `periodSeconds: 5`, both `failureThreshold: 3`.
`startupProbe` appears **0 times** in `deploy/`. So today "unready" is also
"dead", and there is no third state to report a scan into. Resource limits are
`cpu: 500m`, `memory: 512Mi`. `strategy:` is not set on the Deployment and no
values key exists for it, so the Kubernetes default RollingUpdate applies and a
rollout transiently runs two processes despite
[ADR 0033](../adr/0033-a-proxy-instance-holds-its-uploads.md) D1 — which is a
render-time check (`validateReplicas`) and detects nothing at run time.

**The backend surface.** `internal/proxy/interfaces/s3_backend.go` declares 55
methods and **none of them is `CopyObject`, `UploadPartCopy` or
`ListObjectVersions`**. `HeadBucket` and `ListObjectsV2` are there;
`GetBucketVersioning` is there; the object-lock configuration is not. Client-side
copy is refused at the front door under both providers —
[object/operations.go:349-364](../../internal/proxy/handlers/object/operations.go#L349)
answers `422 NotSupportedWithEncryption` on `x-amz-copy-source`, and
[multipart/copy.go:38-43](../../internal/proxy/handlers/multipart/copy.go#L38)
the same for `UploadPartCopy`. There is exactly one backend identity, one static
credential pair, used for everything
([server.go:108-116](../../internal/proxy/server.go#L108)).

**The read path and what a probe would cost.** A ranged read of `bytes=-40`
returns the object's metadata **and** its trailer bytes in one answer
([object/tail.go:66-90](../../internal/proxy/handlers/object/tail.go#L66)), which
strictly dominates a `HeadObject` tier — **a HEAD-only tier should not be built.**
`ListObjectsV2` does not return user metadata (S3 semantics), and the listing
handler reads size only, so every tier above LIST is one request per object.
`PlaintextSize` over a listing is keyless and free but proves only that the
stored length is one a chain could have produced.

**The verdict taxonomy is too coarse for item 3.** There are four reasons today
— `foreign_object`, `key_material`, `stored_length`, `authentication`
([object/helpers.go:94-107](../../internal/proxy/handlers/object/helpers.go#L94)).
`key_material` collapses three states that `codecFor` knows apart and then throws
away ([orchestration/segmented.go:356-383](../../internal/orchestration/segmented.go#L356)):
`ErrUnknownFingerprint` (the key is absent — fixable by supplying it),
`ErrWrappedDEKAuth` (the key is present and the wrap does not authenticate —
**not** fixable by a rewrap, and the case where item 4 would silently do the
wrong thing) and `ErrExitProviderKeyUse`. `foreign_object` collapses genuine
plaintext, an object written under a different metadata prefix, a console folder
marker and an object a third party put in the bucket. Worse, **the same object is
classified differently under different providers**: one carrying the format id
whose wrapped key is not valid base64 is `foreign_object` under an encrypting
provider and `key_material` under `exit`. A probe must classify on the
orchestration sentinels, never on the HTTP status — all four answer an identical
`403 InvalidObjectState` and differ only in a message string.

[ADR 0002](../adr/0002-one-data-key-per-object.md) D13 settles how "is the key
present" should be answered: by **trial unwrap**, not by matching the stored
fingerprint. The fingerprint is a selector; an object whose fingerprint is
damaged but whose wrap still opens is readable, and a fingerprint match would
report it as broken.

**The data-key cache is shared with the serving path.** It is a plain 1024-entry
LRU with no TTL ([orchestration/providers.go:19-24](../../internal/orchestration/providers.go#L19)),
and every object has its own data key. A scan over more than 1024 objects has a
0 % hit rate for itself **and evicts everything live traffic was using**. The
scan must bypass it — a probe path that unwraps without a cache write. This is
one line of requirement and it will be missed if it is not written down.

## Measured

Executed 2026-09-14 against the demo stack (`./start-demo.sh`), in a bucket
created for it. Each row was run, not derived.

| What was run | Result |
|---|---|
| Self-copy of a 400 KB proxy-written object, `MetadataDirective=REPLACE` carrying all four `s3ep-*` keys, then read back through the proxy | Fully readable, sha256 match, `x-amz-checksum-crc32c` served. **The crypto half of item 4 is sound** |
| Self-copy of a 20 MB object, bytes compared | Byte-identical, 46 ms against local MinIO |
| PUT 400 KB → client overwrites → unguarded self-copy carrying the job's now-stale metadata → GET | `403 InvalidObjectState: Object failed authentication`. **The object is unrecoverable** and the client had received `200` on its PUT |
| The same copy with `x-amz-copy-source-if-match` on a stale tag | `412 PreconditionFailed` — MinIO honours it, so a compare-and-swap is available |
| REPLACE on an object with `ContentType: application/json`, `Cache-Control`, `Content-Disposition`, `Content-Encoding` and `x-amz-meta-mtime`, restating only the four `s3ep-*` keys | Read back as `binary/octet-stream`, all four entity headers empty, user metadata `{}`. **rclone stores its modification time in `x-amz-meta-mtime` and is a release gate** |
| The same REPLACE restating every source key plus the entity headers | Object read back clean through the proxy. The copy must restate the **whole** object description |
| Self-copy on an Object-Lock bucket, source carrying `GOVERNANCE` + legal hold ON + a retain-until date | New version carried `lockmode=""`, `legalhold=""`, retain-until zero. **A maintenance job silently strips WORM protection** |
| `ListObjectVersions` after the self-copy | 2 versions; the noncurrent one still carries the **old** wrapped key and the **old** fingerprint. Storage for one 4096-byte logical object was 8192 bytes. `DeleteObject` on that version: `400 InvalidRequest: Object is WORM protected and cannot be overwritten` |
| Client-visible ETag of a 20 MB object (written by the internal multipart producer) before and after the self-copy | `5a3af28d…-2` → `b7e07da9…-0`. The tag changes **value and shape**, because a single `CopyObject` writes a single-part destination. A single-part object's tag survived byte-for-byte |
| A ranged backend GET under the pre-rewrap ETag after the copy | `412 PreconditionFailed` |
| Tags across a REPLACE | Survived intact (`x-amz-tagging-directive` defaults to COPY) |

Two consequences of that table are worth stating in words:

**"No re-upload" is refuted.** There is no S3 operation that edits an object's
user metadata in place. The only mechanism is a self-`CopyObject`, which S3
implements as a full server-side rewrite: a new version, a new `Last-Modified`, a
PUT-class request, a restarted lifecycle clock. **Cost scales with bytes, not
with object count** — a 50 TB bucket is a 50 TB rewrite even though no ciphertext
byte changes. The cryptography is genuinely free: the wrap's associated data is
the constant `s3ep-dek-wrap-v1` with no object binding
([keyencryption/aes.go:31](../../pkg/encryption/keyencryption/aes.go#L31)), and
the object key is bound at the **data** layer instead
([segmented_gcm.go:124-131](../../pkg/encryption/dataencryption/segmented_gcm.go#L124)),
so the segment chain survives a key change and does **not** survive a rename.

**An ordinary GET can answer 412 during the pass.** A whole-object GET above
65,604 stored bytes is two backend requests, the second pinned with `If-Match` on
the first answer's tag, deliberately, so that "an object replaced between the two
reads is a clean 412 rather than two halves of two objects"
([object/operations.go:47-55](../../internal/proxy/handlers/object/operations.go#L47)).
The pass **is** that replacement. The alignment is the worst available: small
objects are one request and their tag survives; large objects are two requests
and their tag does not.

## Costs nobody gets to choose away

Numbers below assume 10 M objects / 50 TB. Request counts and wall-clock bands
are arithmetic over the verified mechanism; **the prices are from knowledge and
must be re-checked before this ticket is quoted at anyone.**

| Depth | Requests | Rough cost | What it actually proves |
|---|---|---|---|
| Listing only | 10,000 (1000 keys/page) | minutes | The stored length is one a chain could produce. A plaintext object of coincidental size passes |
| Trailer read, `bytes=-40` | 10,000,000 | 30 min – 3 h at useful concurrency | Format id present, the key resolves, the wrap authenticates, the trailer opens, and the stored length agrees with the length the trailer authenticates. **Nothing about any data segment** |
| Full read | ~20,000,000 + every stored byte | 14 h at 1 GB/s; ~57 h at the 245 MB/s link this repo measured — and the pod is limited to 500m CPU | The only depth that catches a flipped byte inside an object |

Above roughly 5,500 GET+HEAD per second per partitioned prefix, S3 answers
`503 SlowDown` (S3 semantics, unmeasured here).

**The pre-listener budget is about 50–60 seconds.** With no listener bound both
probes get a connection refusal: NotReady at ~15–20 s, container restarted at
~50–60 s, then CrashLoopBackOff. Even the listing-only depth blows that by an
order of magnitude. And every crash-loop attempt **re-pays the scan's requests**.

**One replica means the scan is the service's downtime, not a slow pod.** ADR 0033
D1 makes `replicaCount > 1` a render failure, so a 20-minute scan makes every
restart a 20-minute total outage: OOMKill, node drain, rollout, configuration
change, and the hourly licence-expiry restart
([license/validator.go:184-186](../../internal/license/validator.go#L184)). Today
that restart is seconds. **The owner has accepted this for the deliberate
unready-until-done setting** (item 5) — what must not happen is the same cost
arriving by accident on a plain restart.

**The scan cannot hold its own results.** 10 M keys at ~100 bytes is ~1 GB before
any verdict is attached, against a 512Mi limit. It must stream into counters and
a bounded sample, which also means it **cannot** produce the per-object report
someone will ask for the day the feature ships. Fix the output shape before the
input shape.

**A 5 GiB cliff sits exactly where the pass was supposed to pay off.**
`CopyObject` is capped at 5 GiB; above it the route is
`CreateMultipartUpload` + `UploadPartCopy` + `Complete`, and **a multipart copy
inherits nothing** — all four `s3ep-*` keys, the entity headers, the storage
class, the tagging and the lock state must be re-supplied by hand. Dropping one
of the four destroys the object as surely as deleting it.
[ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)'s Context records that
this project already hit that wall: "server-side copy is hard-capped at 5 GiB:
every multipart upload above that size failed AFTER all bytes were transferred."
One thing does work in our favour: **re-parting is safe**, because the chain
records no layout and the read path computes segment positions arithmetically
from the stored size.

**A self-copy resets the storage class and the lifecycle clock**, and an object
already in an archive tier cannot be a copy source without a prior restore (S3
semantics; MinIO reported an empty storage class on both sides, so the demo stack
cannot exercise it). `InvalidObjectState` does not appear as an *inbound* backend
code in [error_mapping.go](../../internal/proxy/response/error_mapping.go) at
all, so a lifecycle-tiered bucket has no mapping today.

## Security: four things that must be argued, not assumed

1. **`fail-on-file-not-readable` is a denial-of-service primitive as specified.**
   Its input is the content of a mutable bucket the proxy does not exclusively
   own. Any writer that is not the proxy — a backup product, a replication rule,
   a second credential, a console upload, a lifecycle transition to an archive
   tier — can place **one** object that the scan classifies as unreadable, and
   with the switch on the proxy never starts again. With one replica that is a
   total outage, triggered by a third party, surviving every restart because the
   object is still there. Today's answer to such an object is a `403` on **that
   object**, which is already the correct blast radius. ADR 0025's residual risks
   made the same argument from the other side: enforcing a stored-data
   precondition at startup "would mean refusing to start over data that may no
   longer exist."
2. **`fail-on-bucket-missing` is a delayed remote kill switch.** `DeleteBucket`
   is an unguarded forward
   ([bucket/operations.go:107-127](../../internal/proxy/handlers/bucket/operations.go#L107))
   and every authenticated client may call it against any bucket — there is no
   per-client scope
   ([docs/security/tenancy-and-privilege.md](../security/tenancy-and-privilege.md#what-it-does-not-give-you)). A
   client deletes a listed bucket at 14:00, the proxy keeps serving, and the next
   Helm upgrade or reschedule fails to start. Cause and outage are separated by
   however long the process happens to live.
3. **Probing write permission means writing, and S3 has no dry run.** A probe
   object in a customer's production bucket fires bucket notifications, is
   replicated — possibly to another region or account — leaves a version and a
   delete marker on a versioned bucket, and **under compliance-mode Object Lock
   with a default retention cannot be deleted by anyone, including the account
   root, until the retention expires**. A restart loop litters a WORM bucket once
   per attempt. It also proves less than it looks: success at a probe prefix says
   nothing about `PutObject` at the prefixes clients use, because IAM and bucket
   policies are routinely prefix-scoped. The read-side alternatives do not close
   the gap — a bucket policy does not describe this identity's *effective*
   permission.
4. **The credential's blast radius widens permanently.** There is one static
   backend credential for everything, and `docs/security/tenancy-and-privilege.md`,
   *What an attacker who takes the proxy gets*, already states that it goes with
   the proxy. Item 4 needs
   bucket-wide `PutObject` and, to clear the plaintext version it leaves behind,
   `DeleteObjectVersion` — **whether or not a pass is running**. That moves a
   proxy compromise from "read and write what clients touch" to "silently
   overwrite or destroy the entire bucket including its version history."

And one document that goes stale the day a scan ships:
`docs/security/key-management.md`, *Where each secret lives*, and
`docs/security/tenancy-and-privilege.md` describe the data-key exposure as
"an LRU of up to 1024 already-unwrapped DEKs". A scan unwraps **one per object**.
There is no zeroization of key material anywhere in `internal/` or `pkg/`
(verified by grep, zero non-test hits), and Go does not zero freed memory, so a
heap profile taken during or shortly after a scan yields materially more key
material than one taken during normal serving — on a schedule an attacker can
predict, since it is every restart. `/debug/pprof/heap` is loopback-only for
exactly this reason. Both passages must be rewritten in the same change, and a
32-byte clear per probe would be this tree's first key zeroization and is worth
doing regardless.

## Two destruction paths that must be structurally impossible

1. **A rewrap racing a client PUT.** Measured above: the object is unrecoverable
   and the client was told its write succeeded. `CopySourceIfMatch` on the tag
   read in the same breath as the metadata makes the rewrap a compare-and-swap,
   and MinIO honours it. **This is a required part of the design, not a hardening
   note.** Residual: S3 evaluates the precondition against the source and then
   copies, and whether that pair is atomic against a concurrent PUT is not
   something this repository can establish.
2. **A renamed `metadata_key_prefix`.** Every metadata read is an exact,
   case-sensitive lookup on the lowercase prefixed name with no fallback
   ([orchestration/metadata.go:41-92](../../internal/orchestration/metadata.go#L41)),
   and ADR 0009 records that a prefix change is a stored-data break the startup
   guard cannot see, "because both values are valid in isolation." So a
   deployment whose prefix was edited presents **every** object as carrying no
   proxy metadata — which is the class item 4 proposes to download and encrypt.
   Running it there would seal already-encrypted ciphertext under a fresh key and
   overwrite the originals. **This is the single most dangerous interaction in
   the feature and it is reachable from one mistyped configuration key.** The
   defence has to be structural: refuse any object carrying **any** user-metadata
   key matching the proxy-prefix grammar `^[a-z0-9][a-z0-9-]{2,}-$` followed by
   one of the four known suffixes, not merely the configured prefix; and refuse
   to run when the bucket-wide classification is "everything is plaintext",
   which is far more likely to be a prefix mistake than a real bucket.

## What it must not break

- **Per-bucket pass-through is closed.** [ADR 0001](../adr/0001-the-backend-is-hostile.md)
  D5: "There is no opt-out knob." ADR 0025 D3 names the defect class directly —
  "a bucket then looks protected while the key sits beside the object" — and a
  per-bucket pass-through is that defect at bucket granularity. `CLAUDE.md` MAIN
  GOAL 1 says the same thing. The supported way to have plaintext is the `exit`
  provider, which is per-process, never per-bucket.
- **The two client e2e suites, if the list ever enforces.** Both name their
  buckets at run time — `e2e-rclone-<case>-<nanos>`
  ([rclone_test.go:299](../../test/e2e/rclone/rclone_test.go#L299)) and the same
  in [s3cmd_test.go:272](../../test/e2e/s3cmd/s3cmd_test.go#L272) — so they
  cannot appear in a static list. `harness.EnsureBucket` HEADs through the proxy
  and creates on any error. rclone R6 (`mkdir`) and s3cmd S6 (`mb`) drive the
  bucket lifecycle through the client. Velero is the odd one out — one fixed name
  from `versions.env` — so an enforcement change would red the two suites that
  create buckets and leave green the gate people trust most.
  [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md) forbids
  absorbing that inside the suites.
- **`ListBuckets` filtering is the same decision as refusing a bucket, not a
  second one.** A listing that omits a bucket the proxy still serves answers "not
  there" to `ls` and "here are your objects" to `get` — the shape
  [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D1 forbids. Three assertions
  pin the passthrough today: the s3cmd preflight, rclone R6 in both directions,
  and [list_buckets_test.go:74](../../test/integration/s3-methods/list_buckets_test.go#L74).
- **A bucket label on a metric.** No metric carries bucket or key, deliberately
  ([monitoring/metrics.go:135-136](../../internal/monitoring/metrics.go#L135)),
  and [ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md)
  D4 makes the unauthenticated scrape's emptiness a decision somebody has to keep
  true. A per-bucket verdict is a structured log line first; a metric counts by
  reason without a bucket label. 037 records the same constraint for backends.
- **`CopyObject` must not go on `S3BackendInterface`.** That interface is what
  handlers hold, and a method there is one refactor away from a client-reachable
  metadata-rewrite primitive — which is exactly what 025:63 says must not happen.
  If the pass runs in-process at all, the precedent to copy is the injected
  function value (`SetMultipartAbandoner`,
  [server.go:127-145](../../internal/proxy/server.go#L127)), never an exported
  SDK client.
- **A configuration-shape change owes `make test-conformance`.**
  `scripts/conformance-run.sh` writes its own proxy configuration and is the one
  configuration `TestCfgShippedExamplesCarryNoUnknownKeys` cannot see. It cost a
  red CI job on 2026-09-14.

## The per-bucket slope, drawn on purpose

Once buckets are a configuration concept, four things get asked for within a
release. The line to hold: **a per-bucket key that stays on the control plane —
scan scope, failure policy, reporting — is cheap and additive; a per-bucket key
that reaches the data plane changes what a stored object means and is a storage
format decision.**

1. **A key provider per bucket** — and it *almost* works, which is the danger.
   Reads already select the provider by the fingerprint stored on the object, so
   only the write side is global. Small code change, large decision: it makes
   `encryption.encryption_method_alias` no longer the answer to "what is this
   proxy writing with", and it multiplies the licence gate's subject, which reads
   the active provider only.
2. **Encryption on or off per bucket** — closed, see *What it must not break*.
3. **Prefix scoping** — cheap for the scan, ruinous on the data plane: the object
   key is bound into every segment's associated data, so nothing about a key can
   be re-decided later.
4. **A metadata prefix per bucket** — must be refused; ADR 0009's Consequences
   record that a prefix change is a stored-data break the startup guard cannot
   see.

## Open questions — all undecided

1. **Is this one ticket or two?** Items 1–3, 5 and 6 are additive and need one
   ADR amendment. Item 4 needs three, a separate credential, a process that never
   links the serving handlers, and carries every destruction path above. Shipping
   them together means the dangerous half gates the safe one. *Leaning: split,
   with item 4 becoming its own ticket once the shape of this one is settled.*
2. **Is the bucket list an inventory or a control?** Three readings share a
   configuration key and nothing else: (a) inventory that scopes the scan and the
   pass, data plane untouched; (b) an allowlist that refuses unlisted buckets;
   (c) a per-bucket policy map. (c) is closed by ADR 0001 D5 and ADR 0025 D3. (b)
   breaks two release gates, needs wildcards on day one, and contradicts
   `docs/security/tenancy-and-privilege.md`, *What it does not give you*, which
   says in those words that no bucket
   allowlist exists. *Leaning: (a), with any refusal arriving later as a second,
   separately-named key — adding an inventory is additive, adding a refusal is a
   behaviour break.*
3. **What is "readable" allowed to mean?** Pick one depth from the table above.
   This single choice sets the cost at 10 thousand requests, 10 million, or 50 TB,
   and it decides what the feature may claim. A HEAD-only tier should not be
   built either way.
4. **What is the largest managed bucket the product promises to support**, in
   objects and in bytes? Everything above is arithmetic once that number exists,
   and the progress display has no denominator without it. A stated ceiling
   ("scans up to N objects, then reports incomplete") is a better product than an
   unbounded scan.
5. **Does the verdict gate anything, or only report?** If it gates, the chart
   needs a `startupProbe` and a readiness path separate from liveness, and the
   ~50-second pre-listener budget has to be replaced with an explicit one. If it
   only reports, most of item 3 disappears and the feature gets much cheaper and
   much safer.
6. **Which failure switches survive ADR 0013 D7 and D9a?** D7: "A configuration
   that cannot work, or that silently disables a protection, refuses to start.
   The proxy does not start degraded." The *off* position of each switch means
   "I found objects I cannot read and started anyway"; the *on* position is the
   outage above. Every switch must default to **off** or the release turns every
   running deployment into a crash loop on upgrade — a safety feature shipping
   defaulting to unsafe, which is defensible but has to be written down. D7 also
   forecloses the middle value an implementer will reach for: a `warn` setting
   that is really `off` is the silent-fallback shape it names. And "and further
   ones I have forgotten" is a trap: ADR 0013 D10 makes removing a key a breaking
   change, so ship the smallest set that has a reader and a test each.
7. **Can `fail-on-bucket-missing` and `fail-on-missing-permissions` be
   separated at all?** `HeadBucket` has no response body and AWS deliberately
   conflates absence with denial; MinIO, LocalStack and Wasabi are free to
   differ, which is why ADR 0027's conformance suite exists. If they stay
   separate, the ticket owes backend-specific evidence for each, measured through
   `make test-conformance`, **before** the keys exist.
8. **Are versioned, Object-Lock and lifecycle-tiered buckets in scope?** The
   measured answer says refuse: the pass cannot retire the old key there, which
   is its only purpose, and it strips WORM protection while doing so. The
   perverse part is that versioned and locked buckets are exactly the Velero
   backup deployments this product gates releases on. If they are in scope, the
   pass needs retention and legal-hold re-supply, a noncurrent-version story, a
   restore path for archived objects, and a report that never says "migrated".
   Note also that re-encrypting a plaintext object on a versioned bucket leaves
   the plaintext one `?versionId=` away while reporting the bucket encrypted.
9. **Where does the pass run, and what triggers it?** The binary declares one
   flag (`--config`), ADR 0013 D14 says a flag does not override a configuration
   key, and there is no reload, no `SIGHUP` and no admin API. The three
   candidates — a subcommand on the existing binary, a third binary, a Kubernetes
   Job — differ in ADR consequences, in what the licence gate does to a long run,
   and in chart work: the chart has no Job, CronJob, hook or initContainer today.
   033 and 017 both point at a subcommand; if both land that way it is one
   decision taken once.
10. **Above 5 GiB: multipart copy, or refuse and report?** Either way an
    `AbortIncompleteMultipartUpload` lifecycle rule on the managed buckets
    becomes a documented prerequisite, because an orphaned upload from a dead
    pass is invisible to the proxy's own sweeper (ADR 0029 D2 sweeps only
    sessions that process holds).
11. **What does the checksum verification of the plaintext half verify
    against?** For a plaintext object the backend tag is an MD5 of the content
    only when it was written as a single-part PUT; a multipart-written object's
    tag is not a digest of anything the job can recompute. The honest answer is
    to compute the digest on the way in and verify it by reading the sealed
    object back and comparing its authenticated CRC32C — **a second full read per
    object**, which has to be stated as a cost rather than assumed away.
12. **What shape does the progress take?** S3 knows no object count, so a
    denominator exists only after a full listing pass, which is itself minutes on
    a large bucket. Either monotonic counters with no percentage
    (`scanned=… migrated=… failed=…`), or a listing pass pays for a real
    percentage and an ETA and the work starts later. The owner asked for "not too
    talky", which argues for one periodic line at a fixed interval rather than
    per-object output.
13. **Does the list live at the top level or inside an `s3_backends[]` entry?**
    Both are additive. 037 asks that additions go inside an entry and that the
    list's shape not change again; the top-level form keeps `ErrorUnused`
    strictness for free and reads as deployment-wide. Pick before the first
    example YAML ships — moving it later refuses every configuration in the field
    under ADR 0013 D11. Related: should bucket names join the `${VAR}` expansion
    field list? Deployments that template bucket names per environment will want
    it, and it is a decision rather than an oversight to fix later.
14. **Would a fingerprint-seen counter on the read path satisfy the real
    requirement?** A counter labelled by the *stored* fingerprint answers "which
    keys does this deployment still reference" — precisely the warning ADR 0002's
    Consequences call impossible — for zero extra requests, zero startup cost, no
    new credential and no new failure mode. It is strictly weaker (it sees only
    what has been read) and strictly more honest about what it knows. **If the
    real driver is "do not let an operator delete a still-referenced provider",
    this may be the whole feature**, and the ticket should have to argue why it
    is not enough before the scan is built.
15. **Should the pass be built so the copy verbs ADR 0011 D9 refuses could later
    be served by it?** ADR 0011's residual risks name "the proxy-side copy:
    fetch, decrypt, re-encrypt under the new name, streaming" as the only future
    route for those verbs. If this builds the same pipeline without that in mind,
    the project builds it twice.

## Residual risks and what was not verified

- The prices in *Costs* are from knowledge, not from a bill. Re-check before
  quoting them.
- The 5 GiB `CopyObject` cap was **not** tested against MinIO — staging a 5 GiB
  object was too expensive for the session. The proxy writes objects far past it.
- Whether a metadata replace rewrites the object on the backends this product
  targets is verified for MinIO only. 025 already lists it as outstanding for the
  others, and `make test-conformance` plus the Wasabi run are where that is
  settled.
- Whether `mux.Vars(r)` is populated inside a gorilla/mux subrouter middleware is
  unverified — no middleware in this tree reads it, so there is no precedent to
  copy. It matters only under the enforcement reading, and it needs a test before
  any design commits to the middleware shape.
- Even under the inventory reading the covered set drifts: `CreateBucket` is a
  plain forward, configuration is read once at start with no reload, so a client
  can create a bucket that is never scanned and never covered by any policy while
  the dashboard says the scan passed. Resist the obvious fix of auto-discovery —
  it turns the inventory into a full `ListBuckets` walk with the cost and
  permission problems of the wildcard case.
- Nothing normalizes or validates a bucket name anywhere in the proxy, and
  `router.SkipClean(true)` is set deliberately. Under the inventory reading this
  does not bite (both sides are canonical); under any enforcement reading the
  matching rule — percent-decoding, case, trailing characters — has to be stated
  and pinned with a test per class, because each is a bypass.

## Done when

Not scheduled. This file is a plan, and the next step is a refining session that
answers the fifteen questions above — questions 1, 2, 3 and 4 first, because
every estimate below them depends on those four answers.
