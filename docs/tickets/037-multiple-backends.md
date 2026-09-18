# 037 — Several backends kept in sync, with a fallback on an integrity refusal

## Decided and built 2026-09-14: the configuration shape, not the feature

The owner chose the symmetric list over a primary-plus-fallbacks shape, and it
landed in 5.0.0 because that is the only part of this feature that is breaking:
`s3_backend:` is now `s3_backends:`, a list. Its entry carries exactly the fields
the mapping carried. **This release reads one entry and refuses a second**, so
nothing of the feature below is built — what is built is the shape it needs.

Why it could not wait: ADR 0013 D11 refuses a key the proxy does not define, so
turning a mapping into a list in a minor would refuse every existing
configuration. Doing it in the major costs one line in an upgrade note; doing it
later costs a major of its own. Everything *inside* an entry can still be added
additively — a name, a role, a priority, a per-backend timeout — because a new key
the proxy defines breaks nothing. So this ticket no longer forces a major, and it
should not acquire one: **prefer adding keys inside an entry over changing the
list's shape again.**

Recorded as an amendment to ADR 0013. The refusal of a second entry is deliberate
rather than a stub: serving the first and ignoring the rest would be the
accept-and-discard shape ADR 0007 forbids, and an operator who listed two
backends believing both were written to would have one of them silently empty.

One constraint this ticket inherits from today: **a per-backend label on
`s3ep_object_integrity_failures_total` may not name the backend's endpoint.** The
monitoring listener is unauthenticated by design *because* the scrape carries
nothing identifying (ADR 0030 D4), and a backend host is identifying. Count per
backend by an operator-chosen name, never by address.


Raised 2026-09-14 and **announced, not scheduled**. No work has started, nothing is
designed and nothing here is decided. It is written down now for one reason: 5.0.0
is the major, a configuration key's shape is part of the interface, and under
[ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11 a
key that changes shape refuses an existing operator's start — which
[ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) D5 makes a
breaking change and therefore a major. Whatever this feature needs the
configuration to look like is free today and costs a 6.0.0 later.

The depth below is in the configuration; the feature itself is described only far
enough to make those findings readable.

## What it is

Several S3 backends hold the same objects and are kept in sync. When a read from
one backend does not authenticate — the proxy's own verification, never the
backend's word — the read is retried against another backend and answered from a
copy that opens. Writes have to reach more than one backend, which means a write
policy.

**Half of this already exists, and that is what makes it worth announcing.**
[ADR 0001](../adr/0001-the-backend-is-hostile.md) D1/D2 say the backend is an
adversary and that nothing it says counts as authentication;
[ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) is the format
that makes a manipulated object *detectable* rather than servable — a whole-object
read proves the trailer before the response begins and refuses with
`403 InvalidObjectState` (ADR 0003 D14). A fallback is only meaningful when the
proxy can already tell a bad copy from a good one. It can. What it has nowhere to
fall back *to*.

## What the tree looks like today

The bullets below were verified on 2026-09-14 against `feat/major-v5`, and
re-verified on 2026-09-14 on `feat/eraly-testing` after 5.0.0 shipped. The one that
changed is the first, and it changed because the shape landed.

- **`s3_backends:` is a list of five-field entries and the loader reads exactly
  one.** `internal/config/config.go:28-34` is the entry, `:167` the slice,
  `resolveBackends` at `:449` refuses a second by a message of its own, and
  `Config.Backend()` at `:472` is the accessor everything else calls. It has only
  four callers — `server.go:108`, `bucket/operations.go:156`, `config.go:485` and
  `config.go:570/590` — so *choosing* a backend is a four-site change at the
  configuration layer. The 66 sites below are where it gets expensive.
- **One SDK client is built once at startup and is the only backend anything sees.**
  `internal/proxy/server.go:104` and `:112`, behind the single interface at
  `internal/proxy/interfaces/s3_backend.go:11`. Every handler struct holds exactly
  one of them — `object/handler.go:18`, `bucket/base.go:15`,
  `multipart/handler.go:31`, and so on. There is no point in the request path where
  a backend is chosen.
- **A whole-object GET is already two backend reads pinned to one backend's entity
  tag.** The tail read is `internal/proxy/handlers/object/tail.go:71`
  (`bytes=-65604`, the constant at `tail.go:35`); the prefix read carries
  `IfMatch` on the tail answer's ETag at
  `internal/proxy/handlers/object/operations.go:89`. That tag is backend-local, so a
  fallback cannot switch backend between the two reads — it has to restart the pair.
- **Two backends written independently do not hold the same bytes.** Each object
  gets its own random data key (ADR 0002) and every segment nonce is drawn at seal
  time, `pkg/encryption/dataencryption/segmented_gcm.go:140`. The same plaintext
  written twice yields different ciphertext, a different `s3ep-encrypted-dek` and a
  different backend ETag. The stored *length* is deterministic; the stored *bytes*
  are not.
- **Multipart belongs to one backend by construction.** Sessions are keyed by the
  backend's own upload id with no backend identity in the key —
  `internal/orchestration/segmented_session.go:182` and `:199` — and the shutdown
  sweep aborts by that id.
- **`s3_backend.region` is what the proxy answers a client** when the backend sends
  no region header, `internal/proxy/handlers/bucket/operations.go:148-160`.
- **The integrity metric exists, with four reasons and no backend label.**
  `s3ep_object_integrity_failures_total{reason,phase}`,
  `internal/monitoring/metrics.go:138`. The reasons are `foreign_object`,
  `key_material`, `stored_length` and `authentication`
  (`internal/proxy/handlers/object/helpers.go:98-104`) — four, not the three the
  README's prose counts; phases are `before_response` and `mid_stream`
  (`metrics.go:151`, `:155`).
- **There is no health notion for a backend.** `internal/proxy/handlers/health/handler.go`
  never calls the backend; readiness reports shutdown state only.
- **There is no write fan-out and no retry-elsewhere anywhere.** One `PutObject`
  (`object/operations.go:470`), one `CompleteMultipartUpload` (`:1242`).
- **`${VAR}` expansion already loops over every entry** and already names
  `s3_backends[i].<field>` in its refusal, `internal/config/envexpand.go:51-74`.
  This is the one part of the loader that needs nothing: N entries with N
  credential pairs expand and refuse correctly today.
- **Startup validation, by contrast, is written for entry zero and says so.**
  `validate` at `internal/config/config.go:485`, `backendUsesTLS` at `:540-557`
  and `validateBackendTransport` at `:560-592` spell `s3_backends[0]` into every
  message. Per backend each has to name the entry — and once an entry carries an
  operator-chosen name, the message should name *that*, not an index the operator
  did not write.

Not verified: whether any backend this product is aimed at replicates ciphertext
byte-for-byte between endpoints. It decides open question 4 and was not investigated.

## What the feature costs the request path

Added 2026-09-14, on `feat/eraly-testing`, by reading the request path rather than
the configuration. Everything here is verified in the tree unless it says
otherwise. None of it is a decision; each item either sizes the work or raises an
open question, and the questions are numbered from 10 below.

### The surface is 66 call sites, not one client

`S3BackendInterface` carries **52 methods**
([interfaces/s3_backend.go](../../internal/proxy/interfaces/s3_backend.go)) and is
reached from **66 call sites across 27 files** — 15 files under
`internal/proxy/handlers/bucket/`, 5 under `object/`, 5 under `multipart/`, plus
`root/handler.go` and `server.go`. Every handler holds the interface as a struct
field, so "which backend serves this request" has no place to live today. Two
shapes, and the choice is question 10:

- **A fan-out client that implements the same 52 methods** and hides the set
  behind the interface handlers already hold. Nothing above it changes shape — but
  the policy then lives where no handler can see it, and a per-verb policy
  (a `GetObject` may fall back, a `PutObject` must fan out, a `ListObjectsV2` must
  pick one) becomes 52 special cases inside one type.
- **A backend set the handlers see**, which touches all 66 sites and makes the
  policy explicit at each one.

### Only a `before_response` refusal can fall back at all

This is the finding that most changes what the feature is worth, and the metric's
existing `phase` label already draws the line.

On a whole-object GET the trailer is opened inside the tail read
([tail.go:123-136](../../internal/proxy/handlers/object/tail.go#L123)) — so
`foreign_object`, `key_material`, `stored_length` and a **trailer** authentication
failure are all known before the status line. Everything else is streamed:
`OpenSegmented` returns a reader and the plaintext goes straight into the response
([operations.go:121-146](../../internal/proxy/handlers/object/operations.go#L121)),
so a **segment** that does not authenticate is found `mid_stream`, the 200 is
already out, and the body is cut (ADR 0003 D15).

A fallback cannot reach that. And a rewritten segment is precisely the attack this
feature is aimed at.

The one mitigation the tree already gives for free: an object of at most one
segment is entirely inside the tail buffer (`coversWholeObject()`,
[tail.go:59](../../internal/proxy/handlers/object/tail.go#L59)), so for objects up
to 64 KiB every failure is `before_response` and a fallback covers all four
reasons. Above that the coverage is partial, and it is partial in the direction
that matters.

**Question 11: is a partial fallback the feature, or does it have to cover a
mid-stream fault?** Covering it means not streaming — verify the whole object
before the status line — which is goal 3 traded away for goal 1. Not covering it
means the honest claim is "a damaged *header* of an object falls back; a damaged
*body* still cuts the response", and `SECURITY_ARCHITECTURE.md` has to say exactly
that.

### Conditional requests, entity tags and timestamps are backend-local

- The client's conditional headers ride along to the backend
  ([tail.go:73](../../internal/proxy/handlers/object/tail.go#L73)).
- The prefix read pins `IfMatch` on the tail answer's ETag
  ([operations.go:89](../../internal/proxy/handlers/object/operations.go#L89)).
- Under independent proxy writes the stored bytes differ per backend (the nonce
  finding above), so the backend ETag differs, and so does `LastModified`.

Consequences: a client holding an ETag from a read that backend A answered gets
`412` from backend B; `If-Modified-Since` flaps with whichever backend answered.
rclone syncs on size and modtime and Velero compares entity tags — both are
release gates here (ADR 0019), so this is an e2e-visible behaviour change, not a
theoretical one. **Question 12: what does a fallback do with a client's
conditional headers — drop them, re-evaluate them per backend, or refuse to fall
back on a conditional read?** It is the same question ADR 0032 answered for one
backend, asked again across a set.

### A client-supplied `VersionId` exists on exactly one backend

Forwarded verbatim on every object verb —
[tail.go:70](../../internal/proxy/handlers/object/tail.go#L70),
[range.go:253](../../internal/proxy/handlers/object/range.go#L253), `:363`,
`:418`, [operations.go:84](../../internal/proxy/handlers/object/operations.go#L84),
`:162`, `:521`, `:573`. Under independent writes there is no shared version id, so
a versioned read cannot fall back and a versioned delete addresses one copy.
**Question 13: are versioned buckets supported under several backends, refused, or
supported only when the backends replicate (question 4 answered "backend-side")?**

### A delete that reaches one backend and a read that falls back to another serves deleted data

`handleDeleteObject` is a single call
([operations.go:524](../../internal/proxy/handlers/object/operations.go#L524)) and
`DeleteObjects` a single batch (`:769`). If a delete is not held to the same
policy as a write, the fallback resurrects objects the client deleted — worse than
a missing copy, because the operator believes the data is gone. This belongs in
the write policy of question 3, and in `SECURITY_ARCHITECTURE.md`: a second copy
makes deletion a distributed operation, and ADR 0001 D9 currently puts deletion
out of scope (question 7).

### The write policy governs 27 verbs at 36 call sites, not two

`Put`/`Delete`/`Create` against the backend appear at 26 call sites in the
handlers; `UploadPart` (5), `AbortMultipartUpload` (3) and
`CompleteMultipartUpload` (2) add ten more. They are not all object writes:

| Group | Verbs |
|---|---|
| Object | `PutObject`, `DeleteObject`, `DeleteObjects` |
| Object sub-resource | `PutObjectTagging`, `DeleteObjectTagging`, `PutObjectRetention`, `PutObjectLegalHold` |
| Multipart | `CreateMultipartUpload` (2 sites), `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` |
| Bucket lifecycle | `CreateBucket`, `DeleteBucket` |
| Bucket sub-resource | `PutBucketAcl`, `PutBucketCors`, `DeleteBucketCors`, `PutBucketTagging`, `DeleteBucketTagging`, `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketVersioning`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle`, `PutBucketNotificationConfiguration`, `PutBucketLogging` (2 sites), `DeleteBucketReplication`, `DeleteBucketWebsite` |

**Question 14: does the write policy cover bucket and object sub-resources, or
only object bytes?** Either answer costs something. Fan them out and a partial
success is the same ADR 0007 D1 problem the object policy has, on fifteen more
verbs. Do not, and the backends diverge in lifecycle, versioning, policy and
retention — so the copy that answers a read is governed by rules the client never
set on it, and a lifecycle rule on one backend can delete the copy the other was
going to fall back to.

### Reads that are not object reads still come from one backend

`ListObjectsV2` / `ListObjects`
([bucket/listing.go:75](../../internal/proxy/handlers/bucket/listing.go#L75)),
`ListBuckets` ([root/handler.go:96](../../internal/proxy/handlers/root/handler.go#L96)),
`HeadBucket` ([bucket/operations.go:139](../../internal/proxy/handlers/bucket/operations.go#L139))
and every bucket sub-resource `Get*`. A listing has no integrity verdict to
trigger a fallback on, so it simply comes from whichever backend is asked.

That matters more than it sounds: `rclone sync` deletes on the destination what a
listing omits. A listing served by a lagging copy can drive a client to delete
data that exists. And reconciling two listings is not cheap — the continuation
token is backend-local, so a merged listing means merging two paginated streams
under one synthetic token, while ADR 0010 forbids the per-object round trip that
would make the merge exact. **Question 15: which backend answers a listing, and
what does a divergence between two listings mean — a merge, a preferred backend,
or a refusal?**

### The multipart upload id handed to the client is the backend's

The client is told `result.UploadId`
([multipart/create.go:117](../../internal/proxy/handlers/multipart/create.go#L117),
`:133`), the session map is keyed by it
([segmented_session.go:182](../../internal/orchestration/segmented_session.go#L182)),
and the shutdown sweeper aborts by it through one closure over one client
([server.go:132-145](../../internal/proxy/server.go#L132)). N backends means N
upload ids per logical upload, so either

- the proxy mints its own id and maps it — and then `ListMultipartUploads`, which
  is forwarded, lists backend ids no client has ever seen, and `ListParts` under
  the exit provider is forwarded too; or
- multipart stays single-backend and the object is replicated after
  `CompleteMultipartUpload` — which leaves a window where one copy exists.

This refines the ticket's own question 5; the abandoner closure and the two
listing verbs are the parts it did not name.

### One seal or N seals, and both cost something

The write fan-out is a performance decision before it is a correctness one, and it
runs straight into goal 3 (small memory footprint):

- **Seal once, send to N backends.** The ciphertext is produced on the fly and
  each `PutObject` wants its own reader. A tee makes the slowest backend set the
  pace for every other, or it buffers the difference — unbounded, per request.
- **Seal N times.** N different data keys, N different nonces, N ciphertexts (and
  N different ETags, which is question 12 again), at N times the CPU.

And `optimizations.multipart_short_part_buffer_size` is a process-wide budget
(ADR 0011 D5): fan-out either multiplies what one open upload holds by N, or the
key means something different under the same name and value. **Question 16: which
of the two, and is the short-part budget still per process or now per process per
backend?** This is the first thing to measure (ADR 0020) — it decides whether the
feature is affordable at all, and the answer is a number, not an opinion.

### A failed read attempt is a discarded transfer, not just a round trip

The prefix `GetObject` is issued from a goroutine while the tail is still arriving
and is always collected, or its body leaks
([operations.go:78-104](../../internal/proxy/handlers/object/operations.go#L78)).
Under a fallback each abandoned attempt leaves an in-flight body the size of the
object that has to be closed, and a closed-early body drops the connection instead
of pooling it. On a large object the cost of trying the wrong backend first is a
discarded transfer. This sharpens question 2 rather than answering it.

### A write policy needs a backend health notion; a read fallback does not

`internal/proxy/handlers/health/handler.go` never calls the backend — readiness
reports shutdown state only. A read fallback reacts to a verdict and needs no
health check. "How many backends a 200 requires" (question 3) cannot be answered
without knowing which are reachable, and a readiness probe that stays green while
a backend is unreachable makes the chart's rollout lie. **Question 17: does
readiness gain a backend dimension, and does an unreachable backend make the pod
unready, or only change what a write answers?**

### The metric surface is wider than the one counter

No metric carries a backend label, and `s3ep_requests_total`
([metrics.go:76](../../internal/monitoring/metrics.go#L76)) has none either. So a
fallback that silently rescues every read would be invisible: the only signal
would be latency. A fallback that *works* is exactly the thing an operator must
see, because it means a copy is damaged and nobody is repairing it. **Question 18:
which metric shows a fallback — a label on the integrity counter, a counter of its
own, or both?** The constraint at the top of this ticket holds for whichever wins:
the label value is an operator-chosen name, never an endpoint (ADR 0030 D4).

### Smaller things that are still work

- **`ExpectedBucketOwner` is forwarded from the client** on every verb. Two
  backends in two accounts cannot both satisfy one `x-amz-expected-bucket-owner`.
- **One region answers `HeadBucket`**
  ([bucket/operations.go:156](../../internal/proxy/handlers/bucket/operations.go#L156)
  reads `h.config.Backend().Region`). The call site exists and takes exactly one
  value — question 9 has to produce one.
- **The provider is global, not per backend.** `IsExitProvider()` has 10 call
  sites and reads the active provider, not a backend. "Backend A encrypting,
  backend B exit" is not expressible today, and **question 19: is that a
  non-goal?** Saying so now is cheaper than discovering it during the design.
- **The Helm chart carries exactly one backend credential.**
  `templates/secret.yaml` has a single `access-key-id` / `secret-key` pair and
  `values.yaml` a single `secrets.s3.*` block. N backends is a chart values-shape
  change — breaking for chart users even though the proxy's own key shape is
  already right. The chart README's NetworkPolicy guidance names
  `s3_backends[0].target_endpoint` too.
- **The demo stack runs one MinIO** (`docker-compose.demo.yml:3`), and every
  integration suite points at it. A second backend there is part of the work
  (ADR 0019), and so is deciding what the second one *is*: a second MinIO proves
  fan-out, two different implementations prove the thing conformance exists to
  prove (ADR 0027).
- **Adding `name:` inside an entry owes `make test-conformance`.**
  `scripts/conformance-run.sh` writes its own proxy configuration and is the one
  configuration `TestCfgShippedExamplesCarryNoUnknownKeys` cannot see.

## Neighbouring tickets, and where they collide

- **[039](039-backend-certificate-verification-failure-is-named.md)** makes a
  backend certificate failure nameable. With several backends the log line has to
  say *which* backend — so 039 should either land first, or design its fields with
  the name key of this ticket in mind. Cheap to coordinate, expensive to redo.
- **[040](040-managed-buckets.md)** asks in its question 13 whether its bucket
  list is top-level or lives inside an `s3_backends[]` entry. If backends are
  symmetric and hold the same objects, the list is deployment-wide — but the
  re-wrap pass 040 describes would have to run per backend, and its "read the
  object back and compare the CRC32C" verification would have to say which copy it
  read. The two tickets must not answer this differently.
- **[036](036-high-availability.md)** is orthogonal until both exist, and then it
  is not: two instances could pick different backends for the two halves of one
  read, or fall back differently on the same object. The shared session table 036
  needs would have to carry the backend identity per upload (see the upload-id
  finding above). ADR 0033 keeps this dormant today.
- **[033](033-out-of-band-recovery-path.md)** gets easier and stays necessary: a
  second copy is a better answer than recovery for the damage this ticket covers,
  and no answer at all for damage inside `s3ep-encrypted-dek`, which 033 already
  records as unrecoverable.

## What it would need from the configuration

**Historical as of 5.0.0.** The first row landed — `s3_backends` is the list — and
the blast radius below was paid. The rest of the table still stands as the list of
keys the feature has to add *inside* an entry, and every one of them is additive.
Kept because it is the argument for why the shape moved when it did.

| Key today | Shape the feature needs | Breaking later? |
|---|---|---|
| `s3_backend:` — a mapping | a list of entries, or a mapping plus a second key holding the rest | **Yes**, and it is the one key every deployment writes |
| *(nothing)* | a name per backend: a metric label, a log field and "which copy answered" all need one | No — adding a field inside the entry is additive, *once the entry exists* |
| *(nothing)* | a write policy: how many backends a 200 requires | No, additive |
| *(nothing)* | a read/fallback policy: order, how many to try, whether to try at all | No, additive |
| `s3_backend.region` | per backend, or one value that still answers `HeadBucket` | Moves with the block |
| `s3_backend.access_key_id` / `secret_key` / `insecure_skip_verify` | per backend | Move with the block |

**Blast radius of turning `s3_backend` into a list, counted in this repository:** ten
YAML files carry the block — `config/aes-example.yaml`, `aes-tls-example.yaml`,
`exit-example.yaml`, `multi-example.yaml`, `default.yaml`,
`deploy/helm/s3-encryption-proxy/values.yaml`, `values-development.yaml`,
`values-monitoring.yaml`, `values-production.yaml` and
`test/e2e/velero/values-proxy.yaml` — plus the reference block at `README.md:378`,
the container's variable table at `README.md:729-732`, `CLAUDE.md:369`,
`SECURITY_ARCHITECTURE.md:282` and `:900`, `docs/developer/configuration.md:113-114`
and `deploy/helm/s3-encryption-proxy/README.md:92` and `:132-133`. Two tests decode
what is shipped: the named examples at
`internal/config/default_config_test.go:160-195` and every `config/*.yaml` at
`internal/config/loading_coverage_test.go:817`.

Every operator's file breaks as well, and it breaks *loudly*: ADR 0013 D11 means the
start refuses and the error names the key. That is the product working, and it is
still a major.

**What is already in the right place:** there is no backend timeout, retry or
concurrency key anywhere today, so nothing existing would have to move *into* a
per-backend entry. `read_timeout`, `write_timeout`, `read_header_timeout` and
`idle_timeout` are the client leg (`internal/config/config.go`, `setDefaults`), and
everything under `optimizations` is proxy-wide. The only misplaced-by-then key would
be `s3_backend` itself.

## What 5.0.0 could do now, and what it costs

Candidates, none of them decided here:

- **Nothing.** Cost: a 6.0.0 whose only breaking change may be this one key, and
  every operator edits their file for it. This is the honest default and the one to
  argue against, not the one to justify.
- **Accept `s3_backend:` as either a mapping or a one-element list now**, reading
  only the first entry. It would make the later change additive. Cost: it is a key
  shape with no reader that changes the product, which is what ADR 0013 D1 refuses,
  and a one-element list that silently ignores a second entry is worse than a
  refusal. Raising it here so it is rejected deliberately rather than forgotten.
- **Add the `backend` label to `s3ep_object_integrity_failures_total` now**, with a
  constant value. It has a real reader and changes what is exported, so D1 is
  satisfied. Cost: the label value would name the backend, and the monitoring
  listener is unauthenticated by design
  ([ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md)) —
  an endpoint host in a metric is a disclosure decision, not a formatting one.
  Adding the label later instead breaks recording rules and dashboards, which is the
  cost of not doing it. Undecided, and it needs the naming question below answered
  first: a label should carry a configured alias, and there is no alias today.

## Open questions

Each is undecided. No option below is preferred by this ticket. **Questions 10-19
are raised in *What the feature costs the request path* above**, next to the
evidence that produced them; 1-9 are the original set, and 1, 2, 5 and 9 are
sharpened by findings there.

1. **Which refusal is a fallback trigger?** Four exist today.
   `stored_length` and `authentication` are stored bytes that do not open — the
   clearest case for trying another copy. `foreign_object` is an object this proxy
   did not write, which is normally the same verdict on every backend and so wasted
   round trips — except that a third party *replacing* an object with a foreign one
   is exactly the attack this feature is for. `key_material` is permanent under the
   current configuration and cannot be distinguished from a retired key, so a
   fallback would retry a state no backend can fix. Options: trigger on all four,
   on the two byte-level ones, or make it configurable — the last costs a key and
   the argument that any value is one the product would accept (ADR 0013 D9a).
2. **What a fallback costs on the hot path.** A failed read has already spent its
   round trips, and the tail-and-prefix pair has to restart from the tail because
   `If-Match` is backend-local. Whether that is acceptable is a measurement
   ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)), not an
   opinion.
3. **The write policy.** All-or-nothing, a quorum, or a primary with asynchronous
   replication. ADR 0007 D1 pushes hard at the third: answering 200 while a copy is
   missing is accepting a request and discarding part of what it asked for. Each
   option costs a different upload latency and a different failure story.
4. **Who keeps the copies in sync.** Backend-side replication of the ciphertext —
   then the bytes and the ETags match across backends and one manipulated copy is
   detectable against the other — or independent proxy writes, where the bytes
   differ per backend by construction (see the nonce finding above), so the ETag a
   client is told changes with the backend that answered
   ([ADR 0032](../adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md)).
   **2026-09-17:** bringing an added backend to parity is planned as an
   operation of the pass engine of [017](017-filename-encryption.md) (its F11):
   stored bytes and metadata copied byte for byte from one backend to the other,
   which is the "backend-side replication" answer in tool form. The decision
   stays here; 017 only provides the interfaces.
5. **Multipart across backends.** One upload id per session today. Options: keep
   multipart single-backend and replicate after `CompleteMultipartUpload`, or hold
   N upload ids per session and fan out every part. The second changes the session
   map, the shutdown sweep and the short-part budget (ADR 0011 D5).
6. **What a read answers when every backend refuses.** Today one 403; a fallback
   makes it a set of verdicts, and a client gets one answer.
7. **Whether this changes ADR 0001 D9**, which puts deletion by the backend out of
   scope. A second copy is the first answer this product would have to that, and
   D9 would have to be amended rather than quietly outgrown.
8. **Whether the exit provider participates at all.** Under `exit` the stored bytes
   are the plaintext and a plain object has no trailer
   ([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)), so there is no
   integrity verdict to trigger a fallback on.
9. **Region and credentials: per backend or shared.** Per backend is the general
   answer, and it costs the `HeadBucket` answer a decision: which region does the
   proxy state?

## What it must not break

- **Integrity is not configurable and no byte is served unverified** (ADR 0001
  D3/D4, ADR 0003). A fallback is a second *attempt*, never a relaxation: a copy
  that does not authenticate is still refused.
- **Fail closed** (ADR 0001 D5). "Another backend served it" is not a verification;
  each copy is verified on its own terms.
- **A configuration key exists only if code reads it and that read changes the
  product** (ADR 0013 D1, D11).
- **Forward it or refuse it** (ADR 0007 D1). A write that reached fewer backends
  than the policy requires is not a 200.
- **Sizes and listings describe the plaintext, without a per-object round trip**
  ([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)).
- **The entity tag is a change token** (ADR 0032) — and it is still derived from the
  backend that answered, which is open question 4.
- **No stored-data compatibility is owed**
  ([ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md)), so "kept in
  sync" can never mean a format conversion between backends.
- **Integration and e2e suites are the product** and are never skipped
  ([ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md)): a second
  backend in the demo stack is part of the work, not an optional extra.
- **Uploads stream and the memory footprint stays small** (the project's third
  goal). A fan-out that buffers an object to feed N writers, or a fallback that
  buffers one to verify it before the status line, has traded that away — and if
  either is the answer, it is a decision with a number attached, not a side
  effect (ADR 0020).
- **A claim describes what the code verifies** (ADR 0001 D10). "Survives a
  manipulated copy" may not be written down until the fallback and the delete
  policy both exist, and it has to name the mid-stream gap (question 11) if that
  gap survives the design.
- **Nothing on the unauthenticated scrape identifies a host** (ADR 0030 D4). The
  backend label is an operator-chosen name, and that holds for every metric the
  feature adds, not only the integrity counter.

## Done when

- [ ] All nineteen open questions are answered in an ADR, before any code
- [x] The shape of `s3_backends` is decided and shipped (5.0.0); additions go
      *inside* an entry
- [x] Every place listed under *blast radius* was updated in that change
- [ ] The fan-out write is measured first, before anything else is built
      (ADR 0020): one seal teed to N backends against N seals, and what each does
      to throughput and to resident memory. It decides whether the feature is
      affordable (question 16)
- [ ] A backend carries a name, and it appears in the log field and the metric
      label — never its endpoint (ADR 0030 D4)
- [ ] Startup validation names the backend that failed, not `s3_backends[0]`
- [ ] `s3ep_object_integrity_failures_total` distinguishes the backend that refused,
      and a fallback that succeeded is visible in its own right (question 18)
- [ ] The write policy is implemented and a partial write is not a 200 — and it
      states whether it covers delete, bucket sub-resources and object
      sub-resources (questions 3, 14) or deliberately does not
- [ ] A delete cannot be undone by a fallback: either it is held to the write
      policy, or the ticket records why resurrection is acceptable
- [ ] The listing answer is decided and implemented (question 15)
- [ ] Conditional requests, `VersionId` and the client-visible ETag have a stated
      behaviour across backends (questions 12, 13), asserted in the rclone and
      s3cmd suites because both clients act on them
- [ ] The fallback path is measured before and after (ADR 0020), including the
      cost of an abandoned attempt on a large object
- [ ] Readiness states what an unreachable backend means (question 17)
- [ ] The Helm chart carries N backend credentials, and its NetworkPolicy guidance
      stops naming `s3_backends[0]`
- [ ] The demo stack runs a second backend and the integration suite exercises a
      manipulated copy — including a manipulation *inside a segment* of a
      multi-segment object, which is the case a fallback may not be able to cover
- [ ] `make test-conformance` is run for the entry's new keys
- [ ] `SECURITY_ARCHITECTURE.md` states what a second copy defends against and what
      it does not — explicitly including the mid-stream gap of question 11, and
      only claiming what the code verifies (ADR 0001 D10)
- [ ] ADR 0001 D9 is amended rather than quietly outgrown (question 7)
- [ ] `docs/developer/request-paths.md` and `multipart.md` describe how a backend
      is chosen
- [ ] This ticket is archived, with its decisions extracted into ADRs first
