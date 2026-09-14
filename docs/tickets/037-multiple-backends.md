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

Verified in this repository on 2026-09-14, on `feat/major-v5`.

- **`s3_backend:` is one struct with five fields, and `Config` holds it as a value,
  not a slice.** `internal/config/config.go:29-34` (`target_endpoint`, `region`,
  `access_key_id`, `secret_key`, `insecure_skip_verify`) and
  `internal/config/config.go:162`.
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
- **`${VAR}` expansion is written out field by field** for exactly the four
  `s3_backend` strings, `internal/config/envexpand.go:51-74`.

Not verified: whether any backend this product is aimed at replicates ciphertext
byte-for-byte between endpoints. It decides open question 4 and was not investigated.

## What it would need from the configuration

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

Each is undecided. No option below is preferred by this ticket.

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

## Done when

- [ ] The open questions above are answered in an ADR, before any code
- [ ] The shape of `s3_backend` is decided, and if it changes, the major that
      carries it is named
- [ ] Every place listed under *blast radius* is updated in the same change
- [ ] A backend carries a name, and it appears in the log field and the metric label
- [ ] `s3ep_object_integrity_failures_total` distinguishes the backend that refused
- [ ] The write policy is implemented and a partial write is not a 200
- [ ] The fallback path is measured before and after (ADR 0020)
- [ ] The demo stack runs a second backend and the integration suite exercises a
      manipulated copy
- [ ] `SECURITY_ARCHITECTURE.md` states what a second copy defends against and what
      it does not
- [ ] This ticket is archived, with its decisions extracted into ADRs first
