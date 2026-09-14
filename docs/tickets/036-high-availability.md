# 036 — High availability: several instances sharing the work, multipart included

## Decided 2026-09-14, before any of this is built

**One instance per deployment of the `s3-encryption-proxy` chart, and the chart
now refuses a second** (ADR 0033). This is not a new limitation — it is the one
that was always true and was not enforced: the shipped production profile asked
for three replicas and autoscaling to twenty, and it rendered, while a
client-driven multipart upload that reached the wrong pod was answered
`404 NoSuchUpload`.

**Running several proxies that cooperate is a separate product**, the
`s3-encryption-operator`, with a chart of its own. The two are installed
separately and neither is a mode of the other, so this ticket is the operator's
prerequisite rather than a switch on the existing chart.

Two consequences for the work below. The coordination layer needs no
configuration key reserved in 5.0.0: a block the proxy defines later refuses no
existing file (ADR 0013 D11), so nothing here is foreclosed. And
`optimizations.multipart_short_part_buffer_size` is expected to stay **per
instance** — it bounds memory, and memory is a pod's — so it needs no rename
either. If that expectation is overturned and the budget becomes cluster-wide,
the key means something different under the same name and value, which is the
kind of change that needs a major and a new name.


Raised 2026-09-14 by the owner: *several s3-proxy instances side by side share the
workload and synchronise with each other so that they cooperate on multipart
uploads too.* **Announced, NOT SCHEDULED, no work started.**

Written down now for one reason: 5.0.0 is the major, a configuration key's shape
is a breaking change under
[ADR 0013 D11](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)
and a breaking change ships in a major under
[ADR 0018 D5](../adr/0018-a-major-release-is-declared-by-a-label.md), so what this
feature needs the configuration to look like is free today and costs a 6.0.0
afterwards. Not a design: where a decision is needed it is an **open question**
below, and it is undecided.

## What it is

N proxy instances behind one address, any request to any instance, and a
client-driven multipart upload that survives being spread across them: Create on
one instance, its `UploadPart` calls on any of them, Complete on a third. That
needs the per-upload state the proxy holds today — the object's data key and the
part table Complete is built from — reachable by an instance that did not create
the upload.

Everything else is already stateless between requests — reads, a single-request
`PUT`, and the internal multipart producer, whose whole upload runs inside one
client request — and needs nothing from this feature.

## What the tree looks like today

**Verified in this repo.**

* **The session is process-local, and the code says so.** `Manager` keeps
  `segmentedSessions` and `producerUploads` as maps behind a mutex, register and
  lookup being a map write and a map read
  ([manager.go:16-45](../../internal/orchestration/manager.go),
  [segmented_session.go:182-222](../../internal/orchestration/segmented_session.go)).
  The shutdown comment states the consequence outright — *"the data key and the
  part table live here and nowhere else"*
  ([manager.go:192-196](../../internal/orchestration/manager.go)).
* **`UploadPart` for an upload created on another instance is `404 NoSuchUpload`
  today** ([upload.go:145-149, 162](../../internal/proxy/handlers/multipart/upload.go)),
  and so are `CompleteMultipartUpload`
  ([complete.go:202-208](../../internal/proxy/handlers/multipart/complete.go)) and
  `ListParts` ([list.go:111-118](../../internal/proxy/handlers/multipart/list.go)).
  Under the exit provider there is no session and every one of those verbs
  forwards ([create.go:89-104](../../internal/proxy/handlers/multipart/create.go),
  [upload.go:110-115](../../internal/proxy/handlers/multipart/upload.go)) — that
  provider is already multi-instance, the encrypting ones are not.
* **This is live, not hypothetical.** The production values ship `replicaCount: 3`
  with autoscaling to 20
  ([values-production.yaml:11, 27-32](../../deploy/helm/s3-encryption-proxy/values-production.yaml)),
  the Service sets no `sessionAffinity`
  ([service.yaml](../../deploy/helm/s3-encryption-proxy/templates/service.yaml)) and
  the default ingress annotations are empty
  ([values.yaml:59-64](../../deploy/helm/s3-encryption-proxy/values.yaml)) — so a
  client-driven multipart upload there works only when every request of the upload
  happens to land on the same pod.
* **The upload id is the backend's own**, handed to the client unchanged and used
  as the session key ([create.go:113-119](../../internal/proxy/handlers/multipart/create.go)),
  so the identifier a second instance would look state up by already exists.
* **The short-part budget is one number per process** — `shortPartHeld` on the
  `Manager` ([manager.go:27-31](../../internal/orchestration/manager.go)), compared
  against `ShortPartBufferSize()`
  ([segmented_session.go:123-131, 237-249](../../internal/orchestration/segmented_session.go)).
  Across N instances it bounds one pod, and the deployment holds up to N times it.
* **The sweeps have no owner filter.** `AbandonAllSessions` copies *every* entry of
  both maps and aborts each at the backend, and the idle sweeper walks the whole
  map ([segmented_session.go:308-355, 372-425](../../internal/orchestration/segmented_session.go)).
  Both are correct precisely because the map is this process's own.
* **The DEK cache is per process and has no key** — an LRU bounded by the constant
  `dekCacheCapacity = 1024` ([providers.go:19-23, 63-67](../../internal/orchestration/providers.go)).
* **There is no node identity anywhere** — no hostname read, no `node_id`, no
  `instance_id` in `internal/`, `cmd/` or `pkg/`. The request id is 8 bytes of
  `crypto/rand` as 16 uppercase hex characters, minted per request
  ([requestid.go:26-33](../../internal/proxy/middleware/requestid.go)): unique
  across instances by width, but it names no instance. The licence carries
  `k8s_cluster_id`, logged and never enforced
  ([types.go:15-21](../../internal/license/types.go),
  [logger.go:41-42](../../internal/license/logger.go)), so N instances cost
  nothing in licence terms.
* **No metric describes what an instance holds** — nothing for open sessions or
  held short-part bytes ([metrics.go:76-140](../../internal/monitoring/metrics.go)).

**Not verified.** Whether a backend accepts `UploadPart` for one upload id from a
second proxy instance (plausible — an ordinary S3 call under the same credentials
— but untested here). Whether any backend serves an in-progress upload's metadata
back, which is where the wrapped data key already sits from Create time.

## What it would need from the configuration

Per item: the key today, the shape the feature would need, whether changing it
later is breaking.

**1. `optimizations.multipart_short_part_buffer_size` — the scope is not in the name.**
Today: bytes, process-wide, documented as memory an operator budgets against the
container limit (ADR 0011 D5). Needed: it stays per instance and the name says
so, or it becomes a cluster-wide reservation and the name says *that*.
**Breaking later, and invisibly** — name and value unchanged, meaning changed.
This repo already treats that as breaking and refuses the old key by name for
exactly this reason, twice ([config.go:238-253](../../internal/config/config.go)).

**2. `optimizations.multipart_session_idle_timeout` and `…_cleanup_interval` — same class.**
Today both drive one process's sweeper over its own map (ADR 0028). Under a shared
table, "the last part this upload received" and "who runs the sweep" become
cluster-wide facts. **Breaking later** if the meaning moves without the name.

**3. `shutdown_timeout` — one budget for the whole shutdown** (ADR 0029 D1/D3),
and the chart derives `terminationGracePeriodSeconds` from it. Handing sessions
to a surviving instance would be one more step inside the same budget.
**Not breaking**: the shape and the meaning hold, only the sizing advice changes.

**4. There is no `cluster:` or `coordination:` block, and that forecloses nothing.**
`ErrorUnused` refuses keys the proxy does *not* define
([config.go:309-311](../../internal/config/config.go)), so a block it adds later
breaks no existing file: the store's address, a credential, a lease duration,
this instance's identity are all **additive**.

**5. `tls:` has exactly three keys** — `enabled`, `cert_file`, `key_file`
([config.go:22-26](../../internal/config/config.go)) — no CA bundle, no client
certificate verification. Instance-to-instance traffic would carry key material,
so it wants mutual TLS. **Not breaking**: a CA and a client-auth key later, or a
block of its own for the peer leg, are both additive.

**6. Two discriminators already exist, so nothing there forecloses either.**
`s3_clients[].type` has one value, `static`
([config.go:65, 1040-1041](../../internal/config/config.go)), and
`encryption.providers[].type` is one too — a peer credential type is additive, as
is a DEK cache size, which has no key at all today.

**7. The request id's shape is fixed by an ADR, not a key.** ADR 0008 D12a states
sixteen uppercase hex characters; putting an instance into it changes a
client-visible answer, **breaking** under ADR 0018 D5. The cheap alternative is
free at any time — an instance field in the access log is neither a key nor an
answer (open question 5).

## What 5.0.0 could do now, and what it costs

Honestly: **one item, and it is a rename.** Item 1 — carrying the scope of
`optimizations.multipart_short_part_buffer_size` in its own name — is the only
change that is free today and a major afterwards; the rename machinery
already exists, one `viper.InConfig` check plus a message
([config.go:238-253](../../internal/config/config.go)). Whether to do it is **open
question 4**, because it depends on whether the budget ever becomes cluster-wide.

* Item 2 is the same shape but weaker: counting from the last part is already the
  right sentence under a shared table, and the sweeper's ownership has no key today.
* Everything else — a coordination block, peer TLS keys, a node identity, a cache
  size, a metric — is **additive** and costs no more in 6.0.0 than now. Adding it
  in 5.0.0 would be speculative configuration for an undesigned feature.

## Open questions

All undecided. None is answered here.

1. **Where the shared state lives.** A shared database (operational weight, a new
   dependency to run and secure, but built for leases); a lock service such as etcd
   or Consul (the same, plus a leader); or the S3 backend itself (no new dependency
   — and hostile by [ADR 0001](../adr/0001-the-backend-is-hostile.md), so anything
   parked there must be authenticated by the proxy and a data key must not be
   readable by it). Cost and threat model differ by an order of magnitude.
2. **Whether any shared state is needed at all.** The alternative is sticky
   routing at the load balancer: no new dependency and no new code, an upload dies
   with its pod, and the boundary belongs to the administrator by
   [ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md), so
   the product would document a requirement it cannot enforce.
3. **Whether a data key crosses the network.** It must, if a second instance is to
   seal a part. Either the wrapped key travels and each instance unwraps with the
   KEK it already holds (no plaintext key on the wire), or the plaintext key
   travels over mutual TLS (fewer unwraps, a plaintext key on the wire). This is
   the security question of the feature.
4. **Whether the short-part budget stays per instance or becomes cluster-wide**,
   and therefore what the key is called. Per instance: no coordination on the hot
   path, the deployment holds N times the number. Cluster-wide: the number means
   what an operator reads it to, at a reservation round trip per held part.
5. **Whether an instance gets an identity, and where it shows.** Access log only
   (free, additive, answers "which pod served this"); the request id (breaking,
   ADR 0008 D12a); a metric label (additive); nowhere.
6. **What a shutdown does to a session another instance could finish.** Today it
   ends everything it holds (ADR 0029 D2) because nothing can adopt it. Under a
   shared table: hand over (needs an owner field and a lease), or keep ending it
   (simple, discards an upload a survivor could have completed).

## What it must not break

* [ADR 0001](../adr/0001-the-backend-is-hostile.md) — the backend is an
  adversary; state parked there is state it can change or drop.
* [ADR 0002](../adr/0002-one-data-key-per-object.md) and
  [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) — one
  random data key per object, and no byte served unverified: a part sealed by a
  second instance is bound to the same object key and segment index or it does
  not open.
* [ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md) D2/D5/D6 — the part
  table is the authority at Complete, an unverifiable layout is refused, and the
  short-part budget stays a real memory bound.
* [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11
  — a key the proxy does not define refuses the start.
* [ADR 0028](../adr/0028-an-abandoned-upload-is-ended-not-forgotten.md) and
  [ADR 0029](../adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)
  — an abandoned upload is ended at the backend, not forgotten, and a shutdown
  never completes an object whose client did not finish sending it.
* [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) D12a — every
  answer states this proxy's own request id.
* [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md) — the exit provider keeps
  no session and must keep needing no coordination.

## Done when

- [ ] Open questions 1 and 2 are answered — shared state or documented sticky
      routing, and if shared, which store and what it costs an operator to run —
      and recorded in an ADR.
- [ ] Open question 3 is answered and `SECURITY_ARCHITECTURE.md` carries the key
      flow between instances and its residual risk.
- [ ] Open question 4 is answered and the budget key's name matches its scope.
- [ ] Open question 5 is answered; a change to the request id goes in a major.
- [ ] Open question 6 is answered and ADR 0029's shutdown order is amended or
      confirmed.
- [ ] A client-driven multipart upload whose Create, parts and Complete are
      deliberately spread across instances completes, asserted end to end against
      a real backend.
- [ ] The configuration table in `CLAUDE.md` and the reference in `README.md`
      carry every new key, with its default marked.
- [ ] The chart states what a multi-instance deployment requires, and
      `values-production.yaml` is correct for it.
