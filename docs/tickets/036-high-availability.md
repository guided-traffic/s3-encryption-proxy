# 036 — High availability: several instances sharing the work, multipart included

## Decided 2026-09-14, before any of this is built

**One instance per deployment of the `s3-encryption-proxy` chart, and the chart
now refuses a second** (ADR 0033). This is not a new limitation — it is the one
that was always true and was not enforced: the shipped production profile asked
for three replicas and autoscaling to twenty, and it rendered, while a
client-driven multipart upload that reached the wrong pod was answered
`404 NoSuchUpload`.

**This work is a change to the proxy, not to a chart.** Instances that cooperate
need a session table they share, an owner for the sweeper and a short-part bound
that means something across processes; none of that is a values key, because the
state lives in the process. So the refusal above is lifted by this ticket landing,
not by a deployment option.

**It is independent of [038](038-s3-encryption-operator.md), and the two were
briefly written down as one thing.** An operator that provisions *single*
instances — one custom resource, one Deployment of the single-instance chart — is
a complete product that needs nothing from here. This ticket is equally complete
with no operator anywhere: once the proxy can hand an upload over, a chart could
install such a set. Neither requires the other, and neither delivers the other.

Two consequences for the work below. The coordination layer needs no
configuration key reserved in advance: a block the proxy defines later refuses no
existing file (ADR 0013 D11), so nothing here is foreclosed. And
`optimizations.multipart_short_part_buffer_size` is expected to stay **per
instance** — it bounds memory, and memory is a pod's — so it needs no rename
either. If that expectation is overturned and the budget becomes cluster-wide,
the key means something different under the same name and value, which is the
kind of change that needs a major and a new name.


Raised 2026-09-14 by the owner: *several s3-proxy instances side by side share the
workload and synchronise with each other so that they cooperate on multipart
uploads too.* **Announced, NOT SCHEDULED, no work started.**

## Second pass, 2026-09-14 — what the first pass got wrong

This section exists so the refining round starts from the corrected facts rather
than re-deriving them. Everything below was checked against the tree on
`feat/eraly-testing`; where a claim rests on a probe against a running backend it
says so, and it says which backend.

1. **The 5.0.0 window is shut.** `v5.0.0` is tagged at `052a1d0` (2026-09-14
   10:17 UTC) and `v5.0.1` at `0b854a0` (13:49 UTC); the commit that introduced
   this ticket is an ancestor of `v5.0.0`. So the original section "What 5.0.0
   could do now" was expired before it was written, and its single free item —
   renaming `optimizations.multipart_short_part_buffer_size` — now costs exactly
   the 6.0.0 it was meant to avoid. The same stale premise sits in
   [037](037-multiple-backends.md) and [038](038-s3-encryption-operator.md).
   **Open question 4 changes shape**: no longer "rename now or pay later", but "is
   the rename worth a major on its own".
2. **"The production values ship `replicaCount: 3` with autoscaling to 20" is
   false at HEAD.** [values-production.yaml:15](../../deploy/helm/s3-encryption-proxy/values-production.yaml)
   is `replicaCount: 1`, `:34-35` `autoscaling.enabled: false`, `:40-41` the PDB
   off, and the render refuses both anyway
   ([_helpers.tpl:204-211](../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl)).
   ADR 0033 landed the same day this ticket was written. The urgency argument is
   therefore gone: nobody installing the shipped profile today is running a broken
   fleet. What *is* still wrong is prose: `values-production.yaml:3-5` still
   advertises "multiple replicas behind a PodDisruptionBudget, autoscaling,
   network policies" (network policies were deleted by ADR 0030) and
   [values.yaml:6](../../deploy/helm/s3-encryption-proxy/values.yaml) still points
   an operator at that profile for "multiple replicas, PDB, autoscaling".
3. **"There is no node identity anywhere" is wrong in substance.**
   [metrics.go:13-16](../../internal/monitoring/metrics.go) reads
   `KUBERNETES_NAMESPACE`, `KUBERNETES_POD_NAME`, `HELM_RELEASE_NAME` and
   `HELM_CHART_VERSION` at package init, `:20-37` turns the non-empty ones into
   labels and `:49-54` wraps the one registry with them — so **every exported
   series already carries `kubernetes_pod_name`** when the chart supplies it
   ([deployment.yaml:71-86](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml)).
   The chart also injects `KUBERNETES_POD_IP`, which no Go code reads. Open
   question 5's "a metric label (additive)" is therefore **already built**; what is
   genuinely missing is an identity in the access log, an identity outside
   Kubernetes, and a peer address.
4. **The verb inventory is incomplete, and the missing verb is the one that
   already crosses instances.** `AbortMultipartUpload` forwards to the backend
   **before any session lookup**, under every provider
   ([abort.go:83](../../internal/proxy/handlers/multipart/abort.go), cleanup only
   at `:92`), and answers 204. So an abort landing on the wrong instance really
   ends the upload at the backend while the creating instance keeps the session —
   its data key, its part table, its held plaintext and its claim on the
   process-wide short-part budget — until the idle sweeper fires, by default an
   hour later. Nothing is logged as wrong, because the sweeper's abandoner maps
   `NoSuchUpload` to success
   ([server.go:138-141](../../internal/proxy/server.go)). This is a live,
   client-drivable memory and budget leak at two instances today, and it needs
   none of the six open questions to fix. `ListMultipartUploads` is the second
   omission: it forwards unfiltered
   ([list.go:214-290](../../internal/proxy/handlers/multipart/list.go)), so an
   instance lists uploads it will then deny by upload id. `UploadPartCopy` refuses
   under every provider ([copy.go:35-43](../../internal/proxy/handlers/multipart/copy.go)),
   which is why the exit provider looks fully multi-instance.
5. **"The object's data key and the part table" understates the state by three
   items**, each its own design problem. See *The session is not a record you
   fetch once* below.
6. **The two "not verified" items are answerable, and one is now answered.**
   Whether a backend serves an in-progress upload's metadata back: **no**, and not
   per backend — it is an API fact. Of the S3 operations that take an `UploadId`
   as input (Abort, Complete, ListParts, UploadPart, UploadPartCopy) none returns
   a `Metadata` map, and the only two outputs that do (GetObject, HeadObject) take
   no `UploadId`. The wrapped data key the proxy writes at Create
   ([create.go:103](../../internal/proxy/handlers/multipart/create.go)) is
   write-only until the object is completed. Whether a backend accepts
   `UploadPart` for one upload id from a second client under the same credentials:
   **yes against MinIO**, probed 2026-09-14 on the demo stack with three separate
   clients (Create on A, UploadPart + ListParts on B, Abort on C, then 404 on A's
   Complete). Other backends remain untested; that is a conformance case
   (ADR 0027).
7. **Citations to fix.** `ErrorUnused` is at
   [config.go:324-326](../../internal/config/config.go), not `:309-311`. The
   `s3_clients[].type` refusal is at `:1101-1104`, not `:1040-1041`. The rename
   machinery is `viper.IsSet` (`:252`, `:264`, `:275`), not `viper.InConfig` — and
   the distinction is load-bearing, because `IsSet` consults viper's defaults, so
   any check of what a file actually wrote under a *defaulted* key must use
   `InConfig` (`:289-291` says so). And the repo has **one** precedent of the same
   class as item 1, not two: `multipart_session_max_age` is the same-name-changed-
   meaning case, `streaming_segment_size` is a pure rename "for the opposite
   reason", `s3_backend` changed shape and not meaning.
8. **ADR 0033 D1 holds between rollouts, not during one.** The Deployment
   declares no `strategy:` and the chart has no values key for one (`grep -rn
   strategy deploy/helm/` finds nothing), so Kubernetes' default RollingUpdate
   applies: at one replica that is maxSurge 1 / maxUnavailable 0, i.e. the new pod
   becomes Ready and joins the Service before the old one is terminated. The
   `checksum/config` and `checksum/secret` annotations
   ([deployment.yaml:22,29](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml))
   force that roll on any configuration edit. So two proxy processes back one
   Service on **every** `helm upgrade`, and an upload held by the outgoing pod is
   answered `404 NoSuchUpload` for the rest of its life. Whether the chart should
   set `strategy: Recreate` today, independently of this feature, is open question 20.
9. **`multipart_short_part_buffer_size` does not bound one pod either.** On the
   encrypting held-part path `readHeldPart` reads the body with the whole budget
   as its per-request limit
   ([upload.go:140](../../internal/proxy/handlers/multipart/upload.go)) and the
   reservation is taken afterwards, inside `SealPart`
   ([segmented_session.go:529](../../internal/orchestration/segmented_session.go)).
   C concurrent held parts therefore hold up to C × budget transiently; the number
   bounds *retained* bytes only. The exit-provider pass-through arm is the one
   that reserves before reading (`upload.go:448-456`). So "N times it" understates
   the multiplier, and making the budget cluster-wide without moving the
   reservation ahead of the read would bound nothing new.
10. **The "must not break" list is missing ADR 0009, ADR 0014, ADR 0023 and every
    testing record.** See *What it must not break* below.

## What it is

N proxy instances behind one address, any request to any instance, and a
client-driven multipart upload that survives being spread across them: Create on
one instance, its `UploadPart` calls on any of them, Complete on a third.

**How much of the product that actually covers is narrower than the title
suggests, and worth stating first.** Reads, single-request `PUT` and the internal
multipart producer are per-request and already scale out with no coordination at
all — the exit provider is the existing proof that the session is the only
obstacle (ADR 0033). So the coordination problem is exactly one verb family:
client-driven multipart under an encrypting provider. Everything else needs
nothing from this feature except a chart that will render a second pod.

**And the failure is not intermittent, it is near-certain for the product's
flagship client.** `aws-sdk-go-v2`'s upload manager defaults to five concurrent
`UploadPart` calls at 5 MiB each, and the chart's Service is a plain ClusterIP
with no `sessionAffinity`, where kube-proxy balances per connection. Success would
need every one of k connections to hash to the creating pod. Velero is that
uploader, and one e2e run recorded 1466 `UploadPart` requests. "Happens to land on
the same pod" describes a coin flip the product never wins at that scale.

## What the state actually is

**Verified in this repo.** The ticket's original sentence named two things. There
are four, and they are not the same kind of thing.

1. **The data key.** It is *not* in the session as bytes: `SegmentedUpload` holds
   a `*dataencryption.Codec`
   ([segmented.go:93-96](../../internal/orchestration/segmented.go)), and the
   codec holds an `aead` plus the object key
   ([segmented_gcm.go:103-122](../../pkg/encryption/dataencryption/segmented_gcm.go));
   the 32 raw bytes are a local in `newSegmentedObject` (`segmented.go:311-320`)
   and are never retained. What *is* retained and serialisable is the **wrapped**
   key, base64 in `Upload.metadata` under `<prefix>encrypted-dek`
   ([metadata.go:98-120](../../internal/orchestration/metadata.go)) — the same
   three values `codecFor` needs to rebuild the codec (`segmented.go:342-388`).
2. **The part table**, `map[int]sessionPart{offset, plaintextLen, sum, etag,
   uploadedAt}`
   ([segmented_session.go:42,56-62](../../internal/orchestration/segmented_session.go)).
   `sum` is the part's **plaintext** CRC32C, and `Complete` folds the rows in
   part-number order into the value the trailer authenticates (`:706-709`). The
   backend has never been told it — no `UploadPart` call site sets a checksum
   field (`upload.go:254-264`, `:395-405`), and a backend-computed one would cover
   ciphertext — so it is not recoverable from the backend at any price short of
   downloading and decrypting every part. (It is not *secret*: the same value went
   to the client in `x-amz-checksum-crc32c`, and a held part's ETag is literally
   `<crc32c hex>-<length>`, `:547`.)
3. **`partSize`, an inference that is read-modified-written on the hot path.**
   `SealPart` raises `s.partSize` to the largest part seen that could be a middle
   part and *then* computes `offset := (partNumber-1) * s.partSize` in the same
   critical section (`:503-506`; the streamed path repeats it at `:594-597`). That
   offset becomes the segment index in the per-segment AAD
   ([segmented_gcm_io.go:416](../../pkg/encryption/dataencryption/segmented_gcm_io.go)
   → `segmented_gcm.go:127-131`), i.e. it is baked into ciphertext the backend has
   already stored, and `Complete` refuses any part whose recorded offset disagrees
   with the final inference (`:695-702`). Two qualifications matter for the design:
   it is a *monotone max*, so two instances that have each seen a full-size middle
   part converge on the same value; divergence comes from an instance whose local
   view never contained one. And the known documented defect — an aligned last part
   at or above 5 MiB but smaller than the part size, arriving first
   ([multipart.md:192-203](../developer/multipart.md), ADR 0011 residual risks) —
   is exactly the shape a spread upload makes ordinary rather than unlucky.
4. **`pending`, the held short last part: the client's PLAINTEXT, in RAM.**
   `s.pending = append(s.pending[:0], plaintext...)` (`:534`), kept until Complete
   seals it with the trailer behind it (`:711-724`). It cannot be flushed early:
   its offset is deliberately not taken on arrival (`:537-539`) and is only fixed
   at Complete (`:676`), and it must be sealed with `endsObject=true`. It cannot be
   parked at the backend as a part of its own: S3 refuses a non-final part below
   5 MiB (`:88`). ADR 0011's own Context says most SDK uploaders produce a short
   last part, so this is the common case. **Open question 3 asks only whether a
   data key crosses the network; the larger exposure is up to
   `multipart_short_part_buffer_size` of client plaintext.**

The half that is genuinely cheap, and which the ticket never said: **a part is an
independent slice of the segment chain.** Every segment is sealed with a fresh
random nonce under AAD = `FormatID ‖ objectKey ‖ index`, and `NewPartWriter` sets
`index = plaintextOffset / SegmentSize` on an otherwise zeroed writer. There is no
chaining value, no running nonce counter, no IV carried between parts — to seal
part N an instance needs only the DEK, the Create-time object key, the offset and
the `endsObject` flag. ADR 0011 D1 already says it ("re-encryption draws fresh
segment nonces, so repeating a part is safe"). **No hand-over ever has to move
cipher state.**

## What the tree looks like today

**Verified in this repo.**

* **The session is process-local, and the code says so.** `Manager` keeps
  `segmentedSessions` and `producerUploads` as maps behind a mutex
  ([manager.go:16-45](../../internal/orchestration/manager.go),
  [segmented_session.go:182-222](../../internal/orchestration/segmented_session.go)).
  The shutdown comment states the consequence outright — *"the data key and the
  part table live here and nowhere else"* (`manager.go:192-196`).
* **`UploadPart`, `CompleteMultipartUpload` and `ListParts` answer
  `404 NoSuchUpload` on a foreign instance**
  ([upload.go:145-162](../../internal/proxy/handlers/multipart/upload.go),
  [complete.go:202-208](../../internal/proxy/handlers/multipart/complete.go),
  [list.go:111-118](../../internal/proxy/handlers/multipart/list.go)). **`Abort`
  and `ListMultipartUploads` do not** — see correction 4. Under the exit provider
  Create, UploadPart, Complete and ListParts all take a pass-through branch, so
  that provider is already multi-instance for correctness — but not for resources:
  a pass-through part whose length the request does not declare claims the whole
  process-wide short-part budget (`upload.go:448-456`).
* **A misrouted held part is read in full before it is refused.** A streamable
  part looks the session up first and 404s with no transfer (`upload.go:125-134`);
  every other shape is read into memory first (`:140`) and looked up afterwards
  (`:145`). Under any partial-stickiness design that is a full-body upload into a
  pod that will refuse it — and both demo proxy containers are capped at 512 MB
  against a 64 MiB budget, so a cross-instance test that alternates short parts can
  OOM the container it is asserting against.
* **The upload id is the backend's own**, handed to the client unchanged and used
  as the session key (`create.go:117-121`). It is the **sole** key: only
  `ListParts` checks that it belongs to this request's bucket and key
  (`list.go:114`); `UploadPart`, `Complete` and `Abort` look it up by id alone and
  then seal under whatever `session.ObjectKey` says. Today the backend reconciles
  the two, which under ADR 0001 is an adversary being trusted for consistency.
  `RegisterSegmentedSession` is an unconditional map assignment with no collision
  check (`:182-189`).
* **The sweeps have no owner filter**, and the idle sweeper never re-checks its
  verdict: it collects candidates under the lock, releases it, aborts at the
  backend and then deletes without re-reading `idleFor()` (`:379-421`). A part
  arriving during the abort round trip touches `lastTouched` and the upload is
  killed anyway.
* **`lastTouched` is a monotonic reading today.** It is set from `time.Now()`
  in-process and read with `time.Since` (`:286`, `:288-293`), so an NTP step or a
  VM suspend cannot make a live upload look idle. Serialising it into any shared
  store strips the monotonic reading and turns the sweep into wall-clock
  arithmetic between machines. Nothing in the tree handles inter-node skew;
  `s3_security.max_clock_skew_seconds` governs the *client's* signature time
  ([s3auth_robust.go:245-249](../../internal/proxy/middleware/s3auth_robust.go)).
* **Nothing bounds a single `UploadPart`.** `read_timeout` and `write_timeout`
  default to 0 (ADR 0015 D1/D8); the only de-facto ceiling is the idle sweeper, so
  a 5 GiB part may legitimately run for the best part of an hour
  ([README.md:479-486](../../README.md)). A lease shorter than that must be
  renewed while the body is in flight, and there is no progress hook anywhere —
  `SealStreamingPart` returns a lazy reader and the copy loop belongs to the SDK.
  ADR 0015's Alternatives explicitly rejected "per-connection progress deadlines
  refreshed on every copy iteration".
* **The DEK cache is per process, per object, and has no key** — an LRU of 1024
  keyed `fingerprint:objectKey:sha256(wrapped)[:8]`
  ([providers.go:19-23,345-348](../../internal/orchestration/providers.go)). It is
  not a KEK-unwrap cache any instance would warm identically; its coverage divides
  by N. With the `aes` provider that is free (549.9 ns per unwrap, measured in
  `perf-baseline/`); with a network-backed KEK ([025](025-tink-kms-hcvault.md)) it
  is the whole cost question.
* **An instance identity exists, in one subsystem only** — see correction 3. The
  access log is at **Debug** ([logging.go:56](../../internal/proxy/middleware/logging.go)),
  so at the default `log_level: info` there is no per-request line at all, and the
  line drops the query string (`r.URL.Path`), so `?uploadId=` never appears in the
  one per-request record the proxy keeps.
* **No metric describes what an instance holds** — no open-session gauge, no
  held-bytes gauge, no sweep counter
  ([metrics.go:74-140](../../internal/monitoring/metrics.go) is the complete set).
  Worse, the failure cannot even be counted: the `endpoint` label is the mux path
  template, and every object-level verb shares `/{bucket}/{key:.*}`, so a
  `404 NoSuchUpload` is indistinguishable from any other 404 on `PUT`. And the
  chart ships **no alerting rule at all** — no `PrometheusRule` anywhere under
  `deploy/`.
* **The licence is a correlated, fleet-wide failure.** Each process runs its own
  60-minute expiry ticker from its own start
  ([validator.go:184-197](../../internal/license/validator.go)) and on expiry runs
  the full graceful shutdown and exits 1, then fails the startup gate on restart.
  So a lapsed token takes the whole fleet within an hour, pod by pod — and open
  question 6's "hand over to a survivor" has no survivor in exactly the case an
  operator would most want one. `k8s_cluster_id` is parsed, logged and never
  enforced ([types.go:19](../../internal/license/types.go),
  [logger.go:41-42](../../internal/license/logger.go)); whether N instances cost
  nothing *commercially* is a question for the owner, not a fact about the code.
* **`/health` is both probes and checks nothing but the drain state**
  ([handler.go:51-99](../../internal/proxy/handlers/health/handler.go),
  [values.yaml:134-150](../../deploy/helm/s3-encryption-proxy/values.yaml)), and
  the router registers no second path. So a readiness gate on a coordination store
  is also a liveness gate, and a store blip restarts every pod at once. Liveness is
  `periodSeconds: 10 / failureThreshold: 3`, so a draining pod is killed at roughly
  30 s while `shutdown_timeout` defaults to 30 s — and a SIGKILL skips
  `AbandonAllSessions`, the only non-test caller of which is `Manager.Shutdown`.

**Still not verified.** Whether any backend other than MinIO accepts `UploadPart`
for one upload id from a second client (a conformance case, ADR 0027). Whether two
S3 implementations can mint the same opaque upload id — nothing in this repo
assumes or checks it, and it decides whether a shared table may be keyed on the
id alone once [037](037-multiple-backends.md) lands.

## What it would need from the configuration

Per item: the key today, the shape the feature would need, whether changing it
later is breaking.

**1. `optimizations.multipart_short_part_buffer_size` — the scope is not in the
name.** Unchanged in substance, but see correction 1 (no longer free) and
correction 9 (the number does not bound a pod today either, so the scope question
and the read-then-reserve ordering have to be answered together).

**2. `optimizations.multipart_session_idle_timeout` and `…_cleanup_interval` —
same class**, and see the monotonic-clock finding: the contested resource is not
the timeout's value but *who writes the clock and how often*. Under a shared table
the touch is a store write on every part.

**3. `shutdown_timeout` — one budget for the whole shutdown** (ADR 0029 D1/D3).
Not breaking, but the sizing consequence is sharper than "advice changes":
`runShutdownTail` hands the tail what is *left* of the deadline and, when the
drain used the whole budget, hands it one nanosecond plus a warning
([main.go:418-424](../../cmd/s3-encryption-proxy/main.go)); the sweep then leaves
every upload. **A hand-over placed in that tail is the phase that gets skipped
exactly when the fleet is busy.** The chart derives
`terminationGracePeriodSeconds = shutdown_timeout + 5` unless the operator sets
the key explicitly (`_helpers.tpl:110-118`) — and under
`configMap.useExistingConfigMap: true` it parses `.Values.config` anyway and
stamps 35 s on a pod whose real configuration may say 300.

**4. There is no `cluster:` or `coordination:` block, and that forecloses nothing
in the loader — but it is not deployable by the chart either.** `ErrorUnused`
(`config.go:324-326`) refuses only keys the proxy does not define, so a new block
breaks no existing file. Two traps:
* **`${VAR}` expansion is a hand-maintained per-field allowlist**
  ([envexpand.go:45-104](../../internal/config/envexpand.go)) — four fields per
  `s3_backends` entry, two per `s3_clients` entry, every string under
  `encryption.providers[].config`, and nothing else. A `coordination.shared_secret:
  "${S3EP_PEER_SECRET}"` added without touching that function starts successfully
  and uses the literal placeholder text as the secret. The reverse move is also a
  trap nobody has written down: adding an **existing** field to that list is
  silently breaking for any file whose value contains a literal `${`.
* **The chart generates `tls:` and `monitoring:` itself and fails the render if
  `.Values.config` also carries either key** (`_helpers.tpl:218-228`,
  `configmap.yaml:18-36`). A generated coordination block needs a third
  duplicate-source refusal, new values keys and a recomputed pinned ConfigMap
  hash; a raw one means a peer credential in plaintext in a ConfigMap, because the
  deployment wires exactly three `secretKeyRef` cases.

**5. `tls:` has exactly three keys**, and mutual TLS is a **new mechanism, not two
more keys**: `grep -rnE "ca_file|CAFile|RootCAs|ClientCAs|ClientAuth"` over
`internal/`, `pkg/`, `cmd/` returns no non-test hit, and the listener calls
`ServeTLS(listener, certFile, keyFile)` with no `tls.Config` at all. On the
chart's cert-manager arm the issued certificate hardcodes `usages: digital
signature / key encipherment / server auth` with no values override
([servicetls-certificate.yaml:24-27](../../deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml)),
so it cannot authenticate the initiating side of a peer connection whatever names
it carries. Note the asymmetry this exposes: the **backend** leg — which already
carries the wrapped DEK and every object byte — has no configurable CA either, and
that is [039](039-backend-certificate-verification-failure-is-named.md)'s
territory. Deciding the peer leg's trust model without the backend leg's is how the
two drift.

**6. Two discriminators already exist**, so a peer credential type is additive —
but **it must be plural in its first release.** There is no configuration reload
anywhere (no `SIGHUP`, no `WatchConfig`, no `OnConfigChange`), so rotating a peer
or store credential is a restart of every instance, and a restart ends every
upload each of them holds (ADR 0029 D2). A scalar credential makes rotation an
upload-killing event; singular-to-plural later is exactly the shape change
ADR 0013 D11 makes expensive, and this repo has paid it once already.

**7. The request id's shape is fixed by an ADR, not a key** (ADR 0008 D12a).
Unchanged — but there is a client-visible identity slot the ticket missed:
**`x-amz-id-2` / `<HostId>`**, which this proxy emits nowhere (`s3Error` has
`Code`, `Message`, `Resource`, `RequestID` and no `HostId`). Every AWS SDK logs it
beside the request id and tolerates its absence, so adding it changes no existing
answer. Against it: ADR 0030 D4 says a label that identifies the deployment is a
change to that decision, and a header every client sees is a stronger disclosure
than a scrape.

**8. There is a second, more useful client-visible lever the ticket names as a
fact and never uses: the upload id.** It is the backend's own, handed through
verbatim, and it is the one value the client returns on *every* request of the
upload. A proxy-minted id carrying an opaque per-process token makes ownership a
local string parse — no store, no lease, no identity key, no round trip. Its cost
is specific: `ListMultipartUploads` fills its document from the backend's raw ids,
so a listing would name ids no client holds; and the exit provider must keep
handing the backend's id through untouched (ADR 0025). **Breaking** — clients
persist upload ids.

**9. A shared session key needs a backend discriminator once
[037](037-multiple-backends.md) serves more than one entry.** 037 already says so
(`037:367-371`); 036 argues the opposite ("the identifier already exists"). Only
one of the two can be right.

**10. A lease duration is a third number that must agree with `shutdown_timeout`
and the derived grace period** — the exact drift the chart's own comment refuses
to allow ("two numbers that have to agree drift, and the one that loses is the one
nobody looks at"). Longer than the grace period and an adoptable upload stalls
after every rollout; shorter than the worst pause and two instances own one upload.

**11. A peer listen address cannot reuse the one address validator this product
has**, and the two serving bind addresses are validated nowhere.
`requireLoopbackAddress` (`config.go:651-680`) asserts the exact inverse of what a
peer address needs and runs only when pprof is on; `bind_address` and
`monitoring.bind_address` get no syntax check, no port check and no cross-check.
A third listener makes three addresses that must not collide, checked nowhere —
and the failure precedent is inconsistent: a monitoring listener that cannot bind
logs an Error and the process serves on, while the S3 listener is `Fatal`. **A peer
listener that binds nothing and logs would be an HA deployment that silently is
not one.**

**12. No key can express "this value must be identical on every instance", and
four of them must be.** `encryption.metadata_key_prefix`, the provider set and
each `aes_key` (an object is addressed by KEK fingerprint), the active
`encryption_method_alias`, and the `s3_clients` set. A mismatch produces
`403 InvalidObjectState` or `403 InvalidAccessKeyId` — errors that do not read as
configuration drift. The rollout surge of correction 8 already produces this
window today on every configuration change.

## What a release can carry, and what forces the next major

The original section is void (correction 1). The useful line is different now:
**the first thing that changes a client-visible answer forces the major**, and a
surprising amount does not.

**Ships in a 5.x minor — no answer changes, no key changes, no stored byte
changes:**
* classifying a session miss with one backend `ListParts` and logging the verdict
  — the call is already on `S3BackendInterface` (`s3_backend.go:82`) and already
  used on the exit arm (`list.go:174`). One round trip on the miss path, which is
  a cold path by construction, and it is the only way to tell "not mine" from
  "does not exist";
* a counter for that verdict, beside `s3ep_object_integrity_failures_total`, which
  is the existing precedent for a failure the request counter cannot see;
* an instance field and the upload id in the access log (and the decision whether
  that line moves from Debug to Info);
* **fixing the cross-instance `Abort` leak** — a defect independent of this
  feature;
* a committed red cross-instance acceptance test (ADR 0031);
* a new `coordination:` block and any peer TLS keys (ADR 0013 D11 — additive).

**Forces the next major (ADR 0018 D5):** replacing `404 NoSuchUpload` with an
honest transient code; a proxy-minted upload id; renaming the short-part budget
key; anything that puts an instance into the request id.

**Open question 21 is the one that decides the first list's fate:** is an answer
that is only reachable in a topology the chart refuses to render still "a
client-visible answer"?

## Consequences, by area

### Races between two instances

None of these are reachable today; all of them are what a shared table has to
answer. They are listed because each names an invariant, not a corner case.

* **Same part number from two instances.** S3 keeps the last part written; the
  table keeps whatever `RecordStreamedPart`/`RecordETag` wrote last, and the
  backend call runs unlocked between the two. An SDK retrying a part after a
  timeout onto a second instance is the ordinary way to produce it. When they
  disagree, `Complete` sends the table's ETags, the backend answers `InvalidPart`,
  and `complete.go:296` **aborts the whole upload**. Re-establishing ADR 0011 D2's
  silent assumption — that `table.ETag[n]` names the part currently live under n —
  needs a compare-and-set keyed on `(uploadID, partNumber)` with the backend ETag
  as the token.
* **Complete against an in-flight UploadPart elsewhere — three windows.** The
  complete handler takes the session lock four separate times
  (`complete.go:222`, `:235`, `:265-272`). A part entering between
  `VerifyClientParts` and `Complete` passes no D6 check and is still included; a
  part recorded after the list is built is stored at the backend, answered 200
  with an ETag, and then dropped — **accept, discard, report success**, which
  ADR 0007 exists to forbid.
* **`Complete()` is not idempotent and mutates the table** — it writes the trailer
  in as a real part (`:734-738`) and never clears `s.pending`, so a second call
  re-seals the held part with fresh nonces. Today only the deferred
  `CloseSegmentedSession` hides it (a retry gets `NoSuchUpload`). Under a shared
  table, a client retrying Complete after a timeout, or an instance dying between
  the mutation and the close, leaves an upload **no instance can ever finish**.
  Open question 6 covers shutdown hand-over, not retry semantics of the mutating
  verb.
* **A stale read at Complete is reported as the client's fault.**
  `VerifyClientParts` demands an exact two-way match and every mismatch is
  `400 InvalidPart` (ADR 0011 D6). An eventually-consistent read manufactures that
  for a correct client. **That fixes the consistency level**: the read at Complete
  must be linearizable with respect to every part write, which rules out a
  cache-first or replica-read design for this one call.
* **The sweeper on A kills an upload B is streaming.** `abandon` is a real
  `AbortMultipartUpload` at the backend, and the client's in-flight part then
  fails mid-body with `NoSuchUpload`. ADR 0028 D1 is the invariant broken.
* **Abort or Complete landing on a non-owner frees nothing on the owner.**
  `releaseSessionBudget` is only ever reached by the process holding the map
  entry, so the plaintext and the reservation stay until the idle sweeper fires.
* **Every instance runs a sweeper unconditionally and there is nothing to filter
  on** — a `SegmentedSession` carries no owner field. The owner open question 6
  asks for is not only leader election: even a single elected sweeper must know
  whether an upload is being served *right now*.
* **`AbandonAllSessions` walks both maps with no owner filter**, so a naive shared
  table has the first pod of a rolling restart abort every open upload in the
  deployment. Note the two maps stop being alike: a producer upload belongs to a
  live request in one process and can never be adopted, so ADR 0029 D2 holds for
  it unconditionally.
* **Which uploads survive a truncated shutdown is map iteration order** — no
  oldest-first, no owner filter — and the ones the budget cut off are counted, not
  named (`manager.go:197-202`). There is no metric for it.

### Reconstruction from the backend is foreclosed — and worse than foreclosed

The cheapest imaginable design is that a second instance rebuilds the session from
the backend. It dies three times, and the third death is the dangerous one.

1. **The DEK is unreadable.** Written at Create, returned by no S3 operation
   (correction 6).
2. **The per-part plaintext CRC32C and the held part's bytes are not at the
   backend at all**, and no verb reads an uploaded, uncommitted part (ADR 0011's
   own Alternatives).
3. **A reconstruction silently disarms ADR 0011 D2's offset check.** The recorded
   offset is what makes the check bite; an instance that did not seal a part can
   only recompute `(n-1)*partSize` from its own inference, so the check compares a
   derived value with itself and always passes. The documented failing shape would
   then complete **200 OK** and produce an object that fails authentication on the
   first read — the exact outcome ADR 0011 D3 exists to prevent.

And the asymmetry that makes ADR 0001 bite harder here than on the read path: on a
read, a lie about a stored length is caught because the trailer authenticates the
truth; on a reconstructed Complete the trailer is **being written** from the
backend's answer, so the adversary chooses the value that gets authenticated.

What *is* rebuildable: part numbers, backend ETags, stored sizes, and from a
stored size the plaintext length (`PartStoredLen` inverts uniquely). Enough to
*classify* a miss, which is the whole of the minimum above; never enough to
complete an upload. And a reconstructed `ListParts` would be wrong rather than
partial, because the held part **is** listed today and the backend does not have it.

**Deriving the DEK instead** — KEK plus object key plus upload id, so any instance
regenerates it — is not untried, it is decided against: ADR 0002 D1 requires the
key to be drawn from the system CSPRNG and never derived, and the ADR's
Alternatives rejects derivation explicitly. Taking that route means amending an
accepted ADR.

### Security

* **The wrapped DEK is bound to nothing but a constant purpose label.**
  `EncryptDEK` seals under `aadWrap = "s3ep-dek-wrap-v1"` and the `KeyEncryptor`
  interface has no object-key parameter; ADR 0002 D13 makes that minimality
  deliberate, so out-of-band recovery stays possible. It costs nothing today
  because the wrap travels only inside its own object's metadata. **The moment it
  travels as a field of a message or a store row, nothing cryptographic stops it
  being re-paired with another object key** — the object key is bound at the data
  layer, not the wrap layer, so it cannot be replayed to *read* another object, but
  it can be attached to a newly written one. Any anti-replay property has to come
  from the transport, and SigV4 authenticates the request line and headers, not the
  body, with no nonce store and a 900 s default window.
* **The store's primary key would be adversary-chosen.** The session is filed
  under the backend's upload id and registration overwrites without a collision
  check. Under ADR 0001 that identifier is the backend's to choose.
* **Only `ListParts` checks that an upload id belongs to the request's bucket and
  key.** After a hand-over, "which object key goes into the segment AAD" — the
  store row's or the request's — becomes an explicit choice, and the inconsistent
  answer produces segments sealed under a key the object is not stored at.
* **Parking the part table in S3 hands the backend a confirmation oracle.**
  `sessionPart.sum` is a plaintext CRC32C, and SECURITY_ARCHITECTURE.md §6.4a says
  in so many words why the object's own CRC32C lives sealed inside the trailer:
  "a plaintext checksum in cleartext beside the ciphertext would hand a hostile
  backend a confirmation oracle". Open question 1 prices that option on integrity
  and key secrecy; **authentication does not remove a confidentiality leak from an
  authenticated record.** Bucket, key and part layout are already visible to the
  backend; the per-part plaintext CRC32C is not.
* **There is no reserved object-key namespace.** Every object key reaches the
  backend as the client wrote it, the proxy builds the listings itself but filters
  no key out of them, and ADR 0009's namespace governs `x-amz-meta-*` only. A
  sidecar object holding HA state would sit in the client's namespace, appear in
  the client's own `ListObjectsV2` wearing this proxy's entity-tag mark, answer
  `403 InvalidObjectState` on a GET, and be deletable by the client through the
  proxy. Reserving a prefix is itself a client-visible refusal.
* **A lease or lock service is a new denial-of-service surface.** Readiness today
  depends on nothing outside the process, so no external component can take
  instances out of rotation. And the destructive primitive already exists: both
  sweeps call a real `AbortMultipartUpload` per entry, safe today only because the
  table is the process's own. With an owner field over a shared table, whoever can
  write "this instance is dead" can have a healthy instance abort other instances'
  live uploads.
* **KEK rotation has no rolling form.** The procedure is "add the new provider,
  point the alias at it, restart" (SECURITY_ARCHITECTURE.md §7.1), which at N
  instances is a rolling restart — a window in which pods hold different provider
  sets. An object written by a pod with a new provider is `403 InvalidObjectState`
  on a pod that has not loaded it, which the product documents as a **permanent**
  state of that object. The safe ordering (every instance loads the new provider
  before any makes it active) is written nowhere.
* **What a compromised member gets differs by an order of magnitude between open
  question 3's two arms.** Wrapped-key arm: bucket names, object keys, the part
  table with offsets, lengths, checksums and ETags, and the ability to corrupt or
  abandon uploads — no plaintext of sealed parts, because unwrapping still goes
  through the configured key encryptor. Plaintext-key arm: **membership is DEK
  access**, a path to in-flight plaintext that bypasses the KEK entirely, which
  §5.2 does not contemplate. In both arms a member sees the held part's plaintext
  if hand-over moves it.
* **What has to change in SECURITY_ARCHITECTURE.md**, by name: §2.1 Roles (two
  network rows today; a peer leg and a store are a third and fourth), §2.2
  Boundaries (the sentence "The single boundary that matters runs between the
  proxy and the backend" becomes false), §3.3 Where each secret lives (the
  in-flight-DEK row, plus a new row if client plaintext moves), §3.6 (only if the
  store is S3), §4.1/§4.2, §5.2 ("an attacker who takes the proxy" → any one of
  N), §6.2-6.4 (the replay window becomes a key-handover replay window if SigV4 is
  reused), §6.6 Transport (a third leg), §7.1 (a rolling form), §7.2 (new
  rotatable material). Section 8's next free identifier is **H-12** — and archived
  ticket 031 already records an H-12 owed elsewhere, which is a rule living in an
  archive that ADR 0022 forbids.
* **Sticky routing is what §1.2 rule 2 forbids**, more strongly than ADR 0033's
  best-effort argument: "A control that exists only in configuration or in
  documentation is worse than no control, because it gets relied upon." The chart
  ships no `sessionAffinity` key at all, ADR 0030 D1 says it will ship none, and
  the proxy cannot observe affinity failing — a misrouted part is answered
  `404 NoSuchUpload`, the code that blames the client, with nothing anywhere
  saying affinity broke.
* **A shared, low-latency store removes the standing excuse for two accepted
  residual risks.** ADR 0014 declines rate limiting and a replay nonce store partly
  because the proxy has no shared cross-process place to keep counters. The
  coordination store is that place, and the first person to notice will propose
  putting them there. Saying no in advance, with the reason, is cheaper than
  arguing it afterwards.

### The chart and the deployment

* **Two chart unit tests fail on a `Chart.yaml` version bump alone** — they pin
  literal sha256 values for `checksum/config`, and the rendered ConfigMap carries
  the `helm.sh/chart` label. The release that lifts the refusal is a major, so
  those literals move in the same change. (The test file's own comment says so.)
* **Lifting the refusal has no way to know the image can coordinate.** ADR 0033
  banks on the refusal being "a values check, so it moves with the chart rather
  than with the binary" — but `image.tag` may be pinned to anything and no template
  does a `semverCompare`. A chart that permits three replicas against a 5.x image
  reproduces the intermittent `404` that D2 says must not be left to a paragraph,
  with the chart's blessing.
* **The refusal's message argues only about scale-out**, so it over-reaches: a
  standby that takes no traffic falls inside its scope and outside its argument.
  Whatever shape is chosen, the gate has to become a statement about capability,
  not a count.
* **No metric an HPA can use exists, and the one it would reach for is wrong.**
  `hpa.yaml` renders only Resource cpu/memory. Memory is measurably load-invariant
  for this proxy (peak minus idle 2.36 MB under a 2×128 MiB load) because it
  streams, and a pod that exceeds its limit is OOMKilled — a SIGKILL, so the drain
  and the sweep never run and every upload it held is orphaned at the backend.
  Whether CPU tracks load is unmeasured: no instrument in `test/perf/` records CPU
  utilisation per point.
* **Nothing can tell Kubernetes which pod is expensive to delete.** The one lever
  is the `pod-deletion-cost` annotation, which the process would have to patch
  itself — needing the API token `serviceaccount.yaml:12` switches off.
* **A PodDisruptionBudget counts pods; what needs protecting is uploads.** Without
  hand-over, `minAvailable: N-1` buys capacity and protects no upload at all.
* **The peer leg has no port, no Service and no way to see peers that are not
  Ready.** No headless Service, no `publishNotReadyAddresses`, and the workload is
  a Deployment, so a joining instance cannot see the peers it must join before it
  is itself Ready. A Deployment→StatefulSet change is an **uninstall and
  reinstall**, not an upgrade — Helm cannot change the Kind in place.
* **The Kubernetes API is the one coordination store that needs no new component**
  — `coordination.k8s.io/Lease` is purpose-built for this — and open question 1
  does not list it. Taking it means mounting the service-account token the chart
  disables, adding RBAC, and rewriting the chart README's "The proxy never talks to
  the Kubernetes API" and "no mounted service account token".
* **ADR 0030 D1 has already fixed the deployment layer's answer for a peer port,
  and the answer is "nothing".** Everything defending a port carrying key material
  has to live inside the proxy.
* **There are no `topologySpreadConstraints` anywhere in the chart**, and the
  production anti-affinity selects on `app.kubernetes.io/name` alone. Inert at one
  replica; wrong the day N is allowed.
* **The shipped Grafana dashboard reads as one instance.** The two latency panels
  already `sum by (le, endpoint)`; "Request Rate" does not aggregate and carries no
  instance label, so N pods plot N indistinguishable lines and never a fleet total;
  the two licence panels are gauges that become N tiles. Separately,
  `s3ep_license_info` can never take the `0` its Help string promises — it is set
  only on the valid path — so an alert on `== 0` can never fire.

### Testing

* **A two-instance test bed already exists and is committed.**
  `docker-compose.demo.yml` runs `proxy` (:8080) and `proxy-tls` (:8443) from the
  same image against the same MinIO, with the same `${S3EP_AES_KEY}`, the same
  clients and the same default `s3ep-` prefix; the two configs differ only in
  `bind_address`, the `tls:` block and the monitoring port. Both endpoints are
  already in `test/e2e/harness/demo-stack.env` and in the integration helper
  (`NewProxyTLSClient()`). **ADR 0033's residual risk should read "no suite crosses
  the two instances the stack already runs", which is a much cheaper gap.**
* **Two things would make that test lie.** The two instances differ by *transport*
  as well as by process, so a failure is "another instance" or "the
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` path" and the test cannot say which; and
  `make test-integration-tls` repoints `S3EP_TEST_PROXY_ENDPOINT` to the TLS
  endpoint, so in that run both clients address the **same** container and the test
  silently degenerates into a same-instance test that passes. A third plain-HTTP
  demo service, or a `ProxyHTTPEndpoint` constant that never moves, fixes each.
* **A red test here blocks every release.** `integration-tests` is on
  `semantic-release`'s `needs:`, and ADR 0031 D8 forbids the obvious escape ("a
  suite that asserts a target is placed where it gates, not in a round that gates
  nothing"). The two existing non-gating rounds — the perf baseline and the paid
  conformance run — are exempt for reasons unrelated to red tests. **This is a
  decision to take before anyone writes the test**, and it is open question 22.
* **ADR 0031 D6 puts today's 404 on the open side.** ADR 0033 D1 decides the
  smaller thing (the chart installs one); D3 and both residual risks defer the
  larger one. So red is the correct colour, and a test asserting `404
  NoSuchUpload` green would be D4's "table of known defects" wearing a green badge.
* **Cross-instance *reads* are the feature's load-bearing assumption and nothing
  asserts them either.** `NewProxyTLSClient` has two callers and both write and
  read with the same client. A PUT on one endpoint and GET/HEAD/ranged-GET on the
  other, compared by SHA-256, is green today at no cost and would pin two things
  the stack currently gets by accident.
* **The e2e client suites structurally cannot do it.** rclone and s3cmd each name
  one endpoint per config and `endpoints(t)` runs every case once per endpoint;
  neither client can switch endpoint mid-upload. They would see HA only behind a
  load balancer the demo stack does not have.
* **A Kubernetes-shaped test is blocked by the chart, not the proxy** — the
  refusal is pinned character-for-character in `tests/deployment_test.yaml`, and
  `e2e-up.sh` installs through that same chart.
* **Out of reach for every harness in the repo:** an ungraceful kill mid-part (no
  SIGKILL of an in-process instance; `docker kill` would lose that container's
  coverage counters, which the CI job collects), a lease expiring under a
  partition (no fault injection anywhere), split brain, and N>2.
* **The backend question belongs in conformance** (ADR 0027): does *this* backend
  accept `UploadPart` and `Complete` for one upload id from a second, independent
  client? A backend that binds an upload to a session falsifies the whole
  shared-state design on that backend, which is exactly the finding ADR 0027 exists
  to produce. `conformance.go:274` already provides `BackendClient(t)`.

### Performance

* **The coordination cost is a write per part, not a fetch per upload.** Because
  `partSize` is read-modified-written before every seal, a shared session cannot be
  write-behind for that field. Measured in this repo: an 8 MiB upload runs at
  162.5 MiB/s (HTTP), so one 8 MiB part is ~49 ms and the smallest streamed part
  (5 MiB) ~31 ms. A sub-millisecond cache read is 1-3 % per part; a
  quorum-committed write is 10-40 % on the minimum part. An upload may have 9999
  parts, so a 78 GiB backup is ~10 000 round trips. And there is no slack: the
  streamed path already measures 99.8-99.9 % of direct at 1-2 workers.
* **Open question 3's performance side is noise.** A KEK unwrap is 549.9 ns
  median, amortised per object per instance by the LRU, against a ~660 µs
  small-object GET — 0.08 %. **Decide it on the security argument alone.**
* **Per-pod throughput at the shape the chart ships has never been measured.**
  Every recorded number comes from a demo container with no CPU limit on an
  18-core host; the chart ships `limits.cpu: 500m` (1000m in production), and with
  `go 1.27` the runtime derives GOMAXPROCS from the cgroup quota. So a production
  pod is roughly a one-core process and the baseline says nothing about it —
  **N cannot be sized**, and "the link is the bottleneck" is untested at that
  allotment. Where the proxy plainly *is* the bottleneck is small objects:
  `get_rate_c8` at 1 KiB is 40.6 % of direct, `c32` 32.2 %.
* **ADR 0020's method cannot express a multi-instance run.** `compare.py` pairs on
  `(instrument, transport, operation, subject, size_bytes)` with no topology
  dimension, so a one-instance "before" and a three-instance "after" pair silently
  and the printed percentage reports a capacity change as a code change. And the
  one armed assertion — D14's memory bound — scrapes a single fixed metrics URL,
  which behind N instances reads a process that may not have served the load.
* **The throughput half needs no shared state at all.** Reads, single-request PUT
  and the internal producer scale out the moment the chart's refusal becomes
  conditional. The cost of separating the two halves is a client-visible decision,
  not a performance one: a multi-instance mode without a session store has to
  refuse `CreateMultipartUpload` up front rather than answer a later 404
  (ADR 0006, ADR 0007).

### Other tickets

* **[037](037-multiple-backends.md)** — the shared row needs a backend
  discriminator (037 says so at `:367-371`; this ticket says the opposite), and
  backend health is a per-instance, per-request opinion with no shared view, so two
  instances could pick different backends for the same key during a partial outage.
* **[025](025-tink-kms-hcvault.md)** — the whole cost question is the frequency
  fork this ticket half-states. If an adopting instance unwraps through
  `DecryptDEK` the LRU makes it ~one unwrap per (instance, upload); if the adoption
  path bypasses the cache — which [040](040-managed-buckets.md) separately demands
  for its scan — it is **one unwrap per part**, up to 9999 KMS calls for one
  upload. That fork is the difference between 025 being compatible with 036 and
  not. Separately, spreading *reads* across N instances decays the per-object hit
  rate toward 1/N, which is free with `aes` and expensive with Vault.
* **[040](040-managed-buckets.md)** — claims "no overlap beyond the shared
  argument"; its central cost argument is "One replica means the scan is the
  service's downtime, not a slow pod. ADR 0033 D1 makes `replicaCount > 1` a render
  failure", which is precisely the refusal this ticket lifts. Also: 040's
  fingerprint-seen counter is per process and resets per pod restart, so a fleet
  zero is never evidence of absence.
* **[029](029-multipart-idle-clock.md)** — its remaining work is to move the idle
  clock during a part, as an `atomic.Int64` stored at most once a second. **That
  throttled store is the shape a lease heartbeat needs.** Landing 029 first hands
  036 a designed, tested heartbeat; landing 036 first means 029's fix gets designed
  twice. Neither ticket references the other.
* **[017](017-filename-encryption.md) / ADR 0023** — the session carries the
  client's cleartext bucket and object key, and ADR 0023 D8 puts the name transform
  at exactly one boundary, below which everything is the stored name. A shared row
  parks exactly what filename encryption exists to hide, in a component ADR 0023
  never considered. Either the row carries the stored name and the receiver
  re-derives, or "exactly one place" becomes two. Neither record mentions the other.
* **[026](026-sse-c-passthrough.md)** — needs nothing from here, and that is a
  constraint on the row schema: SSE-C is per request by S3 semantics, so **the
  shared row must carry no field that can hold a customer key.**
* **[039](039-backend-certificate-verification-failure-is-named.md)** — under N
  instances a private CA can be right on some pods and wrong on others, and the
  symptom is intermittent `500 InternalError` on a fraction of requests. It is a
  concrete consumer for open question 5, and the cheap answer (a Debug-only access
  log) does not serve it.
* **[033](033-out-of-band-recovery-path.md)** — unaffected in either direction
  (its inputs are per object). What N instances add is a possible *responder* to a
  crash orphan; the crash case itself is already recorded in ADR 0028 and
  ADR 0029 and is absent from this ticket's questions.

### Documentation and ADR mechanics

* **How ADR 0033 D1 gets reversed is undecided and the ticket does not name it.**
  ADR 0022 D9 mandates in-place amendment; the exact precedents are ADR 0028 D5
  (superseded by ADR 0029, with reciprocals in 0029's Status and References) and
  ADR 0004 D10 (superseded by ADR 0025). **No record in this repo has ever been
  superseded as a whole**, and `docs/adr/README.md:57` asserts it in a sentence
  that would have to change if one were.
* **ADR 0033's title and filename assert the rule being reversed** — "…so the
  chart installs one" — which is precisely the "a reader must never find the old
  rule stated as current" failure D9 exists to prevent. Amending in place leaves
  it; renaming breaks six filename-carrying links. Nothing in
  `docs/adr/README.md`'s "Keeping them current" covers a title change.
* **ADR 0033 has no `## References` section** — one of only two records that
  lacks the required section — so a reversing record would be reachable from 0033
  not at all.
* **Three defects in the ADR index a 036 round would clear:**
  `docs/adr/README.md:8` still says a ticket "is **deleted** when the work lands"
  (ADR 0022 D4 was amended to "moved into `archive/`" on 2026-09-13 — the page that
  indexes the ADRs contradicts the ADR that governs it); the State column is
  stamped "as of 2026-09-13" while the 0033 row is dated 2026-09-14; and the 0033
  row sits out of numeric order.
* **Eight developer pages state something that stops being true**, and the
  original "Done when" named none of `docs/developer/`: `multipart.md` §*Shutdown
  ends what it is still holding* ("no other replica can adopt it" is the feature's
  one-sentence negation), §*Back pressure*, §*A session outlives its request*,
  §*Under the exit provider there is no session at all*; `package-map.md`'s
  `manager.go` row; `request-paths.md` §*Before the handler*; `performance.md`
  §*Memory*; `errors.md`'s two `404 NoSuchUpload` rows; `configuration.md` §3 (and
  §1, whose "nothing else reaches the proxy from outside the file" is already false
  — `metrics.go` reads four variables); `testing.md` §*The layers*;
  `developer/README.md`'s page table and its gap table.
* **`DEVELOPER.md` has no checklist for "a new outbound dependency"**, which is
  what a session store is — its eight checklists cover none of a credential, a
  trust store, a readiness effect, a failure mode and its status class, or a
  metric. And its *A configuration key* checklist does not name CLAUDE.md's
  configuration table, which CLAUDE.md itself declares a startup failure if
  forgotten: two lists of the same duty that disagree.
* **SECURITY_ARCHITECTURE.md is the only document that cites code by line** — 95
  such links, thirteen of them in §3.3 alone, nine into exactly the code this
  feature rewrites — and nothing in the repo owns keeping them true: the update
  rule is stated only for `docs/developer/` and that page puts
  SECURITY_ARCHITECTURE.md outside its scope.
* **The ADR 0029 rationale to re-read before touching it:** D1 step 2 and D7 both
  justify their behaviour with "another replica" / "a replacement instance is
  already taking the traffic". That is true today only because of the rollout surge
  of correction 8 — not because the deployment has a second replica. Whatever this
  work decides, those two sentences should end up meaning what they say.
* **The mirror list for a new configuration key is about sixteen places**, and the
  project's own checklist names five. Beyond the struct, `setDefaults`, the
  validation, the shipped examples and `README.md`: `envexpand.go`; CLAUDE.md's
  table; `docs/developer/configuration.md` §1 and §3;
  `internal/config/default_config_test.go`'s `cfgDefaultEnv`;
  **`scripts/conformance-run.sh`**, the one config `TestCfgShippedExamplesCarryNoUnknownKeys`
  cannot see and which CLAUDE.md already names as a red-CI trap; the chart's
  `values.yaml` `config:` block plus `values-development/-monitoring/-production`
  and `test/e2e/velero/values-proxy.yaml`; `templates/configmap.yaml` and a
  `_helpers.tpl` duplicate-source refusal if the chart generates it; the chart
  README parameter tables; `test/e2e/harness/demo-stack.env`; and the pinned
  ConfigMap sha256 in `tests/deployment_test.yaml`. **Nothing tests the
  documentation tables against the struct**, so a block spelled one way in the code
  and another in CLAUDE.md costs an operator a refused start and turns no test red.

## Open questions

All undecided. None is answered here. 1-6 are the original set, sharpened; 7
onwards are new.

1. **Where the shared state lives.** A shared database; a lock service such as
   etcd or Consul; the S3 backend itself; **or the Kubernetes API's
   `coordination.k8s.io/Lease`**, which the original list omitted and which adds no
   component to run — at the price of the service-account token the chart disables
   and an RBAC surface it has never had. The S3 option carries two costs beyond
   ADR 0001: the confirmation oracle of the per-part plaintext CRC32C, and the
   absence of any reserved object-key namespace.
2. **Whether any shared state is needed at all** — and note this is **not open in
   the sense the first pass implied.** ADR 0033's Alternatives already rejected
   sticky routing on three named grounds, and under ADR 0022 D9 a reversal amends
   that ADR rather than reappearing as an undecided row. So the real question is:
   *which of the three rejection reasons is wrong?* Two further shapes belong
   beside it, neither previously named: **a server-side forward to the owner** (see
   question 12), and **refusing honestly** (question 11).
3. **Whether a data key crosses the network** — unchanged as the security fork,
   but the performance half of it is noise (549.9 ns), so decide it on security
   alone. And it is **not the largest** state-crossing question: see question 7.
4. **Whether the short-part budget stays per instance or becomes cluster-wide.**
   Now also: does the reservation move ahead of the body read (correction 9)? A
   cluster-wide counter with today's ordering bounds nothing new, and moving it
   earlier puts a store round trip at the *start* of every held part and turns a
   local `SlowDown` into one that depends on a remote store. And who reclaims a
   reservation an instance died holding — the budget self-heals today only because
   it *is* process memory.
5. **Whether an instance gets an identity, and where it shows.** The metric-label
   option is already built (correction 3). What remains: the access log (which is
   Debug-only and drops the query string, so it answers nothing by default),
   `x-amz-id-2` (additive, standard, client-visible — and ADR 0030 D4 applies), the
   request id (breaking), or nowhere. And: what identity does a non-Kubernetes
   deployment have? It has none today.
6. **What a shutdown does to a session another instance could finish** —
   unchanged, plus: a hand-over inside the existing budget is the phase that gets
   skipped when the fleet is busy (item 3 above).
7. **Does the held short part's plaintext cross the network, or is Complete pinned
   to the instance holding it?** Up to `multipart_short_part_buffer_size` of client
   plaintext either sits on the peer wire or one verb keeps an affinity
   requirement — and pinning only the last part is a partial stickiness no load
   balancer can express. This is a strictly harder security question than 3.
8. **Is the part size inferred under HA, or declared once at Create?** It decides
   whether coordination is on the hot path of *every* part or only at Create and
   Complete — a 1-3 % versus 10-40 % difference on a 5 MiB part. Pinning it is a
   new client-visible refusal under ADR 0011 D2/D3.
9. **Which reads of the shared table must be linearizable, and which may be
   stale?** `VerifyClientParts` at Complete must be; a stale `lastTouched` makes a
   sweeper abort a live upload. Eventual consistency here is not a slower version
   of the same thing.
10. **Does the shared key stay the bare upload id, or become `(backend, bucket,
    key, uploadId)`?** Two of the four verbs do not check bucket and key today, so
    a compound key is also a new refusal path.
11. **If the proxy cannot serve a foreign upload, what does it answer?** Today's
    `404 NoSuchUpload` is wrong by the project's own class rule in `errors.md` (a
    transient cause deserves a 5xx) and is terminal to every SDK. `SlowDown` (503)
    is already in the vocabulary and in the SDK's throttle-retry set. But `SlowDown`
    alone converges badly: with `DefaultMaxAttempts = 3` the chance of reaching the
    owner is ~70 % at N=3 and ~14 % at N=20, and each retry re-sends the whole part
    body. It converts a lie into a truthful failure and a probabilistic success.
12. **Does an instance forward a misrouted request to the owner instead of moving
    the state?** The proxy canonicalises the **Host header**, not the TCP peer, so a
    byte-faithful forward re-verifies at the owner under the original client's own
    SigV4 signature — no peer credential, no key material on the wire, and open
    question 3 dissolves for this shape. Costs: the process owns no `http.Client`
    at all today, a misrouted part crosses the network twice, and the owner cannot
    tell a forwarded request from a direct one. **A client-facing 307 is dead** —
    Go's client will not follow a 307 with a body it cannot rewind, and
    `aws-sdk-go-v2` never sets `GetBody`; on a bodiless verb it *would* follow but
    Go strips `Authorization` across hosts, so it arrives unsigned.
13. **Does the proxy spend one backend `ListParts` on a session miss to tell "not
    mine" from "does not exist"?** It is the smallest piece with real value, is
    separable from every other question, and without it no honest error and no
    trustworthy metric is possible. Always, only under a coordination mode, or
    never?
14. **Does the upload id stay the backend's own, or does the proxy mint one that
    names the owner?** The fork that decides whether state has to move at all.
15. **Is the cross-instance `Abort` leak fixed now, as a standalone defect?** It
    needs none of the other answers.
16. **What ends an upload whose owner was SIGKILLed, after how long, on whose
    clock, and who deletes the row when the abort keeps failing?** ADR 0028 D2/D4
    are written for the owning process; a shared table is the first thing that makes
    the record outlive it.
17. **Is a lease renewed while a part body is in flight, or simply longer than the
    longest possible part?** Renewal needs the progress hook ADR 0015 explicitly
    rejected; the alternative is a lease of hours.
18. **Is coordination-store reachability a readiness condition, and what does an
    instance do while the store is unreachable — for reads, for single-request PUTs,
    for multipart?** Reads and single PUTs need no coordination, so putting them
    behind a store makes the majority of traffic *less* available than the single
    instance this replaces. And `/health` is both probes today, so any readiness
    gate is a liveness gate.
19. **Does joining the set validate that peers' encryption configuration agrees?**
    A store makes it possible for the first time — and a deliberate temporary
    disagreement is exactly what a rolling KEK rotation is.
20. **Should the chart set `strategy: Recreate` at one replica now, before any of
    this is built?** Correction 8 makes the two-instance state reachable on every
    `helm upgrade`, which is an unguarded hole in an invariant ADR 0033 states as
    held. Independent of this feature.
21. **Is an answer only reachable in a topology the chart refuses to render still
    "a client-visible answer" under ADR 0018 D5?** It decides whether question 11's
    honest error is a minor or a major. The repo's precedent cuts toward breaking
    (ADR 0007 D13; the eight multipart code corrections).
22. **Where does a deliberately red cross-instance test live so it is red without
    blocking releases of an unscheduled feature?** ADR 0031 D8 forbids the parking
    lot, and `integration-tests` gates `semantic-release`.
23. **Is this one ticket or two?** As written, six undecided design answers gate
    five checkboxes, three of which are documentation — so the half that needs no
    decision at all (classifier, counter, log field, the Abort fix, a red test)
    cannot land until the expensive half is designed, and ADR 0033's residual risk
    stays open indefinitely.
24. **Availability or throughput?** The title says the first; the body designs the
    second; ADR 0033 keeps them apart in two separate Consequences. **Active/passive
    with leader election** delivers exactly what the title promises — the service
    survives losing the serving instance — with no shared table, no key on the wire
    and no per-part round trip, and buys no throughput. And **is failover in scope
    at all**, or only cooperation: must something automatically take over an upload
    whose instance was SIGKILLed, or is it only true that another instance *can*
    take it if asked? Open question 6 asks only about graceful shutdown.
25. **Is a fleet single-cluster by definition?** It decides whether a per-part
    round trip is LAN or WAN, whether the licence's singular `k8s_cluster_id` still
    describes the deployment, and whether the chart is even the unit of
    installation.
26. **What is the coordination layer's observability contract, and what does
    support ask for after "my upload failed"?** No alerting rule ships at all, the
    access log is Debug and drops the query string, and no line joins a request id
    to an upload id. The first diagnostic an operator runs — listing incomplete
    uploads at the backend — comes back clean, because the SDK's uploader aborts on
    failure and the abort succeeds from any instance.
27. **Does the coordination store need backup, and what is its data
    classification?** Everything in it is in-flight, so the answer is probably "no
    backup" — which has to be *stated*, or an operator will build one. The half with
    teeth: the row holds wrapped key material and cleartext bucket and object names,
    so any snapshot becomes a durable record of every object name written through
    the proxy — and defeats ADR 0023 outright.
28. **Do the product's client-support claims survive N instances, and on what
    evidence?** ADR 0006 D5/D7 make support a claim about what was exercised. Every
    verdict table behind rclone, s3cmd and Velero was produced at one instance.
29. **On a scale-in, which pod does the autoscaler remove, and does the proxy get
    a say?** Scale-in is repeated and unplanned in a way a rollout is not, and the
    CPU signal falls exactly when uploads stop transferring — so the pod most likely
    to be removed is one holding idle-but-open sessions.
30. **Does a shared, low-latency store reopen ADR 0014's nonce store and its
    refusal of rate limiting, and is that explicitly out of scope?**
31. **What is the licence's pricing unit, and does an elastic instance count
    change what is sold?** `k8s_cluster_id` is singular, logged and unenforced;
    ADR 0016 keeps validation open; a coordination layer with a member registry is
    the one place an instance count would naturally exist. Cheapest to decide before
    the layer exists.
32. **Is anyone running the old three-replica production profile?** If yes, this
    work is a capacity regression owed to them with a deadline; if no, it is a new
    capability that can be sequenced freely.
33. **Is a 6.0.0 bundle branch being opened, and does 036 gate it or ride it?**
    (ADR 0018 D7/D11.) Shared with [037](037-multiple-backends.md) and
    [038](038-s3-encryption-operator.md), which carry the same expired premise.

## What it must not break

* [ADR 0001](../adr/0001-the-backend-is-hostile.md) — the backend is an
  adversary; state parked there is state it can change or drop, **and on a
  reconstructed Complete it chooses the value the trailer authenticates.**
* [ADR 0002](../adr/0002-one-data-key-per-object.md) D1 (the key is random, never
  derived) and D13 (the wrap is bound to nothing, on purpose — which is what makes
  a travelling wrap replayable onto another object) and
  [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md).
* [ADR 0006](../adr/0006-the-proxy-serves-any-s3-client.md) D5/D7 — support is
  claimed only as far as it is exercised, and every existing verdict table was
  produced at one instance.
* [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) — accept-and-discard is
  forbidden, which is what two of the Complete races produce.
* [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) D12a.
* [ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md) D1/D8 —
  the written key set is part of the stored format, so coordination state inside an
  object's metadata is a format change, not a deployment shape. (State as separate
  objects is outside D8 and governed by ADR 0001 plus the missing key namespace.)
* [ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md) D1/D2/D3/D5/D6 — and
  note D3's inference is only safe because D2's recorded offset makes the check
  bite.
* [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11.
* [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) D4/D5/D7/D8
  — every instance validates against its own wall clock, so NTP becomes a
  correctness dependency and the effective replay window is set by the widest clock
  in the fleet.
* [ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)
  D1/D8 and its rejected progress deadlines — which is the mechanism a short lease
  would need.
* [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md),
  [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md),
  [ADR 0027](../adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md)
  and [ADR 0031](../adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md)
  — the first pass cited no testing record at all.
* [ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md) D8 —
  the transform is at exactly one boundary, and a shared row sits above it holding
  cleartext names.
* [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md) — the exit provider keeps
  no session and must keep needing no coordination. **In tension with open question
  4:** its pass-through part path already charges the process-wide short-part
  budget, so a cluster-wide budget gives the exit provider a coordination
  dependency on its write path.
* [ADR 0026](../adr/0026-the-proxy-terminates-tls-at-its-own-service.md) — the
  issued certificate is server-auth only.
* [ADR 0028](../adr/0028-an-abandoned-upload-is-ended-not-forgotten.md) and
  [ADR 0029](../adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md).
* [ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md)
  D1/D4 — the chart will ship nothing to protect a peer port, and a label that
  identifies the deployment is a change to that decision.

## Done when

Split by what each item depends on, so the cheap half is not hostage to the
expensive half (open question 23 decides whether that split becomes two tickets).

**Needs no design decision — could ship in 5.x:**

- [ ] The cross-instance `Abort` leak is fixed, or recorded as accepted with its
      window stated (open question 15).
- [ ] A session miss is classified against the backend and the verdict is logged
      and counted, or question 13 is answered "never" with the reason.
- [ ] A red cross-instance acceptance test exists, placed where question 22
      settles, with the transport confound removed.
- [ ] A green cross-instance *read* test exists (PUT on one endpoint, GET/HEAD/
      ranged GET on the other, compared by SHA-256).
- [ ] The stale chart prose is corrected: `values-production.yaml:3-5`,
      `values.yaml:6`, and the ADR index's three defects.
- [ ] Question 20 (`strategy: Recreate` at one replica) is answered.

**Needs the design, before any code:**

- [ ] Open questions 1, 2, 24 and 25 are answered — which property is being
      bought, whether state is shared at all, which store, and whether a fleet is
      single-cluster — and recorded in an ADR.
- [ ] Questions 3 and 7 are answered and `SECURITY_ARCHITECTURE.md` carries the
      key flow *and* the plaintext flow between instances, with its seven affected
      sections rewritten and H-12 (or H-13) claimed.
- [ ] Questions 8, 9 and 14 are answered — the part-size inference, the
      consistency contract, and the upload id — because together they decide whether
      coordination is on the hot path.
- [ ] Questions 16 and 17 are answered and ADR 0028's and ADR 0029's premises are
      amended or confirmed with their reasons re-derived.
- [ ] Question 4 is answered and the budget key's name matches its scope.
- [ ] Question 5 is answered; a change to the request id goes in a major.
- [ ] Questions 18, 26 and 27 are answered: readiness, the observability contract,
      and the store's classification and retention.
- [ ] Question 31 is put to the owner before the coordination layer is built.

**The work itself:**

- [ ] A client-driven multipart upload whose Create, parts and Complete are
      deliberately spread across instances completes, asserted end to end against a
      real backend — and the same is asserted for an ungraceful loss of the owning
      instance, or failover is declared out of scope and said so in the ADR
      (question 24).
- [ ] The conformance suite answers, per backend, whether one upload id is
      servable by a second independent client (ADR 0027).
- [ ] The configuration table in `CLAUDE.md`, the reference in `README.md`,
      `docs/developer/configuration.md`, the shipped examples,
      `scripts/conformance-run.sh` and the chart's values files all carry every new
      key, with its default marked — and `envexpand.go` carries any field that must
      come from the environment.
- [ ] The eight affected `docs/developer/` pages are updated in the same change,
      and `DEVELOPER.md` gains a checklist for an outbound dependency.
- [ ] ADR 0033 is amended by the mechanic question 1 of the docs section settles,
      its `## References` section is added, and its title is dealt with.
- [ ] The chart lifts the refusal with a gate that says what the *image* can do,
      not what the replica count is; `values-production.yaml` is correct for it; the
      pinned ConfigMap hashes are recomputed; and the chart states what a
      multi-instance deployment requires.
- [ ] ADR 0020's run record carries the topology, or the baseline is declared a
      single-instance instrument by contract.
- [ ] Every reference to this ticket's number is cleared before it is archived
      (ADR 0022 D10): `docs/tickets/README.md`, `037`, `038`, `040` — and the stale
      `036` in `archive/035-the-pinned-defect-sweep.md`, which points at a retired
      ticket of the same number.
