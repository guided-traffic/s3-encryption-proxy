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


## Refining round, 2026-09-15 — what was decided

Worked through with the owner, question by question, against the running scenario
below. **What is written as decided is decided**; everything else says that it is
not. Two things were settled that are not among the thirty-three questions: the
release constraint, and a defect that left in a ticket of its own.

### The release constraint that governs every answer below

**No work on this ticket may produce a commit carrying a breaking marker, and
ADR 0018 is not amended.** The product stays on the 5.x line. That is a design
constraint, not a commit convention: ADR 0018 D1 computes the version from the
commit headers and D3 fails a pull request that carries a marker without the
`release:major` label, and D5 forbids softening a marker to route around the
guard. So an option that changes stored data, an existing configuration or a
client-visible answer has to be replaced by the variant that buys the same thing
additively — and twice below it could be, which is why the constraint is cheap
here rather than crippling.

### The decisions

**1. Where the shared state lives (questions 1, 2, 24).** A **shared session
table in an externally provided Valkey with Sentinel.** The store is never part
of the `s3-encryption-proxy` chart; an operator provides it, which is the same
division ADR 0030 D1 already draws for the network boundary.

Three shapes were weighed and rejected. *Sticky routing* — ADR 0033's
Alternatives already rejects it on three grounds and rule 2 of
`docs/security/threat-model.md` adds a fourth. *Refusing client-driven multipart in a multi-instance
deployment* — honest and free, and it takes Velero, rclone and s3cmd with it,
because every SDK uploader switches to multipart above a threshold; dead as an end
state under ADR 0006. *Owner-routing with a proxy-minted upload id and a
byte-faithful forward* — it dissolves roughly a third of the open questions and
needs no store at all, but it delivers no failover of an upload whose instance is
gone, which is the property the title of this ticket promises.

**Why Valkey rather than etcd or Consul**, stated because it is the whole reason
the shared-table shape is affordable at all: a quorum-committed write is the
10-40 % per part this ticket measures against the smallest streamed part, while a
primary write to Valkey is the sub-millisecond class the same paragraph prices at
1-3 %. The *Performance* section's verdict on a shared table was a verdict on
Raft, not on shared state as such.

**Why Sentinel rather than Valkey Cluster:** Sentinel keeps one keyspace. The
atomic script a part needs — raise the part size, compute the offset, record the
row — touches several keys of one session, and under Cluster those keys would have
to be forced into one slot by hash tags, with every mistake surfacing as a
`CROSSSLOT` error at runtime. Sentinel makes the problem not exist. Its native key
expiry also answers question 16 for free: a row nobody renews disappears.

**2. Three forms of deployment, not two (question 2).**

| Configuration | Meaning |
|---|---|
| no coordination block | in-process session table — **exactly today's behaviour**, no store, no new dependency |
| store configured, one replica | sessions outlive the process: a `helm upgrade` stops killing in-flight uploads |
| store configured, N replicas | high availability |

The middle row is the one that was nearly missed, and it is free — the adoption
path is the same one HA needs. It also matters more than it sounds: the Deployment
declares no `strategy:`, so every configuration edit rolls the pod through
`checksum/config`, and **today that kills every upload in flight**.

Two consequences. The store is not "the HA feature"; it is *sessions outlive the
process*, and HA is one consequence of that — the documentation has to say it that
way round or the middle row gets shipped untested. And ADR 0033's refusal stops
being a guess about the image: the rule becomes **`replicaCount > 1` is permitted
if and only if a coordination store is configured**, which is a values check the
chart can really perform. The leftover case, a new chart against an old image,
resolves itself cleanly — the old image does not define the key, `ErrorUnused`
refuses the start (ADR 0013 D11), and the pod crash-loops loudly instead of
producing an intermittent `404 NoSuchUpload` in the data path.

**3. The session layer becomes one interface with two implementations — never two
code paths.** In-process and Valkey, the way `KeyEncryptor` already has several
providers behind one interface. `if store != nil` branches in the orchestration
would be two products in one binary.

**And the interface is made of operations, not of storage.** This is the part that
decides whether it works: `partSize` is a read-modify-max *and* the offset
computation in one critical section, so an interface cut as
`GetSession`/`PutSession` leaks the atomicity out to the caller, where the
in-process mutex covers it by accident and the store does not. The shape is
`RaisePartSizeAndComputeOffset(...)`, `RecordPartIfCurrent(...)` — a mutex around
a map on one side, a Lua script on the other, and the caller cannot tell.

**4. The part size is pinned, and the refusal stays where it is (question 8).**
The first part that could be a middle part fixes `partSize`; it is immutable
afterwards and may therefore be cached locally, which turns every later offset
into local arithmetic. Coordination drops from two round trips per part to one.

**The early refusal that pinning makes possible is deliberately not taken.**
ADR 0011 D2's check at Complete stays the refusal point, so no client-visible
answer changes. It costs nothing: once the inferred maximum rises after any part
has been sealed the upload is already doomed, because Complete checks every part
against the final inference — so a pin condemns exactly the same set of uploads,
at exactly the same moment. Refusing earlier is a separate, later decision.

**5. The held short part never leaves the owner's memory (question 7).** It stays
as plaintext in the process that received it, as today, and `CompleteMultipartUpload`
is **forwarded to that owner** over the peer leg when it lands elsewhere. The
forward carries the client's own SigV4 and a small XML document, so no client
plaintext and no key material ever crosses between instances.

Rejected: sealing the held part under the object's data key and parking it in the
store. It would have bought complete failover — every other field is in the row —
at the price of a new AEAD construction to specify and review, and of chunking the
value, because a single write of up to `multipart_short_part_buffer_size` bytes
crosses Valkey's default `client-output-buffer-limit replica` soft limit and costs
a replica disconnect and full resynchronisation. Also rejected: parking it at the
backend, which has no reserved object-key namespace to park it in.

**The pin this creates is narrow, and that is what makes the decision cheap.** An
upload is bound to an instance only from the arrival of a held part, and only that
upload. Every SDK uploader produces the short part *last*, so the window is the
tail of the upload — the last part plus Complete — and everything before it stays
freely servable by any instance. **Round 2 corrects how narrow:** the short part is
dispatched last but is the smallest, so it seals while the full-size parts of its
concurrency batch are still uploading and Complete waits for all of them. The
window is the slowest still-running part, not a round trip — and it is an hour when
the client stalls after its 200.

**6. Ungraceful failover was declared in scope (question 24, second half) — and
[round 2](#refining-round-2-2026-09-15--the-idle-clock-landed-and-it-does-not-fit)
withdrew it the same day.** As taken, the decision read: an upload whose instance
is SIGKILLed is adoptable once the lease expires, not after the idle hour, with the
lease bounded from below by the Sentinel failover window — roughly 90 s — because a
TTL inside that window would have a live holder's upload adopted while it is
healthy. Its justification was the throttled idle-clock touch, "one store write per
second per part in flight, a 2600-fold reduction against a 64 KiB read loop at the
measured 162.5 MiB/s", and that this is not the per-iteration progress deadline
ADR 0015 rejected.

**Both halves of the justification are wrong against the code that landed, and
decision 5 forecloses the property the decision promises.** The decision stands
withdrawn; what replaces it is question 34.

**7. A defect found on the way out, since fixed.** One endpoint served both
probes and reported the drain, so a terminating pod failed liveness by design and
could be killed before the shutdown tail ran — which is where the sweep, and under
this design the lease release, live. The chart had no `preStop` hook either, so
the drain began while the pod's endpoints were still propagating. Both landed on
2026-09-15 and neither depended on anything here. What this ticket inherits is the
rule, [ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md): the serving listener answers `/livez` and
`/readyz`, a `preStop` hold runs before SIGTERM, and the grace period covers the
hold plus the drain plus the sweep.

### The reference scenario

**Every remaining question is answered against this, not in the abstract.**

Velero writes a backup of some tens of gigabytes through the proxy.
`aws-sdk-go-v2`'s uploader sends 5 MiB parts, five concurrently — and 5 MiB is
exactly 80 segments of 64 KiB, so **every part but the last is middle-part
capable**: aligned, and above the backend's 5 MiB minimum. The last part is
whatever the object size leaves over, practically never a multiple of 64 KiB, so
it is **held** under ADR 0011 D5. Three pods, a store configured, and a compatible
image update rolled through the API server.

**Phase 0 — before the rollout.** The row in Valkey carries the upload id, the
wrapped data key, the key-encryption fingerprint, the object key, the pinned part
size and the part rows. **The upload has no owner.** Parts are independent
(ADR 0011 D1), so every pod seals whichever part kube-proxy hands it, and the five
in flight spread across all three. This is 99 % of the upload.

**Phase 1 — the new pod joins first.** The chart declares no `strategy:`, so
Kubernetes' default applies: at three replicas that is `maxSurge 1` and
`maxUnavailable 0`, so a **new** pod becomes Ready before any old one is
terminated. It reads the row, learns the pinned part size and serves parts of an
upload the old version created. That is where "compatible image" does real work —
and where a **schema version in the row** earns its keep, because today the
compatibility is an assumption with no mechanism behind it.

**Phase 2 — an old pod is terminated.**
1. The `preStop` hold runs first, so the pod's endpoints are withdrawn before
   anything stops accepting ([ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md) D10). Then SIGTERM, and
   the drain begins.
2. The in-flight middle part finishes: sealed, stored, its row written, `200` to
   Velero. **That part is safe.**
3. The other four in-flight parts have their connections closed, the SDK retries
   them, and they land on another pod. A retried part replaces its own backend
   part and draws fresh nonces (ADR 0011 D1), so this is invisible to Velero.
4. The shutdown tail. *Today:* `AbandonAllSessions` aborts every open upload at
   the backend and **the backup dies here**. *Under this design:* the pod owns
   nothing — the held part is the last one and the upload is somewhere in its
   middle — so it releases its lease and goes.

**Phases 3 and 4** repeat for the remaining two pods. The backup runs through.

### What the scenario exposed

**1. Today this exact rollout kills the backup, at one replica as well as three.**
Kubernetes surges at `replicaCount: 1` too, the old pod drains, the sweep aborts,
and Velero's next part is answered `404 NoSuchUpload`. The `checksum/config`
annotation triggers the same roll on *any* configuration edit. This is the
concrete case for the whole ticket and it is not hypothetical.

**2. The pin window is about a second in an upload of minutes**, which is what
makes question 6 decidable rather than alarming. It is only dangerous when the
arrival of the held part falls inside a drain.

**3. The duplicate part stops being unlucky and becomes ordinary.** A part times
out on the terminating pod, the SDK retries it elsewhere, and the original backend
`UploadPart` may still land. S3 keeps the last part written; the table keeps the
last row written; the two orders are independent because the backend call runs
unlocked between them. When they disagree Complete sends an entity tag that is not
live, the backend answers `InvalidPart`, and `complete.go:296` **aborts the whole
upload**. This race exists in a single process today — the rollout only makes a
retry onto another instance certain. It is what the compare-and-set in *Races
between two instances* is for, and "which entity tag is live" becomes a decision
of its own.

**4. The peer leg needs its own listener, closed after the client-facing one.**
This follows from decision 5 and from the `preStop` hold ([ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md)
D10) together, and nothing else in this ticket would have found it. The hook
withdraws the endpoints before SIGTERM, so a client's `Complete` no longer reaches
the draining owner through the Service — it reaches another pod, which forwards it to the owner by pod address.
But `http.Server.Shutdown` refuses new connections from SIGTERM onward, so a
freshly opened peer connection is rejected in exactly the phase the forward exists
for. `runShutdownTail` already closes the client listener last, after the sweep;
the peer listener has to close behind that one.

### Proposed in this round, not decided

Each of these was raised with its reasoning and none was put to the owner as a
question yet. They are recorded so the reasoning is not re-derived.

* **Extend ADR 0001 to the store.** Row schema rule: a field is either something
  the backend already sees, or it is sealed under the object's data key; the data
  key itself travels only wrapped. Valkey alone is then useless, because the
  key-encryption key never leaves the proxy. Two fields fail that rule as the
  session stands: `sessionPart.sum` is a **plaintext** CRC32C, which
  `docs/security/upload-integrity.md` names as a confirmation oracle in so many words,
  and the object key is the client's cleartext name, which after
  [017](017-filename-encryption.md) the backend no longer sees — so the row must
  carry the *stored* name and the receiver re-derive, or ADR 0023 D8's "exactly
  one boundary" becomes two.
* **Enforce store TLS in code, not in documentation.** The precedent exists: an
  `http://` backend endpoint is refused at startup under a provider that encrypts.
  The same rule for the store URL. Note that the trust store itself does not exist
  yet — `ca_file`, `RootCAs`, `ClientCAs` have no non-test hit anywhere in
  `internal/`, `pkg/` or `cmd/` — which is the same missing mechanism
  [039](039-backend-certificate-verification-failure-is-named.md) needs for the
  backend leg. Deciding one without the other is how the two drift.
* **The store credential and the Sentinel address list are plural from the first
  release.** There is no configuration reload anywhere, so rotating either is a
  restart of every instance and a restart ends every upload it holds
  (ADR 0029 D2). Singular-to-plural afterwards is the shape change ADR 0013 D11
  makes expensive, and this repository has paid it once with `s3_backend`. Both
  fields must also be added to the hand-maintained `${VAR}` allowlist in
  `envexpand.go`, or the proxy starts successfully and uses the literal
  placeholder text as its secret.
* **Neither probe ever depends on the store.** Reads, single-request PUTs and the
  internal producer need no coordination; a readiness gate on the store would make
  the majority of the traffic less available than the single instance it replaces.
  A store outage refuses multipart with `503 SlowDown` and leaves the pod Ready.
  This is no longer this ticket's rule to make: it is [ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md)
  D5, decided and built on 2026-09-15, and it binds whatever this design puts
  behind readiness.
* **Sentinel's own failure modes need two answers the proxy can enforce.**
  Acknowledged rows can be lost on a failover, because replication is
  asynchronous — that is **fail-closed**, since `VerifyClientParts` demands an
  exact two-way match and a missing row is `400 InvalidPart`, never a corrupt
  object, but it blames a correct client and has to be documented rather than
  discovered. And split brain lets two sweepers both believe they hold the lease,
  where the primitive at the end is a real `AbortMultipartUpload` against someone
  else's live upload; `min-replicas-to-write` is the setting that closes it, it
  lives in Valkey's configuration rather than the proxy's, and the proxy can read
  it at startup and refuse rather than leave the control in a document
  (rule 2 of `docs/security/threat-model.md`).
* **Persistence off.** Everything in the store is in flight, so there is nothing
  to back up — which has to be *stated*, or an operator will build a backup and
  turn the row set into a durable record of every object name written through the
  proxy (question 27).

### Where the open questions stand after this round

**Answered above:** 1, 2, 7, 8, 17, 24 — but **17 and 24 were reopened by round 2**
and continue as questions 34 and 35. Question 16 is answered in part — the
store's key expiry deletes the row, but what *ends* an upload whose owner was
SIGKILLed, and on whose clock, is still open.

**Reshaped rather than answered:** 4 (the short-part budget stays per instance,
because under decision 5 the held bytes never leave the process — what is still
open is the read-then-reserve ordering of correction 9); 9 (every immutable field
falls out of the consistency problem, so the question narrows to the part rows and
the lease); 11 (a Sentinel failover is 10-30 s of write unavailability, which is
the textbook case for `503 SlowDown` and makes the question concrete rather than
theoretical); 12 (a forward exists after all, for exactly one verb, so its cost is
paid and its listener ordering is finding 4 above); 14 (the upload id stays the
backend's own — with a shared table the state does not have to move, so nothing
needs minting); 20 (with a store, `RollingUpdate` becomes right rather than
dangerous, so `strategy: Recreate` is not the answer); 21 and 33 (moot under the
release constraint: nothing here may be breaking).

**Untouched and still open:** 3, 5, 6, 10, 13, 15, 18, 19, 22, 23, 25, 26, 27, 28,
29, 30, 31, 32 — and the new one this round produced, *which entity tag is live
after a duplicate part*.

### What this round changed outside the ticket

* **The multipart idle clock was pulled ahead of this work, and has since landed**
  (`fix: multipart clock`, released in 5.0.2). It was scheduled first because its
  throttled `atomic.Int64` store looked like the shape this design's lease
  heartbeat needs. Round 2 checked the landed code: it is not — see there.
* **The probe split and the `preStop` hook were raised here and have since
  landed** ([ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md)).

Raised 2026-09-14 by the owner: *several s3-proxy instances side by side share the
workload and synchronise with each other so that they cooperate on multipart
uploads too.* **Refined 2026-09-15 and 2026-09-16 — see the three rounds above; round 3 closed
twenty-three questions and leaves nine, starting at 37. Not scheduled, no code
written.**

## Refining round 2, 2026-09-15 — the idle clock landed, and it does not fit

The multipart idle-clock fix merged and shipped in 5.0.2. This round checked the
landed code against what decision 6 assumed of it. The assumption did not survive.

### What landed

`lastTouched` is an `atomic.Int64` written outside the session mutex; the part
body is wrapped on both upload paths so the clock moves with the bytes; every
store is skipped while the last one is younger than the touch resolution. Three
facts decide everything below.

* **The throttle is 100 ms, not one second** — a tenth of the smallest idle
  timeout the loader accepts, so the coarseness can never be what expires an
  upload.
* **The value is nanoseconds since this process started**, from one package
  variable set at start. Deliberately not a wall instant: two wall samples can tie
  or run backwards, which had made three sweeper tests intermittently red.
* **It is an atomic store, never an I/O.** A touch costs a load and a branch on
  the hottest path in the product.

### What that does to decision 6

**The rate is out by an order of magnitude, in the wrong direction.** Decision 6
budgeted one store write per second per part in flight. At a 100 ms throttle, a
store write behind each touch is ten per second per part; at three instances
serving five concurrent parts each that is 150 writes per second of pure
heartbeat, at a resolution nothing needs. The "2600-fold reduction" arithmetic was
right for one second against 2600 reads per second at 162.5 MiB/s; against the
landed throttle it is 260-fold.

**The value cannot be a lease at all.** It is measured from *this* process's start
and means nothing in another. Serialising it strips exactly the monotonic reading
it was given for — which is the objection this ticket already records against
wall-clock arithmetic between machines.

**That is the good answer, not the bad one.** There are two clocks, not one, and
they are different instruments with different owners:

| Clock | Owner | Decides |
|---|---|---|
| the idle clock | the process, monotonic since start | abandonment (ADR 0028) — stays local, unchanged |
| a lease TTL, if there is one | the store, server-side expiry | adoptability |

A server-side expiry is compared against nothing the proxy holds, so a lease needs
no agreement between instance clocks at all. ADR 0014's exposure — every instance
validating against its own wall clock, NTP as a correctness dependency — does not
reach it. What the landed work really hands this design is not a rate but a
**pattern**: a throttled store outside the mutex that cannot deadlock inside a
seal.

### The contradiction between decisions 5 and 6

Decision 5 keeps the held short part in the memory of the instance that received
it. Phase 0 of the reference scenario states that before that part arrives **the
upload has no owner**. So ownership begins and ends with those bytes.

Decision 6 promises that an upload whose instance is SIGKILLed becomes adoptable
once its lease expires. **That set is empty.** Before the held part there is no
owner and nothing to adopt — every instance already serves every part. After it,
the bytes are client plaintext in RAM, a SIGKILL destroys them, and the client
never sends them again: it has been answered 200 and its next request is Complete.
No survivor can finish that upload at any price.

Decision 5 is precisely what forecloses ungraceful failover of a pinned upload —
its rejection of "seal the held part under the object's data key and park it in
the store" is what does it. Decision 6 was written as though it did not.

What a lease can still buy here is **ending, not adoption**: its expiry turns
"pinned" into "certainly dead", so the upload is aborted at the backend promptly
instead of waiting out the idle hour. That is an answer to question 16. It is not
an answer to question 24.

### "Owner" is three words wearing one

The holder of the held part is **the pod kube-proxy happened to route the last
part to**. Not elected, not stable, not knowable in advance, non-existent until
that moment, and brought into being only because S3 refuses a non-final part below
5 MiB. The word "owner" makes an accident look like a role, and a role is
something that can be leased, renewed and inherited — which is how decision 6 came
to be phrased the way it was.

The ticket uses "owner" for three unrelated things: the holder of the held part,
the instance that runs the sweeper, and the holder of a lease. They have different
lifetimes and different failure modes, and only the first is created by the data
path. **The holder is a single address, not a tenancy**, and the rest of this
ticket should say holder where it means holder.

### How long the pin actually stands

Corrected from decision 5's "the last part plus Complete".

* **Normal:** the short part is dispatched last but is the smallest, so it seals
  while the full-size parts of its concurrency batch are still uploading, and
  Complete waits for every one of them. The window is the slowest still-running
  part — tenths of a second at 5 MiB and the measured 162.5 MiB/s — and a retry of
  any of those parts extends it by that part's full duration.
* **Pathological:** a client that receives its 200 and then stalls or dies leaves
  the pin standing until the idle sweeper fires — `multipart_session_idle_timeout`,
  3600 s by default. That is the abandoned case, where no instance wants to
  complete anything.

So the exposure is milliseconds to seconds for uploads that are going to succeed,
and an hour for uploads that are already lost. Both halves matter: the first makes
question 34 decidable, the second says an address alone does not clean up.

### The shape this suggests, not decided

If the pin is an **address** rather than a lease, TCP is the liveness check: the
row records where the held part lies, a Complete landing elsewhere is forwarded
there, and a refused or unreachable connection means the bytes are gone, the
upload is unfinishable, and it is ended at the backend with an honest answer. No
TTL, no heartbeat, no renewal, no clock of any kind — questions 9's lease half and
17 dissolve with it.

**What is not free about it, and must be settled before any code:** a partition in
which the holder is alive and merely unreachable from the forwarder has a healthy
instance abort a live upload. The destructive primitive is already there — both
sweeps issue a real `AbortMultipartUpload`, safe today only because the table is
the process's own. "Unreachable" becoming a network-triggerable data loss is the
class rule 2 of `docs/security/threat-model.md` refuses to leave to configuration. A
compare-and-set on the row, where exactly one party may declare an upload over, is
the guard; which party that is, is part of question 35.

## Refining round 3, 2026-09-16 — the pinned tail is given up

Worked through with the owner against the reference scenario, in dependency
order: 34 first, because 35, 16 and 9 hang off it. **What is written as decided
is decided.**

### Decision 8. Failover of a pinned upload is out of scope (question 34, and the second half of 24)

**Option A, taken with the owner's verdict recorded as given: adequate, not
optimal.** Decision 5 stands. An upload whose holder is lost ungracefully while
it holds the short last part is lost; the client's Complete is answered with a
terminal error and the client uploads the whole object again. The graceful cases
— rollout, scale-in, `helm upgrade` — are not in this residual: the forward
reaches the draining holder over the peer listener and Complete succeeds.

**What "failover" can mean at all, which is what made the question decidable.**
An HTTP answer belongs to the TCP connection of the process that accepted the
request. When the holder dies with a Complete in hand, the client sees a reset,
and no other instance can answer on that connection, whatever was parked where.
Failover of the pinned tail is therefore defined as *the client's retried
Complete succeeds on another instance*, and nothing else. Every SDK uploader
retries Complete on a connection error — aws-sdk-go-v2 three attempts, a small
XML body, rewound — so the retry lands, through the Service, on some instance.
That instance can say "complete" only if it can finish, which needs the held
part. Under A it cannot, and the answer is terminal.

**The price, as a number.** Expected cost per upload is the probability of an
ungraceful loss during the upload, times the tail window over the upload
duration, times a re-upload of the whole object. For the reference scenario that
is a window of about half a second in ten minutes: one ungraceful loss in twelve
hundred costs a re-upload of some tens of gigabytes. Re-upload is unavoidable:
S3 binds parts to an upload id and no verb moves them to a new one;
`UploadPartCopy` reads only completed objects. What the client does after the
terminal answer is the client's — rclone repeats the file (`--retries`, default
3); Velero was not checked beyond "the object is sent again"; s3cmd was not
checked. None of this is verified in this repository; the e2e case below is
where it gets measured.

**Decision 5's rejection of parking the held part was overstated, and the ADR
must not repeat the overstatement.** The rejected variant was priced with "a new
AEAD construction to specify and review". There is none to build: the held
part's segments are sealed independently of the trailer — `BodyWithTrailer` is
`Body()` followed by `SealTrailer(sum)` on a `MultiReader`
(`internal/orchestration/segmented.go`) — so the segments could be sealed with
the existing codec when the short part arrives, and only ciphertext under the
object's data key would reach the store, which is exactly what the row rule
proposed in round 1 asks for. The variant stays rejected, on cost against the
number above: the store's memory becomes concurrent pinned uploads times the
short-part size, the value has to be chunked against
`client-output-buffer-limit replica`, Complete pays a fetch in part size, sealing
needs the pinned part size so a short part that arrives before the pin waits in
memory anyway, and Sentinel's asynchronous replication can lose exactly those
bytes on the failover they exist for. It is additive later — the row carries a
schema version and the store is not client-visible — so A forecloses nothing.

**What A needs anyway, found on the way and binding on 35.**

* **A completion state machine in the row, driven by compare-and-set:**
  `open → completing → completed(ETag)`, and `open → dead`. It is not a failover
  mechanism; it is what makes Complete idempotent across instances, which A
  needs with a *live* holder: a client that times out its Complete and retries
  elsewhere has the retry forwarded to a holder that is in the middle of the
  first one or has finished it. Today `Complete()` is not idempotent (see *Races
  between two instances*), and a shared row makes that reachable.
* **A resolver for a holder that is gone.** Row `completing` and holder
  unreachable: ask the backend — `ListParts` answering `NoSuchUpload` with the
  object present under the key means the holder's backend Complete landed before
  it died, and the answer is `200` with the object's ETag, no re-upload. Row
  `open` and holder unreachable: the forwarder that wins `open → dead` answers
  terminally; every later retry reads `dead` and answers the same. Exactly one
  party declares the upload over, which is the guard round 2 asked 35 for.
* **The terminal answer is `404 NoSuchUpload`, given after the proxy has aborted
  its own upload at the backend** (corrected at question 11, decision 18: the
  state is permanent, so errors.md's class rule wants a 4xx, and after the abort
  the answer is true; `500 InternalError` was the first candidate here and was
  wrong by that rule). Never `SlowDown`, which would have the SDK retry a
  Complete that cannot succeed. The uploader's own Abort still works from any
  instance; the sweeper takes what is left.

**Consequences.** Question 24's second half is answered: cooperation yes,
failover of the unpinned upload yes, failover of the pinned tail no. Question 35
is decidable: with no adoption there is nothing a lease would adopt, so the pin
needs an address and the compare-and-set above, not a tenancy. *Done when* gains
one e2e case — SIGKILL the holder while it holds the short part, assert the
terminal answer and that the client's re-upload completes — and its "ungraceful
loss" bullet is answered "declared out of scope in the ADR, with the window".

### Decision 9. The pin is an address with an identity, and only a positive signal is a verdict (question 35; closes 17 and the lease half of 9)

**Option B.** The row carries the holder's peer address and an **instance
identity** drawn at random when the process starts. A forwarded Complete carries
the identity it expects in an internal, unsigned header; the receiver compares it
with its own. The pin has no TTL, no heartbeat, no renewal and no clock of any
kind.

**What a dead pod shows on the network, because it is what sorts the options.**
A pod's IP is released when it dies; a connection to a released address ends in
a timeout or an ICMP unreachable, depending on the CNI. A reset — "connection
refused" — arrives only while the network namespace is alive and no process
listens, which is a container restart inside a living pod. And the address is
**reused** later: another proxy pod can answer at the holder's old address.
Kubernetes knowledge, not verifiable in this repository. Address alone therefore
cannot tell a partition from a death and cannot see reuse at all, which is what
rules that shape out.

**The verdict table.** A verdict is a positive signal or the client's own word,
never a timeout.

| Forward result | Meaning | Answer |
|---|---|---|
| a response from the holder | the holder served it | passed through |
| identity mismatch | holder gone, address reused | CAS `open → dead`, terminal |
| connection refused | process gone, namespace alive | CAS `open → dead`, terminal |
| timeout / unreachable | unknown | `503 SlowDown`, row untouched |
| the client's Abort on any instance | the client's verdict | CAS `open → dead`, backend Abort |

On a partition or a death without a reset, the client is answered `SlowDown` up
to its retry budget; each retry may land on the holder directly; when the budget
is out the uploader sends Abort, and *that* is the verdict. The end state is the
one decision 8 already accepts, reached without a single verdict against an
upload that may still be alive. The guard round 2 asked for — exactly one party
may declare an upload over — is the compare-and-set, and it never fires on
silence.

**Why not a lease.** Its expiry is a timed verdict, and a partition longer than
the TTL with a living holder is precisely the abort of a live upload that
rule 2 of `docs/security/threat-model.md` refuses to leave to a setting. It also buys
nothing on the client path: the TTL has to exceed the Sentinel failover window
(about 90 s, decision 1), the client's retries are spent within seconds, so the
forwarder would answer `SlowDown` in that window under a lease as well. What a
lease really addresses — a dead holder *and* a client that never returns — is
question 16, and a lease is not the answer there either.

**Two costs that come with B.** The forward's connect timeout has to be short,
one to two seconds, or the client's own Complete timeout runs out first; the
process owns no `http.Client` today (question 12), so the peer client is new
code with a dial timeout that is a constant or a key. And the mismatch verdict is
only as trustworthy as the peer leg's transport: an attacker who can answer at
the holder's address can make a forwarder declare an upload dead. That is the
peer-TLS question under 3 and 7, not an argument against B.

**Consequences.** Question 17 is closed — there is nothing to renew. Question 9
loses its lease half and keeps the part rows. Question 5 gains a fact: the
instance identity exists because the row needs it; whether it shows in
`x-amz-id-2` is still 5's. Question 12's forward is confirmed for one verb, with
a dial timeout to decide. Question 16 inherits a boundary: the case of a dead
holder and an absent client is 16's alone, and it is answered by a store-side
activity stamp and the bucket's lifecycle, never by a lease.

### Decision 10. Idle is the store's clock, and every instance sweeps by compare-and-set (question 16; amends the premise of ADR 0028 D2/D4)

**Option B.** Under a store, the idle question is answered by the row and by
nobody's process clock.

* **The clock is the store's.** The atomic script that records a part stamps
  `lastActivity` from the store's own `TIME`; the stamp is written at part start,
  at part end, and coarsely during the body — about every ten seconds — so a
  slow part is never idle in the middle of its bytes. The 100 ms touch of 5.0.2
  stays process-local and keeps doing what it does; it is never mirrored. No
  instance clock is ever compared with another, so ADR 0014's NTP exposure does
  not grow and round 2's objection to wall-clock arithmetic between machines does
  not apply.
* **Every instance sweeps, and the row elects.** Each process `SCAN`s the rows
  every `multipart_session_cleanup_interval` and treats `lastActivity +
  multipart_session_idle_timeout < TIME` as idle. The first to win the
  compare-and-set `open → dead` aborts the upload at the backend; the others read
  `dead` and move on. No leader, no leader lease, no clock behind the election —
  N scans per interval over some hundreds of rows cost nothing. A pinned upload is
  no special case: an idle row means the client is gone whether the holder lives
  or not; the holder frees its held part when it reads `dead` on its own tick, and
  a Complete in progress is `completing`, which the sweep's compare-and-set fails
  against.
* **How long: `multipart_session_idle_timeout`, unchanged in meaning.** No rename,
  and the in-process implementation keeps today's monotonic clock behind the same
  interface.
* **A failing abort is retried by anyone, and bounded as today.** The row carries
  `abandonFailures`; any instance's sweep may retry a `dead` row below
  `maxAbandonAttempts`, because the backend abort is idempotent. At the bound the
  row stays `dead` until it expires and the upload leaks at the backend into the
  bucket's lifecycle rule — the same outcome the single instance documents in its
  give-up message today.
* **Terminal rows outlive their upload by `multipart_session_idle_timeout`.**
  `completed` and `dead` rows get a store-side expiry of that length rather than
  an immediate delete: decision 8 needs a late retry to read the terminal state,
  or it would fall into question 13's classification against the backend. Rows
  are small; an hour of `dead` costs nothing and needs no new key.

**Rejected.** Store-side expiry with keyspace notifications as the primary
mechanism: the event is best-effort, delivered only to subscribers connected at
that moment, and the row is already gone when it arrives, so there is no
compare-and-set, no failure counter and every instance aborts at once. A
leader-elected single sweeper: it needs a leader lease with a TTL, which is the
clock and the partition case decision 9 just refused; the per-row
compare-and-set *is* the election.

**Two limits, stated.** After a Sentinel failover `TIME` comes from another Valkey
node; between NTP-synchronised nodes the skew is seconds against a default of
3600 s, but the loader accepts an idle timeout of 1 s, so the operator
documentation for the store has to say that the value must stand far above the
skew between store nodes. And the coarse body stamp is a store write rate that
did not exist before — fifteen concurrent parts stamping every ten seconds is
1.5 writes per second, negligible and new.

**Consequences.** ADR 0028 D2 and D4 are amended from "the owning process" to
"any instance, by compare-and-set on the row"; their reasons hold. ADR 0029 D2
narrows: a graceful shutdown abandons its producer uploads and any pinned upload
whose Complete did not arrive within the budget, and nothing else — the shared
rows are not the process's to abort (question 6 settles the rest). Question 9's
remaining half — the part rows — is next.

### Decision 11. The row collects every entity tag a part number was stored under, and the backend says which one is live (question 36; closes question 9)

**Option C′.** A part row is a *set* of entries per `(uploadID, partNumber)`,
each `(etag, offset, plaintextLen, sum)`, written by append and never
overwritten. At Complete, a part number with exactly one entry is handled as
today. A part number with several costs one paginated `ListParts` against the
backend; the entity tag the backend reports is the live one, and the entry that
carries it supplies the offset, the length and the checksum that go into the
trailer. `VerifyClientParts` accepts the client's entity tag if it is *in* the
set, and the completion list the proxy sends carries the live tag. The happy path
costs nothing.

**Why the backend has to be asked.** The proxy cannot observe the backend's
commit order. A sequence number taken before the backend call orders who
*started* first; one taken after the response orders who was *answered* first;
neither orders who *committed* last, which is what S3 keeps. The compare-and-set
the *Races* section proposed orders row writes, so it can refuse a writer, but
not know whether the refused one is the live one. Verified on the way: the client
is answered the backend's entity tag (marked, ADR 0032), the table records it
after the backend has answered (`upload.go`), and `VerifyClientParts` compares
tags exactly (`segmented_session.go`) — so today's disagreement is refused as
`400 InvalidPart` before the backend is even asked, or aborts the whole upload
when the backend refuses instead (`complete.go`).

**What binding the checksum to its tag buys.** A retry sends the same bytes, but
S3 lets a client overwrite part n deliberately. With one row per number the
table could hold the checksum of one body and the backend the bytes of the other;
the trailer would then authenticate a CRC32C the object does not have, and the
first read would fail with `403 InvalidObjectState`. With the checksum travelling
beside its own tag, the trailer is computed from the part that is actually live.

**Rejected.** Always listing before Complete: exact and simple, but five backend
requests on every completion of the reference scenario (about 4100 parts at a
thousand per page) for a disagreement that needs two candidates to exist.
De-duplicating on the second instance — read the body, compare the checksum with
the first instance's entry, answer the first tag without uploading: while the
first instance is still uploading there is no entry to compare with, so the
second would have to wait on a process that may be dying, which is the case
decision 9 just closed.

**One limit.** `ListParts` reports a size, not a checksum. `PartStoredLen`
inverts a stored size uniquely, so the length is verified against the backend;
the checksum stays the proxy's own record of the entry that belongs to the live
tag. That is the trust the single instance places in its table today, addressed
to the right entry.

**Consequences.** Question 9 is closed entirely: part-row writes are appends and
commute, so they need no compare-and-set and no linearizable write; the one read
that must be linearizable with respect to every part write is the read at
Complete, which the primary serves, and the sweep's verdict is itself a
compare-and-set on the primary. `ListParts` becomes a verb the proxy issues on
its own behalf, which is the client question 13 asks for anyway. ADR 0011 D6's
"exact two-way match" becomes "every claimed tag is one the part was stored
under, and every stored part is claimed".

### Decision 12. The short-part budget stays per instance, and the reservation moves ahead of the read as a defect of its own (question 4)

**Option A.** `optimizations.multipart_short_part_buffer_size` keeps its name and
its meaning: what the client-driven uploads of *one process* may hold for their
short last parts. Decision 8 confirmed the premise — the held bytes never leave
the process that received them — and memory is a pod's, so a cluster-wide
counter would bound nothing physical, put a store round trip at the start of
every held part, make a local `SlowDown` depend on a remote store, and need
someone to reclaim the reservation of an instance that died holding it, which is
a lease. Nobody has to reclaim a process's memory: it dies with the process, and
the row records nothing of it.

**The ordering defect correction 9 found is fixed on its own, in 5.x, before or
beside this work.** On the encrypting held-part path the body is read with the
whole budget as the per-request limit and the reservation is taken afterwards in
`SealPart`, so C concurrent short parts hold up to C × budget transiently and the
key bounds retained bytes only. The fix has its model in the same file: the
exit-provider arm without a declared length claims before it reads. Every part an
SDK sends declares its plaintext length, so the encrypting arm reserves that
length before the first body byte — `reserveShortPart(0, declared)`, refused with
`503 SlowDown` before anything is buffered — and moves the claim to the sealed
size afterwards with the `held → want` form the function already has; a part
that declares no length claims the whole bound, as the exit arm does. This goes
into the *needs no design decision* block of *Done when*.

**Why it matters more under N instances than under one.** Only when the key
bounds the pod can the pod's memory be derived from the configuration — the
budget, plus part size times concurrency — which is what the chart's requests
and limits need at any replica count. Left as it is, the real ceiling is a
function of client behaviour multiplied by the replica count.

**The one property this costs, and why it is not a defect.** An instance refuses
a short part with `SlowDown` while a neighbour has room. The SDK retries, the
retry lands anywhere, and at N pods mostly elsewhere. With the 64 MB default
against at most 5 MiB per short part the bound is not even reached before twelve
uploads are in their tail on one pod at once.

### Decision 13. A shutdown lets go; it aborts only what dies with the process (question 6; narrows ADR 0029 D2)

**Option B, no hand-over.** Today the tail of a shutdown is one budget in three
phases — drain until no request is active or the budget is out, then
`AbandonAllSessions` aborts every upload in the process's map at the backend,
then the listener closes (`cmd/s3-encryption-proxy/main.go`). Phase two is where
the reference scenario's backup dies today, and under a shared table it would
have the first pod of a rollout abort every open upload of the deployment. The
order becomes:

1. The `preStop` hold; the endpoints are withdrawn (ADR 0034 D10).
2. SIGTERM. The client listener accepts nothing new; parts in flight run out. A
   part the client repeats elsewhere because its connection closed is resolved
   by decision 11.
3. **The peer listener stays open for the whole budget.** Forwarded Completes
   for the uploads this process pins land there and are served.
4. The sweep, at the end of the budget or as soon as nothing pinned is left
   open, whichever is first. Producer uploads are aborted — they belong to a
   live request in this process and nothing else can finish them, ADR 0029 D2
   unchanged. A pinned upload still `open` is ended by compare-and-set
   `open → dead` and a backend abort, **and each one is logged by name** —
   upload id, bucket, key — beside a counter, where today a truncated shutdown
   counts what it cut and names nothing. A pinned upload in `completing` is left
   alone: decision 8's resolver settles it on the client's next retry. A shared
   `open` row this process does not hold is not touched.
5. The peer listener closes, the process exits.

**Why no hand-over.** The pin stands for tenths of a second in an upload that is
going to succeed, and the default budget is 30 s. What the budget cuts is a
client that takes longer than the budget between the 200 for its last part and
its Complete, and for that client the arithmetic is decision 8's: an honest
terminal answer and a re-upload. Handing the held part to a peer — sealed under
the object's data key with the existing codec, the peer unwrapping the key from
the row, a compare-and-set moving the holder's address and identity — would
buy that case at the price of a second state transition nothing else needs, a
new peer verb, and a timing problem inside the drain: too early and a Complete
arriving now hits a holder that is letting go, too late and the budget is gone.
It is the phase the ticket already describes as the one that gets skipped when
the fleet is busy. It stays additive: the row schema is versioned, the verb is
new, nothing in the order above has to be undone for it. It is built when the
counter in step 4 shows that the budget really kills uploads, not before.

**Consequences.** ADR 0029 D2 narrows from "every multipart upload this process
is holding" to *producer uploads, and pinned uploads whose Complete did not
arrive within the budget*, with the reason that the shared rows are not the
process's to end. The chart's derivation of `terminationGracePeriodSeconds`
from `shutdown_timeout` gets one sentence: the budget covers the tail of a
pinned upload, not the upload. Scale-in (question 29) takes the same path — the
autoscaler's victim runs this order like any other terminating pod — so what 29
still asks is only whether the proxy can influence the choice of victim. Step 4's
named log line is the first concrete piece of question 26.

### Decision 14. No data key crosses the network in the clear; the store sees what the backend sees; the peer leg shares the client listener's TLS (questions 3 and the transport half of 7)

**Option A.** The plaintext data key exists only inside a process that unwrapped
it. The row carries the *wrapped* key, the key-encryption fingerprint, bucket,
key, the pinned part size, the part entries, the state and the holder — an early
copy of the four metadata keys plus what Complete needs — and the peer leg
carries the client's own SigV4 request, a small XML and the holder-identity
header. Client plaintext never crosses (decisions 5, 8, 13).

**The rule for a row field, now decided rather than proposed:** it is either
something the backend already sees, or it is sealed under the object's data
key. Wrapped key, fingerprint, bucket, key, entity tags, offsets and lengths are
the backend's view. The per-part plaintext CRC32C is not —
`docs/security/upload-integrity.md` names it a confirmation oracle in so many
words for the backend, and the
store is no more trusted a party — so it is sealed under the object's data key
with AES-GCM under an AAD label of its own, separating it from segments and
trailer. Every instance can open it, the store cannot. After ticket 017 the row
carries the *stored* name and stays inside the rule.

**What a tampering store achieves, so the threat model can say it.** Attaching
X's wrapped key to Y's row seals Y under X's key: segment nonces are random
(`pkg/encryption/dataencryption/segmented_gcm.go`), so no deterministic nonce
reuse; without the key-encryption key the attacker does not know the key; the
object key is in every segment's associated data, so no segment of X reads as
Y. Forging a part entry — offset, length, checksum, tag — fails ADR 0011 D2 at
Complete, is refused by the backend as `InvalidPart`, or writes a trailer the
first read rejects. **Tampering is denial, never silent corruption**, and that
is a property of the storage format, not of the store. It holds before anything
is built. Rejected: the plaintext key in the row — membership in the store
would be data-key access, a path to in-flight plaintext around the
key-encryption key that *What an attacker who takes the proxy gets* does not
contemplate; and a whole-row seal under a
key derived from the key-encryption key — stronger than the threat model asks,
hides from the store what the backend sees anyway, and is foreclosed by the
provider futures below.

**Several key-encryption keys, an asymmetric one, a remote one — what A needs
of a provider.** Raised by the owner in this round. Several providers in one
proxy change nothing: the checksum is sealed under the object's data key, not
under a key-encryption key, and the row names its fingerprint the way object
metadata does, so an instance unwraps through the provider the fingerprint
names, exactly as a GET does today. An asymmetric provider — public key wraps,
private key unwraps — fits `EncryptDEK`/`DecryptDEK`/`Fingerprint` and
therefore fits the row, which is a copy of the metadata contract. A remote
provider, where unwrap is a network call, costs one unwrap per upload *and
instance* on first contact, cached locally, so at most N per upload and never
per part; the checksum seal costs it nothing, because that runs locally under
the data key; an unreachable remote refuses the part with a retryable 503 and
loses nothing; its audit sees N entries per upload where it saw one. **The one
constraint, to be written into the provider contract:** every instance that
serves a part of an upload must be able to unwrap that upload's data key, so a
provider whose unwrap depends on process-local state is incompatible with
running more than one instance. A whole-row key derived from the key-encryption
key would have been blocked by exactly these futures — there are no key bytes to
derive from under a remote provider and no single key under an asymmetric one —
which is the strongest reason A was right. The exit provider is untouched: no
data key, no checksum, nothing to seal.

**The peer leg's transport.** The forward is a client-signed request,
re-verified under SigV4 at the holder, so its authentication is the client
port's and no peer credential exists. What it lacks is transport integrity: the
holder-identity header is unsigned, and the XML body is covered by the signature
only under `verify_payload_hash: true`. An on-path attacker on the peer leg
could flip the header and force a `dead` verdict. The peer listener therefore
uses the same `tls` block as the client listener, on or off together, with no
certificate and no mutual TLS of its own; without TLS the peer leg is as exposed
as the client leg, and that boundary is the operator's under ADR 0030 D1. The
peer port must not be reachable from outside the cluster, which the chart says
and cannot enforce.

**Consequences for `docs/security/`.** *Roles* in `threat-model.md` gains two
rows with one sentence of trust each: the store sees what the backend sees, the
peer leg is a second client port. The in-flight-key row of *Where each secret
lives* in `key-management.md` says "in every instance that touched the upload,
never in the store". The oracle paragraph of `upload-integrity.md` gains the
store. *KEK rotation* in `key-management.md` gains the two-restart rotation
(question 19). H-12 is claimed for the store's tamper-is-denial property, with
the three reasons above, in the closing section of the page whose mechanism it
belongs to.

### Decision 15. A member register makes a one-step rotation work: the active alias takes effect when every live member can read it (question 19)

**Option B′.** The store holds a **member register**: one key per instance —
identity (decision 9), the set of provider fingerprints it has loaded, the
fingerprint its active alias names — written with an expiry, renewed every third
of it, and **deleted explicitly in the shutdown tail** (decision 13, after the
peer listener closes) so the common case never waits for the expiry. Nothing
about an upload is ever decided from this register; at worst it delays or
advances a switch of the writing key. The expiry must exceed the Sentinel
failover window (about 90 s, decision 1), or members "vanish" during a store
failover and a pod switches early.

**The rule it enforces, which is the whole point:** under a fleet,
`encryption_method_alias` names the key-encryption key to write under *as soon
as every live member can read it*. A pod that starts with `{old, new}` and
`new` active, and sees live members without `new`, **writes under `old` until
the last of them is gone**, then switches, and says so in the log at both
moments; a gauge carries the fingerprint currently written under. With one
instance the fleet is the process and the switch is immediate — today's
behaviour, unchanged. The owner's rotation is therefore *one* `helm upgrade`:

| The operator does | What happens |
|---|---|
| adds a key, switches the alias, one upgrade | the roll runs through; every pod writes under the old key during it and under the new one after it; no `503`, no `403`, no forward |
| adds a key, leaves the alias | the roll runs; everyone can read one key more |
| removes an old key, one upgrade | **the removal guard:** a pod does not start while an *open row* names the removed fingerprint, and logs how many and which; the roll waits until those uploads complete or are swept, with `maxUnavailable 0` keeping the old pods serving. Objects at rest under the removed key answer `403`, as today — the operator's decision |
| removes the old key and adds the new one in one upgrade | the pod cannot defer (it no longer has `old`) and refuses to start: add first, remove in a later release. Loud, immediate, nothing broken |
| the store is unreachable during a roll | the register cannot be read: fail-open, immediate switch with a warning, because a start must never depend on the store (ADR 0034 D5's spirit); the runtime floor below carries the roll |

**The runtime floor, kept from option A.** A part for a row whose fingerprint
this instance cannot open is refused with a retryable `503`. In a correct fleet
it never fires; it exists for the store outage in the middle of a roll.

**Why not the guard alone (option B as first put).** A register that *halts* a
wrongly ordered roll turns the owner's one upgrade into a crash-loop with
instructions: rule 2 of `docs/security/threat-model.md` satisfied and the operator
punished. The same register, used to defer the switch, makes the one upgrade the
normal path and leaves only the one action that cannot work — the swap in a
single release — to be refused at start with one sentence. Why not nothing (A
alone): a wrongly ordered roll at three replicas has three quarters of the parts
of every upload created on the new pod land on pods that cannot open its key;
with three SDK attempts about 42 % of those parts fail for good, and every read
of such an object from an old pod is a `403` no SDK retries. No loss, no
corruption, minutes of visible breakage — and the safe order written nowhere,
which is what rule 2 forbids.

**What it costs.** For the length of a roll the configuration says `new` and
the proxy writes `old`. That is made visible, not hidden: the two log lines and
the gauge. The register is a per-instance write every third of its expiry,
independent of upload traffic, and one read at start.

**Consequences.** The read-path `403` for an unknown fingerprint stays right:
no object is ever written under a key a live member lacks, so the only unknown
fingerprint left is a removed key, which is the permanent state ADR 0004's
reasoning describes. The question-21 item this round nearly opened does not
exist. Question 5's identity has its home. Question 31 has an instance count
without asking for one. *KEK rotation* in `docs/security/key-management.md`
gains one sentence instead of a procedure: add,
switch, upgrade; remove in a later release. ADR 0004 gains the fleet reading of
the active alias.

### Decision 16. The row is filed under the backend's upload id, carries bucket and key, and every verb checks them (question 10)

**Option C.** The store key is the upload id the backend issued, under a
per-deployment prefix. The row carries bucket and key, which the sweep
(decision 10), the resolver (decision 8) and the segment AAD need anyway.
**All four verbs compare the request's bucket and key with the row's**, where
today only `ListParts` does (`internal/proxy/handlers/multipart/list.go`);
a mismatch is `404 NoSuchUpload`, logged with both pairs. Registration is
`SET NX`: an id that already has a row — a terminal one included — refuses the
Create with `500 InternalError` and a log line, because it means a backend that
reuses ids within `multipart_session_idle_timeout` or a client that guessed one;
today registration overwrites silently (`segmented_session.go`).

**Why this and not a compound key or nothing.** `404 NoSuchUpload` for an id
under the wrong key is what S3 itself answers, so the proxy says it earlier —
before a part is sealed for nothing — and nothing client-visible changes; the
release constraint is untouched. A compound primary key ends in the same `404`
by way of a miss, but cannot tell a mismatch from an id it never saw, and puts
object names of up to 1024 bytes into the keyspace. Doing nothing lets a valid
id under a foreign key seal a part under the row's object key and send it to
the backend under the request's, which the backend refuses, unseen. With the
check in place there is exactly one object key per upload, so the *Security*
section's question "which key goes into the associated data — the row's or the
request's" no longer exists. The store's primary key stays the backend's to
choose (ADR 0001); `SET NX` is what stops that choice from overwriting.

**The prefix, and where it lives — the owner's instruction in this round.** A
prefix per deployment lets two deployments share one Valkey without seeing each
other's rows. It is a key of the **HA block of the proxy's configuration, the
same block that defines the Valkey connection** — never a separate top-level
key, never derived from something else. The shape of that block is question 37.

### Decision 17. A session miss is classified against the backend, always, and the verdict is logged and counted (question 13; the "Abort leak" of question 15 with it)

**Option B, in both implementations alike.** A miss on `UploadPart` or
`CompleteMultipartUpload` — no row, or no map entry without a store — costs one
`ListParts` against the backend. `NoSuchUpload` back means the upload does not
exist and `404 NoSuchUpload` is the true answer. Anything else means the upload
lives at the backend and the proxy has lost the table that alone could finish
it: the answer is `403 InvalidObjectState` — the read path's own code for an
object this proxy cannot serve, decision 18, which corrected the `500` first
written here — with one log line naming upload id, bucket, key and the verdict,
and one counter. The SDK does not retry a 403, the uploader sends Abort, and
Abort already goes to the backend whether or not a session exists
(`internal/proxy/handlers/multipart/abort.go`), so the backend is left clean. A backend that cannot be reached during the
classification is a `503`, as for any backend failure. The exit provider is
untouched: a pass-through part needs no session.

**What a miss means under the design, which is why the verdict is worth a
call.** An id nobody issued, or an upload created at the backend behind the
proxy's back; a terminal row that expired after `multipart_session_idle_timeout`;
an open row lost on a Sentinel failover, the fail-closed case round 1 named; and
without a store, a process that was SIGKILLed and restarted. In every case but
the first the upload exists and today's `404` blames a correct client while the
operator sees nothing. The counter is the detector for exactly the losses round
1 could only document: rows lost on failover, rows expired under a client that
came back late, and a second deployment sharing a backend.

**Why not only under a store.** Two answers to one situation in one binary
(decision 3), and the SIGKILL-and-restart case is the in-process one, telling
the same lie. Why not never: a miss is abnormal by definition, so one backend
request per abnormal request is not a load, and an attacker with invented ids
gets one backend call per request — the ratio of every proxied request.

**Question 15 closes with this.** Abort on a miss already reaches the backend;
what a non-holder could not free was the holder's memory, and decision 10 frees
it when the holder reads `dead` on its own tick. No standalone fix remains.

**This is buildable now**, without a store and without the rest: the
classification, the log line and the counter belong to the *needs no design
decision* block of *Done when*. Its one client-visible change — `404` becomes
`403 InvalidObjectState` for an upload the backend *has* — is released as a fix
under the owner's ruling recorded in decision 18.

### Decision 18. The answer table, and the owner's ruling that a changed error code in this work is a fix (questions 11 and 21)

**The ruling first, because it shaped the table.** **Changing the code of an
error answer is released as a fix and carries no breaking marker.** Taken by the
owner on 2026-09-16 for this ticket and then generalised the same day into
[ADR 0036](../adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md):
a response follows S3, deviates only so a client stays usable through the proxy,
and adjusting one is a correction that never carries the marker. ADR 0018 D5
keeps its wording and gains a pointer to that reading. With the compatibility
filter gone, every cell was chosen on two criteria only: the status class rule of `docs/developer/errors.md` — a permanent
state is a 4xx, a transient failure a 5xx, because the class decides what the
SDK does next — and the truth of the answer towards client and operator.

**Corrected on the way: the `500 InternalError` candidate of decisions 8 and 17
was wrong by that rule.** A dead holder and a lost table are permanent states of
that upload; a 5xx makes the SDK retry three times a request that cannot
succeed. Both decisions are amended in place to point here.

| Situation | Class | Answer | Why |
|---|---|---|---|
| store unreachable and the verb needs the row | transient | `503 SlowDown` | cell (iii) |
| the row's key-encryption fingerprint unknown to this instance | transient in a fleet | `503 SlowDown` | cell (iii); decision 15's floor |
| holder unreachable by timeout | unknown, treated as transient | `503 SlowDown` | cell (iii); decision 9 |
| holder gone by positive signal, row `open` | permanent | CAS `open → dead`, backend abort, then `404 NoSuchUpload` | true once the abort has run |
| row `dead` | permanent | `404 NoSuchUpload` | true |
| row `completed`, an `UploadPart` | permanent | `404 NoSuchUpload` | what S3 answers |
| row `completed`, a retried Complete | — | **`200` with ETag, `x-amz-checksum-crc32c`, version id** | cell (i) |
| miss, and the backend has the upload | permanent, not this proxy's | **`403 InvalidObjectState`**, log line, counter, **no abort** | cell (ii); decision 17 |
| miss, and the backend does not | permanent | `404 NoSuchUpload` | true |
| bucket or key does not match the row | permanent | `404 NoSuchUpload` | exactly S3's model: under this key the id does not exist; decision 16 |
| Create collision under `SET NX` | a proxy or backend defect | `500 InternalError` | the retry obtains a fresh id and succeeds; decision 16 |

**Cell (i): a retried Complete on a completed upload answers `200`.** The object
exists, the client learns it, the uploader reports success and nothing is sent
again. *Races* lists the non-idempotent Complete as a defect, and this closes it.
The terminal row therefore carries the final ETag, the version id and the
object's checksum — sealed under the data key, decision 14 — and the in-process
implementation keeps the same terminal entry for the same time, so one instance
gives the same `200`. AWS itself answers a second Complete `NoSuchUpload`; the
proxy is kinder than the original here, on purpose.

**Cell (ii): a miss for an upload the backend has answers `403 InvalidObjectState`.**
It is the read path's own code with the read path's own meaning — an object this
proxy did not write and cannot serve — and it separates, for the client, "this id
does not exist" from "this id exists and is not servable here", the distinction
question 13 bought for the log and now gives to the client too. `404` would be
S3-conformant and indistinguishable; `500` is the wrong class. The proxy touches
nothing at the backend for it: **the proxy aborts at the backend only an upload
it has a row for; an upload without a row is never ended on the proxy's own
initiative**, because it may be the live upload of a second deployment sharing
the bucket or of a client working past the proxy. The client's own Abort still
goes through, as it always did.

**Cell (iii): the transient class is `503 SlowDown`.** aws-sdk-go-v2 treats it as
a throttling error with throttling backoff, and in adaptive mode it lowers the
client's rate — which is what a ten to thirty second Sentinel failover wants. It
is also what the short-part budget refusal already answers, so the vocabulary
does not grow.

**Question 21 dissolves.** Every answer marked new in this table is an answer to
a situation that cannot arise today — a store, a fleet, a `dead` row — so no
client sees a different answer to a request it can make now, and the one
changed answer a single instance can reach — the retried Complete, `404` today,
`200` after — is a fix under ADR 0036. Nothing in this ticket waits for a
major.

### Decision 19. The instance identity is answered in `x-amz-id-2`, carried in the logs of every cross-instance event, and mapped to the pod by an info metric (question 5)

**Option B.** The identity decision 9 created — random per process start, held in
the row as the holder and in the member register — is answered on **every
response in `x-amz-id-2`**, the extended request id S3 itself sends on every
answer. aws-sdk-go-v2 reads that header into the `HostID` of its response error,
so a client's own error text names the instance that answered, which is the one
question a fleet adds to "my upload failed"; rclone and s3cmd print the same
error. SDK behaviour is SDK knowledge, not verified in this repository. The
header is additive and in S3's own shape, a correction under ADR 0036 D1 and no
break. The value is the random identity, never the pod name and never an
address: a client learns a token the operator can resolve in the log, and
nothing about the deployment.

**Where else it shows.** In the startup line, which maps identity to pod name
where the chart supplies one; in every log line about a cross-instance event —
a forward, a verdict of decision 9, a sweep won under decision 10, a deferred or
executed switch under decision 15, and each upload decision 13's step 4 ends by
name; and in an info metric `s3ep_instance_info{instance_id}` beside the
`kubernetes_pod_name` label every series already carries, so a dashboard can
join the two. Not in every request line: under Kubernetes the log stream carries
the pod already, and outside it there is one process. Whether the access log
leaves Debug is question 26's.

**Outside Kubernetes** the identity is the same random value, and the pod name
is an optional attribute of it rather than the other way round — so a
non-Kubernetes deployment has an identity for the first time, without a
configuration key.

**Rejected.** Embedding the identity in `x-amz-request-id`: the same
information in the wrong header — S3 separates request id and host id for this
reason, and log tooling treats the request id as opaque. Identity in every
access-log line: the access log is Debug-only and drops the query string, so it
answers nothing by default, and raising it is a logging decision of its own.
ADR 0030 D4 is not touched: it governs the scrape, where a pod-name label
already exists; the info metric is the same class as that label, and the
response header is the S3 surface, not the monitoring listener.

### Decision 20. Six questions closed as consequences of decisions 8–19 (questions 12, 14, 18, 20, 25, 30)

Put to the owner as one block on 2026-09-16 and confirmed without objection.

* **12 — The forward.** Exists for exactly one verb, Complete (decision 5):
  byte-faithful under the client's own SigV4, with the holder-identity header
  (decision 9), over the peer listener under the client listener's `tls` block
  (decision 14), with a connect timeout of one to two seconds as a constant — a
  key only if question 37 wants one. Parts are never forwarded: every instance
  serves every part (decisions 1 and 3). A client-facing 307 stays dead for the
  reasons the question records.
* **14 — The upload id.** Stays the backend's; the row is filed under it
  (decision 16). Nothing is minted.
* **18 — The store is unreachable.** No probe depends on it (ADR 0034 D5).
  Reads, single-request PUTs and the internal producer are untouched. Every
  client-driven multipart verb that has to read or write the row — for an upload
  this instance already knows as well — answers `503 SlowDown` (decision 18).
  The register check at start fails open (decision 15). The sweep skips its
  tick and judges nothing.
* **20 — `strategy: Recreate` at one replica.** No. Recreate kills every
  upload in flight exactly as the surge does, and adds downtime; the answer to
  "a rollout kills uploads" is the store at one replica (decision 2, middle
  row). The one-instance invariant holds through a surge because the `preStop`
  hold withdraws the old pod's endpoints before it stops (ADR 0034 D10). What
  remains is the stale chart prose, already in *Done when*.
* **25 — A fleet is single-cluster by definition.** Sentinel addresses and
  forwarding by pod address are cluster-local; the licence's singular
  `k8s_cluster_id` describes exactly that; a second cluster is a second
  deployment with its own store and its own key prefix (decision 16).
  Multi-cluster is out of scope and the ADR says so.
* **30 — A nonce store and rate limiting.** Explicitly out of scope. The store
  carries session rows and the member register and nothing else; ADR 0014's
  refusals stand, and a later proposal reopens ADR 0014, not this design. The
  ADR says so in advance, with the *Security* section's reason.

**Still open after this decision:** 22, 23, 26, 27, 28, 29, 31, 32, 37.

### Proposed in this round, not decided — question 37, the HA block

Put to the owner as the last item of the round and left for the next session.
The proposal, with every value marked as the loader would document it:

```yaml
high_availability:
  enabled: false                        # default; true switches the session layer to the store
  store:                                # Valkey behind Sentinel, the only store type
    sentinel_addresses:                 # required when enabled; plural from day one; ${VAR}
      - "${VALKEY_SENTINEL_1}:26379"    # example
      - "${VALKEY_SENTINEL_2}:26379"    # example
    primary_name: "mymaster"            # example; Sentinel's name for the primary; required
    username: ""                        # example; ACL user, empty = default user; ${VAR}
    password: "${VALKEY_PASSWORD}"      # example; ${VAR}; unset or empty refuses the start
    sentinel_password: ""               # example; ${VAR}
    database: 0                         # default
    insecure_skip_verify: false         # default; TLS itself is not optional, as on the backend leg
    key_prefix: "s3ep:"                 # default; per deployment; ^[a-z0-9][a-z0-9-]*:$
  peer:
    bind_address: ":8090"               # default; the forward listener, closes last
    advertise_address: "${KUBERNETES_POD_IP}:8090"   # required when enabled; what peers dial; ${VAR}
```

Constants, not keys, each named in the operator documentation and promoted to a
key only when a deployment needs another value (ADR 0013): forward connect
timeout 2 s, store operation timeout 1 s, member register expiry 180 s (above the
Sentinel failover window of about 90 s, decision 1), register renewal every 60 s,
body activity stamp every 10 s (decision 10).

Five choices inside it, with the favourite and its reason:

* **(a) The name.** `high_availability`, `ha` or `coordination`. Favourite
  `high_availability`: spelled out like `s3_security`, `optimizations` and
  `encryption`, greppable, and the word an operator looks for. The middle form
  of decision 2 — a store and one replica — is then "high availability without
  a second instance", which the documentation says in those words.
* **(b) An explicit `enabled` or the block's presence as the switch.** Favourite
  `enabled`: the pattern of `tls` and `monitoring`, and the chart's gate
  "`replicaCount > 1` only with the store" reads a boolean, not a presence.
  `enabled: true` makes `sentinel_addresses`, `primary_name`, `password` and
  `advertise_address` mandatory, and the refusal at start names the field.
* **(c) Store TLS.** Mandatory, no `tls.enabled`, as on the backend leg: the
  row carries wrapped keys and object names, the same class of data, so the
  same rule — a plain connection refuses the start under every provider
  (ADR 0013 D5) — in code rather than in documentation, as round 1 proposed.
  `insecure_skip_verify` stays for the demo stack with the same security note as
  the backend's: it weakens verification, and the missing trust store
  (`ca_file` exists nowhere) is the gap
  [039](039-backend-certificate-verification-failure-is-named.md) names, neither
  larger nor smaller here. The alternative — TLS optional with a warning — is
  what rule 2 of `docs/security/threat-model.md` refuses.
* **(d) The `${VAR}` allowlist** gains the addresses, `primary_name`, `username`,
  `password`, `sentinel_password` and `advertise_address`, or the proxy starts
  with the placeholder text as its password (round 1).
* **(e) The peer port defaults to 8090**, free beside 8080, 8443, 9090 and 6060.
  The peer listener is a second client port (decision 14); the chart opens it in
  the Service and never at the ingress.

Deliberately absent: a store-type switch (one type, as there is one client
type), a `member_ttl`, a forward timeout, a second prefix scheme. Each is
additive later (ADR 0013 D11). The chart derives from `KUBERNETES_POD_IP`, which
it already injects and which no Go code reads today.

### Where the open questions stand after this round

**Closed by decisions 8–20:** 3, 4, 5, 6, 7 (transport half), 9, 10, 11, 12,
13, 14, 15, 16, 17, 18, 19, 20, 21, 24, 25, 30, 34, 35, 36. Questions 1, 2 and 8
were closed in round 1 and stand.

**Still open:** 22 (where the red cross-instance test lives), 23 (one ticket or
two), 26 (the observability contract), 27 (the store's classification and
retention — round 1's "persistence off, no backup" is proposed, not decided),
28 (support claims at N instances), 29 (whether the proxy can influence the
scale-in victim; the path itself is decision 13), 31 and 32 (the owner's own
questions on the licence unit and on who runs the old profile), 33 (moot under
the release constraint, left for the record), and **37, with the proposal
above waiting for the owner's answer to (a)–(e)**.

**The next session starts at 37.** Then 27, 26, 29, 28, 22, 23, 31, 32, in that
order — 27 and 26 shape the ADR's residual-risk and monitoring sections, 22 and
23 shape how the work is cut.

### What this round changed outside the ticket

* **[ADR 0036](../adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md)
  was written**: a response follows S3, deviates only so a client stays usable
  through the proxy, and changing a response is a correction that never carries
  the breaking marker. It settles question 21 for good and leaves nothing in
  this ticket gated on a major.
* **ADR 0018 D5 gained a pointer** to that reading in its Status section and
  after D5; its wording and the guard are unchanged. **ADR 0007's D13 note**
  gained the same pointer as history. The ADR index lists 0036 under *The S3
  surface*.
* **Nothing else moved.** No code, no chart, no configuration, no operator page.
  The knowledge graph under `graphify-out/` is behind by the new ADR and needs
  its user-approved rebuild.

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
  `sessionPart.sum` is a plaintext CRC32C, and `docs/security/upload-integrity.md` says
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
  point the alias at it, restart" (*KEK rotation* in
  `docs/security/key-management.md`), which at N
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
  *What an attacker who takes the proxy gets* does not contemplate. In both arms
  a member sees the held part's plaintext
  if hand-over moves it.
* **What has to change under `docs/security/`**, by page and heading:
  `threat-model.md` — *Roles* (two network rows today; a peer leg and a store are
  a third and fourth), *Boundaries* (the sentence "The single boundary that
  matters runs between the proxy and the backend" becomes false) and *Transport*
  (a third leg); `key-management.md` — *Where each secret lives* (the
  in-flight-DEK row, plus a new row if client plaintext moves), *KEK rotation* (a
  rolling form) and *Client credential rotation* (new rotatable material);
  `stored-objects.md` — *What the backend learns anyway*, only if the store is S3;
  `tenancy-and-privilege.md` — all four sections, and "an attacker who takes the
  proxy" becomes any one of N; `request-authentication.md` — the replay window
  becomes a key-handover replay window if SigV4 is reused. The next free gap
  identifier is **H-12**, and it goes in the closing section of the page whose
  mechanism has the gap — and archived ticket 031 already records an H-12 owed
  elsewhere, which is a rule living in an archive that ADR 0022 forbids.
* **Sticky routing is what rule 2 of the threat model forbids**, more strongly than ADR 0033's
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
* **The security pages cite code by line** — 86 such links on 2026-09-19,
  thirteen of them in *Where each secret lives* alone, nine into exactly the code
  this feature rewrites. The update rule now covers them:
  `docs/security/README.md` says whoever changes the behaviour updates the page
  in the same change. Nothing enforces it, which is the same standing as
  `docs/developer/`.
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

Numbered for reference; **the authority on which are still open is the last
*Where the open questions stand* section of the latest refining round**, not
this list. 1-6 are the original set, sharpened; 7-33 came from the second pass
and the first refining round; 34 and 35 from round 2, which reopened 17 and 24;
36 and 37 from round 3.

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
    rejected; the alternative is a lease of hours. **Reopened by round 2 and
    superseded by question 35** — the landed idle clock is process-local and cannot
    be a lease value, and if the pin is an address there is no lease to renew.
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
    **Reopened by round 2 and sharpened into question 34**: decision 5 makes
    failover of a *pinned* upload impossible whatever the lease says.
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
34. **Is failover of a *pinned* upload — one whose holder already has the held
    part in memory — explicitly out of scope?** Decision 5 makes it impossible, so
    the only alternative is to reverse decision 5 and seal the held part into the
    store, with a new AEAD construction, chunking against Valkey's
    `client-output-buffer-limit replica`, and up to
    `multipart_short_part_buffer_size` of client plaintext per upload at rest in a
    component ADR 0001 never considered. Answering "out of scope" also answers
    question 24's second half and leaves the exposure at the window measured in
    round 2.
35. **Is the pin an address or a lease?** An address makes TCP the liveness check
    and deletes the TTL, the heartbeat, the renewal and every clock; a lease keeps
    them and buys a bounded cleanup of the stalled-client hour an address does not
    reach. The address form needs a compare-and-set naming exactly one party that
    may declare an upload over, or a partition turns "unreachable" into
    network-triggerable data loss. Depends on 34 and subsumes 17.
36. **Which entity tag is live after a duplicate part?** A part retried onto a
    second instance after a lost response lands twice at the backend; S3 keeps
    the last one committed, the table keeps the last one written, and the two
    orders are independent. Today a disagreement is `400 InvalidPart` from
    `VerifyClientParts` or an abort of the whole upload from `complete.go`.
    Raised in round 1, numbered in round 3.
37. **What is the shape of the HA block in the proxy's configuration?** One
    block defines the store connection and everything that belongs to it: the
    Sentinel address list and the credential (plural from the first release,
    round 1), the store's TLS, the per-deployment key prefix (decision 16), the
    peer listener's address. Which keys, which defaults, which of them the
    `${VAR}` allowlist in `envexpand.go` has to carry, and whether the block's
    presence alone switches the session layer to the store implementation
    (decision 2's three forms). Raised by the owner in round 3.

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

**The refining round of 2026-09-15 settled part of the second block** — questions
1, 2, 7 and 8 are answered there and the boxes below that depend on them are
answered with them; **17 and 24 were reopened by round 2** and continue as
questions 34 and 35. One further item lived elsewhere and is done: the probe
split and the `preStop` hook landed on 2026-09-15, and the rule they left behind
is [ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md). The idle-clock work this design looked to for a
heartbeat has landed too and does not serve that purpose — see *Refining round 2*.

**Round 3 (2026-09-16) settled most of the second block and moved two items into
the first.** Answered there: 3 and 7 (decision 14), 8, 9 and 14 (decisions 4, 11,
16), 16 and 17 (decisions 9 and 10), 4 (decision 12), 5 (decision 19), 18
(decision 20), 24 and 25 (decisions 8 and 20). Still needing a decision: 26, 27
and 31. New in the first block: the read-then-reserve ordering fix (decision 12)
and the session-miss classification with its log line and counter (decision 17),
both buildable without a store. New in the work block: the e2e case that SIGKILLs
the holder while it holds the short part and asserts the terminal answer and the
client's re-upload (decision 8), the deferred key switch and the removal guard
(decision 15), and the answer table as conformance assertions cited to their
records (decision 18, ADR 0036). The "ungraceful loss" clause of the first work
item is answered: declared out of scope in the ADR, with the window stated.
ADR 0036 exists, so no item here waits for a major.

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
- [ ] Questions 3 and 7 are answered and `docs/security/` carries the key flow
      *and* the plaintext flow between instances, with every affected page
      rewritten and H-12 claimed in the closing section of the page whose
      mechanism has the gap.
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
