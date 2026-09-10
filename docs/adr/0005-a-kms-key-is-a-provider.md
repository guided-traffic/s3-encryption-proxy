# ADR 0005: A KMS-backed key encryption key is a provider, not a mode

## Status

**Accepted.** Date: 2026-09-07.

Nothing of this is built. The proxy has no KMS integration of any kind: no KMS provider type, no
remote wrap, no remote unwrap, no Vault client, and no KMS library among its dependencies. The only
key custody the product ships is a locally configured key encryption key (ADR 0004). The demo stack
still runs a HashiCorp Vault in development mode that no proxy code talks to — the proxy only waits
for it to be healthy — and the deployment chart still offers credential values for AWS and GCP that
no proxy code reads.

**The first step landed, 2026-09-10.** This ADR attached a condition to its own decision: the
misleading provider type goes first, before any KMS code exists. That is done. The stub is out of
the tree and its library is out of the dependency graph, so there is no longer a provider type that
claims a KMS and mints a random key in process memory instead. What survives the removal is the
refusal: a configuration naming `type: "tink"` still fails at startup, now by a name that names
nothing, with an error still saying the type is "not yet implemented with the new architecture" — a
promise under a name D4 has already replaced with Vault Transit. Deleting the stub does not reverse
the decision to build the provider; it is the order the decision prescribed.

**Re-checked 2026-09-10** against the tree after the 5.0.0 work. Two things this ADR assumes have
moved. D10 calls the data key cache "load-bearing" and says it carries a size bound and an expiry —
it has the bound, 1024 entries evicted least-recently-used first, and **no expiry**, which is a
prerequisite to build before a provider with a network round trip behind it. And D13's stated reason
for shipping after the format rewrite, that the read path unwraps the data key twice per object, no
longer holds: it unwraps once, and a cache hit does not unwrap at all. The conclusion stands; the
argument for it has been overtaken. Otherwise D13's precondition is met — the segment chain is in
the tree and is the only encrypted format the proxy reads or writes — so what stands between this
ADR and a provider is the work itself, plus two prerequisites nothing implements today: the cache
expiry above and the per-call timeout D7 requires.

**Amended 2026-09-07.** The owner's stated direction is now HashiCorp Vault's Transit engine
addressed directly with a widely used client, wired to the Vault the demo stack already runs,
with key rotation implemented in full — which supersedes the earlier intent of completing the
existing abstraction-library stub. **The direction is stated, the concrete choices are not
decided**: the library, the fingerprint salt, how the development environment reaches Vault
without transport security, whether the re-wrapping tool ships with the provider, and which
authentication methods the first release carries were all put to the owner and deliberately
deferred. They are listed with their trade-offs under Residual risks below, together with the
findings that would otherwise have to be rediscovered. **This provider is not part of the next major
release.**

One consequence of the direction is a rule, not an option, and it belongs here because it
constrains every later choice: **the key version must not take part in the fingerprint.** Routine
rotation inside the KMS produces a new key version, and objects written before it keep decrypting
because the KMS selects the version from the stored ciphertext. If the version were part of the
published identity, a proxy restarted after a rotation would publish a different fingerprint for
the same logical key and could no longer select the provider for objects it wrote itself. This
settles the second open question below.

Decided and specified; not implemented. It lands in its own additive release **after** the
storage format rewrite of 5.0.0 — which is in the tree and not released — and it is deliberately
not part of that major release. Seven design points are deliberately left open and are listed under
Residual risks; the eighth, whether the key version participates in the fingerprint, is settled by
the amendment above. The Decision section states the rules that hold for the provider whenever it is
built.

## Context

The proxy does envelope encryption: a data key per object encrypts the object, a configured key
encryption key wraps that data key, and the wrapped data key travels with the object in
`s3ep-encrypted-dek` (ADR 0002). With the local key provider the key encryption key is 32 bytes
that live in the process for the lifetime of the process, in a Kubernetes Secret, and in whatever
renders that Secret. Removing the asymmetric provider (ADR 0004) leaves exactly one local key
shape and sharpens the one custody question it does not answer: does the key have to be in the
process at all?

The concrete failure that forced the decision was a provider type that read like a KMS
integration and was not one. It declared a KMS key address, a credentials path and a key
template, validated the template name — and then discarded both the address and the credentials
and generated a random key in memory on every construction. It was never reachable, because
configuration validation refuses the type outright, and that is the only reason it never
destroyed data: had it been reachable, every process restart would have produced a different key
encryption key and every object written under the previous one would have been permanently
unreadable. Meanwhile the user-facing documents advertised it as the production, cloud-native
option; the security architecture was the single document that said it is not usable.

So the choice was to delete the stub or to complete it. It is completed — on the condition that
the misleading path is removed first, before any KMS code exists, so that no intermediate state
can be mistaken for a working provider.

A second force came from the same week. When the asymmetric provider was removed, the question
was asked whether a key can still be kept in a HashiCorp Vault. Two different things were being
named by one word, and separating them is what this ADR is titled after:

* **Custody in a KMS** — the key encryption key never leaves the KMS, and the proxy calls it to
  wrap and to unwrap. That is a new provider type, and it is what this ADR decides.
* **Custody by injection** — a secrets manager delivers the local key into the pod, for example
  through an environment reference such as `${S3EP_AES_KEY}` filled by a Vault agent, an operator
  or an external-secrets controller. This works today with no code at all, and the key is
  afterwards in process memory exactly as if it had been typed into the values file.

The two look alike in a deployment diagram and differ completely in what a compromised process
yields.

## Decision

**D1.** A key encryption key held inside a KMS is a **provider type of its own**, chosen per
provider alias like any other provider. It is not a mode, a flag or a variant of the local
provider, and it does not change the local provider, its key configuration or its key format.

**D2.** Delivering the local key into the process from a secrets manager is **custody by
injection, not a KMS**. It is supported, it requires no code, and no user-facing document
describes it as keeping the key in a KMS: the key is in process memory for the lifetime of the
process, and a compromised process yields it.

**D3.** Under a KMS provider the key encryption key **never enters the proxy**. Wrapping the data
key on write and unwrapping it on read are remote operations. The proxy keeps no local copy of
the key and has no path that could serve a request while the KMS is unreachable.

**D4.** **HashiCorp Vault Transit is the first backend** and the one this decision is about. AWS
KMS and GCP KMS are named candidates behind the same provider shape and ship no earlier.

**D5.** A provider that names a remote key and cannot reach it **does not exist**. Reaching the
KMS and confirming that the configured key is usable is part of startup — the key itself never
leaves the KMS, by D3; an unreachable KMS, a missing credential or a misconfigured key address
is a startup error, not a warning (ADR 0013). No code path constructs a
KMS-backed provider around a locally generated key — the failure mode of the stub is closed by
construction, not by validation.

**D6.** Runtime failure is **fail-closed and per request**: a KMS error while wrapping fails the
upload with an S3 error, a KMS error while unwrapping fails the download. There is no fallback to
another provider, no degraded mode, and no path on which an object is stored unencrypted or
served without its key having been unwrapped (ADR 0001).

**D7.** Every KMS call carries an **explicit timeout**, configured and shorter than the client's
patience, so that an unresponsive KMS produces an error the client can see rather than a proxy
that stops answering. This bounds one outbound dependency call; it is not a server-side wall
clock on the transfer, which the product does not have (ADR 0015).

**D8.** The fingerprint published in `s3ep-kek-fingerprint` **identifies the key, not its
material**. Every other provider derives it from the key with a pseudo-random function; this one
cannot, because the proxy never holds the key, so it is derived from the key's identity — its
address in the KMS. It is stable across a proxy restart, because provider selection on read is by
that fingerprint. This is the one fingerprint in the design that is not a function of key
material, and it is written down as such in the security architecture.

**D9.** **Rotation is the KMS's job and it is versioned.** The wrapped data key carries the key
version that produced it (for Vault Transit, the `vault:vN:` ciphertext prefix), so a key rotated
in the KMS still unwraps objects written before the rotation, with no re-upload. The proxy's own
rotation between provider aliases is a different mechanism; the documentation states which to use
when.

**D10.** The **data key cache is load-bearing** for this provider and covers it: it is what keeps
repeat reads of the same object off the network. It carries a size bound and an expiry, because a
miss now costs a network call rather than microseconds.

**D11.** KMS credentials **never live in a configuration file**. Vault authentication comes from
the environment or from the workload's platform identity; cloud backends use their SDK's default
credential chain. Example configurations carry references, never secrets (ADR 0021).

**D12.** The KMS provider is a **key encryption key provider only**. The object storage format is
unaffected by it (ADR 0003), and the choice of KMS backend is invisible in the stored object apart
from the fingerprint.

**D13.** It **ships after the storage format rewrite**, in its own additive release, and is not
part of the 5.0.0 bundle (ADR 0018). The read path today unwraps the data key twice per object
read; that is a few hundred nanoseconds against a local key and would be a second network round
trip per read against a KMS. The rewrite removes the duplicate; the KMS provider does not ship in
front of it.

## Consequences

* **The KMS becomes part of the proxy's availability.** During a KMS outage every upload fails and
  every read that misses the data key cache fails, for every client (ADR 0006) — a backup, a
  restore, a database archiver. This is accepted; there is deliberately no fallback, because a
  fallback is a path on which data is readable without the KMS, which is the whole point of the
  provider.
* **Latency per write and per cold read grows by one network round trip.** The data key cache
  stops being an optimisation and becomes a component with an availability story, a bound and an
  expiry to size.
* **Startup can now fail for reasons outside the deployment**: a sealed Vault, an expired token, a
  network partition. A pod restart during a KMS outage does not come back.
* **Two rotation mechanisms coexist** and both have to be documented, including which one an
  operator reaches for.
* **One fingerprint in the design is not a function of key material.** Anyone reasoning about
  fingerprints has to know about the exception.
* **The operating surface grows**: a KMS to run, authenticate to, monitor, back up and unseal. The
  proxy inherits someone else's failure modes.
* **Documentation debt has to be paid before any of this exists.** Until the provider is built,
  every document that presents a KMS option describes something that is not there, and the honest
  state — no KMS integration — is what they say. Since 2026-09-10 that is sharper: a document that
  still describes the stub describes code that exists in no form at all.
* **Nobody is forced to move.** The local provider stays the default, stays supported and stays
  fast; the KMS provider is an option for deployments that want the key out of the process.

## Alternatives Considered

**Delete the stub instead of completing it.** The audit recommended exactly this: dead code with
dependency and supply-chain surface and no function. It lost because it also deletes the only
route to key custody outside the process, which is the one property no local provider can have.

**Ship the stub as it stands, or leave it in the tree unchanged.** Rejected outright. It produces
a new random key on every construction; reachable, it would have made every object unreadable
after a restart. Its removal is the first step of the work, ahead of any KMS code, so that no
intermediate state looks like a working provider.

**Make the KMS a mode of the local provider** — one provider entry with a flag saying the key
lives remotely. Rejected: the two differ in fingerprint derivation, in failure behaviour, in
latency and in availability. A flag hides four different contracts behind one name, and the
configuration would have to describe both anyway.

**Declare secrets-manager injection to be KMS support and build nothing.** Rejected. Injection is
real, is supported and is documented, but it does not change what a compromised process yields;
calling it key custody in a KMS would be a documentation claim the product does not honour.

**Make the KMS the only key provider and remove the local one.** Rejected: no KMS backend exists
at 5.0.0, a remote unwrap would become the floor for every cold read, and every shipped default
would move off the fast path for a property most deployments have not asked for.

**Ship the KMS provider before the storage format rewrite.** Rejected: the duplicate data key
unwrap on the read path, deliberately left in place until the rewrite, would become a second KMS
round trip on every read.

**Bundle it into the 5.0.0 major release.** Rejected: it is purely additive, nothing about it
requires a breaking release, and with the local provider hardened in that release there is no gap
at 5.0.0 for a KMS to fill.

## Residual risks

**Open, not decided — these are not rules yet.**

1. **What the provider is built on.** Either a KMS abstraction library or the Vault HTTP API
   directly. Nothing is pinned any more — the stub's library left the dependency graph with it — so
   there is no incumbent and no sunk cost, and an abstraction library would exist solely to wrap a
   single remote encrypt/decrypt call, since nothing on the object data path uses one. This also
   decides the configuration type name, which is why the name is not stated in the Decision section.
2. ~~**Whether the KMS key version participates in the fingerprint.**~~ **Settled 2026-09-07 by
   the amendment in Status: it does not.** The original text is kept because the reasoning is
   what makes the answer obvious. Including it makes two proxies
   started before and after a rotation publish different fingerprints for the same logical key, and
   provider selection by fingerprint then fails; excluding it makes the fingerprint stable but
   silent about which version is configured. D8 fixes only that the fingerprint is derived from
   identity; the exact input is open — that part is now item 6 — and it must be settled before
   anything writes a fingerprint.
3. **One layer or two.** Whether the remote key wraps the proxy's data key directly, or whether the
   KMS integration's own envelope inserts a second, locally generated key between them. Direct is
   what the wrap contract means and is one layer for the same single KMS call; **not verified**
   that the Vault integration supports direct use.
4. **Which authentication methods ship** — a token from the environment, the workload's Kubernetes
   identity, AppRole, or a subset. Undecided.
5. **Whether AWS KMS and GCP KMS ship at all, and on what evidence.** Neither can be exercised by
   an automated test without cloud credentials, and the product does not accept manually verified
   paths as tested (ADR 0019). Deferring both to their own work, when someone needs them and can
   test them, is on the table and is not decided.
6. **What goes into the fingerprint besides the key's address.** D8 fixes that it is derived from
   identity, not from material; whether the derivation takes a fixed product-wide salt, a
   deployment-specific one or none is open. A fixed input makes the same remote key produce the same
   `s3ep-kek-fingerprint` in every deployment, which is what lets a second proxy read the first
   one's objects; a deployment-specific one keeps the metadata from naming a key across
   deployments and gives that portability up. The local provider derives its fingerprint with
   HKDF-SHA256 and no configured salt, so there is a precedent but no decision.
7. **How the development environment reaches Vault.** The demo Vault listens on plain HTTP with a
   fixed root token. A provider that refuses an unencrypted KMS address cannot be exercised against
   it without a TLS setup; a provider that allows one carries a switch that must be impossible to
   turn on by accident in production, because a wrap and an unwrap over plain HTTP expose the data
   key on the wire. Which of the two the first release carries is open.
8. **Whether the re-wrapping tool ships with the provider.** Rotation inside the KMS needs no
   re-upload (D9), but moving objects from a local key to a KMS key — or between two KMS keys the
   KMS does not treat as versions of one key — means re-wrapping every object's stored data key.
   Without that tool the only migration is re-uploading every object, and whether it is part of this
   release or a later one is undecided.

**Accepted risks and unverified claims.**

* **A KMS outage is a proxy outage** for writes and for cold reads. Accepted by D6; the operator's
  levers are the timeouts and the data key cache, not a fallback.
* **The cache has a bound and no expiry.** It is a bounded least-recently-used cache of 1024
  entries; the expiry D10 requires does not exist yet, so adding it is part of this work and D10
  does not hold until it is.
* **The dependency situation is unverified.** With the stub gone there is no library to inherit;
  the module path, maintenance status and current API of any candidate are unchecked in this tree,
  and open question 1 must not be answered from memory.
* **Credential plumbing exists for backends that do not.** The deployment chart offers GCP and AWS
  credential values: setting the GCP one mounts a credentials file into the pod, setting the AWS
  ones puts them in the generated Secret and nowhere else, and no proxy code reads either. The
  chart's comment on them still names the removed stub. Until one of those backends ships, that is
  configuration nobody consumes, which the product does not allow (ADR 0013); removing it or wiring
  it is open.
* **The demo Vault is demo scaffolding, and it is still running.** It runs in development mode with
  a fixed root token and creates its Transit engine and two example keys, one AES and one RSA, in
  its own start-up command; the initialisation directory it also mounts is empty and never executed.
  Whatever is set up there is unfit for anything but the demo stack, and the RSA example key — named
  for the asymmetric provider this product removed — is still created.
* **A refusal that names nothing.** Configuration still rejects `type: "tink"` by name, with an
  error announcing an implementation that is neither in the tree nor planned under that name. It is
  a leftover of the removal: harmless to a client, misleading to an operator. The name the provider
  will actually carry is open question 1, not this one.
* **Key custody is the only thing this changes.** A compromised proxy process can still ask the
  KMS to unwrap any data key it can present, for as long as its credential is valid. The KMS
  removes the key from the blast radius of a leaked configuration or a stolen Secret; it does not
  remove plaintext from the blast radius of a compromised process.

## References

* ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
* ADR 0002 — One data key per object, wrapped by a configured key encryption key
* ADR 0003 — Objects are stored as an authenticated segment chain
* ADR 0004 — One local key provider: 256 random bits, an authenticated wrap, no passphrases
* ADR 0006 — The proxy serves any S3 client
* ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
* ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
* ADR 0018 — A major release is declared by a label, never discovered at merge
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0021 — Key material and licenses are generated, never committed
* [README.md](../../README.md) — provider reference and configuration
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — trust boundaries, key custody and
  the fingerprint exception
