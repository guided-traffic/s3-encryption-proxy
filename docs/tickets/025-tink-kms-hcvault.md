# Vault as a key provider — open decisions, parked

**Not in release 5.0.0.** The direction is set, the decisions below are deliberately
deferred (owner, 2026-09-07). Nothing here is started. Pick this up only after the
storage-format change has shipped: the read path unwraps the data key twice today,
which with a network-backed key would be two round trips per read.

The decision that a key held in a KMS is a provider type of its own, and that
injecting a local key from a secret store is something different, is
[ADR 0005](../adr/0005-a-kms-key-is-a-provider.md). This file is the work list and
the parked design.

## The direction the owner stated (2026-09-07)

Talk to HashiCorp Vault's **Transit** engine directly, with a widely used library,
wired to the Vault the demo stack already runs, and implement key rotation fully.
The existing Tink-based stub is replaced rather than completed: after this work
Tink would exist solely as a wrapper around one HTTP call, on a module path its
own authors deprecated.

**This direction is not yet a decision.** It amends what was recorded before, and
the amendment is one of the open points below.

## Decisions to make before any code

| # | Decision | Recommendation, and the tension |
|---|---|---|
| 1 | **Library**: `github.com/hashicorp/vault/api`, or ~300 lines of `net/http` against two endpoints | The official client. It costs roughly 15–20 transitive modules against 16 current direct dependencies; what a hand-rolled client reimplements is TLS trust, retry semantics and token lifetime, which is where a subtle bug is a security bug. **Check the `api` module's licence (believed MPL-2.0, separate from the BUSL-1.1 server) before the first commit.** |
| 2 | **Fingerprint salt**: ship an optional `key_scope`, or not | Ship it, default empty. Without it the fingerprint published on every object is a guessable hash of mount plus key name, so a hostile backend learns the Vault path — reconnaissance the local provider never leaks. With it, it becomes cryptographically load-bearing configuration with no backup: change it and every object written under the old value is orphaned. |
| 3 | **Plaintext transport to the dev Vault**: an explicit `allow_plaintext_transport`, or serve the demo Vault over TLS from the existing test PKI | The explicit key. A MITM on the S3 channel sees ciphertext; a MITM on the Vault channel sees **every data key in plaintext**. There must be no `insecure_skip_verify` on this path, and the demo's need must be visible in the configuration rather than hidden in a skip. |
| 4 | **The rewrap tool**: with the provider, or later | With it. Without the tool, rotation works but retiring an old key version is not an operation anyone can perform safely, and the version floor stays a knob nobody can afford to turn. |
| 5 | **Authentication in the first release**: token only, or token plus Kubernetes auth | Token only, from an environment variable or a file. Only a cluster can prove Kubernetes auth, and [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md) does not accept a manually verified path. A token file re-read on a rejection covers the Kubernetes deployment through the Vault Agent sidecar pattern; Kubernetes auth lands later with its own end-to-end test. |

## Findings worth keeping

Expensive to rediscover, so they are recorded even though the work is parked.

**Rotation has three mechanisms and they must never be confused.**

| The operator wants | Mechanism | Restart | Bytes rewritten |
|---|---|---|---|
| Scheduled key rotation | Rotate the key in Vault, or set an automatic rotation period | no | **none** |
| Retire an old key version | A rewrap campaign, **then** raise the decryption floor | no | the whole bucket, server-side |
| Move to a different key or cluster | Add a second provider, switch the active alias | yes | none for reads |

- **Routine rotation is free.** A new key version costs nothing: new objects are wrapped under it, old objects keep decrypting because Vault picks the version out of the stored ciphertext itself. The proxy does nothing — provided the key **version is not part of the fingerprint**. That is the design constraint everything else hangs on: the fingerprint identifies mount plus key name, never the version and never the address.
- **A rewrap campaign is not a metadata edit.** Vault can re-wrap a stored key under the new version without the data key ever leaving Vault, but writing it back means a server-side copy that replaces the object's metadata — and S3 rewrites the object to do that. A campaign over 5 TB is a 5 TB server-side rewrite, even though no ciphertext byte changes. Cost scales with bytes, not with object count. The campaign restates every proxy metadata key it carries forward; a replace that drops one destroys the object as surely as deleting it.
- **On a versioned or object-locked bucket a campaign cannot retire a key version at all.** The copy creates a new object version; the old one still carries the old wrapping and, under object lock, cannot be deleted. Storage doubles and the version stays referenced until retention expires. Anyone promising a key-retirement date has to know this first.
- **The campaign cannot run through the proxy.** A client-issued copy is refused and must stay refused, or every authenticated client gets a metadata-rewrite primitive. It is a separate tool with its own backend credentials and its own Vault policy.
- **Raising the decryption floor too early is a recoverable outage; trimming key versions is data loss.** Both belong on the never-do list, and the proxy's own Vault policy must deny both paths so a stolen proxy token cannot reach them.
- **Vault availability becomes proxy availability.** Cold reads fail during an outage and the proxy refuses to start without a reachable key, which during a rolling update turns an outage into a deployment that cannot scale back up. That is correct and it is dangerous; it belongs in the operator documentation as the headline, not a footnote.
- **The data-key cache stops being an optimisation.** It is what keeps repeat reads off the network, and its lifetime becomes a security parameter: a cached key keeps serving after Vault access is revoked. No value is right for both concerns.
- **There is no request coalescing around the unwrap today.** A client reading one object with parallel ranged requests would produce a burst of identical Vault calls. That belongs in this work, not after it.
- **Key custody is what this buys, and only that.** The key leaves the configuration file and the deployment secret. A compromised proxy still holds plaintext and can still ask Vault to unwrap anything it can present, for as long as its token is valid. Any sentence that blurs the two is a claim the product does not honour.

## Verify first — nothing here was checkable

This design was written without network access. **Every statement about the Vault
API is from knowledge.** The demo stack already runs a Vault with the Transit
engine enabled, so the first task is an afternoon of `curl` against it, capturing
the real request and response bodies into this file:

1. Encrypt and decrypt: exact request and response field names, the base64 layering, the ciphertext version prefix.
2. Rotate, then decrypt a ciphertext written before the rotation, without naming a version. The entire rotation story rests on this working.
3. Rewrap: confirm it never returns plaintext, and which capability it needs.
4. Raise the decryption floor, confirm the failure, lower it again, confirm recovery.
5. Key read: which fields exist on the pinned Vault version, and which of them the shipped policy needs.
6. The exact error status codes and messages for: unknown key, malformed ciphertext, ciphertext under the wrong key, version below the floor, denied token, sealed Vault.
7. The library: current module path, whether the context-aware calls are the current entry points, whether the client is safe to share across goroutines, and whether its retry layer honours a request deadline.
8. Server-side copy with metadata replace against the demo backend: what it preserves, what it drops, how it behaves above the single-copy size limit, and on a versioned bucket.

## Work list, once the decisions exist

- [ ] Delete the Tink stub, its module and every reference: the provider type in the factory and the two provider type switches, the configuration validation, the command-line help that still advertises a KMS integration, the stub's tests, and the chart values labelled for cloud KMS that nothing reads.
- [ ] Thread the request context through to the key provider. Today the calls into it use a background context, so no deadline and no client cancellation reach a network-backed provider. Mechanical, and a prerequisite: without it a client that has hung up still costs a full round trip.
- [ ] Give the provider registry a shutdown path. A network-backed provider owns a token-renewal goroutine and nothing closes it today.
- [ ] The provider itself: strict configuration decoding, an explicit HTTP transport, a startup probe that wraps and unwraps 32 random bytes and compares them, wrap and unwrap, an error taxonomy an operator can act on, request coalescing.
- [ ] The rewrap tool, with its own credentials and its own Vault policy.
- [ ] Integration tests against the demo Vault, covering the eight verification points above.
- [ ] Documentation: the operator runbook for all three rotation mechanisms, what to back up, and the never-do list.

## The demo Vault needs fixing regardless

Independent of this work, and cheap:

- The image is unpinned.
- The entrypoint exports the Vault address **after** the loop that waits for Vault, so that loop may be talking to the wrong address; check whether the transit keys are created at all.
- It uses obsolete command-line syntax for the login.
- It creates a `rsa-2048` transit key that nothing will ever use, and mounts a directory it never reads.
