# Vault as a key provider — open decisions, parked

**Status (2026-09-10): still parked. One work-list item landed, the rest is untouched.**
The Tink stub and its module are out of the tree; everything else below is outstanding
work. **Not in release 5.0.0** — that is the owner's decision (2026-09-07), not a
missing precondition, and the precondition this ticket set itself is now met: the
storage-format change shipped
([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md), implemented on
the 5.0.0 branch), and the read path unwraps the data key **once**, not twice —
[segmented.go:243-265](../../internal/orchestration/segmented.go#L243) (`codecFor`) is
the only caller of `ProviderManager.DecryptDEK`, and a data-key cache hit unwraps not at
all. What stands between this ticket and a provider is the work itself plus the two
prerequisites named in the work list (a request context that reaches the provider, and a
shutdown path that reaches it too).

The decision that a key held in a KMS is a provider type of its own, and that injecting a
local key from a secret store is something different, is
[ADR 0005](../adr/0005-a-kms-key-is-a-provider.md); its status block records what landed
and what the removal did **not** reverse. This file is the work list and the parked
design.

## The direction the owner stated (2026-09-07)

Talk to HashiCorp Vault's **Transit** engine directly, with a widely used library,
wired to the Vault the demo stack already runs, and implement key rotation fully.
The Tink-based stub was replaced rather than completed, and it was deleted first
(2026-09-10) so that no provider type in the tree claims a KMS it does not have: after
this work Tink would have existed solely as a wrapper around one HTTP call, on a module
path its own authors deprecated.

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

Whether the key **version** takes part in the fingerprint was the sixth open point and is
no longer open: it must not, and that is settled in the amendment section of
[ADR 0005](../adr/0005-a-kms-key-is-a-provider.md).

## Findings worth keeping

Expensive to rediscover, so they are recorded even though the work is parked.

**Rotation has three mechanisms and they must never be confused.**

| The operator wants | Mechanism | Restart | Bytes rewritten |
|---|---|---|---|
| Scheduled key rotation | Rotate the key in Vault, or set an automatic rotation period | no | **none** |
| Retire an old key version | A rewrap campaign, **then** raise the decryption floor | no | the whole bucket, server-side |
| Move to a different key or cluster | Add a second provider, switch the active alias | yes | none for reads |

- **Routine rotation is free.** A new key version costs nothing: new objects are wrapped under it, old objects keep decrypting because Vault picks the version out of the stored ciphertext itself. The proxy does nothing — provided the key **version is not part of the fingerprint**. That is the design constraint everything else hangs on: the fingerprint identifies mount plus key name, never the version and never the address.
- **A rewrap campaign is not a metadata edit.** Vault can re-wrap a stored key under the new version without the data key ever leaving Vault, but writing it back means a server-side copy that replaces the object's metadata — and S3 rewrites the object to do that. A campaign over 5 TB is a 5 TB server-side rewrite, even though no ciphertext byte changes. Cost scales with bytes, not with object count. The campaign restates every proxy metadata key it carries forward; a replace that drops one destroys the object as surely as deleting it. Under the segment chain that is four keys — `s3ep-dek-algorithm`, `s3ep-encrypted-dek`, `s3ep-kek-fingerprint`, `s3ep-kek-algorithm` — and no others; the `s3ep-hmac` and `s3ep-aes-iv` this finding was first written against no longer exist.
- **On a versioned or object-locked bucket a campaign cannot retire a key version at all.** The copy creates a new object version; the old one still carries the old wrapping and, under object lock, cannot be deleted. Storage doubles and the version stays referenced until retention expires. Anyone promising a key-retirement date has to know this first.
- **The campaign cannot run through the proxy.** The proxy has no copy primitive left to borrow: a PUT carrying `x-amz-copy-source` is refused with `NotSupportedWithEncryption` ([operations.go:199-212](../../internal/proxy/handlers/object/operations.go#L199)) and `CopyObject` is not on the backend interface at all any more. It must stay that way, or every authenticated client gets a metadata-rewrite primitive. The campaign is a separate tool with its own backend credentials and its own Vault policy.
- **Raising the decryption floor too early is a recoverable outage; trimming key versions is data loss.** Both belong on the never-do list, and the proxy's own Vault policy must deny both paths so a stolen proxy token cannot reach them.
- **Vault availability becomes proxy availability.** Cold reads fail during an outage and the proxy refuses to start without a reachable key, which during a rolling update turns an outage into a deployment that cannot scale back up. That is correct and it is dangerous; it belongs in the operator documentation as the headline, not a footnote.
- **The data-key cache stops being an optimisation.** It is what keeps repeat reads off the network, and its lifetime becomes a security parameter: a cached key keeps serving after Vault access is revoked. No value is right for both concerns. As it stands the cache is an LRU bounded at 1024 entries ([providers.go:22](../../internal/orchestration/providers.go#L22)) with **no expiry at all** — an entry lives until eviction or process exit. Adding one is a prerequisite for a network-backed provider, not part of it.
- **There is no request coalescing around the unwrap today.** `DecryptDEK` goes cache, then provider, with nothing between ([providers.go:205-262](../../internal/orchestration/providers.go#L205)); `grep -r singleflight` over the tree is empty. A client reading one object with parallel ranged requests would produce a burst of identical Vault calls. That belongs in this work, not after it.
- **Key custody is what this buys, and only that.** The key leaves the configuration file and the deployment secret. A compromised proxy still holds plaintext and can still ask Vault to unwrap anything it can present, for as long as its token is valid. Any sentence that blurs the two is a claim the product does not honour.

## Verify first — nothing here was checkable

This design was written without network access. **Every statement about the Vault
API is from knowledge.** The demo stack already runs a Vault with the Transit
engine enabled ([docker-compose.demo.yml:231](../../docker-compose.demo.yml#L231)), so the
first task is an afternoon of `curl` against it, capturing the real request and response
bodies into this file:

1. Encrypt and decrypt: exact request and response field names, the base64 layering, the ciphertext version prefix.
2. Rotate, then decrypt a ciphertext written before the rotation, without naming a version. The entire rotation story rests on this working.
3. Rewrap: confirm it never returns plaintext, and which capability it needs.
4. Raise the decryption floor, confirm the failure, lower it again, confirm recovery.
5. Key read: which fields exist on the pinned Vault version, and which of them the shipped policy needs.
6. The exact error status codes and messages for: unknown key, malformed ciphertext, ciphertext under the wrong key, version below the floor, denied token, sealed Vault.
7. The library: current module path, whether the context-aware calls are the current entry points, whether the client is safe to share across goroutines, and whether its retry layer honours a request deadline.
8. Server-side copy with metadata replace against the demo backend: what it preserves, what it drops, how it behaves above the single-copy size limit, and on a versioned bucket. This is now purely the rewrap tool's mechanism — the proxy itself no longer copies anything, so nothing in the tree exercises it.

## Work list, once the decisions exist

- [x] **Delete the Tink stub, its module and every reference** — landed 2026-09-10 with the
  dead-code removal. `pkg/encryption/keyencryption/tink.go` is gone,
  `github.com/google/tink/go` is out of [go.mod](../../go.mod) (`grep -i tink go.mod` is
  empty), `factory.KeyEncryptionTypeTink` is gone
  ([factory.go:13-16](../../pkg/encryption/factory/factory.go#L13) knows `aes` and `none`
  only, as does the provider type switch at
  [providers.go:93-98](../../internal/orchestration/providers.go#L93)), the stub's tests went
  with it, and the command-line help now advertises exactly the two live provider types
  ([main.go:40-43](../../cmd/s3-encryption-proxy/main.go#L40)) instead of a KMS
  integration. Two deliberate departures from "every reference":
  configuration **still refuses `type: "tink"` by name**
  ([config.go:568-569](../../internal/config/config.go#L568)), so a configuration written
  for the stub fails loudly rather than falling through to the generic invalid-type
  error — kept on purpose and documented as such in `README.md`,
  `SECURITY_ARCHITECTURE.md`, `CONTRIBUTING.md` and `CLAUDE.md`; and that refusal's
  wording still promises the deleted name ("tink encryption is not yet implemented with
  the new architecture"), a promise
  [ADR 0005](../adr/0005-a-kms-key-is-a-provider.md) has already replaced with Vault
  Transit, so it is the provider work below that retires it.
- [ ] **Remove the chart values labelled for cloud KMS** — the one part of the item above
  that did not land, because it is chart-side and the removal round was code-side.
  `secrets.gcp.serviceAccountKey` and `secrets.aws.accessKeyId` / `.secretAccessKey`
  ([values.yaml:226-233](../../deploy/helm/s3-encryption-proxy/values.yaml#L226)) are
  written into the release Secret
  ([secret.yaml:15-22](../../deploy/helm/s3-encryption-proxy/templates/secret.yaml#L15))
  and the GCP one is mounted at `/app/secrets` and volume-projected
  ([deployment.yaml:101-105](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L101),
  [:120-127](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L120)). No
  provider reads any of the three. The chart README already lists all three as inert; this
  removes them. No other ticket owns them.
- [ ] Thread the request context through to the key provider. The `KeyEncryptor` interface
  already takes one ([interfaces.go:10](../../pkg/encryption/interfaces.go#L10), `:14`),
  but nothing carries a request context to it: `ProviderManager.EncryptDEK` /
  `.DecryptDEK` take no `ctx` argument and hand
  [`context.Background()`](../../internal/orchestration/providers.go#L180) to the provider
  ([providers.go:180](../../internal/orchestration/providers.go#L180) and
  [:243](../../internal/orchestration/providers.go#L243)), so no deadline and no client
  cancellation reach a network-backed provider. Two call sites feed them
  ([segmented.go:226](../../internal/orchestration/segmented.go#L226) wrap,
  [:257](../../internal/orchestration/segmented.go#L257) unwrap). Mechanical, and a
  prerequisite: without it a client that has hung up still costs a full round trip.
- [ ] Give the provider registry a shutdown path. There **is** a shutdown path now, but it
  stops one goroutine short of the providers: `Manager.Shutdown`
  ([manager.go:130](../../internal/orchestration/manager.go#L130)) is reached from
  `Server.Shutdown` ([server.go:236-243](../../internal/proxy/server.go#L236)) and from the
  signal handler in [main.go:280](../../cmd/s3-encryption-proxy/main.go#L280), and all it
  does is cancel the multipart-session cleanup loop. `ProviderManager` has no `Close` or
  `Shutdown` and nothing walks the registry, so a network-backed provider's token-renewal
  goroutine would still have nothing to close it. The missing hop is manager → registry →
  provider.
- [ ] The provider itself: strict decoding of its own configuration block (the proxy-level
  rule, ADR 0013 D11, deliberately leaves a provider block's catch-all to the provider),
  an explicit HTTP transport, a startup probe that wraps and unwraps 32 random bytes and
  compares them, wrap and unwrap, an error taxonomy an operator can act on, request
  coalescing.
- [ ] The rewrap tool, with its own credentials and its own Vault policy.
- [ ] Integration tests against the demo Vault, covering the eight verification points above.
- [ ] Documentation: the operator runbook for all three rotation mechanisms, what to back up, and the never-do list.

## The demo Vault needs fixing regardless

Independent of this work, and cheap. All four re-checked against
[docker-compose.demo.yml](../../docker-compose.demo.yml) on 2026-09-10 and all four still
hold:

- The image is unpinned — `hashicorp/vault:latest` ([:199](../../docker-compose.demo.yml#L199)).
- The entrypoint exports the Vault address ([:227](../../docker-compose.demo.yml#L227)) **after** the loop that waits for Vault ([:222-224](../../docker-compose.demo.yml#L222)), so that loop may be talking to the wrong address; check whether the transit keys are created at all.
- It uses obsolete command-line syntax for the login: `vault auth -method=token` ([:230](../../docker-compose.demo.yml#L230)).
- It creates a `rsa-2048` transit key that nothing will ever use ([:235](../../docker-compose.demo.yml#L235)), and mounts `./vault-init` at `/vault/init` ([:209](../../docker-compose.demo.yml#L209)) which it never reads — the directory is empty in the tree.
