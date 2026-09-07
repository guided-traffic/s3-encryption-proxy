# Ticket 025: Tink KEK provider with a real KMS behind it, HashiCorp Vault first

## Status (2026-09-07)

**Open, decided (D-23).** The repository owner decided on 2026-09-07 that the Tink
provider is to be **completed rather than deleted**, with HashiCorp Vault as the
integration that matters most and the other KMS backends Tink supports (AWS KMS, GCP KMS)
taken along. This ticket is the design and the work list. Nothing here is started.

Sequencing: **after [013](013-storage-format-v2.md)**. The reason is P-1 in
[024](024-coverage-round-findings.md): today the DEK is unwrapped twice per GCM GET. With a
local AES KEK that costs 392 ns; with a KMS-backed KEK every unwrap is a network round-trip
to Vault, so the duplicate would double the KMS latency and load on every read. 013 rewrites
that path and D-28 says no interim fix, so this provider must not ship in front of it.

---

## Context: what is in the tree today, verified

**The provider is a stub that reads like an implementation.**
[tink.go](../../pkg/encryption/keyencryption/tink.go) declares `TinkConfig` with `kek_uri`,
`credentials_path` and `key_template`, validates the template name against four Tink
templates, and then `loadKEKHandle(_ string, _ string)` **discards both the URI and the
credentials path** and returns `keyset.NewHandle(aead.AES256GCMKeyTemplate())` — a fresh
random keyset in process memory, on every construction. The comment in the function says
so. Had it been reachable, every restart would have produced a different KEK and every
object written under the previous one would have been unrecoverable.

**It is not reachable.** `validateProvider` refuses `type: "tink"` with *"tink encryption is
not yet implemented with the new architecture"*
([config.go](../../internal/config/config.go)), and `isValidProviderType` lists only `aes`,
`rsa` and `none`. The factory has the type
([factory.go](../../pkg/encryption/factory/factory.go)) and `registerProvider` maps to it
([providers.go](../../internal/orchestration/providers.go)), so the wiring below config is
in place; only the gate and the KMS are missing.

**The documentation says the opposite.** [CLAUDE.md](../../CLAUDE.md) lists *"Tink Provider:
Google Tink with KMS integration (production, cloud-native)"*,
[main.go](../../cmd/s3-encryption-proxy/main.go) prints *"Tink with KMS integration
(production, cloud-native)"* in its help text, and
[CONTRIBUTING.md](../../CONTRIBUTING.md) says all cryptographic operations use Tink, which
is not true of any reachable path. [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md)
is the one place that states the truth: *"Not usable."*

**The dependency is the deprecated module path.** `go.mod` pins
`github.com/google/tink/go v1.7.0`. Tink's Go implementation moved to the
`tink-crypto` organisation with a v2 module; the KMS integrations are separate modules
there. **Not verified in this tree, and the first thing to check:** the exact module paths
(`github.com/tink-crypto/tink-go/v2`, `github.com/tink-crypto/tink-go-hcvault/v2`,
`github.com/tink-crypto/tink-go-awskms/v2`, `github.com/tink-crypto/tink-go-gcpkms/v2`),
whether v1.7.0 is still maintained, and what the v2 keyset and KMS-client APIs look like.
Do not design against v1.7.0 without checking it is not end-of-life.

**Scaffolding already exists and is unused.**
[docker-compose.demo.yml](../../docker-compose.demo.yml) runs `hashicorp/vault:latest` in
dev mode (`VAULT_DEV_ROOT_TOKEN_ID: myroot`, port 8200), the proxy `depends_on` it, and it
mounts `./vault-init` — a directory that is **empty**. No Go file, config file or script in
the repository talks to Vault. The Helm chart carries `secrets.gcp.serviceAccountKey` and
`secrets.aws.accessKeyId` "for Tink KMS" / "for AWS KMS"
([values.yaml](../../deploy/helm/s3-encryption-proxy/values.yaml)), which nothing reads.

---

## Decision (D-23)

Complete the provider. Vault is the primary target; AWS KMS and GCP KMS ride along because
Tink's integration layer makes them cheap once the provider shape is right. Deleting was
the recommendation in 024 (dead code with supply-chain surface for no function); the owner
chose the feature. That means the stub must **stop existing as a stub** — the first step
below removes the random-keyset path so no intermediate state can ever be mistaken for a
working one.

---

## What the provider has to do

The proxy does envelope encryption: a per-object DEK encrypts the data, a KEK wraps the DEK,
and the wrapped DEK travels in the object's `s3ep-encrypted-dek` metadata. A KMS-backed KEK
means **the KEK never leaves the KMS**: wrapping and unwrapping the DEK are remote
operations. That changes three things relative to `aes` and `rsa`.

1. **Every PUT and every GET makes a KMS call.** Wrap on write, unwrap on read. Latency and
   availability of Vault become latency and availability of the proxy. The DEK cache from
   [011](011-dek-cache-stale-on-reupload.md), keyed on the wrapped DEK, is what keeps repeat
   reads of the same object off the network; it must cover this provider.
2. **The fingerprint cannot be a hash of the key.** H-8 / [013](013-storage-format-v2.md)
   decided the `aes` fingerprint becomes `HMAC-SHA256(KEK, "s3ep-kek-fingerprint")`. That
   is impossible here — the proxy never holds the KEK. The fingerprint has to be a hash of
   the key **identity**: the KEK URI plus the KMS key version. The current stub hashes the
   URI alone, which is stable across a Vault key rotation and would therefore map two
   different keys to one fingerprint. **Open question 1 below.**
3. **Rotation is the KMS's job, and it is versioned.** Vault Transit keeps every key
   version and decrypts ciphertext with whichever version produced it, so a rotated KEK
   still unwraps old DEKs. The proxy's own multi-provider rotation (alias A → alias B) is a
   different mechanism; both have to coexist and the README has to say which to use when.

---

## Design

### Configuration

```yaml
encryption:
  encryption_method_alias: "vault-transit"
  providers:
    - alias: "vault-transit"
      type: "tink"
      description: "DEK wrapped by HashiCorp Vault Transit"        # example
      config:
        kek_uri: "hcvault://vault.example.internal:8200/transit/keys/s3ep"   # example
        # Authentication, exactly one of:
        vault_token_env: "VAULT_TOKEN"                                        # example
        # vault_kubernetes_role: "s3-encryption-proxy"                         # example
        # vault_approle_env: "VAULT_ROLE_ID,VAULT_SECRET_ID"                   # example
        vault_ca_file: "/etc/s3ep/vault-ca.pem"                               # example
        key_template: "AES256_GCM"                                            # default
```

Points that need deciding or verifying while implementing, not now:

- The URI scheme. Tink's hcvault integration defines one; use theirs, do not invent one.
- **Secrets never in the config file.** `credentials_path` in the current stub points at a
  file; for Vault the token should come from the environment or from Kubernetes auth, never
  from YAML, consistent with [022 item 5](022-s3-surface-fidelity.md) on key material in
  example configs. AWS and GCP credentials follow their SDKs' default chains
  (`AWS_*` env, workload identity, `GOOGLE_APPLICATION_CREDENTIALS`), which is also what the
  Helm `secrets.aws` / `secrets.gcp` values were evidently meant to feed.
- `key_template` names the **DEK-wrapping** AEAD Tink uses locally around the KMS call
  (Tink's "KMS envelope AEAD" wraps a local data key with the remote KEK). Whether the proxy
  needs that second envelope at all — it already has its own DEK layer — is open question 2.

### Fingerprint

`SHA-256(kek_uri ‖ key_version)` where `key_version` is read from the KMS at startup
(`GET /v1/transit/keys/<name>` for Vault, `latest_version`). Stored in
`s3ep-kek-fingerprint` as today. On decrypt the proxy selects the provider by fingerprint,
so the fingerprint must identify the **provider configuration**, not the version that
wrapped a specific DEK: Vault decrypts with the version embedded in its own ciphertext
(`vault:v3:...`). So the version in the fingerprint is the version *at provider start*, and
a Vault-side rotation does not change which provider is selected — the ciphertext prefix
does the rest. Write this down in `SECURITY_ARCHITECTURE.md` next to H-8, because it is
the one fingerprint that is not a function of key material.

### Failure behaviour

Fail closed, on both ends:

- **Startup:** the provider must reach the KMS and read the key before the proxy accepts
  requests. A misconfigured URI, a missing token or an unreachable Vault is a startup
  error, not a warning. This is rule 2 of the threat model and it is exactly what the stub
  violated.
- **Runtime:** a KMS error on wrap fails the PUT with an S3 error, never a fallback to
  another provider. A KMS error on unwrap fails the GET. No "degraded mode".
- **Timeouts:** explicit, configured, and shorter than the request timeout, so a hung Vault
  produces an error the client sees rather than a proxy that stops answering.

### The DEK cache

[011](011-dek-cache-stale-on-reupload.md) keys the cache on the wrapped DEK. Keep that;
it is correct here and it is what makes repeat reads cheap. Add one thing: a bound on the
cache size and an expiry, because with a KMS the cost of a miss is a network call and the
cache will be relied upon in a way it is not today. Check whether the cache already has
both; if not, that is item 6.

---

## What is explicitly out

- Tink for the **data** layer. 013 defines the segmented AES-GCM format directly on
  `crypto/cipher`; Tink is the KEK provider only. CONTRIBUTING.md's claim that all crypto
  goes through Tink is to be corrected, not made true.
- Vault as a secret store for the proxy's *other* secrets (S3 credentials, TLS keys).
  Different feature, different ticket if ever.
- KEK rotation orchestration beyond documenting how Vault versioning and the proxy's
  multi-provider rotation relate.

---

## Work breakdown

Ordered so each step leaves the tree honest.

- [ ] 1. **Kill the stub first.** Replace the body of `loadKEKHandle` with
      `return nil, errors.New("tink: no KMS backend compiled in")` and make
      `NewTinkProviderFromConfig` fail on it. Config keeps refusing `tink`. Now the
      dangerous path cannot exist in any intermediate commit. Correct CLAUDE.md, the
      `main.go` help text and CONTRIBUTING.md in the same commit so the docs stop
      describing a provider that does not exist.
- [ ] 2. **Verify the dependency situation** (see Context): module paths, maintenance
      status of `google/tink/go v1.7.0`, the v2 API. Migrate to the maintained module.
      Record what was found at the top of this ticket.
- [ ] 3. **Vault Transit backend.** `hcvault://` URI parsing, client construction with
      token / Kubernetes / AppRole auth, CA file, timeouts. Startup key read for the
      fingerprint. Wrap and unwrap through Tink's hcvault AEAD.
- [ ] 4. **Config gate.** `validateProvider` accepts `tink` with the fields above; every
      invalid combination (no URI, two auth methods, token in YAML) is a startup error with
      a message naming the field. Unit tests per branch, in the style of
      `validation_coverage_test.go`.
- [ ] 5. **Fingerprint** as designed, plus the `SECURITY_ARCHITECTURE.md` paragraph.
- [ ] 6. **DEK cache bound and expiry** if absent.
- [ ] 7. **Integration tests** against the compose Vault. Populate `vault-init/` with the
      script that enables Transit and creates the key on first start, add a
      `config/vault-example.yaml`, and extend the `encryption-modes` suite with a
      `vault_provider_test.go` mirroring `aes_provider_test.go`: round trip by sha256,
      ciphertext at rest read directly from MinIO, `s3ep-*` metadata present, the
      fingerprint stable across a proxy restart, and **a Vault-side key rotation after
      which old objects still read**.
- [ ] 8. **AWS KMS and GCP KMS** through Tink's respective integrations, behind the same
      config shape (`aws-kms://` and `gcp-kms://` URIs). No integration test can run
      without cloud credentials; unit-test the URI parsing and the client construction
      with the SDKs' fake clients, and document that the two are exercised manually.
- [ ] 9. **Helm.** Wire `secrets.gcp` / `secrets.aws` to the environment the SDK chains
      read, add a Vault auth block, and a `values-vault.yaml` example.
- [ ] 10. **README.** Provider reference entry for `tink` with every field; the
      rotation section explaining Vault versioning versus alias rotation; the failure
      behaviour stated as it is built.

## Success criteria

1. `type: "tink"` with a Vault URI starts the proxy, and the same config with Vault
   unreachable **does not start it**.
2. The `encryption-modes` integration suite has a Vault scenario that proves ciphertext at
   rest, a sha256 round trip, and read-after-rotation, and it runs in CI against the
   compose Vault.
3. No code path can construct a Tink provider around a locally generated keyset. Step 1
   is verified by a unit test that asserts the error.
4. Every document that mentioned Tink as a production option describes what is actually
   built, and `go.mod` carries no deprecated Tink module.
5. Measured: the added GET latency with a warm DEK cache is one Vault round-trip or zero,
   never two — which is why this ships after 013.

## Risks and open questions

1. **Fingerprint semantics under rotation** (see Design). The version-at-start choice means
   two proxies started before and after a Vault rotation report different fingerprints for
   the same logical key. Objects written by one are still readable by the other — Vault
   decrypts by ciphertext version — but provider *selection* by fingerprint would fail if
   the fingerprints differ. Resolution to verify: the fingerprint must not include the
   version at all, and rotation must be Vault-only; or the proxy must register every
   version it can see. Decide before item 5.
2. **Is Tink's KMS envelope worth a second envelope?** Tink's `KMSEnvelopeAEAD` generates
   its own data key per call and wraps it remotely; the proxy already does that one level
   up. Using Tink's remote AEAD *directly* to wrap the proxy's DEK is one KMS call and one
   layer; using the envelope AEAD is one KMS call and two layers. The direct form is
   simpler and is what `EncryptDEK` semantically is. Verify the hcvault AEAD supports
   direct use.
3. **Vault availability is now proxy availability.** A Velero restore during a Vault
   outage fails. Document it, and make the timeouts and the cache bound the operator's
   levers; do not build a fallback.
4. **The deprecated module** may not receive security fixes. Item 2 exists because
   designing against it and then migrating would be the work twice.
5. **`vault-init` mounts a host directory into the container.** Whatever script goes in
   there runs with the dev root token; it is demo scaffolding and must be labelled as
   such, in the same spirit as [022 item 5](022-s3-surface-fidelity.md).
