# Security Architecture

How the S3 Encryption Proxy defends the data it stores, what it deliberately
does not defend, and where the gaps are. This is the design document; it is not
the GitHub vulnerability-reporting policy (see [Reporting a vulnerability](#9-reporting-a-vulnerability)
at the end).

Every statement here was checked against the code on branch
`feat/velero-support-and-tests`. Where a claim could not be verified, it says so.
Where the code and an older document disagree, the code wins and the disagreement
is named.

**Related documents**

| Document | Contents |
|---|---|
| [README.md](README.md) | Install, configuration reference, provider setup, Velero notes |
| `DEVELOPER.md` | Contributor guide. **Does not exist yet**; the repository layout and the per-package responsibilities currently live in [CLAUDE.md](CLAUDE.md) and [internal/orchestration/README.md](internal/orchestration/README.md) |
| [`docs/adr/`](docs/adr/) | The architecture decision records. Section 8 names the ADR that owns each open item, and each checklist entry below restates the substance rather than only pointing at it, so this document stands on its own |

---

## 1. Threat model

### 1.1 The S3 backend is hostile

The objects this proxy stores belong to whatever S3 client writes through it —
cluster backups with Velero, database backups with CNPG Barman, anything an
`aws` CLI, rclone or SDK puts in a bucket — and their data is worth protecting.
The S3 endpoint they land on is treated as **hostile**, not merely
untrusted. Assume the backend can:

- read every byte it stores,
- change any byte,
- swap one object for another,
- serve a stale version of a key it once held,
- truncate a response,
- lie in a listing, in object metadata, in an ETag, and in an error.

**Nothing the backend says or does counts as authentication.** "The backend
returned 200" and "the transport was TLS" are statements about availability and
about the network, not about integrity of the stored object.

### 1.2 Three rules

These three rules decide every open question in this document.

1. **Integrity means the proxy verifies.** Authentication performed by the
   backend, or implied by TLS to the backend, is not integrity under this model,
   because the backend is the adversary.
2. **A control that exists only in configuration or in documentation is worse
   than no control**, because it gets relied upon. Section 6.5 and checklist
   item [H-7](#h-7-dead-security-configuration-knobs) both exist because of this
   rule.
3. **The stored-object format may change without a migration path**
   ("no backward compatibility", [CLAUDE.md](CLAUDE.md)). *Assumption to
   confirm before format v2 ships:* no deployment holds data that must stay
   readable across the change. If that is wrong, v2 keeps a read-only v1 decrypt
   path until everything is re-encrypted, and nothing else in this document
   changes.

### 1.3 What is out of scope

- Denial of service by the backend. A backend that refuses to serve, or deletes,
  cannot be stopped by a proxy; it can only be detected by the client.
- The confidentiality of key *names*, object *sizes*, *timestamps* and *access
  patterns*. All four are visible to the backend today; see section 3.6 and
  ADR 0023 (filename encryption, decided and not implemented).
- Side channels against the host the proxy runs on. An attacker with code
  execution on that host is covered in section 5.2, not defended against.

---

## 2. Roles and trust boundaries

### 2.1 Roles

| Role | Concretely | Trusted for | Explicitly not trusted for |
|---|---|---|---|
| **Operator** | Whoever writes the proxy configuration and holds the KEK material | Everything. The operator chooses the KEK, the integrity mode and the backend | — |
| **S3 client** | Any S3 client: Velero and its kopia-based node agent, CNPG Barman, `aws` CLI, rclone, any AWS SDK | Reading and writing **any** key in **any** bucket the backend credential can reach, once its SigV4 signature verifies | Nothing finer-grained. There is no per-client bucket or prefix scoping (section 4) |
| **Proxy process** | `s3-encryption-proxy` | The KEK, every decrypted DEK in its cache, the backend credential, and every plaintext in flight | — it is the single point of compromise (section 5.2) |
| **S3 backend** | MinIO, AWS S3, any S3-compatible endpoint | Storing and returning opaque bytes, best effort | Confidentiality, integrity, freshness, truthful listings, truthful metadata, truthful errors |
| **Client leg network** | Client to proxy; often pod to pod inside one cluster, but any host that reaches the listener | Nothing on its own. Optional proxy-side TLS (`tls.enabled`, [config.go:32-36](internal/config/config.go#L32)) protects it | — |
| **Backend leg network** | Proxy to the S3 endpoint | Nothing. This is the adversary leg by assumption | — |

### 2.2 Boundaries

```
        operator-controlled, plaintext lives here
 ┌───────────────────────────────────────────────────────────────────┐
 │                                                                   │
 │   ┌───────────────┐                ┌──────────────────────────┐   │
 │   │  S3 client    │   plaintext    │  s3-encryption-proxy     │   │
 │   │               │  ============> │                          │   │
 │   │  Velero/kopia │   SigV4 hdr    │  - SigV4 verify          │   │
 │   │  CNPG Barman  │   or presign   │  - KEK (aes | none)      │   │
 │   │  aws cli/sdk  │  <============ │  - random DEK per object │   │
 │   └───────────────┘   plaintext    │  - HMAC-SHA256 / GCM tag │   │
 │                                    │  - DEK cache (in memory) │   │
 │                                    └────────────┬─────────────┘   │
 │                                                 │                 │
 └─────────────────────────────────────────────────┼─────────────────┘
                                                   │
        ciphertext + s3ep-* metadata               │
 ══════════════════════════════════════════════════╪══════════════════
        TRUST BOUNDARY: everything below is the adversary
                                                   │
                                    ┌──────────────▼──────────────┐
                                    │  S3 backend (HOSTILE)       │
                                    │                             │
                                    │  learns: ciphertext bytes,  │
                                    │  key names, object sizes,   │
                                    │  timestamps, request order  │
                                    │                             │
                                    │  can: alter, swap, replay,  │
                                    │  truncate, strip metadata,  │
                                    │  fabricate listings         │
                                    └─────────────────────────────┘
```

The single boundary that matters runs between the proxy and the backend.
Everything above it is operator-controlled and handles plaintext; everything
below it is assumed adversarial. A second, weaker boundary runs between the
client and the proxy, and is defended by SigV4 (section 6).

---

## 3. Data and secret flow

### 3.1 Key hierarchy

Envelope encryption, two layers:

```
  KEK  (Key Encryption Key)     configured once, long-lived, never leaves the proxy
   │                            provider types: aes | none
   │  wraps
   ▼
  DEK  (Data Encryption Key)    256-bit, freshly generated per object from
   │                            crypto/rand, wrapped by the KEK, stored wrapped
   │                            in S3 metadata
   │  encrypts
   ▼
  object bytes                  AES-GCM below optimizations.streaming_threshold
                                (5 MiB # default), AES-CTR at or above it and for
                                every multipart upload
   │
   ▼
  HMAC-SHA256 key               HKDF-SHA256 from the same DEK, salt
                                "s3-proxy-integrity-v1", info "file-hmac-key"
```

The HKDF salt and info are fixed constants
([hmac_manager.go:16-17](internal/validation/hmac_manager.go#L16)), so the HMAC
key is a deterministic function of the DEK alone. Nothing else is mixed in — not
the object key, not the bucket. That is why the HMAC binds an object to its DEK
and not to its name (section 3.5).

A fresh DEK per object comes from `crypto/rand` on every write path:
[singlepart.go:95](internal/orchestration/singlepart.go#L95) and
[singlepart.go:407](internal/orchestration/singlepart.go#L407) for single-part,
[multipart.go:138](internal/orchestration/multipart.go#L138) for a multipart
session, [aes_gcm.go:126](pkg/encryption/dataencryption/aes_gcm.go#L126) and
[aes_ctr.go:97](pkg/encryption/dataencryption/aes_ctr.go#L97) inside the
envelope provider. No DEK is ever reused across objects.

### 3.2 KEK providers

| `type` | KEK operation | Where the secret lives | Notes |
|---|---|---|---|
| `aes` | **AES-256-GCM** wrap of the DEK under a key derived per wrap: HKDF-SHA256 expands the master key with a fresh 16-byte salt, and the 76-byte value stored in `s3ep-encrypted-dek` is `salt ‖ nonce ‖ ciphertext ‖ tag` ([aes.go](pkg/encryption/keyencryption/aes.go)). A flipped bit anywhere in it, or a wrap made under another key, fails to unwrap with a named error before any body byte is read | `encryption.providers[].config.aes_key`, base64 of exactly 32 random bytes, in the config file or via `${ENV_VAR}` | The only key provider that encrypts. The fingerprint is `HKDF-Expand(master key, "s3ep-kek-fingerprint")`, not a hash of the key (ADR 0004, closes H-8) |
| `none` | No wrap and no encryption at all: the body is passed through untouched and no `s3ep-*` metadata is written ([manager.go:109-116](internal/orchestration/manager.go#L109), [manager.go:139-146](internal/orchestration/manager.go#L139)) | — | Testing and end-of-life only. Objects written under it are plaintext at rest |
| `tink` | **Not usable.** The factory has a Tink key type and `registerProvider` maps to it, but config validation rejects `type: "tink"` outright with "tink encryption is not yet implemented with the new architecture", and the stub mints a random in-memory keyset instead of talking to a KMS | — | Not a production option. A key held in a KMS is a provider type of its own (ADR 0005) |

### 3.3 Where each secret lives

| Secret | At rest | In memory | Ever sent to the backend? |
|---|---|---|---|
| KEK (`aes_key`) | Config file, or an environment variable referenced as `${VAR}` and expanded at load ([envexpand.go:17](internal/config/envexpand.go#L17), applied to every provider config value at [envexpand.go:74-87](internal/config/envexpand.go#L74)) | For the process lifetime | **Never** |
| DEK | Only KEK-wrapped, in `s3ep-encrypted-dek` | Plaintext while an object is being processed; also in the bounded LRU DEK cache keyed by fingerprint, object key and a hash of the wrapped DEK ([providers.go:209-268](internal/orchestration/providers.go#L209)) | **Never in plaintext** |
| HMAC key | Nowhere. Re-derived from the DEK on every use | For the duration of one operation | **Never** |
| Backend credential (`s3_backend.access_key_id` / `secret_key`) | Config or `${VAR}` | For the process lifetime | Yes, as SigV4 to the backend — that is its purpose |
| Client credentials (`s3_clients[].secret_key`) | Config or `${VAR}`, minimum 16 characters | In a lookup map built at startup ([s3auth_robust.go:88-91](internal/proxy/middleware/s3auth_robust.go#L88)) | **Never** |

An expansion failure is fatal at load: a `${VAR}` that is unset or empty makes
`expandEnvVars` return an error ([envexpand.go:30-33](internal/config/envexpand.go#L30)),
so a deployment that forgets the key does not silently fall back to anything.

### 3.4 What is written into S3 object metadata

Exactly six keys, each carrying the configured prefix
(`encryption.metadata_key_prefix`, `s3ep-` # default,
[config.go:364](internal/config/config.go#L364)). The prefix is validated at
startup against `^[a-z0-9-]+$` (ADR 0009): an empty prefix made the writer store the
keys unprefixed while `isNoneProviderData` still looked for `s3ep-`, so every
`GET` decided the object was unencrypted and served the **ciphertext** behind a
200, and a prefix with a capital in it never matched on the way back, because S3
lower-cases metadata keys in transit while the comparisons here do not — which
disabled decryption and leaked these six keys to the client. Both are refused
rather than normalised.

The namespace itself is no longer client-writable. A client sending
`x-amz-meta-s3ep-encrypted-dek` used to reach the same map the proxy writes
these keys into: `net/http` canonicalises the header name, so the key arrived as
`S3ep-Encrypted-Dek` and the case-sensitive filter never matched it. Both
spellings then went to the backend, which lowers one onto the other, and the
client value won often enough — four of ten uploads against a running proxy — to
leave the object permanently undecryptable. The filter compares
case-insensitively now, and the none-provider write path, which had no filter at
all, has one. What remains open is only the answer: such a key is dropped
silently instead of being refused with `InvalidArgument`, which is what ADR 0009
specifies.

| Key | Written by | Contains | Consequence if the backend alters it |
|---|---|---|---|
| `s3ep-encrypted-dek` | [metadata.go:50](internal/orchestration/metadata.go#L50) | base64 of the KEK-wrapped DEK | Decryption fails, loudly |
| `s3ep-dek-algorithm` | [metadata.go:51](internal/orchestration/metadata.go#L51) | `aes-gcm` or `aes-ctr` | Wrong cipher selected; decryption fails or produces garbage that then fails the HMAC |
| `s3ep-kek-fingerprint` | [metadata.go:52](internal/orchestration/metadata.go#L52) | hex SHA-256 identifying which configured KEK wrapped this DEK | Provider lookup fails: `no provider found with fingerprint` |
| `s3ep-kek-algorithm` | [metadata.go:53](internal/orchestration/metadata.go#L53) | KEK provider algorithm string | Informational on the read path |
| `s3ep-aes-iv` | [metadata.go:57](internal/orchestration/metadata.go#L57), only when an IV exists | base64 IV (AES-CTR); for AES-GCM the nonce is also prepended to the ciphertext and is taken from there ([singlepart.go:216-219](internal/orchestration/singlepart.go#L216)) | Garbage plaintext, caught by the HMAC or the GCM tag |
| `s3ep-hmac` | [metadata.go:241](internal/orchestration/metadata.go#L241) | base64 HMAC-SHA256 over the **plaintext** | The computed and the stored value differ, and nothing acts on the difference: on the `aes-ctr` path the plaintext is delivered in full in every mode, and removing the key entirely skips the check in every mode, `strict` included. See [H-5](#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object) |

**Never written to the backend:** the KEK, the unwrapped DEK, the HMAC key, the
provider *alias* (it is a local configuration label only, never stored), and any
client credential.

**Filtered out of client responses**, so a client never sees the proxy internals:
[`IsEncryptionMetadata`](internal/orchestration/metadata.go#L305) and
[`FilterEncryptionMetadata`](internal/orchestration/metadata.go#L331).

### 3.5 What the two algorithms actually guarantee

This distinction decides most of section 8, so it is stated precisely.

| | `aes-gcm` (below `streaming_threshold`) | `aes-ctr` (at or above it, and every multipart) |
|---|---|---|
| Confidentiality | Yes | Yes |
| Ciphertext authenticated | **Yes.** GCM tag, checked by `gcm.Open` before a single plaintext byte is returned — the whole ciphertext is read first ([aes_gcm.go:91-121](pkg/encryption/dataencryption/aes_gcm.go#L91)) | **No.** CTR is a stream cipher: a flipped ciphertext bit is a flipped plaintext bit, and nothing in the cipher notices |
| Bound to the object key | **Yes.** The object key is passed as AEAD associated data on both write and read ([singlepart.go:32](internal/orchestration/singlepart.go#L32), [singlepart.go:202](internal/orchestration/singlepart.go#L202)), so the backend cannot move object A onto key B | **No.** No associated data is used on the CTR path. Moving a CTR object and its metadata to another key decrypts cleanly |
| Integrity mechanism | GCM tag, plus the `s3ep-hmac` when integrity verification is on | `s3ep-hmac` only |
| What the HMAC covers | The **plaintext**, not the ciphertext ([singlepart.go:109](internal/orchestration/singlepart.go#L109) tees the plaintext into the calculator; [multipart.go:310-317](internal/orchestration/multipart.go#L310) states it explicitly: "Update HMAC calculator with plaintext data BEFORE encryption") | Same |
| When the failure is detected | Before any plaintext leaves the proxy: `gcm.Open` reads the whole ciphertext and checks the tag first, so a tampered object is answered `500 DecryptionError` and no byte of it is served ([operations.go:250-257](internal/proxy/handlers/object/operations.go#L250)) | **Never, in any mode.** The verifying reader is written to withhold the final chunk and does not: its "near end of stream" branch hands the bytes straight to the caller ([streaming_io.go:199-208](internal/orchestration/streaming_io.go#L199)), and the withholding in the EOF branch only has something to hold back when the terminating read carries bytes ([streaming_io.go:211-251](internal/orchestration/streaming_io.go#L211)). A `bufio.Reader` signals EOF in a separate zero-byte read, so verification runs when the last byte is already on the wire. See [H-5](#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object) |

Two consequences follow, and both are load-bearing:

1. The construction on the CTR path is **encrypt-and-MAC over the plaintext**.
   Forgery still requires the DEK, and the DEK is KEK-wrapped, so a backend that
   rewrites ciphertext cannot produce a matching `s3ep-hmac`. The mismatch is
   therefore real — but **nothing acts on it**. In `strict` mode a client asking
   for a tampered 20 MiB object receives all 20 MiB of tampered plaintext behind
   `200 OK` with a matching `Content-Length`; the failure exists only as a log
   line. Pinned by `TestObjGetGetObjectTamperedCTRIsServedDespiteStrictMode`
   ([getobject_coverage_test.go:469](internal/proxy/handlers/object/getobject_coverage_test.go#L469)).
   [H-5](#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object) states it in full.
2. The comment at [server.go:167-170](internal/proxy/server.go#L167) claims the
   proxy "computes and verifies its own HMAC-SHA256 over the ciphertext". That
   is wrong in two ways — the HMAC is over the plaintext, and `s3_backend.use_tls`
   does not select the transport ([H-7](#h-7-dead-security-configuration-knobs)).
   The comment is corrected when `s3_backend.use_tls` is deleted (ADR 0013); it
   is recorded here so nobody plans against it.

### 3.6 What the backend learns anyway

Even with everything above working: object **key names** in the clear, object
**sizes** (ciphertext sizes, which differ from plaintext by a fixed 28 bytes for
GCM and by nothing for CTR), **timestamps**, and the **request pattern**. For a
Velero bucket that is a readable map of backup names, schedules, namespaces and
volume layout. Directory-segment filename encryption is decided in ADR 0023 and
is not implemented.

---

## 4. Isolation and tenancy

### 4.1 What the design gives you

- **Object isolation.** Every object has its own DEK. Compromising one DEK
  compromises one object. Recovering the KEK compromises all of them.
- **Provider isolation.** Several KEK providers can be configured at once. Each
  object records the fingerprint of the KEK that wrapped its DEK, so objects
  written under an older provider stay readable while new writes use the active
  one (section 7).
- **Client authentication.** A request without a valid SigV4 signature over a
  configured `s3_clients` credential never reaches a handler
  ([router.go:31-37](internal/proxy/router.go#L31)).
- **Metadata isolation.** The `s3ep-*` keys are stripped from every client
  response.

### 4.2 What it does NOT give you

- **No multi-tenancy.** `S3ClientCredentials` carries `type`, `access_key_id`,
  `secret_key` and `description` and nothing else
  ([config.go:76-81](internal/config/config.go#L76)). There is no bucket
  allowlist, no prefix scope, no per-client policy. **Every authenticated client
  can do everything any other authenticated client can do.** Two clients
  sharing one proxy — two Velero installations, or a Velero and a CNPG Barman
  deployment — share one blast radius.
- **No per-client keys.** The active provider is global
  (`encryption.encryption_method_alias`). All clients write objects under the
  same KEK, so a client that can read an object can always decrypt it.
- **No isolation from the backend credential.** The proxy holds one static
  credential pair for the backend ([server.go:114-116](internal/proxy/server.go#L114))
  and uses it for every request from every client. Whatever that credential can
  reach, any authenticated client can reach through the proxy.
- **No protection against a client that lies about itself.** The failed-attempt
  counter is keyed on the first `X-Forwarded-For` value, an attacker-chosen
  string ([s3auth_robust.go:448-452](internal/proxy/middleware/s3auth_robust.go#L448)).
  It only logs; see [H-7](#h-7-dead-security-configuration-knobs).

If tenant separation is required, run one proxy per tenant with its own KEK, its
own client credentials and its own backend credential.

---

## 5. Privilege footprint

### 5.1 What the proxy can do to the backend bucket

The proxy holds one static backend credential and needs it to be broad. The
object-level operations it actually issues are:

<details>
<summary>Backend operations the proxy calls (from <code>S3BackendInterface</code>)</summary>

| Operation | Why the proxy needs it |
|---|---|
| `ListBuckets`, `CreateBucket`, `DeleteBucket` | Bucket CRUD proxied for the client. Note the destructive pair: a bug in sub-resource routing once made `DELETE /bucket?encryption` delete the bucket — fixed by the allowlist at [handler.go:91-129](internal/proxy/handlers/bucket/handler.go#L91) |
| `ListObjectsV2`, `ListObjects` | Listings, and `HEAD /bucket`, which is answered by a `ListObjectsV2` existence probe with `MaxKeys=0` rather than a real `HeadBucket` ([operations.go:184-202](internal/proxy/handlers/bucket/operations.go#L184)) |
| `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `DeleteObjects` | The object data path |
| `CopyObject` | **Self-copy only**, to attach `s3ep-*` metadata after a multipart completion (section 5.3). A client-issued `CopyObject` is refused, see section 6.5 |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` | Both the client-driven multipart path and the internal auto-multipart path |
| `GetObjectTorrent` | Passed through verbatim ([operations.go:963-991](internal/proxy/handlers/object/operations.go#L963)) |
| Bucket sub-resources: ACL, CORS, policy, location, logging, versioning, tagging, notification, lifecycle, replication, website, accelerate, requestPayment | Passed through so S3 tooling works |

Declared on the interface and **never called**: `GetObjectLegalHold`,
`PutObjectLegalHold`, `GetObjectRetention`, `PutObjectRetention`,
`SelectObjectContent`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectTagging`,
`PutObjectTagging`, `DeleteObjectTagging`, `ListParts` and
`ListMultipartUploads`. Not on the interface at all: `HeadBucket`,
`GetObjectAttributes` and `UploadPartCopy`.

All of them except `ListParts` refuse at the handler, deliberately — see section
6.5 — with `NotImplemented`, or `422 NotSupportedWithEncryption` for
`UploadPartCopy`. `ListParts` is the exception in both directions: it neither
calls the backend nor refuses, and answers a fabricated empty success instead.

</details>

There is no least-privilege story to configure: the credential is one pair, used
for everything. The realistic hardening is on the backend side — scope the
backend credential to the single bucket the proxy serves.

### 5.2 What an attacker who takes the proxy gets

Everything.

- The **KEK**, in process memory, and therefore the ability to unwrap every DEK
  ever written under it — retroactively, for every object still in the bucket.
- The **DEK cache**, an LRU of already-unwrapped DEKs.
- Every **plaintext in flight**, in both directions.
- The **backend credential**, and with it direct read, write and delete on the
  bucket, bypassing the proxy entirely.
- Every **client credential** in `s3_clients`, which are stored as plaintext
  secrets in the configuration, not as hashes.

There is no key isolation, no HSM path and no separate signing identity that
survives a proxy compromise. The proxy is the trust anchor; protect it like one:
non-root container, read-only root filesystem, no shell, secrets from a
Kubernetes Secret rather than a baked-in config, and `${VAR}` references rather
than literals in any file that reaches a registry or a chart repository.

### 5.3 The self-copy window

Multipart completion cannot carry metadata: S3 does not propagate metadata from
`CreateMultipartUpload` to the finished object and `CompleteMultipartUpload`
accepts none. The proxy therefore completes the upload and then rewrites the
object onto itself with `CopyObject` + `MetadataDirective=REPLACE` to attach the
`s3ep-*` keys ([operations.go:1326-1379](internal/proxy/handlers/object/operations.go#L1326)
for the auto-multipart path, [complete.go:217-262](internal/proxy/handlers/multipart/complete.go#L217)
for the client-driven one).

Between those two calls the backend holds **ciphertext with no encryption
metadata**. Two guards exist:

- The copy runs on a detached context with a 30 s budget
  ([`utils.CleanupContext`](internal/proxy/utils/utils.go#L126)), so a client
  disconnect cannot cancel it. Aborts of a failed upload use the same context,
  so a disconnect cannot orphan a multipart upload either.
- If the copy fails, the client gets an error saying the upload effectively
  failed, rather than a success for an object that can never be decrypted.

The window is still real: a crash between completion and copy leaves an
undecryptable object in the bucket. Under the current pass-through behaviour a
later `GET` of that object would hand the **ciphertext to the client as if it
were plaintext** — which is exactly what [H-6](#h-6-an-object-without-encryption-metadata-is-served-as-plaintext)
closes.

---

## 6. The validation story

### 6.1 Two authentication forms

`AuthenticateRequest` ([s3auth_robust.go:102](internal/proxy/middleware/s3auth_robust.go#L102))
accepts exactly what S3 accepts:

1. **Header form** — `Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...`.
2. **Pre-signed query form** — `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
   `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`
   ([s3auth_presigned.go:56](internal/proxy/middleware/s3auth_presigned.go#L56)).

Both forms are needed by real clients. Velero, for example, signs headers on its
data path and uses pre-signed URLs for its download path (`velero backup
download`, backup and restore logs).

### 6.2 What is verified on every S3 request

| Check | Where |
|---|---|
| `Authorization` header at most 8192 bytes | [s3auth_robust.go:41](internal/proxy/middleware/s3auth_robust.go#L41) |
| Credential scope has 5 components, an 8-digit date, `service == "s3"`, `aws4_request` | [s3auth_robust.go:188-195](internal/proxy/middleware/s3auth_robust.go#L188) |
| Access key exists in `s3_clients` | [s3auth_robust.go:128-132](internal/proxy/middleware/s3auth_robust.go#L128) |
| Request timestamp within the clock-skew window, in both directions | [s3auth_robust.go:222-256](internal/proxy/middleware/s3auth_robust.go#L222) |
| Credential date matches the request date | [s3auth_robust.go:256-260](internal/proxy/middleware/s3auth_robust.go#L256) |
| Full SigV4 signature over method, canonical URI, canonical query, signed headers and payload hash, compared in constant time | [s3auth_robust.go:295](internal/proxy/middleware/s3auth_robust.go#L295) |
| Pre-signed only: `X-Amz-Expires` present, positive, at most 7 days; signing time not in the future beyond the skew; URL not expired | [s3auth_presigned.go:134-158](internal/proxy/middleware/s3auth_presigned.go#L134) |
| Bucket requests: every query parameter is on a known allowlist, otherwise `NotImplemented` | [handler.go:107-129](internal/proxy/handlers/bucket/handler.go#L107) |
| Auto-multipart uploads: bytes received match the declared plaintext length | [operations.go:1269](internal/proxy/handlers/object/operations.go#L1269) |

Authentication failures return a **fixed message per error code**. The raw error
text carries the attempted access key, signed header names and clock offsets;
reflecting it echoed attacker-controlled text into the response body and broke
the XML whenever a key contained `&` or `<`. It is now logged and not echoed
([middleware_setup.go](internal/proxy/middleware_setup.go)).

### 6.3 The clock-skew window

**900 seconds (15 minutes)** in both forms, but from two different places, and
this is worth knowing:

- The **header form** uses the compile-time constant `MaxClockSkewSeconds = 900`
  ([s3auth_robust.go:40](internal/proxy/middleware/s3auth_robust.go#L40)).
  `s3_security.max_clock_skew_seconds` does **not** affect it.
- The **pre-signed form** uses `s3_security.max_clock_skew_seconds` when it is
  set and above zero, and falls back to the same 900
  ([s3auth_presigned.go:162-167](internal/proxy/middleware/s3auth_presigned.go#L162)).

So the documented knob configures half of what its name suggests. Verified by
grep over `internal/`; the header path has no reference to the config value.

### 6.4 What is NOT verified

- **The request payload.** A missing `X-Amz-Content-Sha256` on a non-empty body
  becomes `UNSIGNED-PAYLOAD` rather than a rejection
  ([s3auth_robust.go:322-332](internal/proxy/middleware/s3auth_robust.go#L322)),
  and the pre-signed form defaults to `UNSIGNED-PAYLOAD` as well
  ([s3auth_presigned.go:182-186](internal/proxy/middleware/s3auth_presigned.go#L182)).
  The signature therefore authenticates the request line and headers, not the
  bytes.
- **Per-chunk signatures in aws-chunked uploads.** See
  [H-2](#h-2-per-chunk-signatures-are-never-verified).
- **Client checksums.** `Content-MD5` and `x-amz-checksum-*` are accepted and
  dropped. They are no longer forwarded to the backend with the ciphertext they
  do not describe (fixed on both the streaming PUT path,
  [operations.go:670](internal/proxy/handlers/object/operations.go#L670), and
  `UploadPart`, [upload.go:234](internal/proxy/handlers/multipart/upload.go#L234)),
  but nothing verifies them either. Any client that sends a checksum has its
  integrity intent discarded; kopia, for example, sends `Content-MD5` on every
  blob it writes. Verifying them against the plaintext is ADR 0012.
- **Replay within the window.** There is no nonce store. A captured signed
  request can be replayed until its timestamp ages out of the 15-minute window.
- **Anything on `/health` and `/version`.** Both are registered before the auth
  middleware ([router.go:25-28](internal/proxy/router.go#L25)) and are
  unauthenticated by design.
- **Anything on the monitoring listener.** `monitoring.bind_address`
  (`:9090` # default) serves `/metrics`, `/health` and `/info` with **no
  authentication at all** ([monitoring/server.go](internal/monitoring/server.go)).
  Bind it to a private interface or fence it with a network policy; never expose
  it publicly.
- **`/debug/pprof` is no longer on that listener (ADR 0013).** When
  `monitoring.pprof_enabled` is set (`false` # default) the profiling endpoints
  run on their own listener at `monitoring.pprof_bind_address`
  (`127.0.0.1:6060` # default, [monitoring/pprof.go](internal/monitoring/pprof.go)).
  A non-loopback value is a **startup error**, not a warning: `/debug/pprof/heap`
  on a proxy that holds KEK material, DEKs and plaintext buffers in memory is a
  key disclosure primitive, and the log line that previously told the operator to
  restrict access was a control that existed only in documentation. Reach it with
  an SSH tunnel or `kubectl port-forward`. The listener no longer depends on
  `monitoring.enabled` either — that coupling made `pprof_enabled: true` silently
  do nothing on its own, which is the same class of lie.

### 6.5 Handlers that refuse rather than pretend

Under rule 2, an operation that answers 200 for work it did not do is worse than
one that refuses. The following now return an explicit refusal —
`NotImplemented` ([errors.go:94](internal/proxy/response/errors.go#L94)) unless
noted — instead of a misleading success:

- `PUT`/`GET ?legal-hold`, `?retention` on an object. The old legal-hold handler
  **always set the hold ON**, so a client asking to release a hold applied one
  instead.
- `SelectObjectContent`.
- `GET /bucket/key?attributes`, which used to return the object **bytes** where
  an XML document was expected ([handler.go:82-89](internal/proxy/handlers/object/handler.go#L82)).
- `UploadPartCopy` answers `422 NotSupportedWithEncryption`
  ([copy.go:35-44](internal/proxy/handlers/multipart/copy.go#L35),
  [errors.go:108-118](internal/proxy/response/errors.go#L108)) — a server-side
  copy cannot be re-encrypted at the proxy. It was previously **unreachable**
  (the route was shadowed and its header matcher compared the literal string
  `{source}`), so such a request silently stored a 0-byte part; the route now
  matches and the honest error is returned
  ([router.go:66-70](internal/proxy/router.go#L66)).
- Client-issued `CopyObject` (`PUT` with `x-amz-copy-source`) answers the same
  `422 NotSupportedWithEncryption`
  ([operations.go:373-386](internal/proxy/handlers/object/operations.go#L373)).
  The backend credential can copy; the client cannot ask it to, because a
  server-side copy would move ciphertext without re-encrypting it.
- `GET /bucket/key?legal-hold`, `?retention`, object ACL and object tagging, and
  `ListMultipartUploads`, all `NotImplemented`.
- Any bucket sub-resource without a route. Previously such a request fell through
  to the base operation for its HTTP method, which is how
  `DELETE /bucket?encryption` deleted the bucket
  ([handler.go:86-104](internal/proxy/handlers/bucket/handler.go#L86)).

**One handler still pretends.** `ListParts` answers `200` with a fabricated,
always-empty `ListPartsResult` and never asks the backend
([list.go:64-72](internal/proxy/handlers/multipart/list.go#L64)). Under rule 2
that is the failure mode this section is about, and it is not fixed: a client
cannot use `ListParts` to discover what a multipart upload actually holds, which
is why the tests that pin this behaviour check the backend directly. The fix is
ADR 0011: `ListParts` is answered from the proxy's own part table.

### 6.6 Transport

| Leg | Control | Reality |
|---|---|---|
| Client to proxy | `tls.enabled`, `tls.cert_file`, `tls.key_file` ([config.go:32-36](internal/config/config.go#L32)) | Works. The integration suite runs against both the HTTP and the TLS endpoint |
| Proxy to backend | `s3_backend.target_endpoint`, `s3_backend.use_tls`, `s3_backend.insecure_skip_verify` | **The scheme in `target_endpoint` decides**, not `use_tls`. `use_tls` is assigned at [server.go:107-109](internal/proxy/server.go#L107) and then never read; only `insecure_skip_verify` and `target_endpoint` reach the SDK options ([server.go:153-196](internal/proxy/server.go#L153)). See [H-7](#h-7-dead-security-configuration-knobs) |

`insecure_skip_verify: true` disables backend certificate verification and logs a
warning. Under this threat model that is a smaller loss than it looks — the
backend is the adversary regardless — but it also removes the only defence
against an *additional* attacker on that leg. Do not use it outside development.

---

## 7. Rotation and change propagation

### 7.1 KEK rotation, by fingerprint

Rotation is the one thing the metadata design is built for.

1. Add the new provider to `encryption.providers` and leave the old one in place.
2. Point `encryption.encryption_method_alias` at the new alias.
3. Restart the proxy.

From then on, every write uses the new KEK, and every read picks the provider
whose fingerprint matches `s3ep-kek-fingerprint` on the object
([providers.go:305-322](internal/orchestration/providers.go#L305),
[providers.go:209-268](internal/orchestration/providers.go#L209)). Objects
written under the old KEK stay readable for exactly as long as the old provider
stays configured. Removing it makes them permanently unreadable — there is no
re-encryption job; re-writing objects through the proxy is the migration.

**Fingerprints are derived, not configured**, so they cannot drift: for `aes` the
fingerprint is `HKDF-Expand(master key, "s3ep-kek-fingerprint")` — a derivation
under a label of its own, so publishing it in object metadata says nothing about
the key and nothing about the key used to wrap any DEK — and for `none` it is the
constant `none-provider-fingerprint`.

`aes` has no `RotateKEK` call and neither has any other provider: rotation is the
configuration procedure above, not an API call.

### 7.2 Client credential rotation

Add the new `s3_clients` entry, restart, move clients over, remove the old entry,
restart again. The lookup map is built once at startup; there is no reload.

### 7.3 The propagation gap: the Helm chart does not roll pods on a config change

**This is live today.** [templates/deployment.yaml:15-19](deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L15)
renders only `.Values.podAnnotations`. There is **no `checksum/config`
annotation**, so `helm upgrade` with a changed `config` string updates the
ConfigMap, reports success, and leaves the old pods running the old
configuration.

Everything that decides how the proxy encrypts lives in that string: the active
provider alias, the key material, the integrity mode. An operator who rotates a
KEK and is told the rotation succeeded, while the old key is still encrypting
every new object, has been handed a false statement about the security of their
data by the deployment tooling — rule 2, precisely. Until the chart renders a
`checksum/config` annotation, a `kubectl rollout restart
deployment/<release>-s3-encryption-proxy` after every config change is
mandatory, and the Velero e2e harness does exactly that.

Related, in the same chart: enabling `tls.enabled` without rewriting both
probe blocks yields a pod that never becomes Ready, which pushes operators
towards running the proxy in plaintext.

### 7.4 A published chart default that was a working key

Historic, fixed on this branch, recorded because anyone who installed the chart
before it is affected. `deploy/helm/s3-encryption-proxy/values.yaml` shipped
`aes_key: "0123456789abcdef0123456789abcdef"` as the default provider key, and
`values-monitoring.yaml` shipped a real base64 AES-256 key. **Any `helm install`
that did not override the value encrypted every object with a key published in
this repository.** Both are now `${S3EP_AES_KEY}` environment references.

If a deployment ever ran with either value: treat every object written under it
as compromised, configure a new KEK, re-write the data through the proxy, and
only then remove the old provider.

### 7.5 License expiry stops the proxy

Not an attack, but a propagation property with security consequences. The
license validator checks hourly and calls `os.Exit(1)` once the license expires
([validator.go:167-210](internal/license/validator.go#L167),
[validator.go:236-246](internal/license/validator.go#L236)), and without a valid
license only `type: "none"` is permitted
([validator.go:152-164](internal/license/validator.go#L152)). An expired license
therefore means no decryption path at all — every object in the bucket becomes
unreadable until the proxy is relicensed (ADR 0016).

---

## 8. Residual risks — hardening checklist

Ordered by how much they matter under this threat model. Each item states what is
true today, what closes it, and what an operator can do in the meantime.

### H-1 Ranged reads of `aes-ctr` objects are not verified by the proxy

**ADR 0003 (objects are an authenticated segment chain). Open.**

A ranged `GET` of an AES-CTR object returns bytes authenticated by the backend
and by TLS — **not by the proxy**. The `s3ep-hmac` covers the whole object and
cannot be checked against a partial read
([rangeread.go:39-44](internal/orchestration/rangeread.go#L39)). Ranged
`aes-gcm` reads are unaffected: the object is read and verified in full and the
range is taken from the plaintext afterwards
([range.go:150-155](internal/proxy/handlers/object/range.go#L150)), at the cost
of two backend requests.

Whole-object reads of `aes-ctr` objects are not verified either, for an unrelated
reason: the HMAC is computed, compared, and then ignored. That is
[H-5](#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object). H-1
is about a check that cannot run; H-5 is about a check that runs too late.

This is not a corner case. It affects every client that reads with ranged GETs;
the motivating case is kopia, which **reads its pack blobs with small ranged
GETs**, so every Velero volume restore consists almost entirely of reads the
proxy does not authenticate. Refusing partial reads instead breaks every such
client — Velero restores become impossible — and reading a whole 20 MiB blob to
verify a 32-byte read is pathological.

Storage format v2 exists to close exactly this: per-segment AEAD, so a range is
verifiable against the segments it overlaps.

> **Until the segmented format of ADR 0003 ships, the proxy must not be described
> as fit for a hostile backend, and not for an untrusted one either — for any
> client, Velero included.** The backend has to be treated as trusted
> infrastructure, which is the wording
> [README.md](README.md) uses and the line the findings document draws
> (*"do not describe Velero support as fit for an untrusted backend before v2
> ships"*). Setting the kopia repository password of
> [H-4](#h-4-velero-kopia-repositories-default-to-a-published-password) makes
> kopia a real second layer over its own data and is the interim mitigation — it
> narrows the gap, it does not close it, and it covers nothing Velero writes
> outside the kopia repository and nothing any other client writes.

- [ ] Ship segmented-AEAD storage format v2
- [ ] Re-write existing objects through the proxy afterwards
- [ ] Only then update the backend-trust claims in [README.md](README.md), the Velero section included

### H-2 Per-chunk signatures are never verified

**ADR 0014. Accepted.**

In an `aws-chunked` upload the seed signature in the `Authorization` header is
verified; the `chunk-signature` on each chunk is not, in either the old or the
new decoder.

**Why this is judged acceptable:** the chunk signatures protect the **client
leg**, and the adversary in this model is on the **other** leg. The client leg
is operator-controlled (section 2.2) and normally runs over TLS. The seed signature never covered the
body in any case, `UNSIGNED-PAYLOAD` is already accepted (section 6.4), and the
AWS SDK chooses the unsigned-trailer framing over TLS precisely because transport
integrity comes from TLS. The residual exposure is a client that signs chunks
over plain HTTP and expects the proxy to catch a man in the middle.

Verifying the chain is a real implementation with real CPU cost, and the client
checksum verification of ADR 0012 buys most of the same benefit for much less.

- [ ] Enable TLS on the client leg (`tls.enabled`) — this is the mitigation
- [ ] Verify client upload checksums against the plaintext (ADR 0012)

### H-3 Rollback and object substitution are not prevented

**Structural.**

No AEAD and no HMAC prevents a backend from serving an **older version of the
same key**: the old bytes, the old metadata and the old HMAC are all internally
consistent, because the proxy wrote them. The same holds for serving nothing, or
for a listing that omits an object.

Partial mitigation exists for `aes-gcm` objects only: the object key is the AEAD
associated data (section 3.5), so bytes cannot be moved to a *different* key.
CTR objects have no such binding — an object and its metadata relocated to
another key decrypt cleanly.

**The only defence today is the client.** Velero and kopia, for example, run
their own consistency checks over their own manifests; a rolled-back or missing
blob shows up there. A client without such checks has no defence at all. The
proxy contributes nothing.

- [ ] Enable object versioning and, where available, object lock on the backend
      bucket, so a rollback needs a privilege the backend credential does not have
- [ ] Rely on the client's own consistency checks where it has them (Velero and
      kopia do); treat their failures as integrity alerts, not as flakes

### H-4 Velero kopia repositories default to a published password

**Operator action required. Upstream, not a proxy defect.**

Velero creates the `velero-repo-credentials` secret with the well-known default
password **`static-passw0rd`** unless the operator sets it **before the first
backup**
([velero#6443](https://github.com/vmware-tanzu/velero/issues/6443),
[velero#8137](https://github.com/vmware-tanzu/velero/issues/8137)).

With the default, kopia AES-GCM and its content HMACs are **forgeable by anyone
who can read the bucket**, because the repository salt sits in
`kopia.repository` in the same bucket. Kopia is then neither confidentiality nor
integrity against this backend. The objects Velero writes itself — resource
tarballs including Secrets, backup logs, results — are never encrypted by Velero
at all.

That leaves the proxy as the only protection for both, which is precisely the
situation [H-1](#h-1-ranged-reads-of-aes-ctr-objects-are-not-verified-by-the-proxy)
makes uncomfortable. Setting a strong password turns kopia into a genuine second
layer and is the interim mitigation for H-1.

- [ ] **Create `velero-repo-credentials` with a strong random value BEFORE the
      first backup.** Changing it later does not re-key an existing repository

### H-5 `integrity_verification` does not refuse a tampered `aes-ctr` object

**Documented, not fixed: the segmented format of ADR 0003 closes it by
construction. Open.**

This section previously said `strict` was "the only recommended mode" and that it
aborts on a mismatch. On the `aes-ctr` read path it aborts nothing. Two independent
routes produce that, both reproduced by unit tests in this tree, so **there is
currently no configuration in which a tampered `aes-ctr` object is refused.**

**1. The verifying reader releases the plaintext before it verifies.**
`hmacValidatingReader` buffers a final chunk only when the terminating read carries
bytes ([streaming_io.go:211-251](internal/orchestration/streaming_io.go#L211)), and
its "near end of stream" branch returns the tail to the caller instead of holding it
([streaming_io.go:199-208](internal/orchestration/streaming_io.go#L199)). The source
is a `bufio.Reader`, which signals EOF in a separate zero-byte read, so
`VerifyIntegrity` runs when the whole plaintext has already been written to the
`ResponseWriter` behind a `200` and a matching `Content-Length`. The mismatch is
logged and nothing else. Even where the reader does work as written it withholds
only the last chunk, so the best available outcome was a truncated body, never an
error document. Pinned by
`TestObjGetGetObjectTamperedCTRIsServedDespiteStrictMode/content_length_known`.

**2. A backend answering without `Content-Length` switches the check off.** The
verifying reader is constructed only under
`m.hmacManager.IsEnabled() && expectedSize > 0`
([singlepart.go:483](internal/orchestration/singlepart.go#L483)), and `expectedSize`
is the backend response's `Content-Length`, forwarded as `-1` when it is absent
([operations.go:123-128](internal/proxy/handlers/object/operations.go#L123)). A
backend that answers chunked, or any intermediary that drops the header, disables
HMAC verification for that object — no error, no log line, no configuration change.
The adversary in this model chooses that header. Pinned by the
`content_length_absent` subtest of the same test.

A third gap sits in the same place: an object carrying no `s3ep-hmac` at all is
read without verification in **every** mode. `GetHMAC` returns an error for the
missing key ([metadata.go:220-224](internal/orchestration/metadata.go#L220)), and
both read paths then fall through silently
([singlepart.go:510](internal/orchestration/singlepart.go#L510) for CTR,
[singlepart.go:237](internal/orchestration/singlepart.go#L237) for GCM). The
`"expected HMAC is empty"` branch of `VerifyIntegrity`
([hmac_manager.go:117-124](internal/validation/hmac_manager.go#L117)) is unreachable,
because both call sites require `len(expectedHMAC) > 0`. So the "backend strips one
metadata key and verification is skipped" downgrade is **not** specific to `hybrid`;
`strict` behaves identically.

A reader that holds the tail back correctly does exist — `hmacGatedDecryptionReader`,
one 64 KiB chunk of lag, verify-then-emit
([streaming_io.go:317-378](internal/orchestration/streaming_io.go#L317)) — but its
only entry point, `DecryptMultipartWithHMACVerification`
([multipart.go:762](internal/orchestration/multipart.go#L762)), has no production
caller. Every `aes-ctr` GET, multipart objects included, is routed by the stored
`dek-algorithm` into the reader above
([operations.go:95-102](internal/proxy/handlers/object/operations.go#L95)). The
handler's own pre-response check is inert as well: `shouldValidateHMACEarly` returns
`false` unconditionally
([operations.go:186-204](internal/proxy/handlers/object/operations.go#L186)).

**What the modes do today**

| Mode | On an `aes-ctr` object | On an `aes-gcm` object |
|---|---|---|
| `off` | No HMAC written, none read. No detection signal | The GCM tag is still checked before delivery |
| `lax` | Mismatch logged, data delivered ([hmac_manager.go:141-144](internal/validation/hmac_manager.go#L141)) | The GCM tag is still checked before delivery |
| `strict` | Mismatch logged **after** the last byte is delivered, or not checked at all when the backend omits `Content-Length`. Client-visibly identical to `lax` | The tag has already refused the object: `500 DecryptionError`, nothing served |
| `hybrid` | As `strict`; its documented "legacy object without HMAC passes" is not a difference, because that passes in `strict` too | As `strict` |

**Scope.** The read path branches on the stored `s3ep-dek-algorithm`
([operations.go:95](internal/proxy/handlers/object/operations.go#L95)), so the line
is drawn by algorithm, not by size. The write path decides which objects land on
which side:

- `aes-gcm`, genuinely protected: a single `PUT` body below
  `optimizations.streaming_threshold` (5 MiB # default,
  [config.go:354](internal/config/config.go#L354)) when integrity verification is
  off, or below 5 MiB when it is on. **There is no enforced lower bound on that
  threshold**, so the protected window is whatever the operator types: the 1 MiB
  minimum in `validateOptimizations`
  ([config.go:740-745](internal/config/config.go#L740)) only runs when
  `enable_adaptive_buffering` is on, and it defaults to off
  ([config.go:352](internal/config/config.go#L352)); the `validate:"min=1048576"`
  struct tag ([config.go:124](internal/config/config.go#L124)) is inert, because
  no validator library is part of this module. `streaming_threshold: 65536`
  starts the proxy and puts every object of 64 KiB or more on the unverified
  path.
- `aes-ctr`, unprotected on read: every object at or above `streaming_threshold`
  ([operations.go:457](internal/proxy/handlers/object/operations.go#L457)); with
  integrity verification on and an encrypting provider, every object at or above
  5 MiB whatever `streaming_threshold` says, because that routes through
  auto-multipart ([operations.go:446-452](internal/proxy/handlers/object/operations.go#L446));
  every upload of unknown `Content-Length` at any size, same branch; every
  client-driven multipart upload
  ([multipart.go:169](internal/orchestration/multipart.go#L169) writes
  `dek-algorithm: aes-ctr`); and anything sent as
  `application/x-s3ep-force-aes-ctr`, including bodies under 1 KiB
  ([operations.go:394](internal/proxy/handlers/object/operations.go#L394)).

For any client that writes large or streamed objects that is nearly everything;
for a Velero or kopia bucket it is, because kopia's pack blobs are large and
streamed.

**What `strict` is still worth setting for.** It writes the HMAC on upload, and it
produces `HMAC validation FAILED` in the log when an object has been altered. It
is a detection signal for an operator watching logs, not an enforcement
mechanism, and it must not be presented as one.

- [ ] Set `encryption.integrity_verification: "strict"` — for the stored HMAC and
      the log line, not for enforcement
- [ ] Alert on `HMAC validation FAILED`; it is the only integrity signal that exists
      today for `aes-ctr` objects
- [ ] Do not rely on any mode to refuse a tampered `aes-ctr` object. Treat the
      backend as trusted infrastructure until the segmented format of ADR 0003 ships
- [ ] ADR 0003 removes the knob: in the segmented format integrity is not
      separable from decryption

### H-6 An object without encryption metadata is served as plaintext

**ADR 0003 closes it by failing closed. Open.**

When an object carries no `s3ep-*` metadata, the proxy assumes a `none`-provider
pass-through and hands the backend body straight to the client — **even when the
active provider encrypts**
([manager.go:185-189](internal/orchestration/manager.go#L185),
[`isNoneProviderData`](internal/orchestration/singlepart.go#L327)). The ranged
path does the same ([range.go:142-148](internal/proxy/handlers/object/range.go#L142)).

A hostile backend strips the metadata from an object, replaces the body, and the
proxy delivers the substitute as plaintext without an error, whatever client
reads it. For Velero, concretely, that is a way to inject a crafted
`velero-backup.json`, a restore result, or kopia
manifests — and the kopia layer above them is forgeable under
[H-4](#h-4-velero-kopia-repositories-default-to-a-published-password). The same
path also turns a crashed self-copy (section 5.3) into ciphertext delivered as
plaintext.

The decided fix: when the active provider encrypts, an object without the proxy
metadata is an **error** on `GET`, `HEAD` and ranged `GET`, with a distinct
documented error code. Only the `none` provider passes through. No opt-out knob.
A bucket holding pre-existing plaintext is not migrated and never read in place:
its content is uploaded through the proxy from the source.

- [ ] Fail closed on missing encryption metadata (ADR 0003)
- [ ] Meanwhile: never point an encrypting provider at a bucket that also holds
      objects the proxy did not write

### H-7 Dead security configuration knobs

**ADR 0013. Open.**

Verified by grep over `internal/`: these keys are parsed, validated, defaulted
and documented — and then referenced by nothing.

| Key | Reality |
|---|---|
| `s3_security.enable_rate_limiting` | **No rate limiter exists.** Declared at [config.go:92](internal/config/config.go#L92), validated at [config.go:824-832](internal/config/config.go#L824), used nowhere |
| `s3_security.max_requests_per_minute` | Same |
| `s3_security.max_failed_attempts` | Unused. [s3auth_robust.go:438](internal/proxy/middleware/s3auth_robust.go#L438) compares a hardcoded `5` and only logs |
| `s3_security.unblock_ip_seconds` | Unused. Nothing is ever blocked, so nothing is ever unblocked |
| `s3_security.strict_signature_validation` | Declared at [config.go:86](internal/config/config.go#L86) and read nowhere. Signature validation is always on, which is the safe default, but the knob suggests a choice that does not exist |
| `s3_security.enable_security_logging` | Declared at [config.go:98](internal/config/config.go#L98) and read nowhere. `logSecurityEvent` always logs, regardless of the value |
| `s3_backend.use_tls` | Read only to assign itself ([server.go:107-109](internal/proxy/server.go#L107)). The scheme of `target_endpoint` decides the transport (section 6.6) |

Two consequences: **no protection exists where the configuration says it does**,
and the failed-attempt map is keyed by an attacker-chosen `X-Forwarded-For`
value and never expires, so unauthenticated requests grow proxy memory without
bound.

Per-IP rate limiting is also the wrong tool here — a legitimate client is one
authenticated identity that may issue thousands of requests from one address
(Velero bursts from a single pod IP; any client behind a NAT looks the same),
and the real controls are authentication and resource
limits. The decision is to **delete the knobs and the map**, keep the security
log line, and require any real limiter to arrive with a test that proves it
throttles (ADR 0014).

- [ ] ADR 0013: delete the six dead `s3_security` keys and the unbounded map
- [ ] ADR 0013: refuse to start on a plain-HTTP backend when the active
      provider encrypts; warn for `none`
- [ ] ADR 0014: add `s3_security.max_presign_expiry_seconds` (default 3600 s,
      hard cap 7 days). Today the only ceiling is the AWS maximum of 7 days
      ([s3auth_presigned.go:25](internal/proxy/middleware/s3auth_presigned.go#L25))
- [ ] Meanwhile: set a memory limit on the pod, and do not rely on any
      `s3_security` key except `max_clock_skew_seconds` (and that one only for
      pre-signed URLs, section 6.3)

### H-8 The AES KEK fingerprint is a plain hash of the key — **closed**

**Closed by ADR 0004.** The fingerprint written to every object as
`s3ep-kek-fingerprint` is now `HKDF-Expand(master key, "s3ep-kek-fingerprint")`,
a derivation under a label of its own rather than `hex(SHA-256(key))`.

What it was: the published value was a hash of the master key itself. For a
256-bit key from `s3ep-keygen` that was harmless — inverting SHA-256 is not a
thing — but a **low-entropy or published key** could be confirmed offline by
anyone able to read one object, which turned the fingerprint into a verification
oracle for a dictionary attack.

Two changes close it together, and the second is the one that matters:

- The fingerprint is derived under its own label, so it is not a hash of the key
  and confirms nothing about it.
- A key that is not base64 of 32 bytes is refused at startup, and so is one that
  decodes to printable characters only or to fewer than 16 distinct byte values.
  A passphrase can no longer become an AES-256 key, so the dictionary the oracle
  would have been useful against no longer exists.

What remains, and is accepted: the fingerprint still **links deployments** — two
buckets carrying the same value provably share a master key. That is inherent to
selecting the right key by a value the backend can read.

---

## 9. Reporting a vulnerability

Report privately. Do not open a public GitHub issue and do not describe the
problem in a pull request.

- Open a **private security advisory** on
  <https://github.com/guided-traffic/s3-encryption-proxy/security/advisories/new>.
  This is the preferred route and reaches the maintainers without disclosing the
  issue.
- If that page is not available to you, open a GitHub issue that says only that
  you have a security report and asks for a private channel — **no details** —
  and wait for a maintainer to open one.

> **Gap, stated plainly:** the repository carries no dedicated security contact.
> [CONTRIBUTING.md](CONTRIBUTING.md) points at issues and discussions, both
> public ([CONTRIBUTING.md:155-157](CONTRIBUTING.md#L155)), and there is no
> `SECURITY.md` — the GitHub vulnerability-reporting file, which is a different
> document from this one. Nothing in the repository currently links to a
> `SECURITY.md`, so no link is broken; what is missing is the file itself, with a
> real address and a disclosure window. Until it lands, the advisory form above
> is the only private route, and it has not been exercised.

Please include: the version or commit, the configuration that reproduces it
(**with every key and credential redacted**), what you observed, and what you
expected. A proof of concept against the local demo stack
(`./start-demo.sh`) is the most useful form, because it can be replayed without
touching production data.

Anything on this page is already known — a report that adds a working exploit,
a wider consequence, or a case the analysis missed is still valuable. Anything
that is **not** on this page is what we most want to hear about.
