# Security Architecture

How the S3 Encryption Proxy defends the data it stores, what it deliberately
does not defend, and where the gaps are. This is the design document; it is not
the GitHub vulnerability-reporting policy (see [Reporting a vulnerability](#9-reporting-a-vulnerability)
at the end).

Every statement here was checked against the code on branch
`feat/major-v5`, after the storage format was replaced by the authenticated
segment chain and after the removal that deleted the replaced format's read path
and every configuration key no code reads. Where a claim could not be verified,
it says so. Where the code and an older document disagree, the code wins and the
disagreement is named.

**Related documents**

| Document | Contents |
|---|---|
| [README.md](README.md) | Install, configuration reference, provider setup, Velero notes |
| [`docs/developer/`](docs/developer/) | Contributor guide: package map, storage format, request paths, multipart, error conventions, test layers. A single `DEVELOPER.md` at the root **does not exist**; this directory is what replaced it |
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
   than no control**, because it gets relied upon. Section 6.5 exists because of
   this rule, and so do checklist items
   [H-7](#h-7-dead-security-configuration-knobs--closed), now closed by deleting
   every such control, and
   [H-10](#h-10-three-configuration-decisions-are-specified-and-not-built--closed),
   closed by building the three controls the decisions promised.
3. **The stored-object format may change without a migration path**
   ("no backward compatibility", [CLAUDE.md](CLAUDE.md)). It did: 5.0.0 stores
   the authenticated segment chain and there is no read path for what earlier
   releases wrote. An object written by 3.x or 4.0.x is **refused**, not read
   (ADR 0017). The precondition — that no deployment holds data which must stay
   readable across the change — was confirmed with the repository owner rather
   than assumed.

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
| **Operator** | Whoever writes the proxy configuration and holds the KEK material | Everything. The operator chooses the KEK and the backend | — |
| **S3 client** | Any S3 client: Velero and its kopia-based node agent, CNPG Barman, `aws` CLI, rclone, any AWS SDK | Reading and writing **any** key in **any** bucket the backend credential can reach, once its SigV4 signature verifies | Nothing finer-grained. There is no per-client bucket or prefix scoping (section 4) |
| **Proxy process** | `s3-encryption-proxy` | The KEK, every decrypted DEK in its cache, the data key of every upload in flight, the backend credential, and every plaintext in flight | — it is the single point of compromise (section 5.2) |
| **S3 backend** | MinIO, AWS S3, any S3-compatible endpoint | Storing and returning opaque bytes, best effort | Confidentiality, integrity, freshness, truthful listings, truthful metadata, truthful errors |
| **Client leg network** | Client to proxy; often pod to pod inside one cluster, but any host that reaches the listener | Nothing on its own. Optional proxy-side TLS (`tls.enabled`, [config.go:15-19](internal/config/config.go#L15)) protects it | — |
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
 │   │  CNPG Barman  │   or presign   │  - KEK (aes | exit)      │   │
 │   │  aws cli/sdk  │  <============ │  - random DEK per object │   │
 │   └───────────────┘   plaintext    │  - AES-256-GCM segments  │   │
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
   │                            provider types: aes | exit
   │  wraps
   ▼
  DEK  (Data Encryption Key)    256-bit, freshly generated per object from
   │                            crypto/rand, wrapped by the KEK, stored wrapped
   │                            in S3 metadata
   │  encrypts
   ▼
  object bytes                  64 KiB segments, each sealed on its own with
                                AES-256-GCM: a 12-byte nonce and a 16-byte tag
                                per segment, plus a 40-byte trailer. The same on
                                every write path — there is no second cipher and
                                no size threshold that chooses one
```

There is no third key layer. Integrity is not a value derived alongside the data
and stored next to it; it is the tag on every segment, produced by the same
operation that encrypts it.

What each seal is bound to is what makes the chain a chain. The additional data
of segment *i* is `s3ep-gcm-seg-v2 ‖ object key ‖ i`
([segmented_gcm.go:117-122](pkg/encryption/dataencryption/segmented_gcm.go#L117)),
so a segment cannot be moved to another position in its object, to another
object, duplicated or dropped without the read failing — and the trailer carries
the same binding with an index no segment can reach, plus the object's plaintext
length and a CRC32C over it, so truncation and extension fail too.

A fresh DEK per object comes from `crypto/rand`, drawn once for every write path
at [segmented.go:216-217](internal/orchestration/segmented.go#L216). No DEK is
ever reused across objects, and no nonce is ever reused under one DEK.

### 3.2 KEK providers

| `type` | KEK operation | Where the secret lives | Notes |
|---|---|---|---|
| `aes` | **AES-256-GCM** wrap of the DEK under a key derived per wrap: HKDF-SHA256 expands the master key with a fresh 16-byte salt, and the 76-byte value stored in `s3ep-encrypted-dek` is `salt ‖ nonce ‖ ciphertext ‖ tag` ([aes.go](pkg/encryption/keyencryption/aes.go)). A flipped bit anywhere in it, or a wrap made under another key, fails to unwrap with a named error before any body byte is read | `encryption.providers[].config.aes_key`, base64 of exactly 32 random bytes, in the config file or via `${ENV_VAR}` | The only key provider that encrypts. The fingerprint is `HKDF-Expand(master key, "s3ep-kek-fingerprint")`, not a hash of the key (ADR 0004, closes H-8) |
| `exit` | **No wrap at all.** The provider holds no key material and answers both `EncryptDEK` and `DecryptDEK` with an error ([exit.go:34-46](pkg/encryption/keyencryption/exit.go#L34)). Under it every write path stores the body as the client sent it, with no `s3ep-*` metadata: the single request ([operations.go:259-264](internal/proxy/handlers/object/operations.go#L259)), the proxy's own multipart producer ([operations.go:634](internal/proxy/handlers/object/operations.go#L634)) and a client-driven upload ([create.go:105-113](internal/proxy/handlers/multipart/create.go#L105), [upload.go:119-124](internal/proxy/handlers/multipart/upload.go#L119), [complete.go:166-187](internal/proxy/handlers/multipart/complete.go#L166)). A read decides **per object**: one carrying the current format's metadata is decrypted through the provider its own fingerprint names, anything else is served verbatim ([operations.go:62-74](internal/proxy/handlers/object/operations.go#L62), [range.go:166-182](internal/proxy/handlers/object/range.go#L166)) | — | The provider an operator selects to **leave the product**. Needs no license. New objects have no protection from the backend at all — that is the declared intent, not a defect |

There are two provider types and no third. `type: "tink"` is still **refused at
startup**, *tink encryption is not yet implemented with the new architecture*,
and there is no longer any Tink code behind that refusal: the stub that used to
mint a random in-memory keyset is gone from the tree. `type: "none"` is refused
by name as well, with a message naming `exit` and telling the operator to keep
the provider that holds the old key configured beside it. Both refusals are in
`validateProvider` ([config.go:568-582](internal/config/config.go#L568)), by
name rather than through the generic *unsupported encryption type* arm, so an
old configuration fails loudly. A key held in a KMS is a provider type of its own
and is decided, not built (ADR 0005).

### 3.2.1 What the exit provider means for this threat model

The provider and the reasoning behind it are
[ADR 0025](docs/adr/0025-leaving-is-a-supported-mode.md).

Selecting `exit` moves the plaintext below the boundary of section 2.2 on
purpose. Every object written from then on lies in the bucket exactly as the
client sent it, so the backend — and anyone who can read the bucket — has the
object itself, not ciphertext. **That is the operator's declared intent, not a
defect in the model.** It is how you leave the product: you stop encrypting,
your existing data stays readable, and you copy it out. The proxy states it in a
warning line at every start, and the license gate lets the configuration run
without a license precisely so that a lapsed license can never be the reason the
data cannot be read.

Three properties survive the switch, and they are what keeps it from being a
back door into the encrypted objects:

- **The read path is unchanged for an encrypted object.** An object carrying the
  current format's metadata is opened segment by segment as always, so a wrapped
  data key that fails its tag is refused with `InvalidObjectState`, HTTP 403, and
  a modified segment aborts the body. Nothing about `exit` softens that; it does
  not decide what happens to an encrypted object, only what happens to one the
  proxy never wrote.
- **The exit fingerprint is not a key.** `EncryptDEK` and `DecryptDEK` both
  return `ErrExitProviderKeyUse`, so a backend that stamps
  `s3ep-kek-fingerprint: exit-provider-fingerprint` onto an object of its own
  gets a failed read, not a data key. Its predecessor unwrapped by returning the
  stored bytes unchanged, which is a key of the backend's choosing: it could have
  sealed any plaintext it liked under that key and had every segment
  authenticate, producing a forgery a client cannot tell from a real object
  (ADR 0001, ADR 0003). That path no longer exists — the short-circuit in
  `DecryptDEK` is gone and the provider's own error is the enforcement
  ([providers.go:224-227](internal/orchestration/providers.go#L224)). The answer
  is `DecryptionError`, HTTP **500**, not the 403 an unreadable wrap gets: the
  error is not `ErrWrappedDEKAuth`, so it falls through to the generic arm
  ([operations.go:122-147](internal/proxy/handlers/object/operations.go#L122)).
  The key is never handed over either way; what the 5xx costs is a client SDK
  retrying a state that is permanent, which is the reason the other two answers
  are 4xx (ADR 0003 D10a).
- **The proxy's namespace is still the proxy's.** The pass-through write paths
  drop client-supplied `x-amz-meta-s3ep-*` headers exactly as the encrypting ones
  do ([helpers.go:159-171](internal/proxy/handlers/object/helpers.go#L159),
  [create.go:154-169](internal/proxy/handlers/multipart/create.go#L154)), so a
  client cannot label its own plaintext as an encrypted object through this proxy
  (ADR 0009).

What it does **not** protect, and what an operator has to plan for: an object
written under `exit` cannot be told from an object someone wrote straight into
the bucket, because neither carries proxy metadata. Under `exit` both are served.
Switching the active provider back to `aes` makes every object written during the
exit period foreign, and they are then refused on read — the switch out is a
one-way door for the objects written behind it.

### 3.3 Where each secret lives

| Secret | At rest | In memory | Ever sent to the backend? |
|---|---|---|---|
| KEK (`aes_key`) | Config file, or an environment variable referenced as `${VAR}` and expanded at load ([envexpand.go:17](internal/config/envexpand.go#L17), applied to every provider config value at [envexpand.go:75-88](internal/config/envexpand.go#L75)) | For the process lifetime | **Never** |
| DEK | Only KEK-wrapped, in `s3ep-encrypted-dek` | Plaintext while an object is being processed; also in an LRU DEK cache bounded at 1024 entries, keyed by fingerprint, object key and a hash of the wrapped DEK ([providers.go:205-262](internal/orchestration/providers.go#L205), [providers.go:339-386](internal/orchestration/providers.go#L339)) | **Never in plaintext** |
| DEK of a multipart upload in flight | — | In the session for that upload id, together with whatever short last part is buffered for it, until `Complete`, `Abort`, the expiry sweep, or process exit ([segmented_session.go:18-35](internal/orchestration/segmented_session.go#L18)) | **Never in plaintext** |
| Backend credential (`s3_backend.access_key_id` / `secret_key`) | Config or `${VAR}` | For the process lifetime | Yes, as SigV4 to the backend — that is its purpose |
| Client credentials (`s3_clients[].secret_key`) | Config or `${VAR}`, minimum 16 characters | In a lookup map built at startup ([s3auth_robust.go:74-79](internal/proxy/middleware/s3auth_robust.go#L74)) | **Never** |

An expansion failure is fatal at load: a `${VAR}` that is unset or empty makes
`expandEnvVars` return an error ([envexpand.go:30-32](internal/config/envexpand.go#L30)),
so a deployment that forgets the key does not silently fall back to anything.

The third row is the one that changed on this branch, and it was a leak. The
background sweep that expires abandoned multipart sessions was walking the old,
always-empty session map, while the map the live sessions are in had a sweeper
nothing called. An upload that was neither completed nor aborted therefore held
its data key and its buffered short part — up to
`optimizations.multipart_short_part_buffer_size` (`67108864` # default) per
session — for the life of the process. The sweep now walks the live map
([manager.go:98-124](internal/orchestration/manager.go#L98),
[segmented_session.go:127-140](internal/orchestration/segmented_session.go#L127)),
and `Manager.Shutdown` is reached from the proxy's own shutdown
([server.go:239-244](internal/proxy/server.go#L239)), so the goroutine stops
with the process rather than outliving it. Setting
`optimizations.multipart_session_cleanup_interval` to `0` disables the sweep and
restores the unbounded behaviour.

### 3.4 What is written into S3 object metadata

Exactly four keys, each carrying the configured prefix
(`encryption.metadata_key_prefix`, `s3ep-` # default,
[config.go:254](internal/config/config.go#L254)). The prefix is validated at
startup against `^[a-z0-9-]+$` (ADR 0009): an empty prefix made the writer store the
keys unprefixed while the read path still looked for `s3ep-` to decide whether an
object was one of its own, so every `GET` decided the object was unencrypted and
served the **ciphertext** behind a
200, and a prefix with a capital in it never matched on the way back, because S3
lower-cases metadata keys in transit while the comparisons here do not — which
disabled decryption and leaked these keys to the client. Both are refused
rather than normalised.

The namespace itself is no longer client-writable. A client sending
`x-amz-meta-s3ep-encrypted-dek` used to reach the same map the proxy writes
these keys into: `net/http` canonicalises the header name, so the key arrived as
`S3ep-Encrypted-Dek` and the case-sensitive filter never matched it. Both
spellings then went to the backend, which lowers one onto the other, and the
client value won often enough — four of ten uploads against a running proxy — to
leave the object permanently undecryptable. The filter compares
case-insensitively now, and the pass-through write path, which had no filter at
all, has one — so a client cannot label its own plaintext as an encrypted object
under the exit provider either. What remains open is only the answer: such a key is dropped
silently instead of being refused with `InvalidArgument`, which is what ADR 0009
specifies.

| Key | Contains | Consequence if the backend alters it |
|---|---|---|
| `s3ep-encrypted-dek` | base64 of the KEK-wrapped DEK, 76 bytes | The wrap fails its authentication tag: `InvalidObjectState`, HTTP 403, *Object key material failed authentication*. Permanent, and answered as a client error precisely so an SDK does not retry it (ADR 0003 D10a) |
| `s3ep-dek-algorithm` | always `s3ep-gcm-seg-v2`, the format id | Any other value makes the object foreign: `InvalidObjectState`, HTTP 403, *Object is not encrypted by this proxy* |
| `s3ep-kek-fingerprint` | `HKDF-Expand(master key, "s3ep-kek-fingerprint")` in hex, identifying which configured KEK wrapped this DEK | Provider lookup fails: `no provider found with fingerprint` |
| `s3ep-kek-algorithm` | KEK provider algorithm string | Informational on the read path |

All four are written by
[`BuildSegmentedMetadata`](internal/orchestration/metadata.go#L88) and describe
only **how the data key was wrapped**. Nothing about the data itself is in
metadata: nonces live in the segments they belong to, and the integrity value is
the tag on each of them, where the backend cannot edit it without the read
noticing. `s3ep-aes-iv` and `s3ep-hmac`, which earlier releases wrote, are gone
for that reason.

All four exist before the first backend byte is sent, on every write path, so no
completed object is ever rewritten to attach metadata.

**Never written to the backend:** the KEK, the unwrapped DEK, the
provider *alias* (it is a local configuration label only, never stored), and any
client credential.

**Filtered in both directions**, by one comparison used on both sides, so a
client never sees the proxy internals and never writes into them:
[`Handler.isEncryptionMetadata`](internal/proxy/handlers/object/helpers.go#L109)
drops every key inside the prefix, out of
[`cleanMetadata`](internal/proxy/handlers/object/helpers.go#L85) on `GET`, `HEAD`
and ranged responses and out of
[`userMetadataFromRequest`](internal/proxy/handlers/object/helpers.go#L159) on
every write. The multipart create path filters the same way against the same
prefix ([create.go:143-158](internal/proxy/handlers/multipart/create.go#L143)).
There is no filter left in `internal/orchestration/`; the two that lived there
had no production caller and are gone.

### 3.5 What the storage format guarantees

There is one format on every write path, so there is one answer, not a table of
them. It is stated precisely because most of section 8 rests on it.

| | Segment chain (`s3ep-gcm-seg-v2`) |
|---|---|
| Confidentiality | Yes. AES-256-GCM, one fresh nonce per segment under a DEK used for one object |
| Ciphertext authenticated | **Yes, segment by segment.** A modified byte fails the tag of the segment it lands in, before that segment is released |
| Bound to the object key | **Yes, in every segment.** The object key is part of each seal's additional data, so the backend cannot serve object A's bytes under key B |
| Bound to its position | **Yes.** The segment index is in the same additional data, so segments cannot be reordered, duplicated or dropped |
| Total length authenticated | **Yes.** The trailer seals the plaintext length, so truncation and extension are refused |
| Plaintext checksum | A CRC32C over the whole plaintext, sealed in the trailer, checked by the proxy on every whole-object read and served to the client as `x-amz-checksum-crc32c` on a whole-object `GET` and on `HEAD`. It is a detector for a fault in the proxy's own assembly of already-verified plaintext, and the client's end-to-end check on the read leg — not a second integrity value against a hostile backend, which the segment tags already are |
| A ranged read | Verified like any other read: it opens only the segments its window covers, each under its own tag |

**Where the failure surfaces matters as much as whether it is caught.** Two
shapes, and a client has to handle both:

- **Before the response begins.** Anything decided from metadata — a foreign
  format id, a missing marker, a wrap that fails its tag — is an S3 error
  document: `InvalidObjectState`, HTTP 403. Nothing is served.
- **After the response begins.** The proxy answers `200 OK` and its headers
  before it opens the first segment, so a fault found while streaming can only be
  reported by **aborting the body**. The client's HTTP stack surfaces that as an
  unexpected EOF on a body shorter than its `Content-Length`.

The second shape has two consequences worth stating plainly, because "a tampered
object is never delivered whole" is true and is not the whole story:

1. **A prefix of authentic plaintext is released before the fault is found** —
   up to *n−1* whole segments of it. Every released byte carried its own tag and
   is genuinely the object's, but the client holds a partial object.
2. **The abort is the only signal.** There is no status code to inspect, no error
   document and no trailer. A client that does not check the error from its read,
   or that treats `ErrUnexpectedEOF` as a transport flake and retries, accepts a
   truncated object as a complete one. The proxy cannot do better once a status
   line is out.
3. **What the tail-first read of ADR 0003 D14 narrowed, 2026-09-11.** A
   whole-object `GET` opens the object's trailer before it answers, so a damaged
   trailer, a truncation and an extension — the three that used to release 192 KiB
   before failing — are now `403 InvalidObjectState` with **nothing** written, and
   the `Content-Length` the client is given is the authenticated one. What remains
   in the shape above is a fault **inside a segment**, which no ordering can find
   ahead of time without reading the object twice; a bit flipped in the third
   segment of a four-segment object still releases 128 KiB first. A read under the
   exit provider stays a single forward pass and keeps the old shape for both
   (ADR 0025).

### 3.6 What the backend learns anyway

Even with everything above working, the backend still sees:

- **Key names**, in the clear. They carry structure: a Velero backup name, a
  namespace, a database identifier. Encrypting the directory segments of a key is
  decided and **not implemented** (ADR 0023).
- **Object sizes.** The stored length differs from the plaintext by 28 bytes per
  64 KiB segment plus a 40-byte trailer
  ([segmented_gcm.go:194-203](pkg/encryption/dataencryption/segmented_gcm.go#L194)).
  That is a pure function of the plaintext length, and the proxy inverts it
  itself to answer `HEAD`, so the backend can do the same arithmetic. Padding is
  not offered.
- **Timestamps, request order and access patterns**, including which objects a
  restore touches and in what sequence.
- **Which objects share a key.** `s3ep-kek-fingerprint` is the same value for
  every object wrapped under one master key, across buckets and across
  deployments (section 7.1).
- **How many parts an upload had**, from the part boundaries a multipart object
  keeps at rest.
- **The user metadata a client sends** (`x-amz-meta-*`) and, since the storage
  headers are forwarded, **the object tags it sets** (`x-amz-tagging`). Both sit
  in the clear next to the ciphertext. For a backup bucket that is a labelled
  index of what each object is — the accepted cost of treating storage
  attributes as the client's business (ADR 0007 D2, D12).
- **Whatever a forwarded access-control header grants.** `x-amz-acl: public-read`
  makes the ciphertext object, its size, its timing and its `s3ep-*` metadata
  readable by anyone the grant names. The proxy does not second-guess that: it is
  what the client ordered.

Two forwarded families are worth reading carefully, because each protects
against a different adversary than its name suggests:

- **`x-amz-server-side-encryption` asks the adversary to encrypt.** Under the
  rule in section 1.1 the backend reads every byte anyway, so its at-rest
  encryption is a control the adversary operates over its own copy. Only the
  proxy's envelope encryption protects the content, and the backend's response
  header is not a statement about it.
- **Object lock defends the credential, not the backend.** A compromised backend
  can ignore its own retention; a compromised *client credential* cannot, and
  that is the common ransomware path for a backup bucket. Forwarding
  `x-amz-object-lock-*` is worth it for the second adversary and worthless
  against the first.

The three SSE-C headers are the one request family the proxy refuses outright
(`501 NotImplemented`, naming the header): no read path carries the customer key,
so accepting one on upload would write an object nobody could ever read back
(ADR 0007 D6).

None of this is defended and none of it should be assumed hidden. A deployment
that cannot afford to leak key names is a deployment that needs ADR 0023 built
first.

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
  ([router.go:52-59](internal/proxy/router.go#L52)).
- **Metadata isolation, both ways.** The `s3ep-*` keys are stripped from every
  client response, and a client cannot write into that namespace: the same
  comparison drops them out of the user metadata on every write (section 3.4).

### 4.2 What it does NOT give you

- **No multi-tenancy.** `S3ClientCredentials` carries `type`, `access_key_id`,
  `secret_key` and `description` and nothing else
  ([config.go:57-62](internal/config/config.go#L57)). There is no bucket
  allowlist, no prefix scope, no per-client policy. **Every authenticated client
  can do everything any other authenticated client can do.** Two clients
  sharing one proxy — two Velero installations, or a Velero and a CNPG Barman
  deployment — share one blast radius.
- **No per-client keys.** The active provider is global
  (`encryption.encryption_method_alias`). All clients write objects under the
  same KEK, so a client that can read an object can always decrypt it.
- **No isolation from the backend credential.** The proxy holds one static
  credential pair for the backend ([server.go:92-95](internal/proxy/server.go#L92))
  and uses it for every request from every client. Whatever that credential can
  reach, any authenticated client can reach through the proxy.
- **No rate limit and no blocking**, by decision rather than by omission
  (ADR 0014). An authenticated client may issue as many requests as it likes, and
  an unauthenticated one is refused per request without anything being counted or
  remembered. Nothing in the proxy derives an identity from a client address any
  more: a security event logs `remote_addr` and the raw `X-Forwarded-For` as two
  separate fields and interprets neither
  ([s3auth_robust.go:403-418](internal/proxy/middleware/s3auth_robust.go#L403)).
  That closes the state an attacker used to control; it does not add a control.
  See [H-7](#h-7-dead-security-configuration-knobs--closed).

If tenant separation is required, run one proxy per tenant with its own KEK, its
own client credentials and its own backend credential.

---

## 5. Privilege footprint

### 5.1 What the proxy can do to the backend bucket

The proxy holds one static backend credential and needs it to be broad. The
operations it actually issues are:

<details>
<summary>Backend operations the proxy calls (from <code>S3BackendInterface</code>)</summary>

| Operation | Why the proxy needs it |
|---|---|
| `ListBuckets`, `CreateBucket`, `DeleteBucket` | Bucket CRUD proxied for the client. Note the destructive pair: a bug in sub-resource routing once made `DELETE /bucket?encryption` delete the bucket — fixed by the allowlist at [handler.go:104-127](internal/proxy/handlers/bucket/handler.go#L104) |
| `ListObjectsV2`, `ListObjects` | Listings, and `HEAD /bucket`, which is answered by a `ListObjectsV2` existence probe with `MaxKeys=0` rather than a real `HeadBucket` ([operations.go:184-202](internal/proxy/handlers/bucket/operations.go#L184)) |
| `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `DeleteObjects` | The object data path |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` | Both the client-driven multipart path and the internal multipart producer |
| `GetObjectTorrent` | Passed through verbatim ([operations.go:563-594](internal/proxy/handlers/object/operations.go#L563)) |
| Bucket sub-resources: ACL, CORS, policy, location, logging, versioning, tagging, notification, lifecycle, replication, website, accelerate, requestPayment | Passed through so S3 tooling works. Only the `GET` and `DELETE` arms reach the backend for accelerate, requestPayment, replication and website; their `PUT` arms answer `NotImplemented` |

The interface is 42 methods and **every one of them has a production caller**.
The 17 that had none — `CopyObject`, `ListParts`, `ListMultipartUploads`, the
object ACL, tagging, legal-hold and retention families, `SelectObjectContent`
and the four bucket `PUT` arms above — were declared for handler arms that
refuse, and are gone from the interface. That matters beyond tidiness: a declared
method is a capability the credential is expected to have, so an interface that
names operations no code issues overstates the privilege the deployment needs.

**Refused at the handler, and therefore on no interface:** `CopyObject` and
`UploadPartCopy` (`422 NotSupportedWithEncryption`), and `GetObjectAttributes`,
`ListMultipartUploads`, object ACL, object tagging, legal-hold, retention and
`SelectObjectContent` (`NotImplemented`) — see section 6.5. `HeadBucket` is
absent for a different reason: `HEAD /bucket` is answered by the `ListObjectsV2`
probe above, so the credential never needs the permission. `ListParts` is the one
exception in both directions: it neither calls the backend nor refuses, and
answers a fabricated empty success instead.

</details>

There is no least-privilege story to configure: the credential is one pair, used
for everything. The realistic hardening is on the backend side — scope the
backend credential to the single bucket the proxy serves.

### 5.2 What an attacker who takes the proxy gets

Everything.

- The **KEK**, in process memory, and therefore the ability to unwrap every DEK
  ever written under it — retroactively, for every object still in the bucket.
- The **DEK cache**, an LRU of up to 1024 already-unwrapped DEKs, plus the data
  key of every multipart upload currently in flight.
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

---

## 6. The validation story

### 6.1 Two authentication forms

`AuthenticateRequest` ([s3auth_robust.go:90](internal/proxy/middleware/s3auth_robust.go#L90))
accepts exactly what S3 accepts:

1. **Header form** — `Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...`.
2. **Pre-signed query form** — `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
   `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`
   ([s3auth_presigned.go:57](internal/proxy/middleware/s3auth_presigned.go#L57)).

Both forms are needed by real clients. Velero, for example, signs headers on its
data path and uses pre-signed URLs for its download path (`velero backup
download`, backup and restore logs).

### 6.2 What is verified on every S3 request

| Check | Where |
|---|---|
| `Authorization` header at most 8192 bytes | [s3auth_robust.go:41](internal/proxy/middleware/s3auth_robust.go#L41), checked at [:97](internal/proxy/middleware/s3auth_robust.go#L97) |
| Credential scope has 5 components, an 8-digit date, `service == "s3"`, `aws4_request` | [s3auth_robust.go:167-181](internal/proxy/middleware/s3auth_robust.go#L167) |
| Access key exists in `s3_clients` | [s3auth_robust.go:116-120](internal/proxy/middleware/s3auth_robust.go#L116) |
| Request timestamp within the clock-skew window, in both directions | [s3auth_robust.go:229-241](internal/proxy/middleware/s3auth_robust.go#L229) |
| Credential date matches the request date | [s3auth_robust.go:243-247](internal/proxy/middleware/s3auth_robust.go#L243) |
| Full SigV4 signature over method, canonical URI, canonical query, signed headers and payload hash, compared in constant time | [s3auth_robust.go:280](internal/proxy/middleware/s3auth_robust.go#L280) |
| Pre-signed only: `X-Amz-Expires` present, positive, at most 7 days; signing time not in the future beyond the skew; URL not expired | [s3auth_presigned.go:134-159](internal/proxy/middleware/s3auth_presigned.go#L134) |
| Bucket requests: every query parameter is on a known allowlist, otherwise `NotImplemented` | [handler.go:104-127](internal/proxy/handlers/bucket/handler.go#L104) |
| Object requests: the same allowlist one level down, so a sub-resource with no implementation cannot fall through to the base verb | [handler.go:103-180](internal/proxy/handlers/object/handler.go#L103) |
| A `PUT` delivers the plaintext length it declared. On the single-request path this is not an explicit check: the codec is given the length up front, so a body that ends early cannot fill the ciphertext the backend was promised and the upload fails with nothing stored. The multipart producer checks it outright, because a short body there would otherwise commit an object that verifies against its own trailer | [operations.go](internal/proxy/handlers/object/operations.go) `putObjectSegmented`, `putObjectAutoMultipart` |
| Every checksum a client declares matches the plaintext it sent, on every write path, with the verdict taken before anything is committed (section 6.4a) | [checksum.go](internal/proxy/request/checksum.go), [parser.go](internal/proxy/request/parser.go) |
| A body that stopped early never ends an object. Only a literal `io.EOF` counts as the end; the error a truncated aws-chunked stream raises is indistinguishable from the legitimate short last read through `io.ReadFull`, and treating them alike committed a silently short object that verified against its own trailer | [operations.go](internal/proxy/handlers/object/operations.go) `fillPart` |
| `DeleteObjects` carries a body digest at all, and it matches the document, checked before the document is parsed | [operations.go](internal/proxy/handlers/object/operations.go) `handleDeleteObjects` |

**The canonical request is built the way the signer builds it.** A header value
has its leading and trailing spaces removed and every run of spaces inside it
collapsed to one, matching `aws-sdk-go-v2`'s own canonicalisation byte for byte —
including what that does not do: only the space character is collapsed, never a
tab, and a quoted string is not exempt. The proxy used to trim only, so a
correctly signed request whose header carried repeated spaces was answered
`SignatureDoesNotMatch` while the backend accepted the identical request.
`Content-Disposition` with a filename is where that showed up, because filenames
contain spaces and that header is what a pre-signed download URL carries. The
failure was a false negative, never a false positive: no request was ever
accepted that should have been refused.

Authentication failures return a **fixed message per error code**. The raw error
text carries the attempted access key, signed header names and clock offsets;
reflecting it echoed attacker-controlled text into the response body and broke
the XML whenever a key contained `&` or `<`. It is now logged and not echoed
([middleware_setup.go:88-110](internal/proxy/middleware_setup.go#L88)).

### 6.3 The clock-skew window

**One window, `s3_security.max_clock_skew_seconds`, 900 seconds by default, and
it governs both authentication forms.** Every shipped configuration sets 300.

This used to be half true. The header form compared against a compile-time
constant and ignored the configured value, so an operator who narrowed the window
narrowed only the pre-signed path — the one most requests do *not* take. Closed
2026-09-11 ([H-10](#h-10-three-configuration-decisions-are-specified-and-not-built--closed)).

`0` is refused at startup rather than read as the default. It is the value an
operator would reach for to mean "no tolerance", and it used to widen the window
to the 900-second maximum instead. There is no value that disables the check.

The window is a replay window, and the proxy keeps no nonce cache: a captured
request can be replayed inside it. Narrowing it narrows the exposure and costs
tolerance for client clock drift; 900 is AWS's own figure, which is why it is the
default rather than something tighter.

### 6.4 What is NOT verified

- **The request payload.** A missing `X-Amz-Content-Sha256` on a non-empty body
  becomes `UNSIGNED-PAYLOAD` rather than a rejection
  ([s3auth_robust.go:306-315](internal/proxy/middleware/s3auth_robust.go#L306)),
  and the pre-signed form defaults to `UNSIGNED-PAYLOAD` as well
  ([s3auth_presigned.go:182-186](internal/proxy/middleware/s3auth_presigned.go#L182)).
  The signature therefore authenticates the request line and headers, not the
  bytes.
- **Per-chunk signatures in aws-chunked uploads.** See
  [H-2](#h-2-per-chunk-signatures-are-never-verified).
- **Client checksums: verified since 2026-09-11, and this is the one control on
  the client leg.** See [6.4a](#64a-the-client-leg-what-the-upload-checksum-does-and-does-not-buy)
  below for what it does and does not buy.
- **Replay within the window.** There is no nonce store. A captured signed
  request can be replayed until its timestamp ages out of the 15-minute window.
- **Anything on `/health` and `/version`.** Both are registered on a subrouter
  that carries no middleware, before the S3 subrouter that carries the auth
  middleware ([router.go:47-59](internal/proxy/router.go#L47)), and are
  unauthenticated by design.
- **Anything on the monitoring listener.** `monitoring.bind_address`
  (`:9090` # default) serves `/metrics`, `/health` and `/info` with **no
  authentication at all** ([monitoring/server.go:32-44](internal/monitoring/server.go#L32)).
  Bind it to a private interface or fence it with a network policy; never expose
  it publicly. Seven metrics are declared, down from twenty after the thirteen
  nothing ever observed were removed
  ([monitoring/metrics.go:44-100](internal/monitoring/metrics.go#L44)), and none
  of them carries a bucket name, an object key or a provider identity — the
  request labels are the gorilla/mux path *template*, not the request path
  ([middleware.go:79-86](internal/monitoring/middleware.go#L79)). So the listener
  discloses little; it is still unauthenticated, and it is still the process that
  holds the KEK.
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

### 6.4a The client leg: what the upload checksum does and does not buy

Everything the proxy stores is defended by its own key layer and by the segment
chain's own tags. Nothing defends the **client-to-proxy leg**, and that leg is
the last place where the plaintext exists. A byte corrupted before the proxy
encrypts it is encrypted faithfully, authenticated faithfully, and from then on
indistinguishable from correct data: every integrity mechanism this product has
confirms the corruption. The checksum the client already computed is the only
check that can catch that, and it is the only one the proxy runs on that leg.

**What is checked.** Every checksum a client declares, against the decoded
plaintext payload, on every write path — `Content-MD5`, `x-amz-checksum-crc32`,
`-crc32c`, `-crc64nvme`, `-sha1`, `-sha256`, `-sha512` and `-md5`, as a request
header or as an aws-chunked trailer ([checksum.go](internal/proxy/request/checksum.go), wired
into both body readers at [parser.go](internal/proxy/request/parser.go)). A
mismatch is `400 BadDigest`, a value that is not a digest of its algorithm's
length is `400 InvalidDigest`, and a trailer named in `X-Amz-Trailer` that never
arrives is a failed verification rather than an absent one. `DeleteObjects`
requires a digest and verifies it before the document is parsed.

**The verdict precedes the commit.** The verifying reader holds the final payload
byte back until it has a verdict, so a consumer streaming the body straight to
the backend can never have delivered the complete payload while verification is
still open. On the internal multipart path the verdict is taken before
`CompleteMultipartUpload` and the upload is aborted on failure. A refused upload
leaves no object and no dangling multipart upload.

**A cyclic redundancy check is a transmission-corruption check, not an integrity
guarantee.** CRC-32 is 32 bits and trivially forgeable. It catches a byte damaged
in transit, which is what it is for; it does not detect a deliberate modification
by anyone positioned on the client leg, and nothing here claims it does. The
adversary on that leg is outside this threat model
([ADR 0014](docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md)); the
mitigation for it is TLS on the client leg (`tls.enabled`), not the checksum.

**What is still not checked on that leg.** The per-chunk signatures of an
aws-chunked upload ([H-2](#h-2-per-chunk-signatures-are-never-verified)), and a
client that declares no checksum at all — the proxy cannot invent one, and the
lever is the client's configuration. The AWS SDKs send CRC-32 by default.

**The header family is claimed as a whole.** Anything under `x-amz-checksum-`
that is not an implemented algorithm, and is not one of the three that carry no
digest (`-algorithm`, `-mode`, `-type`), answers `501 NotImplemented`. That
covers the `xxhash` family the pinned SDK can send and no standard-library hash
can compute. The point is that a checksum can never be accepted behind a `200`
without being checked, including one S3 adds later.

**One exception, and it is not a gap in the check.** On
`CompleteMultipartUpload` the header is the digest of the *completed object*,
not of the completion document, so it is not compared against that document. The
proxy can neither verify it — the plaintext object it would have to hash is gone
by then — nor forward it, because the backend holds ciphertext. It is dropped,
and serving the proxy's own value instead is ADR 0012 D10, which is not built.

**Nothing is forwarded and nothing is stored.** The value describes the plaintext
while the body the proxy uploads is ciphertext, so it is meaningless to the
backend; and a plaintext checksum in cleartext beside the ciphertext would hand a
hostile backend a confirmation oracle — for a small or low-entropy object it
could guess a candidate plaintext offline and confirm it against a few bytes of
checksum. This is the same reason the format's own CRC32C lives sealed inside the
trailer rather than in metadata.

**No configuration can switch the check off.** aws-chunked decoding used to be a
configuration key, and setting it to false made the proxy store chunk framing as
object content and left a declared checksum unverifiable, because what it saw was
the framing rather than the payload. The key is gone: the framing is always
stripped, so a checksum always covers the payload, and there is no value an
operator can set that turns the check into accept-and-discard.

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
  an XML document was expected ([handler.go:120-125](internal/proxy/handlers/object/handler.go#L120)).
- `UploadPartCopy` answers `422 NotSupportedWithEncryption`
  ([copy.go:35-44](internal/proxy/handlers/multipart/copy.go#L35),
  [errors.go:108-118](internal/proxy/response/errors.go#L108)) — a server-side
  copy cannot be re-encrypted at the proxy. It was previously **unreachable**
  (the route was shadowed and its header matcher compared the literal string
  `{source}`), so such a request silently stored a 0-byte part; the route now
  matches and the honest error is returned
  ([router.go:90-93](internal/proxy/router.go#L90)).
- Client-issued `CopyObject` (`PUT` with `x-amz-copy-source`) answers the same
  `422 NotSupportedWithEncryption`
  ([operations.go:199-215](internal/proxy/handlers/object/operations.go#L199)).
  A server-side copy would move ciphertext without re-encrypting it, so the
  proxy neither performs one nor keeps the ability to: `CopyObject` is no longer
  on the backend interface at all (section 5.1).
- `GET /bucket/key?legal-hold`, `?retention`, object ACL and object tagging, and
  `ListMultipartUploads`, all `NotImplemented`.
- Any bucket sub-resource without a route. Previously such a request fell through
  to the base operation for its HTTP method, which is how
  `DELETE /bucket?encryption` deleted the bucket
  ([handler.go:104-127](internal/proxy/handlers/bucket/handler.go#L104)).

**One handler still pretends.** `ListParts` answers `200` with a fabricated,
always-empty `ListPartsResult` and never asks the backend
([list.go:63-71](internal/proxy/handlers/multipart/list.go#L63)). Under rule 2
that is the failure mode this section is about, and it is not fixed: a client
cannot use `ListParts` to discover what a multipart upload actually holds, which
is why the tests that pin this behaviour check the backend directly. The fix is
ADR 0011: `ListParts` is answered from the proxy's own part table — and that
table now exists, on the session
([segmented_session.go:211-227](internal/orchestration/segmented_session.go#L211),
[:341-350](internal/orchestration/segmented_session.go#L341)). The handler
does not read it.

### 6.6 Transport

| Leg | Control | Reality |
|---|---|---|
| Client to proxy | `tls.enabled`, `tls.cert_file`, `tls.key_file` ([config.go:15-19](internal/config/config.go#L15)) | Works. The integration suite runs against both the HTTP and the TLS endpoint |
| Proxy to backend | `s3_backend.target_endpoint`, `s3_backend.insecure_skip_verify` | **The scheme in `target_endpoint` decides.** Those two are the only backend values that reach the SDK options ([server.go:145-171](internal/proxy/server.go#L145)). `s3_backend.use_tls` is gone: it was read only to assign itself, and a key that describes a transport it does not select is exactly what rule 2 refuses ([H-7](#h-7-dead-security-configuration-knobs--closed)) |

`insecure_skip_verify: true` disables backend certificate verification and logs a
warning. Under this threat model that is a smaller loss than it looks — the
backend is the adversary regardless — but it also removes the only defence
against an *additional* attacker on that leg. Do not use it outside development.

A `target_endpoint` of `http://` under a provider that encrypts refuses the start
(closed 2026-09-11, [H-10](#h-10-three-configuration-decisions-are-specified-and-not-built--closed)).
The object bytes would be sealed either way, but the backend credential travels
in a SigV4 header over plaintext and a listener on that leg learns every key name
and every object size. **Under the `exit` provider plain HTTP is still allowed**,
because there is no unseekable ciphertext stream to fail on — and there the
object bytes travel in the clear as well. Nothing warns about that yet.

---

## 7. Rotation and change propagation

### 7.1 KEK rotation, by fingerprint

Rotation is the one thing the metadata design is built for.

1. Add the new provider to `encryption.providers` and leave the old one in place.
2. Point `encryption.encryption_method_alias` at the new alias.
3. Restart the proxy.

From then on, every write uses the new KEK, and every read picks the provider
whose fingerprint matches `s3ep-kek-fingerprint` on the object
([segmented.go:243-266](internal/orchestration/segmented.go#L243),
[providers.go:205-262](internal/orchestration/providers.go#L205)). Objects
written under the old KEK stay readable for exactly as long as the old provider
stays configured. Removing it makes them permanently unreadable — there is no
re-encryption job; re-writing objects through the proxy is the migration.

**Fingerprints are derived, not configured**, so they cannot drift: for `aes` the
fingerprint is `HKDF-Expand(master key, "s3ep-kek-fingerprint")` — a derivation
under a label of its own, so publishing it in object metadata says nothing about
the key and nothing about the key used to wrap any DEK — and for `exit` it is the
constant `exit-provider-fingerprint`, which no object ever carries, because that
provider writes plaintext and plaintext carries no metadata. Meeting it in an
object's metadata therefore means the backend put it there, and the read is
refused rather than served (section 3.2.1).

`aes` has no `RotateKEK` call and neither has any other provider: the
`KeyEncryptor` interface is `EncryptDEK`, `DecryptDEK`, `Name`, `Fingerprint` and
nothing else ([interfaces.go:7-23](pkg/encryption/interfaces.go#L7)). Rotation is
the configuration procedure above, not an API call.

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
provider alias, the key material. An operator who rotates a
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
([validator.go:167-220](internal/license/validator.go#L167),
[validator.go:230-240](internal/license/validator.go#L230)), so an expired
license stops the proxy where it stands and every read stops with it.

**Reading the data back does not need a license.** The gate looks at the active
provider only, and `type: "exit"` is the one type it admits without one
([validator.go:152-165](internal/license/validator.go#L152),
[config.go:460-475](internal/config/config.go#L460)). Point
`encryption.encryption_method_alias` at an exit provider, leave the `aes`
provider listed beside it, and the proxy starts unlicensed and decrypts
everything written under that key — new writes are stored as the client sends
them from then on (ADR 0016, and section 3.2.1). The security consequence to
name is the one that follows from *not* doing this: an operator who does not know
about the exit provider sees a proxy that will not start and data they cannot
read, which is the situation that makes people copy ciphertext out of the bucket
and hunt for the key by hand.

---

## 8. Residual risks — hardening checklist

Open items first, ordered by how much they matter under this threat model, then
the closed ones — six of them, closed by the segment chain, the derived
fingerprint, the exit provider, and the removal that deleted the replaced
format's read path and every configuration key no code reads. Each item states
what is true today, what closes it, and what an operator can do in the meantime. Closed items are kept
rather than deleted: what a defect was is how you tell whether it came back, and
several of them are the reason a rule elsewhere in this document reads the way it
does. The numbers are identifiers and do not change when an item moves or
closes.

### H-2 Per-chunk signatures are never verified

**ADR 0014. Accepted.**

In an `aws-chunked` upload the seed signature in the `Authorization` header is
verified; the `chunk-signature` on each chunk is not. The decoder reads the
chunk sizes, yields the payload bytes and discards the signatures and any
trailer without looking at them
([streaming_aws_decoder.go:18-27](internal/proxy/request/streaming_aws_decoder.go#L18)).

**Why this is judged acceptable:** the chunk signatures protect the **client
leg**, and the adversary in this model is on the **other** leg. The client leg
is operator-controlled (section 2.2) and normally runs over TLS. The seed signature never covered the
body in any case, `UNSIGNED-PAYLOAD` is already accepted (section 6.4), and the
AWS SDK chooses the unsigned-trailer framing over TLS precisely because transport
integrity comes from TLS. The residual exposure is a client that signs chunks
over plain HTTP and expects the proxy to catch a man in the middle.

Verifying the chain is a real implementation with real CPU cost, and the client
checksum verification of ADR 0012 buys most of the same benefit for much less —
it shipped on 2026-09-11 (section 6.4a). It is not a substitute for TLS: a
cyclic redundancy check catches corruption, not a deliberate modification by
someone positioned on that leg.

- [ ] Enable TLS on the client leg (`tls.enabled`) — this is the mitigation
- [x] Verify client upload checksums against the plaintext (ADR 0012) — done
      2026-09-11; a corruption check, not a defence against an active attacker

---

### H-3 Rollback and object substitution are not prevented

**Structural.**

No authenticated format prevents a backend from serving an **older version of
the same key**: the old segments, the old trailer and the old metadata are all
internally consistent, because the proxy sealed them itself. The same holds for serving nothing, or
for a listing that omits an object.

What the segment chain does prevent, and did not before: every segment is sealed
against **the object key and its own index**, so bytes cannot be moved to another
key, reordered within their object, duplicated or dropped, and the trailer's
sealed length refuses truncation and extension. Substitution across keys is
closed; substitution across *time* is not.

**Against a rollback, the only defence is the client.** Velero and kopia, for
example, run their own consistency checks over their own manifests; a rolled-back
or missing blob shows up there. A client without such checks has no defence at
all, because a genuine earlier version of the same key is a correctly sealed
object that the proxy itself wrote.

- [ ] Enable object versioning and, where available, object lock on the backend
      bucket, so a rollback needs a privilege the backend credential does not have
- [ ] Rely on the client's own consistency checks where it has them (Velero and
      kopia do); treat their failures as integrity alerts, not as flakes

---

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

That leaves the proxy as the only protection for both. The proxy does hold up
its end now — kopia's ranged reads are verified segment by segment
([H-1](#h-1-ranged-reads-are-not-verified-by-the-proxy--closed)) — but a second
layer that is decoration is still worth fixing: a strong repository password
makes kopia's own encryption real rather than a published default.

- [ ] **Create `velero-repo-credentials` with a strong random value BEFORE the
      first backup.** Changing it later does not re-key an existing repository

---

### H-10 Three configuration decisions are specified and not built — closed

**ADR 0013, ADR 0014. Closed 2026-09-11.**

All three landed. Recorded rather than deleted, because each changes what an
operator's existing configuration does:

| Decision | Now |
|---|---|
| `s3_security.max_clock_skew_seconds` governs both authentication forms (ADR 0013 D3, ADR 0014 D4) | It does. A configuration that narrows the window narrows it for every request, so **a client whose clock is off by more than the configured value starts being refused where it was accepted** — the one change in this family that can break a healthy deployment (section 6.3) |
| `s3_security.max_presign_expiry_seconds`, default 3600 s, hard cap 7 days (ADR 0013 D6, ADR 0014 D5) | The key exists. A pre-signed URL may declare at most one hour by default, and the S3 maximum of seven days is the ceiling the setting may not exceed. A client that mints longer URLs needs it raised |
| The proxy refuses to start on a plain-`http://` backend endpoint under an encrypting provider, and warns for the exit provider (ADR 0013 D5) | The refusal is in configuration validation, so it fires before a listener or an S3 client exists. A scheme-less endpoint is refused with it. **The warning under the `exit` provider is still outstanding** |

- [x] ADR 0013 D3: honour `max_clock_skew_seconds` on the header-signed path
- [x] ADR 0013 D6: add `s3_security.max_presign_expiry_seconds`
- [x] ADR 0013 D5: refuse to start on a plain-HTTP backend under an encrypting
      provider
- [ ] ADR 0013 D5, the warning half: warn under `exit`, where credentials, bucket
      names and object keys travel in the clear to the backend
- [x] Meanwhile: terminate TLS on the backend endpoint — now enforced under an
      encrypting provider rather than advised

---

### H-11 The pass-through provider was not a pass-through above one part — **closed**

**Closed by the exit provider.** All three write paths now pass through, and the
read paths decide per object instead of on the active provider: the single
request ([operations.go:259-264](internal/proxy/handlers/object/operations.go#L259)),
the proxy's own multipart producer
([operations.go:634](internal/proxy/handlers/object/operations.go#L634)) and a
client-driven upload
([create.go:105-113](internal/proxy/handlers/multipart/create.go#L105),
[upload.go:119-124](internal/proxy/handlers/multipart/upload.go#L119),
[complete.go:166-187](internal/proxy/handlers/multipart/complete.go#L166)); `GET`
([operations.go:62-74](internal/proxy/handlers/object/operations.go#L62)), a
ranged `GET` ([range.go:166-182](internal/proxy/handlers/object/range.go#L166))
and `HEAD` ([operations.go:347-351](internal/proxy/handlers/object/operations.go#L347))
each read the object's own metadata.

What it was: `type: "none"` passed through only a `PUT` that fitted one backend
request. A larger or undeclared `PUT`, and any client-driven multipart upload,
sealed the object as a segment chain and stored its data key **unwrapped** in
`s3ep-encrypted-dek`, because `EncryptDEK` returned the key unchanged for that
provider. The read path then decided on the provider before it looked at the
object and handed the sealed bytes back, while `HEAD` reported the plaintext
size — the two disagreed about the same object, and a large object written that
way was not readable through the proxy at all. The key also sat next to the data,
unwrapped, on an object the metadata described as encrypted.

Both halves of that are gone: nothing is sealed under `exit`, so no data key is
drawn to leave lying about, and `EncryptDEK` no longer returns a key at all — it
returns an error, on the reasoning in section 3.2.1.

- [ ] Under `exit` an object written before the switch and an object written
      after it are told apart by metadata alone. An operator who switches back to
      an encrypting provider makes everything written during the exit period
      foreign, and it is refused on read — plan the direction of travel before
      the switch

---

### H-1 Ranged reads are not verified by the proxy — **closed**

**Closed by ADR 0003.** A ranged read opens only the segments its window covers,
each under its own tag, so a partial read is authenticated exactly like a whole
one. Measured against a running stack: a range over a tampered segment delivers
nothing and the body is aborted
([segment_tamper_test.go](test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: the integrity value covered the whole object, so it could not be
checked against part of it. A ranged read was therefore authenticated by the
backend and by TLS — that is, by the adversary — and kopia, which is how Velero
stores volume data, reads its pack blobs exactly that way. Entire restores ran on
reads the proxy did not verify.

**What a ranged read still does not tell you**, and this is inherent to any
per-segment format rather than a defect to close:

- It authenticates only the segments in its window. Damage elsewhere in the
  object is invisible to it, and a client that only ever reads ranges never
  checks the object as a whole. Pinned by a test so that nobody "fixes" it by
  reading more than was asked for.
- A range that does not reach the end of the object never sees the trailer, so it
  cannot check the object's authenticated total length; for the object's size it
  trusts what the backend reports.

- [ ] A client that needs whole-object assurance must read the object whole; a
      ranged read is not a cheap substitute for that

---

### H-5 A tampered object is delivered, not refused — **closed**

**Closed by ADR 0003.** A modified object is never delivered whole. Measured
against a running stack across six attacks — a flipped bit in the first, a
middle and the last segment, two segments swapped, a truncation and an extension
— each one aborts the body, and the prefix the client did receive is
byte-identical to the object's own opening plaintext
([segment_tamper_test.go](test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: the integrity value was verified after the last plaintext byte had
already been written to the client, and it was not verified at all when the
backend answered without a `Content-Length` — a header the backend chooses. No
setting refused tampered data; `strict` was `lax` with a different log line.

**The knob that appeared to control it is gone**, and that is the second half of
this item. `encryption.integrity_verification` and the four modes it selected —
`off`, `lax`, `strict`, `hybrid` — no longer exist: not in
`internal/config/config.go`, not in any shipped example, not in the chart values.
Verified by grep over the tree. Nothing in the product now offers a choice about
integrity, because there is no longer a choice to offer: the tag on each segment
is produced by the same operation that encrypts it, so a build that skipped
verification could not decrypt either.

**What replaces the knob is not a setting.** Integrity is a property of the
format, so there is nothing to enable and nothing to get wrong — and, more to the
point, nothing an operator can switch *off* by misreading a configuration
reference. What an operator does need to know is *where* the refusal surfaces —
before the response for anything decided from metadata, as an aborted body once
streaming has begun — and what that costs a client. Section 3.5 states both.

---

### H-6 An object without encryption metadata is served as plaintext — **closed**

**Closed by ADR 0003.** Under an encrypting provider, an object carrying no
proxy metadata — or naming a format this proxy does not read — is refused with
`InvalidObjectState`, HTTP 403, on `GET`, `HEAD` and ranged `GET` alike. The
exit provider serves an object that carries no proxy metadata verbatim, which is
what it is for, and still refuses one whose key material does not authenticate
(section 3.2.1).
Measured: stripping the format marker, and stripping every proxy key, both
answer 403
([segment_tamper_test.go](test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: such an object was served to the client unchanged, whatever the
active provider. Anyone able to write to the backend bucket could substitute an
object by stripping four metadata keys off it, and the proxy would hand the
substituted bytes over as if it had written them.

**The consequence an operator has to plan for** is that a refusal is permanent
and has no repair path in the product. The object is not readable through this
proxy again; it is restored from its source. The 403 is the notification.

---

### H-7 Dead security configuration knobs — **closed**

**Closed by ADR 0013 and ADR 0014.** `s3_security` now carries
`max_clock_skew_seconds` and nothing else
([config.go:65-69](internal/config/config.go#L65)), and the machinery behind the
deleted keys is gone with them. Verified by grep over the tree: the six key names
appear in no Go file, in no `config/*.yaml`, and in no chart values file.

What it was: six keys under `s3_security` — `enable_rate_limiting`,
`max_requests_per_minute`, `max_failed_attempts`, `unblock_ip_seconds`,
`strict_signature_validation` and `enable_security_logging` — were parsed,
defaulted, range-checked and documented, and read by nothing. No rate limiter, no
block list and no unblock timer existed anywhere in the product. Alongside them,
`s3_backend.use_tls` was read only to assign itself while the scheme of
`target_endpoint` decided the transport, `encryption.integrity_verification`
offered a choice between integrity settings that the format decides, and
`optimizations.streaming_threshold` claimed to choose a cipher that no longer
exists.

**The one piece of machinery that looked like an implementation was worse than
the absence it hid.** It counted authentication failures per client, keyed that
count on the first `X-Forwarded-For` value — an attacker-chosen string — compared
it against a hardcoded `5` rather than the configured value, only ever wrote a
log line, and never expired an entry. Unauthenticated requests therefore grew
proxy memory without bound, under a name that read like brute-force protection.
It is deleted: the type, the map, the accessors, the threshold, the
`getClientIP` helper that produced the attacker-controlled key, and the
`client_ip` and `failed_count` log fields. A security event now logs
`remote_addr` and the raw `X-Forwarded-For` as two separate fields and interprets
neither
([s3auth_robust.go:403-418](internal/proxy/middleware/s3auth_robust.go#L403)).

**Per-IP rate limiting was also the wrong tool**, which is why nothing replaced
it: a legitimate client is one authenticated identity that may issue thousands of
requests from one address — Velero bursts from a single pod IP, and anything
behind a NAT looks the same. The controls that do the work here are
authentication and resource limits. Any real limiter arrives with a test that
proves it throttles (ADR 0014).

What this closes is a lie in the configuration, not a hole in the product: there
was never protection where those keys said there was. **The gain is that an
operator can no longer believe otherwise** — and, in the failure-counting case,
that an unauthenticated caller can no longer make the process allocate.

Three decisions taken with this one landed on 2026-09-11; they are
[H-10](#h-10-three-configuration-decisions-are-specified-and-not-built--closed).

---

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

### H-9 The replaced format's decrypt path is still in the tree — **closed**

**Closed by ADR 0013, by analogy.** The old whole-object GCM and streaming CTR
readers, the HMAC verifier, the CTR multipart session, the envelope layer and the
whole of `internal/validation/` are deleted; what is left in
`pkg/encryption/dataencryption/` is the segment codec and its readers, and
nothing else. Verified on this tree: `deadcode ./cmd/s3-encryption-proxy`
(`golang.org/x/tools/cmd/deadcode`) reports **zero** unreachable functions, where
it reported 206 before.

What it was: nothing reached that code, but all of it compiled.
`Manager.DecryptDataWithMetadata`, the entry point to the algorithm switch that
chose between the old readers, had no production caller — only tests. Rule 2 of
this document says a control that exists only in configuration or in
documentation is worse than no control; the mirror case is an **unauthenticated
decrypt path that exists only in dead code**. It was not a vulnerability, because
no request could reach it, and it would have become one the moment somebody wired
a caller to it — easy to do by accident, because the function names read like the
live ones.

**What it also removed is the last thing that could read an object written by
3.x or 4.0.x.** That is deliberate and is the point of ADR 0017: such an object
is refused, not read (section 1.2, rule 3).

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
> public ([CONTRIBUTING.md:163-167](CONTRIBUTING.md#L163)), and there is no
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
