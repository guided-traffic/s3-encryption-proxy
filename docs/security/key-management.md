# Key management: hierarchy, providers, custody, rotation

The two key layers, the two providers that can hold the upper one, where every
secret lives while the process runs, and how a key is replaced without losing
the objects written under the old one. What the keys protect the *objects*
against is [stored objects](stored-objects.md); the adversary they protect
against is [the threat model](threat-model.md).

## Key hierarchy

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
([segmented_gcm.go:117-122](../../pkg/encryption/dataencryption/segmented_gcm.go#L117)),
so a segment cannot be moved to another position in its object, to another
object, duplicated or dropped without the read failing — and the trailer carries
the same binding with an index no segment can reach, plus the object's plaintext
length and a CRC32C over it, so truncation and extension fail too.

A fresh DEK per object comes from `crypto/rand`, drawn once for every write path
at [segmented.go:306-309](../../internal/orchestration/segmented.go#L306). No DEK is
ever reused across objects, and no nonce is ever reused under one DEK.

## KEK providers

| `type` | KEK operation | Where the secret lives | Notes |
|---|---|---|---|
| `aes` | **AES-256-GCM** wrap of the DEK under a key derived per wrap: HKDF-SHA256 expands the pseudorandom key extracted from the master key with a fresh 16-byte salt, and the 76-byte value stored in `s3ep-encrypted-dek` is `salt ‖ nonce ‖ ciphertext ‖ tag` ([aes.go](../../pkg/encryption/keyencryption/aes.go)). A flipped bit anywhere in it, or a wrap made under another key, fails to unwrap with a named error before any body byte is read | `encryption.providers[].config.aes_key`, base64 of exactly 32 random bytes, in the config file or via `${ENV_VAR}` | The only key provider that encrypts. The fingerprint is `hex(HKDF-Expand(HKDF-Extract(master key), "s3ep-kek-fingerprint"))`, not a hash of the key (ADR 0004; *Why the fingerprint is derived rather than hashed* below) |
| `exit` | **No wrap at all.** The provider holds no key material and answers both `EncryptDEK` and `DecryptDEK` with an error ([exit.go:34-46](../../pkg/encryption/keyencryption/exit.go#L34)). Under it every write path stores the body as the client sent it, with no `s3ep-*` metadata: the single request ([operations.go:437-442](../../internal/proxy/handlers/object/operations.go#L437)), the proxy's own multipart producer ([operations.go:875](../../internal/proxy/handlers/object/operations.go#L875)) and a client-driven upload ([create.go:89-93](../../internal/proxy/handlers/multipart/create.go#L89), [upload.go:109-118](../../internal/proxy/handlers/multipart/upload.go#L109), [complete.go:178-195](../../internal/proxy/handlers/multipart/complete.go#L178)). A read decides **per object**: one carrying the current format's metadata is decrypted through the provider its own fingerprint names, anything else is served verbatim ([operations.go:52-56](../../internal/proxy/handlers/object/operations.go#L52), [range.go:167-183](../../internal/proxy/handlers/object/range.go#L167)) | — | The provider an operator selects to **leave the product**. Needs no license. New objects have no protection from the backend at all — that is the declared intent, not a defect |

There are two provider types and no third. `type: "tink"` is still **refused at
startup**, *tink encryption is not yet implemented with the new architecture*,
and there is no longer any Tink code behind that refusal: the stub that used to
mint a random in-memory keyset is gone from the tree. `type: "none"` is refused
by name as well, with a message naming `exit` and telling the operator to keep
the provider that holds the old key configured beside it. Both refusals are in
`validateProvider` ([config.go:751-767](../../internal/config/config.go#L751)), by
name rather than through the generic *unsupported encryption type* arm, so an
old configuration fails loudly. A key held in a KMS is a provider type of its own
and is decided, not built (ADR 0005).

## What the exit provider means for this threat model

The provider and the reasoning behind it are
[ADR 0025](../adr/0025-leaving-is-a-supported-mode.md).

Selecting `exit` moves the plaintext below
[the boundary](threat-model.md#boundaries) on purpose. Every object written from then on lies in the bucket exactly as the
client sent it, so the backend — and anyone who can read the bucket — has the
object itself, not ciphertext. **That is the operator's declared intent, not a
defect in the model.** It is how you leave the product: you stop encrypting,
your existing data stays readable, and you copy it out. The proxy states it in a
warning line at every start, and the license gate lets the configuration run
without a license precisely so that a lapsed license can never be the reason the
data cannot be read.

Three properties survive the switch, and they are what keeps it from being a
back door into the encrypted objects:

- **An encrypted object is still authenticated the same way.** An object carrying
  the current format's metadata is opened segment by segment as always, so a
  wrapped data key that fails its tag is refused with `InvalidObjectState`,
  HTTP 403, and a modified segment aborts the body. What `exit` changes is the
  shape of the read, not its verdict: it is a single forward pass, so the
  plaintext length comes from the backend's stored length rather than from the
  trailer, no `x-amz-checksum-crc32c` is served, and a damaged trailer, or a
  truncation the stored length alone does not disprove, surfaces at the end of
  the body instead of before it
  ([where a failure surfaces](stored-objects.md#what-the-storage-format-guarantees),
  and ADR 0025). Nothing
  about `exit` softens the refusals; it does not decide what happens to an
  encrypted object, only what happens to one the proxy never wrote.
- **The leg from the proxy to the backend carries a checksum, and it is not this
  codebase that puts it there.** aws-sdk-go-v2 defaults `RequestChecksumCalculation`
  to `when_supported` and computes a CRC32 over the bytes it sends on every
  `PutObject` and `UploadPart`, so a write mangled between the proxy and the
  backend is refused where it lands rather than discovered on a later read. This
  is worth stating because grepping this repository for a checksum on a backend
  write finds nothing and invites the opposite conclusion. The proxy deliberately
  names no algorithm of its own there: a second `x-amz-checksum-*` header on one
  request is refused outright by at least one S3 implementation
  ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D16).
- **A fault found mid-stream truncates the response, and is reported rather than
  hidden.** The status line is committed before the first plaintext byte moves,
  so a segment that fails its tag partway through a read can only cut the body —
  there is no error document left to write, and the object is deliberately not
  buffered to be verified first ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)
  D15). The client's defence is the one it has anyway: a truncated read is short
  against the `Content-Length` it was given, and the AWS SDKs additionally verify
  `x-amz-checksum-crc32c` by default. The operator's defence is
  `s3ep_object_integrity_failures_total{phase="mid_stream"}`, which is otherwise
  zero and is the only place such a read is visible — `s3ep_requests_total`
  counts it as the `200` it announced.
- **The exit fingerprint is not a key.** `EncryptDEK` and `DecryptDEK` both
  return `ErrExitProviderKeyUse`, so a backend that stamps
  `s3ep-kek-fingerprint: exit-provider-fingerprint` onto an object of its own
  gets a failed read, not a data key. Its predecessor unwrapped by returning the
  stored bytes unchanged, which is a key of the backend's choosing: it could have
  sealed any plaintext it liked under that key and had every segment
  authenticate, producing a forgery a client cannot tell from a real object
  (ADR 0001, ADR 0003). That path no longer exists — the short-circuit in
  `DecryptDEK` is gone and the provider's own error is the enforcement
  ([providers.go:232-235](../../internal/orchestration/providers.go#L232)). The answer
  is the one an unreadable wrap gets, `InvalidObjectState`, HTTP 403: the exit
  provider's error joins `ErrWrappedDEKAuth` and an unknown fingerprint on the
  arm that reports a permanent state of the object
  ([segmented.go:357-361](../../internal/orchestration/segmented.go#L357),
  [operations.go:247-255](../../internal/proxy/handlers/object/operations.go#L247)),
  because a 5xx would have the client's SDK retry a read that cannot succeed
  (ADR 0003 D10a).
- **The proxy's namespace is still the proxy's.** The pass-through write paths
  refuse a client `x-amz-meta-s3ep-*` header with `400 InvalidArgument` exactly as
  the encrypting ones do, through the one collector all of them use
  ([helpers.go:157-176](../../internal/proxy/handlers/object/helpers.go#L157),
  [create.go:83](../../internal/proxy/handlers/multipart/create.go#L83)), so a client
  cannot label its own plaintext as an encrypted object through this proxy
  (ADR 0009).

What it does **not** protect, and what an operator has to plan for: an object
written under `exit` cannot be told from an object someone wrote straight into
the bucket, because neither carries proxy metadata. Under `exit` both are served.
Switching the active provider back to `aes` makes every object written during the
exit period foreign, and they are then refused on read — the switch out is a
one-way door for the objects written behind it.

**What it replaced was a pass-through only below one part.** `type: "none"`
passed through a `PUT` that fitted one backend request and nothing else. A
larger or undeclared `PUT`, and any client-driven multipart upload, sealed the
object as a segment chain and stored its data key **unwrapped** in
`s3ep-encrypted-dek`, because `EncryptDEK` returned the key unchanged for that
provider. The read path then decided on the active provider before it looked at
the object and handed the sealed bytes back, while `HEAD` reported the plaintext
size — the two disagreed about the same object, and a large object written that
way was not readable through the proxy at all. The key also sat next to the
data, unwrapped, on an object whose metadata described it as encrypted. Both
halves are gone: nothing is sealed under `exit`, so no data key is drawn to be
left lying about, and `EncryptDEK` returns an error rather than a key.

## Where each secret lives

| Secret | At rest | In memory | Ever sent to the backend? |
|---|---|---|---|
| KEK (`aes_key`) | Config file, or an environment variable referenced as `${VAR}` and expanded at load ([envexpand.go:17](../../internal/config/envexpand.go#L17), applied to every provider config value at [envexpand.go:91-103](../../internal/config/envexpand.go#L91)) | For the process lifetime | **Never** |
| DEK | Only KEK-wrapped, in `s3ep-encrypted-dek` | Plaintext while an object is being processed; also in an LRU DEK cache bounded at 1024 entries, keyed by fingerprint, object key and a hash of the wrapped DEK ([providers.go:212-269](../../internal/orchestration/providers.go#L212), [providers.go:345-390](../../internal/orchestration/providers.go#L345)) | **Never in plaintext** |
| DEK of a multipart upload in flight | — | In the session for that upload id, together with whatever short last part is buffered for it, until `Complete`, `Abort`, the expiry sweep, or process exit ([segmented_session.go:21-47](../../internal/orchestration/segmented_session.go#L21)) | **Never in plaintext** |
| Backend credential (`s3_backends[0].access_key_id` / `secret_key`) | Config or `${VAR}` | For the process lifetime | Yes, as SigV4 to the backend — that is its purpose |
| Client credentials (`s3_clients[].secret_key`) | Config or `${VAR}`, minimum 16 characters | In a lookup map built at startup ([s3auth_robust.go:74-79](../../internal/proxy/middleware/s3auth_robust.go#L74)) | **Never** |

An expansion failure is fatal at load: a `${VAR}` that is unset or empty makes
`expandEnvVars` return an error ([envexpand.go:30-32](../../internal/config/envexpand.go#L30)),
so a deployment that forgets the key does not silently fall back to anything.

The third row is the one that changed on this branch, and it was a leak. The
background sweep that expires abandoned multipart sessions was walking the old,
always-empty session map, while the map the live sessions are in had a sweeper
nothing called. An upload that was neither completed nor aborted therefore held
its data key and its buffered short part — up to
`optimizations.multipart_short_part_buffer_size` (`67108864` # default), which
until 2026-09-12 was a budget *per session*, is now the total across all of them,
and since 2026-09-13 also bounds the one read that no session owns — a
pass-through part whose length the request does not declare (ADR 0011 D5). Until
that date such a part was read whole with no bound at all: any client holding an
`s3_clients` credential could end the process with a single large part against a
proxy running the `exit` provider, which needs no licence. A part whose length
the request declares is now forwarded to the backend while it arrives and is
never held — for the life of the process. The sweep now walks the live map
([manager.go:134-167](../../internal/orchestration/manager.go#L134),
[segmented_session.go:344-413](../../internal/orchestration/segmented_session.go#L344))
and measures from the last part an upload received rather than from its start, so
an upload that is still moving bytes is never dropped under its client (ADR 0028).
A session it drops, and every session still open when the process stops, is first
ended at the backend with `AbortMultipartUpload`
([segmented_session.go:309](../../internal/orchestration/segmented_session.go#L309),
[segmented_session.go:364](../../internal/orchestration/segmented_session.go#L364),
wired at [server.go:127-131](../../internal/proxy/server.go#L127) and run at shutdown
by [main.go:426-441](../../cmd/s3-encryption-proxy/main.go#L426)): the data key and the
part table exist in this process alone, so an upload left behind is parts nobody
can finish or reach (ADR 0029). Setting
`optimizations.multipart_session_cleanup_interval` to `0` disables the periodic
sweep; the one at shutdown still runs.

## KEK rotation, by fingerprint

Rotation is the one thing the metadata design is built for.

1. Add the new provider to `encryption.providers` and leave the old one in place.
2. Point `encryption.encryption_method_alias` at the new alias.
3. Restart the proxy.

From then on, every write uses the new KEK, and every read picks the provider
whose fingerprint matches `s3ep-kek-fingerprint` on the object
([segmented.go:333-347](../../internal/orchestration/segmented.go#L333),
[providers.go:212-269](../../internal/orchestration/providers.go#L212)). Objects
written under the old KEK stay readable for exactly as long as the old provider
stays configured. Removing it makes them permanently unreadable — there is no
re-encryption job; re-writing objects through the proxy is the migration.

**Fingerprints are derived, not configured**, so they cannot drift: for `aes` the
master key is extracted once into an HKDF pseudorandom key and the fingerprint is
`hex(HKDF-Expand(prk, "s3ep-kek-fingerprint"))` — its own label beside the
`s3ep-kek-wrap-v1` every wrapping key uses, so publishing it in object metadata
says nothing about the key and nothing about the key used to wrap any DEK — and
for `exit` it is the constant `exit-provider-fingerprint`, which no object ever
carries, because that provider writes plaintext and plaintext carries no
metadata. Meeting it in an object's metadata therefore means the backend put it
there, and the read is refused rather than served (*What the exit provider
means for this threat model* above).

`aes` has no `RotateKEK` call and neither has any other provider: the
`KeyEncryptor` interface is `EncryptDEK`, `DecryptDEK`, `Name`, `Fingerprint` and
nothing else ([interfaces.go:7-23](../../pkg/encryption/interfaces.go#L7)). Rotation is
the configuration procedure above, not an API call.

## Why the fingerprint is derived rather than hashed

The published value used to be `hex(SHA-256(master key))`. For a 256-bit key out
of `s3ep-keygen` that was harmless — inverting SHA-256 is not a thing — but a
**low-entropy or published key** could be confirmed offline by anyone able to
read one object, which turned the fingerprint into a verification oracle for a
dictionary attack.

Two changes close that, and the second is the one that matters:

- The fingerprint is derived under a label of its own, so it is not a hash of
  the key and confirms nothing about it.
- A key that is not base64 of exactly 32 bytes is refused at startup, and so is
  one that decodes to printable characters only or to fewer than 16 distinct
  byte values. A passphrase can no longer become an AES-256 key, so the
  dictionary such an oracle would have been useful against no longer exists.

What remains, and is accepted: the fingerprint still **links deployments** — two
buckets carrying the same value provably share a master key. That is inherent to
selecting the right key by a value the backend can read (ADR 0004).

## Client credential rotation

Add the new `s3_clients` entry, restart, move clients over, remove the old entry,
restart again. The lookup map is built once at startup; there is no reload.

## What this does not cover

- **No per-client keys.** The active provider is global
  (`encryption.encryption_method_alias`), so every client writes under the same
  KEK and a client that can read an object can always decrypt it
  ([tenancy and privilege](tenancy-and-privilege.md)).
- **No key isolation from the process.** The KEK, every unwrapped DEK in the
  cache and every data key of an upload in flight live in the proxy's memory.
  There is no HSM path and no signing identity that survives a proxy compromise.
- **No re-encryption job.** Rotation changes what new writes use; existing
  objects stay under the old KEK until they are written again through the proxy.
  Removing the old provider makes them permanently unreadable, and the proxy
  cannot tell an operator which objects that would be.
- **The fingerprint is public by design.** It identifies the key without
  revealing it, and it links every object and every deployment that shares the
  master key.
- **Credential rotation needs two restarts.** The client lookup map is built once
  at startup and there is no reload, so an exposed credential stays valid until
  the process is restarted without it.
