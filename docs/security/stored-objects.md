# Stored objects: what is written, what it guarantees, what leaks

What lands in the bucket beside the ciphertext, what the segment chain proves
about those bytes, where a failed proof surfaces, and what the backend learns
even when every proof holds. The keys behind the seals are
[key management](key-management.md).

## What is written into S3 object metadata

Exactly four keys, each carrying the configured prefix
(`encryption.metadata_key_prefix`, `s3ep-` # default,
[config.go:332](../../internal/config/config.go#L332)). The prefix is validated at
startup against `^[a-z0-9][a-z0-9-]{2,}-$`
([config.go:673](../../internal/config/config.go#L673), applied at
[config.go:687-693](../../internal/config/config.go#L687), ADR 0009 D2), so it is at
least four characters and ends in a dash — without the dash a prefix `s3ep`
would claim every client key that begins `s3ep` as well. An
empty prefix made the writer store the keys unprefixed while the read path still
looked for `s3ep-` to decide whether an object was one of its own, so every `GET`
decided the object was unencrypted and served the **ciphertext** behind a 200,
and a prefix with a capital in it never matched on the way back, because S3
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
under the exit provider either. Such a key is refused with `400 InvalidArgument`
naming it, not dropped silently, which is what ADR 0009 D6 asks for.

| Key | Contains | Consequence if the backend alters it |
|---|---|---|
| `s3ep-encrypted-dek` | base64 of the KEK-wrapped DEK, 76 bytes | The wrap fails its authentication tag: `InvalidObjectState`, HTTP 403, *Object key material failed authentication*. Permanent, and answered as a client error precisely so an SDK does not retry it (ADR 0003 D10a) |
| `s3ep-dek-algorithm` | always `s3ep-gcm-seg-v2`, the format id | Any other value makes the object foreign: `InvalidObjectState`, HTTP 403, *Object is not encrypted by this proxy* |
| `s3ep-kek-fingerprint` | `hex(HKDF-Expand(HKDF-Extract(master key), "s3ep-kek-fingerprint"))`, identifying which configured KEK wrapped this DEK | No provider is loaded for the altered value, so the data key never unwraps: `InvalidObjectState`, HTTP 403, *Object key material failed authentication*. The same permanent answer as the first row, for the same reason (ADR 0003 D10a) |
| `s3ep-kek-algorithm` | KEK provider algorithm string | None. It is written and never read back — no read path looks at it, so altering it changes nothing |

All four are written by
[`BuildSegmentedMetadata`](../../internal/orchestration/metadata.go#L88) and describe
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

**Filtered on the way out, refused on the way in**, so a client never sees the
proxy internals and never writes into them:
[`Handler.isEncryptionMetadata`](../../internal/proxy/handlers/object/helpers.go#L122)
drops every key inside the prefix out of
[`cleanMetadata`](../../internal/proxy/handlers/object/helpers.go#L97) on `GET`, `HEAD`
and ranged responses — where it is applied as the response is written, so a read
path cannot be added without it — and
[`UserMetadata`](../../internal/proxy/handlers/object/helpers.go#L157) refuses a client
key inside the prefix on every write.
All three write paths call that one exported collector, the multipart create
path included ([create.go:83](../../internal/proxy/handlers/multipart/create.go#L83)),
rather than each carrying a check it could forget.
The one filter left in `internal/orchestration/` is inside
`BuildSegmentedMetadata`, which drops a client key inside the prefix before it
writes the four ([metadata.go:94-102](../../internal/orchestration/metadata.go#L94)):
the collector already refused that key, and dropping it here as well means no
future caller can put one in this namespace that a read would then find beside
the four. The two response-side filters that lived there had no production caller
and are gone.

## What the storage format guarantees

There is one format on every write path, so there is one answer, not a table of
them. It is stated precisely because most of what every other page here claims
rests on it.

| | Segment chain (`s3ep-gcm-seg-v2`) |
|---|---|
| Confidentiality | Yes. AES-256-GCM, one fresh nonce per segment under a DEK used for one object |
| Ciphertext authenticated | **Yes, segment by segment.** A modified byte fails the tag of the segment it lands in, before that segment is released |
| Bound to the object key | **Yes, in every segment.** The object key is part of each seal's additional data, so the backend cannot serve object A's bytes under key B |
| Bound to its position | **Yes.** The segment index is in the same additional data, so segments cannot be reordered, duplicated or dropped |
| Total length authenticated | **Yes.** The trailer seals the plaintext length, so truncation and extension are refused |
| Plaintext checksum | A CRC32C over the whole plaintext, sealed in the trailer, checked by the proxy on every whole-object read and served to the client as `x-amz-checksum-crc32c` on a whole-object `GET` and on `HEAD` — under the `exit` provider neither carries it, because that read is a single forward pass and the value is not known before the response begins ([the exit provider](key-management.md#what-the-exit-provider-means-for-this-threat-model)). It is a detector for a fault in the proxy's own assembly of already-verified plaintext, and the client's end-to-end check on the read leg — not a second integrity value against a hostile backend, which the segment tags already are |
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
   exit provider stays a single forward pass and keeps the old shape for both,
   except where the stored length alone already disproves the object (ADR 0025).

## Why a refusal is permanent, and why there is no setting

**A tampered object is never delivered whole.** Measured against a running stack
across six attacks: a flipped bit in the first segment, in a middle segment and
in the trailer, two segments swapped, a truncation and an extension. The three
the trailer proves — truncation, extension and a damaged trailer — are refused
with `403 InvalidObjectState` before the response begins and nothing is written
at all; the other three abort the body, and the prefix the client did receive is
byte-identical to the object's own opening plaintext
([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)).

Both halves of that used to fail, and the pair is why this page offers no
choice. The integrity value was verified *after* the last plaintext byte had
already been written to the client, and not at all when the backend answered
without a `Content-Length` — a header the backend chooses. No setting refused
tampered data: `strict` was `lax` with a different log line. Separately, an
object carrying no proxy metadata was served to the client unchanged whatever
the active provider, so anyone able to write into the bucket could substitute an
object by stripping four metadata keys off it and the proxy handed the
substituted bytes over as if it had written them.

**The knob that appeared to control it is gone.**
`encryption.integrity_verification` and the four modes it selected — `off`,
`lax`, `strict`, `hybrid` — exist nowhere: not in the loader, not in a shipped
example, not in the chart values. There is no longer a choice to offer, because
the tag on each segment is produced by the same operation that encrypts it: a
build that skipped verification could not decrypt either. What replaces the knob
is not a setting but a fact an operator has to know — *where* the refusal
surfaces, and what that costs a client, which the section above states.

**A refusal has no repair path in the product.** The object is not readable
through this proxy again; it is restored from its source. The 403 is the
notification.

## What a ranged read proves

A ranged read opens only the segments its window covers, each under its own tag,
so a partial read is authenticated exactly like a whole one. Measured against a
running stack: a range over a tampered segment delivers nothing and the body is
aborted
([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)).
That matters beyond ranged downloads being a feature: kopia, which is how Velero
stores volume data, reads its pack blobs exactly that way, so before the segment
chain entire restores ran on reads the proxy did not verify at all.

What a ranged read still does not tell you is inherent to any per-segment format
rather than a defect to close:

- It authenticates only the segments in its window. Damage elsewhere in the
  object is invisible to it, and a client that only ever reads ranges never
  checks the object as a whole. Pinned by a test, so that nobody "fixes" it by
  reading more than was asked for.
- A range that does not reach the end of the object never sees the trailer, so
  it cannot check the object's authenticated total length; for the object's size
  it trusts what the backend reports.
- A client that needs whole-object assurance must read the object whole. A
  ranged read is not a cheap substitute for that.

## What the backend learns anyway

Even with everything above working, the backend still sees:

- **Key names**, in the clear. They carry structure: a Velero backup name, a
  namespace, a database identifier. Encrypting the directory segments of a key is
  decided and **not implemented** (ADR 0023).
- **Object sizes.** The stored length differs from the plaintext by 28 bytes per
  64 KiB segment plus a 40-byte trailer
  ([segmented_gcm.go:194-203](../../pkg/encryption/dataencryption/segmented_gcm.go#L194)).
  That is a pure function of the plaintext length, and the proxy inverts it
  itself to answer `HEAD`, so the backend can do the same arithmetic. Padding is
  not offered.
- **Timestamps, request order and access patterns**, including which objects a
  restore touches and in what sequence.
- **Which objects share a key.** `s3ep-kek-fingerprint` is the same value for
  every object wrapped under one master key, across buckets and across
  deployments ([KEK rotation](key-management.md#kek-rotation-by-fingerprint)).
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
  rule in [the threat model](threat-model.md#the-s3-backend-is-hostile) the
  backend reads every byte anyway, so its at-rest
  encryption is a control the adversary operates over its own copy. Only the
  proxy's envelope encryption protects the content, and the backend's response
  header is not a statement about it.
- **Object lock defends the credential, not the backend.** A compromised backend
  can ignore its own retention; a compromised *client credential* cannot, and
  that is the common ransomware path for a backup bucket. Forwarding
  `x-amz-object-lock-*` is worth it for the second adversary and worthless
  against the first.

The three SSE-C headers are the one header family the proxy refuses in its
entirety (`501 NotImplemented`, naming the header): no read path carries the
customer key, so accepting one on upload would write an object nobody could ever
read back (ADR 0007 D6). They are not the only refusal — `x-amz-copy-source` on a
`PUT` and `UploadPartCopy` are `422 NotSupportedWithEncryption` under every
provider ([refusals](refusals.md)), and an `x-amz-checksum-*` naming an algorithm this proxy
cannot compute is `501 NotImplemented` without naming it — but they are the only
family refused whatever value they carry.

None of this is defended and none of it should be assumed hidden. A deployment
that cannot afford to leak key names is a deployment that needs ADR 0023 built
first.

## What this does not cover

### H-3 Rollback and object substitution are not prevented

**Structural.**

No authenticated format prevents a backend from serving an **older version of
the same key**: the old segments, the old trailer and the old metadata are all
internally consistent, because the proxy sealed them itself. The same holds for
serving nothing, or for a listing that omits an object.

What the segment chain does prevent, and did not before: every segment is sealed
against **the object key and its own index**, so bytes cannot be moved to
another key, reordered within their object, duplicated or dropped, and the
trailer's sealed length refuses truncation and extension. Substitution across
keys is closed; substitution across *time* is not.

**Against a rollback, the only defence is the client.** Velero and kopia, for
example, run their own consistency checks over their own manifests; a
rolled-back or missing blob shows up there. A client without such checks has no
defence at all, because a genuine earlier version of the same key is a correctly
sealed object that the proxy itself wrote.

What an operator can do in the meantime: enable object versioning and, where
available, object lock on the backend bucket, so that a rollback needs a
privilege the backend credential does not have; and treat a client's own
consistency failures as integrity alerts rather than as flakes.
