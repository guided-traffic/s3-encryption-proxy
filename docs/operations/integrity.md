# What the proxy guarantees about your bytes

Integrity is not a setting. It is the stored format, on every read
([ADR 0001](../adr/0001-the-backend-is-hostile.md),
[ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)) — so this
page describes guarantees, not options. There is nothing here to enable and
nothing to switch off.

Per-operation behaviour — ranges, listings, conditional requests, sub-resources
— is [s3-api.md](s3-api.md). The codec's internals are
[docs/developer/storage-format.md](../developer/storage-format.md).

## Storage format (`s3ep-gcm-seg-v2`)

Every object this proxy encrypts is stored in one format, whichever write path
produced it. The plaintext is cut into 64 KiB segments; each segment is sealed
on its own with AES-256-GCM under a 12-byte nonce and a 16-byte tag, and the
object ends with a 40-byte trailer carrying the plaintext length and a CRC32C
over the plaintext, sealed the same way.

Each seal's additional data binds the segment to **its index within the object**
and to **the object key the client used**. A segment therefore cannot be moved
within an object, swapped between objects, duplicated, dropped or reordered
without the read failing, and an object copied to another name inside the
backend is undecryptable under that name — which is why server-side copy is
refused rather than forwarded.

The stored length is a pure function of the plaintext length, so the proxy
reports plaintext sizes on `HEAD` and `GET` and finds any segment arithmetically,
with nothing about the layout stored where a backend could edit it:

```
stored = plaintext + ceil(plaintext / 65536) * 28 + 40
```

What a client sees when a stored object has been modified: the proxy has already
answered `200 OK` by the time it opens the first segment, so it aborts the
response body, and the client's HTTP stack reports an unexpected EOF on a body
cut short at a segment boundary. Every byte it did receive carried its own tag.
A modified object is never delivered whole.

## Object metadata

Four keys are written, and they describe how the data key was wrapped — never
the data itself, which is sealed inside the object where the backend cannot edit
it:

| Key | Value |
|---|---|
| `s3ep-dek-algorithm` | Always `s3ep-gcm-seg-v2`, the format id |
| `s3ep-encrypted-dek` | The object's data key, wrapped under the KEK |
| `s3ep-kek-algorithm` | The key provider type that wrapped it, e.g. `aes` |
| `s3ep-kek-fingerprint` | Which key wrapped it, so a retired key still reads what it wrote |

The prefix is `encryption.metadata_key_prefix`; the four names after it are
fixed. No nonce and no HMAC is stored beside the object: the nonces live in the
segments, and the integrity value is the tag on each of them. That namespace
belongs to the proxy alone — an `x-amz-meta-` header a client sends inside it is
**refused** with `400 InvalidArgument` naming the key, on `PUT` and on
`CreateMultipartUpload` alike, and every key carrying the prefix is stripped from
`GET` and `HEAD` responses on the way out. Nothing is stored by a refused
request, and a client that legitimately uses such a key renames it.

All four exist before the first backend byte is sent on every write path, so a
completed object is never rewritten afterwards to attach metadata.

## Objects this proxy did not write

Under an encrypting provider, an object that carries no proxy metadata, or whose
`s3ep-dek-algorithm` names another format, is **refused** — on `GET`, `HEAD` and
ranged `GET` alike. Objects written by an earlier release of this proxy fall
under exactly that rule: their algorithm is `aes-gcm` or `aes-ctr`, not
`s3ep-gcm-seg-v2`, and they are refused rather than served
([Upgrading from 3.x or 4.x](upgrading.md)).

| Condition | Answer |
|---|---|
| No proxy metadata, or a foreign format id | `403` `InvalidObjectState`, *Object is not encrypted by this proxy* |
| The wrapped data key fails its authentication tag | `403` `InvalidObjectState`, *Object key material failed authentication* |
| `s3ep-kek-fingerprint` names a key this proxy does not have configured | `403` `InvalidObjectState`, *Object key material failed authentication* — the object is intact, the key is missing |

Under an encrypting provider there is no mode in which such an object is handed
to a client.

**Under the exit provider only the first row changes.** The decision is taken per
object, from that object's own metadata: an object carrying no proxy metadata, or
naming a format this proxy does not read, is not one of its own and is served
verbatim — that is what the provider is for. An object that does carry the
current format's metadata is decrypted, and the other two rows still refuse it:
a wrapped data key that fails its authentication tag is refused, and a
fingerprint naming a key that is no longer configured is an error, not a
pass-through. A backend cannot talk its way past the key by relabelling an object
([ADR 0001](../adr/0001-the-backend-is-hostile.md)).

The third row is the one an operator causes: dropping a retired key from
`encryption.providers` makes every object written under it unreadable while it
is still there. Keep the key listed as long as its objects exist.

All three refusals are `4xx` deliberately: the state is permanent, and a `5xx`
would have a client SDK retry a read that cannot succeed and let a client file a
corrupted object as a passing outage.

## A read that fails after it has started

A read streams: the proxy verifies each 64 KiB segment against its own
authentication tag and hands it on, and it checks the assembled plaintext against
the CRC32C sealed in the object before it reports the end. An object that fails
either check is refused with `403 InvalidObjectState` **if the fault is found
before the response begins**, which is where the trailer is opened and where most
faults surface.

A fault found later cannot be an error document: the status line and the headers
are already on the wire. **The proxy stops writing, and the client receives a
short body.** It is not buffered first — an object is never held in memory to be
verified before it is delivered, because that would cost the memory profile and
the first-byte latency this product is built for
([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D15).

What a client must therefore do is what it should do anyway: **check the length
it received against the `Content-Length` it was given.** A truncated read is
short, always. Clients that verify `x-amz-checksum-crc32c` — the AWS SDKs do this
by default — catch it there as well.

On the proxy's side the same event is loud: an error-level log line naming the
bucket, the key and what failed, and `s3ep_object_integrity_failures_total` with
`phase="mid_stream"`. The request itself is still counted as the `200` it
announced, which is the reason that counter exists.

## Verifying what a client uploaded

Every checksum a client **declares** is verified against the decoded plaintext
before a byte reaches the backend, and then dropped — `Content-MD5` and the
`x-amz-checksum-*` family, as a header or as an `aws-chunked` trailer
([ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md)).
That needs no configuration and cannot be switched off.

The SigV4 payload hash, `x-amz-content-sha256`, is the one digest that is **not**
verified by default:

```yaml
s3_security:
  verify_payload_hash: true   # default false
```

It is a key rather than a rule because every signed client sends that header. A
`Content-MD5` is a client asking to be checked, and the cost lands on that
client's uploads; the payload hash is on essentially every signed request, so
verifying it is a SHA-256 pass over **every** upload this proxy accepts. Whether
that is worth paying depends on the deployment — a client leg on TLS already has
the record MAC over the wire.

Turn it on when a client of yours declares nothing else. **s3cmd is the known
case**: it sends no `Content-MD5` for an object body, so without this key its
uploads carry no end-to-end digest anywhere.

What the key does not do:

- It is **skipped for an `aws-chunked` body**, where the header carries a
  `STREAMING-*` sentinel and the trailers are the declaration.
- A value that is not a digest — `UNSIGNED-PAYLOAD`, anything that is not 64 hex
  characters — is ignored, not refused.
- It **never satisfies the `DeleteObjects` digest rule**. A batch delete without a
  deliberate `Content-MD5` or `x-amz-checksum-*` stays refused with
  `400 InvalidRequest` whatever this key says.
- With it on, a request that also declares a checksum of its own has **both**
  verified.

A mismatch answers `400 BadDigest`, decided before the last payload byte is
released, so a refused upload stores nothing.

**Every write answers `x-amz-checksum-crc32c`** under an encrypting provider — a
single-request `PUT`, every `UploadPart`, and `CompleteMultipartUpload`. A part's
answer is that part's checksum, the completion's is the object's, and it is the
same value a later `GET` or `HEAD` of that object answers. Compare it against
your own file and you know the proxy received what you sent
([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D16).

That costs nothing — the value is sealed into the object either way — which is
what separates it from `verify_payload_hash` above: **verification refuses a bad
upload, this one lets you detect one.** Under the exit provider no write answers
a checksum, and neither does a ranged read.

## Checksums

**Every checksum you declare on an upload is verified against your plaintext**
([ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md)).
The value may arrive as a request header or as an aws-chunked trailer, and the
check runs on every write path: single-request `PUT`, large uploads the proxy
splits into parts internally, `UploadPart`, the bucket configuration writes and
`DeleteObjects`.

| Declaration | Algorithm | Where it may arrive |
|---|---|---|
| `Content-MD5` | MD5 | request header |
| `x-amz-checksum-crc32` | CRC-32/IEEE | header or `X-Amz-Trailer` |
| `x-amz-checksum-crc32c` | CRC-32C | header or `X-Amz-Trailer` |
| `x-amz-checksum-crc64nvme` | CRC-64/NVME | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha1` | SHA-1 | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha256` | SHA-256 | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha512` | SHA-512 | header or `X-Amz-Trailer` |
| `x-amz-checksum-md5` | MD5 | header or `X-Amz-Trailer` |

- A value that does not match your payload → **`400 BadDigest`**.
- A value that is not base64, or decodes to the wrong length → **`400 InvalidDigest`**.
- A trailer named in `X-Amz-Trailer` that never arrives → **`400 BadDigest`**. Naming
  it is how you ask for the check; omitting the value is not a way out of it.
- **Nothing is stored on a failure.** The verdict lands before anything is
  committed: no object, no part, and no multipart upload left behind for you to
  find and clean up.
- `DeleteObjects` **requires** a digest, as S3 does, and a request without one is
  refused with `400 InvalidRequest`. The digest is checked before the document is
  parsed, so a refused request deletes nothing.
- An algorithm the proxy does not compute → **`501 NotImplemented`**, naming the
  header. The `x-amz-checksum-xxhash3`, `-xxhash64` and `-xxhash128` families are
  the ones this affects: none has a Go standard-library hash and the proxy takes
  no dependency for one. It refuses them rather than accepting a check it cannot
  run. `x-amz-checksum-algorithm`, `-mode` and `-type` carry no digest and are
  unaffected.
- **`CompleteMultipartUpload` is the exception.** There `x-amz-checksum-*` is the
  digest of the *completed object*, not of the completion document, so it is not
  checked against that document — it is dropped, because the proxy no longer
  holds the plaintext object it would have to hash and the backend holds only
  ciphertext.

**What a checksum costs you.** Only the algorithm you declare is computed, and
declaring none costs nothing at all. Per-byte throughput on one core of an Apple
M5 Pro, 128 KiB blocks, Go 1.27.1:

| Algorithm | Throughput | Hardware |
|---|---|---|
| CRC-32 | 12.1 GB/s | dedicated instructions on amd64 and arm64 |
| CRC-32C | 12.1 GB/s | dedicated instructions on amd64 and arm64 |
| SHA-1 | 3.5 GB/s | ARMv8 SHA1 / x86 SHA-NI where the CPU has them |
| SHA-256 | 3.4 GB/s | ARMv8 SHA2 / x86 SHA-NI where the CPU has them |
| SHA-512 | not measured | ARMv8 / x86 where the CPU has them |
| CRC-64/NVME | 2.4 GB/s | none, software only |
| MD5 | 0.94 GB/s | none on either architecture |

End to end the difference is much smaller, because the hash runs while the
request is bound by the write to the backend: measured over the development
stack at 8 MiB and 20 MiB, every algorithm but MD5 was inseparable from an
upload declaring nothing, and MD5 cost about three percent. Pick CRC-32 or
CRC-32C if your client lets you choose; the AWS SDKs send CRC-32 by default.

**A CRC is a transmission-corruption check, not an integrity guarantee.** It
catches a byte damaged on the way to the proxy, which is what it is for. It does
not detect a deliberate modification, and nothing here claims it does — see
[docs/security/upload-integrity.md](../security/upload-integrity.md).

**Your value is never forwarded and never stored.** It describes the plaintext
while the body the proxy uploads is ciphertext, so a digest-checking backend
would answer `BadDigest` for a perfectly good upload; and a plaintext checksum
sitting in cleartext next to the ciphertext would hand a hostile backend a way to
confirm a guessed plaintext. Responses carry no backend checksum header either,
for the mirror-image reason: it would describe the stored ciphertext, not the
plaintext delivered.

Object integrity at rest is covered by the per-segment tags of the
[storage format](#storage-format-s3ep-gcm-seg-v2), which refuse a modified object
outright. The format also seals a CRC32C over the plaintext in its trailer, the
proxy checks it on every whole-object read, and **it serves it back to you**: a
whole-object `GET` and a `HEAD` answer with `x-amz-checksum-crc32c` over the
plaintext, recorded when the object was written and never computed from the bytes
about to be sent. There is no configuration key for it, and a ranged read carries
none.


## Entity tags

**The entity tag this proxy answers is a change token, never a digest of your
file's content** ([ADR 0032](../adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md)).
Equal bytes carry equal tags and different bytes carry different ones, which is
all HTTP asks of it and all this proxy promises.

S3 makes a stronger promise by convention: a single-request upload answers the
MD5 of the object's content, thirty-two hex digits. This proxy cannot keep that
promise — the backend's tag is the MD5 of the encrypted bytes, under a data key
that is random per object — so it stops making it. Under an encrypting provider
a tag with that shape is answered with a `-0` suffix inside the quotes:

```
"2c52a8e3b689c5ea7f55444e2000b35a"    what the backend holds
"2c52a8e3b689c5ea7f55444e2000b35a-0"  what a client is told
```

The suffix stays inside the `<hex>-<number>` grammar every S3 client already
parses — it is what a multipart object's tag looks like — and S3 itself cannot
produce it, because a completed multipart upload has at least one part. What it
buys is that a client which would otherwise compare the tag against its own file
stops doing so, instead of concluding the transfer was corrupted.

What this means in practice:

- It applies to **every verb that states an entity tag**: an upload, a completed
  multipart upload, a `GET`, a ranged `GET`, a `HEAD`, both listings, **and every
  part** — `UploadPart` and `ListParts` — because a client driving its own
  multipart upload judges each part and never sees an object-level tag.
- **Send back what you were given.** The marker is removed again before any
  precondition or part list is used, so `If-Match`, `If-None-Match` and the
  completion document all behave as if it were not there.
- A tag that already says it is not a digest — a multipart `<hex>-N` — is
  answered unchanged.
- **Under the exit provider nothing is marked.** There the stored bytes are the
  plaintext and the backend's tag is the truth about them.
- **To verify content, use `x-amz-checksum-crc32c`**, the CRC32C this proxy seals
  into every object and answers on a whole-object `GET` and on a `HEAD`. It
  describes the bytes you actually receive, which an entity tag never did.
- **A documented limit** ([ADR 0006](../adr/0006-the-proxy-serves-any-s3-client.md)
  D2): a multipart object's tag is not S3's composite over your plaintext parts,
  so a client that recomputes that formula — `rclone` with `use_multipart_etag`
  on, its default for some providers — reports a mismatch. Set
  `use_multipart_etag = false` for this endpoint; the upload is verified anyway,
  by this proxy, against every part's own `Content-MD5`.
