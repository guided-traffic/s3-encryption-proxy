# The storage format

One format on every write path: the authenticated segment chain, format id
`s3ep-gcm-seg-v2`. The decision and its reasoning are
[ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md); this page
is what you need in your head before you change the codec or anything that
computes a size or an offset.

Code: `pkg/encryption/dataencryption/segmented_gcm.go`, `segmented_gcm_io.go` and
`segmented_gcm_range.go`, driven by `internal/orchestration/segmented.go` and
`segmented_session.go`.

The `exit` provider is the exception to "every write path", and it is a whole
one: while it is active nothing is sealed on any path. A PUT that fits one
backend request, the internal producer above that size and a client-driven
multipart upload all store the object exactly as the client sent it, with no
proxy metadata and no chain. The read path does not follow the provider: it looks
at the object's metadata, opens a chain when it finds one and serves the stored
bytes when it does not, so a bucket on the way out holds both kinds and both come
back correctly. [request-paths.md](request-paths.md) has the routing.

## Layout

```
segment 0        segment 1              segment n-1        trailer
┌──────────────┐ ┌──────────────┐  ...  ┌──────────────┐ ┌──────────┐
│ nonce  ct+tag│ │ nonce  ct+tag│       │ nonce  ct+tag│ │ 40 bytes │
│  12     64Ki │ │  12     64Ki │       │  12    ≤64Ki │ │          │
└──────────────┘ └──────────────┘       └──────────────┘ └──────────┘
      +16 tag         +16 tag                 +16 tag
```

Every segment carries 64 KiB of plaintext except the last, which carries what is
left. A plaintext that is a whole number of segments ends on a full segment and
has no short one at all; the empty object is a trailer and nothing else, 40
stored bytes.

The trailer holds the object's **plaintext length** and a **CRC32C over the whole
plaintext**, sealed the same way as a segment. The checksum is not what
authenticates the object — the seals are. It is there to catch a fault in the
proxy's *own* assembly of already verified plaintext, a dropped byte at a segment
boundary or a reused buffer, which no seal in this format can see because such a
fault happens after verification (ADR 0003 D13).

It is a CRC and not a hash because the multipart paths fold it from per-part
values (`Checksum.Append`, the zlib `crc32_combine` construction): a part is
sealed the moment it arrives, in whatever order, and the object's checksum has to
be assembled from those terms at completion. A cryptographic hash cannot be
combined that way, and it does not have to be one — the seal around it supplies
the cryptography.

## What marks an object as ours

Four metadata keys under the configured prefix (`s3ep-` # default):
`dek-algorithm`, which is always the format id, `encrypted-dek`,
`kek-fingerprint` and `kek-algorithm`.

Two predicates read them, and the difference between them decides one case:

- `Manager.ClaimsSegmentedFormat` is true when `dek-algorithm` names this format,
  whatever state the wrapped key is in. Since the prefix is the proxy's exclusive
  namespace in both directions (ADR 0009), an object that claims the format is
  **ours** — a client cannot have written that key.
- `Manager.IsSegmentedObject` additionally requires a wrapped key that decodes,
  which is what the read path needs to open it.

An object naming another format, or carrying no proxy metadata at all, is foreign.
An object of ours whose wrapped key is gone or unreadable is **not** foreign: it is
a missing key, and it is refused on every read verb under every provider — the exit
provider included, where foreign is the one class served verbatim (ADR 0025). See
[errors.md](errors.md) for the answers.

Nothing about the byte layout lives in metadata. That is what lets every write
path send the complete metadata set before the first backend byte, and it is why
no object is rewritten after its last part.

## The three invariants everything rests on

**1. Each seal is bound to its position and its object.** The additional data of
segment *i* is `s3ep-gcm-seg-v2 ‖ object key ‖ i`, the index an 8-byte big-endian
integer. A segment therefore cannot be moved within its object, moved to another
object, duplicated or dropped without the read failing. The trailer uses an
all-ones index no segment can reach, so it cannot be swapped with one.

The bucket is deliberately absent from the additional data (ADR 0003 D5): a
bucket can be replicated or renamed without re-encryption, at the price of
leaving a same-key cross-bucket substitution undefended.

This is why server-side copy is refused rather than forwarded — `CopyObject` and
`UploadPartCopy` both, whatever the provider: a backend copy to another key
produces an object that is undecryptable under its new name, and the client would
only find out on the first read.

**2. The stored length is a pure function of the plaintext length.**

```
stored = plaintext + ceil(plaintext / 65536) * 28 + 40
```

It inverts exactly, including for the empty object and for a plaintext that is a
whole number of segments, and the inverse **refuses** a stored length no writer of
this format could have produced instead of answering with a plausible size (ADR
0003 D12a). Both directions refuse a plaintext above S3's 5 TiB object limit
rather than letting the segment arithmetic overflow.

Nothing about the layout is stored anywhere the backend could edit, which is what
lets a ranged read find a segment arithmetically and lets `HEAD` report the
plaintext size without a second request. What the function converts is still a
number the backend reported, so it is not itself an integrity check: the trailer
is the authenticated copy of the length, and only a read that reaches the trailer
has seen it.

**When you change a constant, you change this function**, and with it every
stored object. `SegmentSize`, `SegmentOverhead` and `TrailerSize` are frozen for
the life of the format id. A different value needs a different format id. Outside
the codec they are used by `orchestration.PartStoredLen`, by `provisionalWindow`
and `maxWindowOverAsk` in `internal/proxy/handlers/object/range.go` and by the two
fetch lengths in `internal/proxy/handlers/object/tail.go`; `git grep` for the
three names is the change list.

**3. A nonce is never reused under one key.** One data key per object, one fresh
random 96-bit nonce per segment, inline — never derived from a segment counter or
an object prefix. A part re-sealed for a retry draws fresh nonces, and that is
safe because a segment is bound to its own index rather than to when it was
written. The stream cipher this format replaced could not say that: there, a
re-uploaded part was key-stream reuse.

The bound holds only while the segment size is a constant: 2^32 segments under
one key is 256 TiB in a single object, far past the 5 TiB the format refuses
anyway.

## Parts are segment-aligned

A part is a run of whole segments. `NewPartWriter` refuses an offset that is not
a multiple of the segment size, and `FinishPart` refuses a part that ends inside
a segment without ending the object — such a part writes cleanly and never reads,
so it is refused where it is produced rather than discovered on the first `GET`.
Only the part that closes the object may be short, and the trailer is sealed
once, at completion. What that costs the two multipart paths is
[multipart.md](multipart.md).

The one configured value that has to respect the grid is
`optimizations.streaming_segment_size` (`12582912` # default), the internal
producer's part size. A value that is not a whole multiple of 64 KiB is refused at
startup, by name (`validateOptimizations`, ADR 0011 D7); the default and the 5 MiB
minimum both are.

## What the reader guarantees, and what it does not

Verification is per segment, and a segment is verified before it is released. So
a modified object is never delivered whole, and every byte a client did receive
carried its own tag.

It is not delivered *not at all*, though, and that difference matters when you
write a handler: the response status is already out by the time the first segment
is opened, so a fault found mid-stream can only be reported by **aborting the
body**. The client sees an unexpected EOF on a short body.

**A whole-object read narrows that window by reading the object's end first**
(ADR 0003 D14, `internal/proxy/handlers/object/tail.go`). The trailer is opened
before the response begins, so a damaged trailer, a truncation and a stored length
the trailer contradicts are refusals with nothing written; the `Content-Length`
stated is the authenticated one; and `x-amz-checksum-crc32c` goes out with the
headers. What still aborts a body is a fault **inside a segment**, which no
ordering can find ahead of time without reading the whole object twice.

The trailer's length and checksum are also checked by the reader, before the last
segment is released — the same check, from the other end, and what catches a
chain the proxy itself assembled wrongly.

A fault that can be decided from metadata — a foreign format id, a wrap that
fails its tag — is caught before anything is sent and is a proper S3 error
document. Prefer that side of the line where you can.

## Ranged reads

A range is planned into a **window**: the segments that cover it, at most one
segment of over-read at each end, plus the trailer when the range reaches the end
of the object. The over-read stays within 2·65536 + 2·28 + 40 bytes above what
was asked for, a bound `TestSegRangeAmplificationBound` walks. The window is
computed without the data key, so a handler can issue the backend request before
it unwraps anything.

One contiguous backend request serves it, but for an explicit `bytes=a-b` that
request is not the window: `provisionalWindow` in
`internal/proxy/handlers/object/range.go` computes it from the format constants
alone, assuming every segment is full and always adding a trailer, because the
object's stored total only comes back with the answer. The real window is planned
from that answer and the body is cut to it before the reader sees a byte. Which
range forms cost a `HEAD` first is [request-paths.md](request-paths.md).

Three consequences worth knowing:

- A ranged read authenticates only its own window. Damage elsewhere in the object
  is invisible to it. This is inherent to any per-segment format and is pinned by
  a test so nobody "fixes" it by reading more than was asked for.
- A range that reaches the end of the object opens the trailer too and checks its
  authenticated length against the length the window was planned against. A range
  that stops earlier never sees the trailer, so it can check neither the total
  length nor the checksum.
- Small ranges amplify. A 512-byte read fetches a whole 64 KiB segment, and there
  is no segment cache to soften it.

## Testing convention for this package

Every crypto-carrying change here gets a **mutation round** before it is called
done: introduce deliberate defects, one at a time, and confirm the tests catch
each one. A green suite on freshly written cipher code is not evidence. The
codec's first round caught 4 of 8 injected defects — dropping the segment index
from the additional data, deleting either half of the trailer check, and
collapsing the trailer's reserved index onto segment 0 all survived it — and the
tests were strengthened until a second round of 14 caught all 14. A constant
nonce survived even the strengthened suite until `TestSegNoncesAreUnique` was
added.
