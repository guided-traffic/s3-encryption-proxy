# The storage format

One format on every write path: the authenticated segment chain, format id
`s3ep-gcm-seg-v2`. The decision and its reasoning are
[ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md); this page
is what you need in your head before you change the codec or anything that
computes a size or an offset.

Code: `pkg/encryption/dataencryption/segmented_gcm*.go`.

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
left — possibly zero, for an object that is an exact multiple of the segment
size, and for the empty object, which is a trailer and nothing else.

The trailer holds the object's **plaintext length** and a **CRC32C over the whole
plaintext**, sealed the same way as a segment.

## The three invariants everything rests on

**1. Each seal is bound to its position and its object.** The additional data of
segment *i* is `s3ep-gcm-seg-v2 ‖ object key ‖ i`. A segment therefore cannot be
moved within its object, moved to another object, duplicated or dropped without
the read failing. The trailer uses an index no segment can reach, so it cannot be
swapped with one.

This is why server-side copy is refused rather than forwarded: a backend copy to
another key produces an object that is undecryptable under its new name, and the
client would only find out on the first read.

**2. The stored length is a pure function of the plaintext length.**

```
stored = plaintext + ceil(plaintext / 65536) * 28 + 40
```

It inverts exactly, including for the empty object and for a plaintext that is a
whole number of segments. Nothing about the layout is stored anywhere the backend
could edit, which is what lets a ranged read find a segment arithmetically and
lets `HEAD` report the plaintext size without a second request.

**When you change a constant, you change this function**, and with it every
stored object. `SegmentSize`, `SegmentOverhead` and `TrailerSize` are frozen for
the life of the format id. A different value needs a different format id.

**3. A nonce is never reused under one key.** One DEK per object, one nonce per
segment. A part re-uploaded during a multipart upload draws fresh nonces, which
is what makes re-uploading a part safe — under the stream cipher this format
replaced, it was not.

## What the reader guarantees, and what it does not

Verification is per segment, and a segment is verified before it is released. So
a modified object is never delivered whole.

It is not delivered *not at all*, though, and that difference matters when you
write a handler: the response status is already out by the time the first segment
is opened, so a fault found mid-stream can only be reported by **aborting the
body**. The client sees an unexpected EOF on a short body. Up to *n−1* whole
segments of authentic plaintext have already been released by then.

A fault that can be decided from metadata — a foreign format id, a wrap that
fails its tag — is caught before anything is sent and is a proper S3 error
document. Prefer that side of the line where you can.

## Ranged reads

A range is planned into a **window**: the segments that cover it, at most one
segment of over-read at each end. Only those segments are fetched and opened. The
window is computed without the data key, so a handler can issue the backend
request before it unwraps anything.

Two consequences worth knowing:

- A ranged read authenticates only its own window. Damage elsewhere in the object
  is invisible to it. This is inherent to any per-segment format and is pinned by
  a test so nobody "fixes" it by reading more than was asked for.
- A range that does not reach the end never sees the trailer, so it cannot check
  the object's authenticated total length.

## Testing convention for this package

Every crypto-carrying change here gets a **mutation round** before it is called
done: introduce deliberate defects, one at a time, and confirm the tests catch
each one. A green suite on freshly written cipher code is not evidence. The
codec's first round caught 4 of 8 injected defects, and the tests were
strengthened until a second round of 14 caught all 14.
