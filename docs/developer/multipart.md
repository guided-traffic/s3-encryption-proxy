# Multipart uploads

Two things share the name. The **internal producer** is the proxy uploading a
large or unbounded body as a multipart upload the client never sees. The
**client-driven** upload is a client issuing the multipart verbs itself. They
produce identical bytes; only the part boundaries differ, and the format leaves
no trace of them.

The rules and their reasoning are
[ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md). This page is the part
that bit us.

## The internal producer

`putObjectAutoMultipart` in `internal/proxy/handlers/object/operations.go`.

It reads plaintext into a bounded pool of buffers, and upload workers seal each
part while they send it, so receiving, sealing and sending overlap. Parts are
`streaming_segment_size` bytes; the trailer rides the last one, so this path
spends no extra part number.

The bound on the pool is what keeps memory flat: one buffer per worker plus the
one being filled. Changing the worker count changes the memory budget.

## The client-driven upload

`internal/orchestration/segmented_session.go`, driven by
`internal/proxy/handlers/multipart/`.

One client part becomes exactly one backend part. Nothing waits for anything: a
part is bound to its own segment indices, so a part that arrives before its
predecessors is sealed and stored where it belongs.

### The part table is the authority

Complete is built from the proxy's own table, not from the ETags in the client's
XML — those describe ciphertext the proxy produced, and the trailer makes one of
them stale. The client's document **is** parsed and its part set checked against
the table; a mismatch is `InvalidPart` and the upload survives it, so the client
can complete again with a correct list.

### Four things that are not obvious

**A part is held when it is short *or* unaligned.** A part that does not cover
whole segments cannot be stored on its own — a short segment inside a chain
writes cleanly and never reads. But alignment is not enough: S3 refuses any part
but the last below 5 MiB, so a small-but-aligned part with the trailer behind it
makes the whole upload `EntityTooSmall`. Both conditions hold a part back.

**The trailer is a part, and a part has to be in the table.** When the client's
last part is large enough to stand on its own, the trailer goes as an extra part
of its own — and that part number has to be recorded, or the list Complete is
built from leaves it out, the backend drops it, and the object stores cleanly and
fails to authenticate on the first read.

**A held part still needs an ETag.** Nothing is stored yet, so there is no
backend ETag, but an SDK puts the value into its Complete request and an empty
one is refused. The proxy answers with a value derived from the part — so a retry
of the same bytes answers the same value — and replaces it with the backend's
once the part is stored.

**The part size is inferred, and the inference must survive arrival order.** The
size is taken from the largest part *that could be a middle part*; a short last
part never contributes. A held part takes its offset at Complete, not on arrival.
Both are necessary because a client that puts all its parts in flight at once —
which every uploader does — regularly delivers the short last part first. ADR 0011
assumed part 1 is *dispatched* first, which is true; dispatch is not arrival.

A wrong inference is always a refusal at Complete, never a stored object. That is
what makes inferring safe at all.

### What Complete checks

Contiguous part numbers from 1; every part but the highest at the offset its
number implies; every part but the highest of the same size, and that size a
multiple of the segment size. A violation is `InvalidPart` and the upload is
aborted, so no object is created with a layout the read path cannot verify.

### Back pressure

A second short part in one session can never complete, so it is refused at upload
time with `EntityTooSmall`. A short part that exceeds
`optimizations.multipart_short_part_buffer_size` answers `SlowDown` (503) — back
pressure an SDK retries, not a refusal; the upload stays open.

Note the bound is **per session**, not global across sessions, which is narrower
than ADR 0011 D5 describes.
