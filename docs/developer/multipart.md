# Multipart uploads

Two things share the name. The **internal producer** is the proxy uploading a
large or unbounded body as a multipart upload the client never sees. The
**client-driven** upload is a client issuing the multipart verbs itself. They
produce identical bytes; only the part boundaries differ, and the format leaves
no trace of them.

The rules and their reasoning are
[ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md). This page is the part
that bit us.

Every key both paths depend on lives under `optimizations`:

| Key | Value | What it decides |
|---|---|---|
| `streaming_segment_size` | `12582912` # default | one part on the producer path |
| `multipart_upload_concurrency` | `4` # default | parallel `UploadPart` workers, and with it the memory bound |
| `multipart_short_part_buffer_size` | `67108864` # default | what one client-driven session may hold |
| `multipart_session_cleanup_interval` | `300` # default | seconds between session sweeps, `0` disables the sweeper |
| `multipart_session_max_age` | `3600` # default | seconds a session may live |

## The internal producer

`putObjectAutoMultipart` in `internal/proxy/handlers/object/operations.go`. A PUT
reaches it when the plaintext length is undeclared or larger than one part; the
routing is in [request-paths.md](request-paths.md).

It reads plaintext into a bounded pool of buffers, and upload workers seal each
part while they send it, so receiving, sealing and sending overlap. Parts are
`streaming_segment_size` bytes; the trailer rides the last one, so this path
spends no extra part number.

The bound on the pool is what keeps memory flat: one buffer per worker plus the
one being filled, so `multipart_upload_concurrency + 1` parts are resident —
60 MiB at the defaults. Changing the worker count changes the memory budget.

Ten thousand parts is the ceiling S3 sets and the producer enforces, so the
largest object this path writes is `streaming_segment_size` × 10000: 117 GiB at
the default.

**A part size that is not a multiple of the segment size fails every large
upload** — on the first part, before anything is stored, with `500 UploadError`.
ADR 0011 D7 wants that caught at startup instead; the check does not exist, so
the cost of a mistyped `streaming_segment_size` is one aborted transfer per PUT
rather than a proxy that refuses to start. The rule it violates is in
[storage-format.md](storage-format.md).

**A client that hangs up mid-body must not commit.** `io.ReadFull` reports a
truncated stream the same way it reports a clean end of it, and an object the
producer sealed short verifies perfectly against its own trailer — a silently
truncated backup that passes every check. So the producer compares what it
received against the length the client declared and aborts the upload when it
falls short. The comparison uses `Parser.PlaintextContentLength`, which reports
*unknown* for an aws-chunked body without `X-Amz-Decoded-Content-Length` rather
than handing back a wire length that counts framing.

Every abort here runs on a context of its own (`utils.CleanupContext`). The
request context is already cancelled in exactly the case where the abort matters
most, and the parts would otherwise stay at the backend.

## The client-driven upload

`internal/orchestration/segmented_session.go`, driven by
`internal/proxy/handlers/multipart/`.

One client part becomes exactly one backend part. Nothing waits for anything: a
part is bound to its own segment indices, so a part that arrives before its
predecessors is sealed and stored where it belongs.

The part body is read into memory whole before it is sealed, then sealed as the
backend request drains it. The resident cost of this path is therefore one part
per request in flight, plus the one short part a session may hold.

### The part table is the authority

Complete is built from the proxy's own table, not from the ETags in the client's
XML — those describe ciphertext the proxy produced, and the trailer makes one of
them stale. The client's document **is** parsed and its part set checked against
the table; a mismatch is `InvalidPart` and the upload survives it, so the client
can complete again with a correct list. A part table that is not a chain is
`InvalidPart` too, but that one aborts the backend upload and drops the session.

### Five things that are not obvious

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
what makes inferring safe at all. It is not what makes the upload succeed, and
one shape still fails: **a last part that is segment-aligned, at or above 5 MiB
and smaller than the part size counts as a possible middle part.** Sealed before
part 1, it sets the inferred size to its own length and takes an offset computed
from that; the larger parts then raise the inference, its recorded offset stays
where it was, and Complete refuses the layout. Reproduced against
`SegmentedSession` directly — parts of 10, 10 and 6 MiB sealed in the order
3, 1, 2 end in `ErrPartTableInvalid`, the same parts in order complete cleanly. A
30 MiB object cut into 8 MiB parts ends in exactly that shape, so ordinary
concurrent uploaders reach it. Neither
`TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst` nor
`TestMpuPartsUploadedOutOfOrder` covers it: both end in a short part, which is
the case that works.

**The trailer's part number is reserved** (2026-09-11). A client-driven upload
has 9999 usable numbers, and part 10000 is answered `400 InvalidArgument` naming
the reason when the part is sent — not at Complete, after every byte has been
transferred. `ErrPartNumberReserved` in `segmented_session.go` carries it. The
pass-through provider keeps all 10000: there the backend owns the part layout and
nothing of the proxy's goes behind the client's last part.

### What Complete checks

Contiguous part numbers from 1; every part but the highest at the offset its
number implies; every part but the highest of the same size, and that size a
multiple of the segment size. A violation is `InvalidPart` and the upload is
aborted, so no object is created with a layout the read path cannot verify.

### Back pressure

A second short part in one session can never complete, so it is refused at upload
time with `EntityTooSmall`. A short part that exceeds
`multipart_short_part_buffer_size` answers `SlowDown` (503) — back pressure an SDK
retries, not a refusal; the upload stays open.

Note the bound is **per session**, not global across sessions, which is narrower
than ADR 0011 D5 describes.

### A session outlives its request, so something has to end it

A session is created at `CreateMultipartUpload` and lives in the `Manager` until
Complete or Abort drops it. It holds the object's data key and, once a short last
part arrives, that part's plaintext — plaintext, not the ciphertext ADR 0011 D5
describes; it is sealed at Complete. So an upload nobody finishes is memory that
never comes back, with key material and a piece of the object in the heap.

`CleanupExpiredSegmentedSessions` sweeps them from the manager's background
goroutine every `multipart_session_cleanup_interval` seconds, dropping every
session older than `multipart_session_max_age`. Two things about it are worth
knowing:

- **The age is measured from creation, never refreshed.** An upload still running
  after `multipart_session_max_age` loses its session and every further part
  answers `NoSuchUpload`. Sizing that key is sizing the longest upload a client
  may take, not its longest idle gap.
- **The goroutine used to sweep the wrong map.** It swept the pre-segment session
  map, which is always empty, while the live sessions had a sweeper nothing
  called — so every abandoned upload leaked for the lifetime of the process. It
  now sweeps the live map, and `Manager.Shutdown` — reached through
  `Server.Shutdown` from `main` — stops it on the way out.

The sweeper starts only when `multipart_session_cleanup_interval` is greater than
zero. Setting it to zero leaves nothing to reclaim an abandoned session.

### The two listing verbs

`ListParts` is answered **from the session part table** (2026-09-11, ADR 0011 D6).
The backend cannot answer it: its part sizes are stored sizes, its ETags are over
ciphertext the proxy produced, and the object's last part may still be held in the
session rather than uploaded. So each `<Part>` carries the plaintext length the
client sent (ADR 0010) and the ETag `UploadPart` answered with — the held part
included, because the client uploaded it and was given an ETag for it.
`part-number-marker` and `max-parts` are honoured, `max-parts` clamped at 1000, and
a value that is not a non-negative number is `400 InvalidArgument`. An upload id
with no session, or one whose session names another bucket or key, is
`404 NoSuchUpload`. Until 2026-09-11 the verb answered a fabricated, always-empty
document with `200` for any upload id at all.

Under the exit provider the proxy keeps no part table, so `ListParts` is forwarded
and the backend's sizes are the client's own bytes.

`ListMultipartUploads` is **forwarded** (2026-09-11). It names uploads rather than
bytes, so nothing in it has to be converted; the document is still the proxy's
own, and `<Owner>` and `<Initiator>` name the calling client rather than the
account the proxy holds credentials for (ADR 0008).

`UploadPartCopy` answers `422 NotSupportedWithEncryption`, deliberately, because
the copy would run inside the backend where the proxy has no plaintext
(ADR 0011 D9).

## Under the exit provider there is no session at all

`type: exit` passes through on every path, this one included. Create, UploadPart
and Complete ask `IsExitProvider` before they do anything else; Abort needs no
branch, because it only forwards and then deletes a session key that was never
registered:

| Verb | What happens |
|---|---|
| `CreateMultipartUpload` | No `SegmentedSession` is built and none is registered. The upload is created with the client's own user metadata (`s3ep-*` headers still dropped), so the backend holds a plain upload |
| `UploadPart` | `uploadPassThroughPart`: the part goes to the backend exactly as it arrived, and the backend's ETag is answered. No part table, no short-part buffer |
| `CompleteMultipartUpload` | The completed-part list is built from the **client's** list, sorted by part number, because the proxy owns no part table to build it from. Nothing is sealed, no closing record is written, and the backend is what validates the list |
| `AbortMultipartUpload` | Forwarded; there is no session to close |

Two consequences worth having in your head before you change any of it. The part
rules of this page are the proxy's, and they exist because the proxy owns the
part layout — under `exit` it does not, so the 64 KiB-multiple rule does not
apply and a client meets the backend's own rules instead. And the object that
comes out is a plain object: on the way back it is served verbatim, because
`serveWholeObject` decides from the object's metadata rather than from the
provider.

Everything above this section describes the encrypting path and is unchanged by
`exit`; the routing side is in [request-paths.md](request-paths.md).
