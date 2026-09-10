# Ticket 012: Performance Improvements Round 2 — Post-010 Audit Findings

## Status (2026-09-10)

**Open, and most of what it described is gone.** Six items are closed (1.1, 1.3,
1.4, 3.1, 3.2 and, since 2026-09-10, both halves of 3.3), **two are obsolete**
because their
subject no longer exists (5.1, 5.2), and thirteen carry work — 1.2, 2.0's
measurement, 2.1, the second half of 2.2, the last copy in 2.3, 4.1, 4.2, 4.3 and
the five measurement items of Tier 6. Everything this ticket said about a
two-cipher tree — AES-CTR streaming, AES-GCM whole objects, envelope encryption,
whole-object HMAC and the four `integrity_verification` modes — is void: the
stored format is one authenticated segment chain ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)),
and the deletion round of 2026-09-10 removed the code and the configuration keys
most of Tier 1, 2 and 5 were written against.

**Re-checked 2026-09-10 against the two changes that landed after it: the listing
rewrite ([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)) and
the exit provider ([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)).**
The List half of 3.3 closed with the first. The second closed nothing here; it
changed the shape of two items. The read path now branches **per object** — an
object this proxy sealed is decrypted, one stored plain is passed through
([operations.go:66-73](../../internal/proxy/handlers/object/operations.go#L66)) —
so the GET copy of 4.2 sees two body shapes instead of one; the write paths branch
on the active provider ([operations.go:259](../../internal/proxy/handlers/object/operations.go#L259),
[:634](../../internal/proxy/handlers/object/operations.go#L634),
[upload.go:121](../../internal/proxy/handlers/multipart/upload.go#L121)), which
gave 2.1 a second caller of the fully buffered part body. 2.2 was re-verified line
by line and is unchanged. No item here named the `none` provider or any symbol the
exit provider renamed; the one place that named the type by role is 6.1's closing
note, corrected below.

The audit's own dates stay on the findings, because the *reasoning* is still what
justifies the work that is left. What is not left has been cut down to one line
each under [Closed — the record](#closed--the-record).

### Fate of every item

| Item | State | Evidence in the tree |
|---|---|---|
| 1.1 SDK flexible checksums | **Done** (`1e6c017`, F-4) | `WhenRequired` at [server.go:147-148](../../internal/proxy/server.go#L147) |
| 1.2 30 s `Read`/`WriteTimeout` | **Open**, decided ([ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)) | still 30 s at [server.go:115-116](../../internal/proxy/server.go#L115) |
| 1.3 dead code + per-GET Info logs | **Closed** by the format change and the 2026-09-10 deletion round | every named symbol greps to nothing; the surviving `.Info(` calls in `internal/orchestration` are startup and shutdown lines |
| 1.4 D-29 pooled copy buffer | **Done** 2026-09-07, including the ranged-read gap it reported | `writerOnly` at [helpers.go:71](../../internal/proxy/handlers/object/helpers.go#L71); [range.go:405](../../internal/proxy/handlers/object/range.go#L405) |
| 2.0 auto-multipart producer | **Fix landed** ([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md)); **the after-measurement is open** | free list + overlapping workers at [operations.go:700-751](../../internal/proxy/handlers/object/operations.go#L700) |
| 2.1 stream the client-driven `UploadPart` | **Open**, and it grew one branch | ciphertext `io.ReadAll` gone; [upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77) still materialises the whole part, validation still runs after it, and the exit provider's pass-through part is handed the same buffer |
| 2.2 destructive body-sniff | **Half done** | aws-chunked detection is header-based ([parser.go:49](../../internal/proxy/request/parser.go#L49)); the HTTP `Transfer-Encoding` half still exists, behind a predicate that can never fire ([parser.go:56-66](../../internal/proxy/request/parser.go#L56)) |
| 2.3 exact-size part buffers | **Mostly done; one measured defect left** | auto-multipart pool at [operations.go:702-705](../../internal/proxy/handlers/object/operations.go#L702); `readAllSized` still allocates twice ([parser.go:73-87](../../internal/proxy/request/parser.go#L73)) |
| 3.1 metadata at initiate, self-copy removal, >5 GiB failure | **Closed** by the format change | `Metadata` in `CreateMultipartUploadInput` ([operations.go:651](../../internal/proxy/handlers/object/operations.go#L651), [create.go:118](../../internal/proxy/handlers/multipart/create.go#L118)); no `CopyObject` call anywhere in `internal/` |
| 3.2 Range GET | **Done** (`df12c84`, F-6), reimplemented under the segment chain | [range.go](../../internal/proxy/handlers/object/range.go), `OpenSegmentedRange` |
| 3.3 HEAD/List size | **Done** — HEAD (`646932b`, F-7), List (`d696763`, [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)) | `PlaintextSize` at [operations.go:360](../../internal/proxy/handlers/object/operations.go#L360) and [listing.go:31](../../internal/proxy/handlers/bucket/listing.go#L31) |
| 4.1 backend transport defaults | **Open**, unchanged | bare `http.Transport` at [server.go:160-169](../../internal/proxy/server.go#L160) |
| 4.2 fill before writing to the client | **Open**, premise changed twice | one 64 KiB segment per read for an encrypted object, the raw backend body for an exit-provider one |
| 4.3 `GOMEMLIMIT` | **Open**, decided ([023](023-major-v5.md) D8) | set nowhere: no `GOMEMLIMIT` in compose, chart or `Containerfile` |
| 5.1 GCM GET unwraps the DEK twice | **Obsolete** | `pkg/encryption/envelope` is gone; exactly one, cached, unwrap at [segmented.go:257](../../internal/orchestration/segmented.go#L257) |
| 5.2 GCM `[]byte` fast path | **Obsolete** | `dataencryption/aes_gcm.go` is gone; the segment codec is one buffer per segment by construction |
| 6.1 baseline without backend TLS | **Half done** | `s3_backend.use_tls` deleted; the baseline was never run; no scheme check in [config.go](../../internal/config/config.go#L262) |
| 6.2 parallel-stream benchmark | **Open**; the local baseline suite covers part of it | `test/perf/` |
| 6.3 small-object / high-QPS benchmark | **Instrument done, ceiling measured, attribution open** | `test/perf/smallobject_test.go` |
| 6.4 block/mutex profiles | **Open** | `SetBlockProfileRate` and `SetMutexProfileFraction` appear nowhere in the tree (grep, 2026-09-10); the harness captures CPU and heap only ([memory_test.go:228-231](../../test/perf/memory_test.go#L228)) |
| 6.5 part-size × concurrency sweep | **Open** | no sweep instrument in `test/perf/` |

---

## Context, and what survives of it

Ticket [010](010-performance-improvements.md) finished with upload ~80 MB/s,
download ~120 MB/s (1 GB, local MinIO loopback), proxy alloc_space 9.94 GB per
1 GB round-trip, and `io.ReadAll` at 64.6 % of alloc_space on the upload path.
**Those numbers were taken on the format that no longer exists** — they are
history, not a baseline. The baseline that counts is the local suite of
[ADR 0020](../adr/0020-performance-is-measured-before-and-after.md), recorded
under `perf-baseline/`.

Two structural observations from the audit are still true of this tree:

1. **The 1 GB benchmark exercises the client-driven multipart handler**
   ([upload.go](../../internal/proxy/handlers/multipart/upload.go)), not the
   proxy's own producer: the benchmark client is `manager.NewUploader` with
   `PartSize` 5 MB
   ([performance_test.go:170-174](../../test/integration/performance-test/performance_test.go#L170)),
   so it drives `UploadPart` requests. That handler is the one item 2.1 is about.
2. **A "crypto floor" measured against an HTTPS backend includes the backend TLS
   hop.** In the 010 profiles ~10 of the 42 points were `crypto/tls` record AEAD,
   not object crypto. Item 6.1 exists to measure the difference once.

---

## Measurement protocol

Superseded by the local baseline suite ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) D17-D22,
`test/perf/`, `make perf-baseline`). It measures a proxy leg against a
direct-to-backend leg in the same run, captures a CPU and a heap profile of the
proxy, records the machine and writes the run under `perf-baseline/`. The
per-tier `docker run --network container:proxy curlimages/curl …` recipe this
ticket used to carry is gone with it; the suite does that itself
([memory_test.go](../../test/perf/memory_test.go), `pprof` on `127.0.0.1:6060`
inside the container).

Two rules from that ADR bind every item below:

- Before and after are run **on the same machine and the same power source**;
  the recorded three-leg run was taken on battery and is comparable only with
  itself.
- No performance claim is made for 5.0.0 until an *after* run exists. The
  newest recorded run (`perf-baseline/20260910T090543Z-530472c/`) is the *before*
  column for the format change, the producer restructuring and the removal of the
  self-copy, which all landed in one commit.

---

## Still open

### 1.2 Replace the 30 s blanket HTTP timeouts

**Decided 2026-09-07** ([023](023-major-v5.md) decision 10), specified in
[ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md),
**not implemented**. Rides 5.0.0.

`ReadTimeout: 30s` / `WriteTimeout: 30s`
([server.go:115-116](../../internal/proxy/server.go#L115)) are wall-clock budgets
for the ENTIRE body read / response write, not for a stalled one. A 5 GB GET at
120 MB/s takes ~42 s → connection reset mid-stream. Effective object-size cap =
30 s × client bandwidth (~3.6 GB at 1 Gbps, ~375 MB at 100 Mbps). Benchmarks pass
only because a 12 MiB part finishes in well under a second. **This is a
correctness bug for any S3 client moving a large object over a real link**:
`velero backup download` streams one large tarball and dies on `WriteTimeout`; a
node-agent (kopia) upload over a slow link that moves less than one part per 30 s
dies on `ReadTimeout`. The same 30 s used to cancel the post-completion metadata
self-copy as well; that half is gone twice over — the copy runs on
[`utils.CleanupContext`](../../internal/proxy/utils/utils.go#L90) and the format
change removed the copy entirely.

- [ ] `ReadHeaderTimeout: 30 * time.Second`, keep `IdleTimeout: 60s`
- [ ] Drop `ReadTimeout` / `WriteTimeout`
- [ ] Slow-loris protection: extend per-connection deadlines per copy iteration
      via `http.NewResponseController` in the object handlers, on BOTH `r.Body`
      reads and response writes. **The blocker is cleared**: both response-writer
      wrappers now declare `Unwrap`, `FlushError`, `Flush` and `Hijack`
      ([logging.go:73-99](../../internal/proxy/middleware/logging.go#L73),
      [middleware.go:29-55](../../internal/monitoring/middleware.go#L29)), which
      they did not when this item was written
- [ ] Remove the second, hard-coded 30 s deadline: the server drain at
      [server.go:222](../../internal/proxy/server.go#L222) runs under
      `context.WithTimeout(…, 30*time.Second)` inside a wait loop that already
      honours `shutdown_timeout`
      ([main.go:234-237](../../cmd/s3-encryption-proxy/main.go#L234)), so a
      configured 120 s cannot do what it says
- [ ] Chart: set `terminationGracePeriodSeconds` = `shutdown_timeout` + 5. It is
      absent from every template today, so Kubernetes kills at 30 s whatever the
      budget says; compose already has `stop_grace_period: 45s`
- [ ] Integration test: a GET/PUT that takes > 30 s (rate-limited reader) survives

**Expected impact:** availability fix, zero loopback throughput change. Must-fix
before any real-network or > 3 GB object claim.

### 2.0 The proxy-driven auto-multipart producer — fix landed, measurement outstanding

The producer was the bigger half of Tier 2 and it has been restructured
([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md), landed
2026-09-10): a free list of `multipart_upload_concurrency + 1` part buffers
([operations.go:702-705](../../internal/proxy/handlers/object/operations.go#L702)),
the producer filling one while workers seal and send the others
([operations.go:725-751](../../internal/proxy/handlers/object/operations.go#L725)),
the buffer returned only after the backend call returns.
The routing premise this item was written under is also gone: there is no
`streaming_threshold` and no integrity mode to switch on — a PUT goes to the
producer when its plaintext length is unknown or larger than one part
([operations.go:236-241](../../internal/proxy/handlers/object/operations.go#L236)).
The producer runs under the exit provider too; only the sealing step is skipped
([operations.go:634](../../internal/proxy/handlers/object/operations.go#L634)), so
the free list and the worker fan-out this item measures are the same on both.

What was measured before the change, and why the fix took the shape it did, is in
ADR 0024's Context: three legs (direct backend, proxy streaming write path, proxy
auto-multipart) at 8/12/16 MiB, plus a size sweep from 8 to 256 MiB that put the
deficit at 1.96× on one part and 1.45× from six parts up, with the self-copy, the
extra hop, the cipher and the integrity pass each ruled out as the cause. The raw
record is `perf-baseline/20260910T090543Z-530472c/`, still the newest run
(`perf-baseline/LATEST`) — it now predates the listing rewrite and the exit
provider as well, so the *after* run covers all three changes at once.

- [ ] **Re-run the three-leg comparison** (`make perf-baseline`, same machine,
      same power source) and record the *after* column. Until it exists no upload
      gain may be stated for 5.0.0 (ADR 0024 D7, ADR 0020 D1/D4)
- [ ] Verify the implementation against ADR 0024 D1 while doing it: the producer
      still fills a whole part with `io.ReadFull` before it seals and dispatches
      it ([operations.go:792](../../internal/proxy/handlers/object/operations.go#L792)),
      so receiving and sending overlap *across* parts (D2) but not *within* one.
      D1 asks for both. Whether the remainder is worth closing is a measurement
      question, which is what the run above answers
- [ ] Fallback if the measurement does not move: take the block profile (item
      6.4). No profile has ever been taken under this load

### 2.1 Stream the client-driven multipart `UploadPart` handler

**File**: [upload.go](../../internal/proxy/handlers/multipart/upload.go)

The format change rewrote this handler (one client part → one backend part, sealed
by `SegmentedSession.SealPart`) and removed two of the four copies the audit
found: the ciphertext `io.ReadAll` is gone, and so is the 12 MiB pre-sized
`processPartOrdered` buffer. **What is left is the first copy, the ordering defect
and, since the exit provider, a second branch that wants the same treatment:**

1. [upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77)
   `Parser.ReadBody` materialises the whole part before anything else happens,
   and [SealPart](../../internal/orchestration/segmented_session.go#L148) takes
   `plaintext []byte`, so streaming the part needs an entry point that takes a
   reader. Segments are independent, so nothing in the format prevents it
2. `ReadBody` still runs **before** the uploadId/partNumber checks
   ([upload.go:87-108](../../internal/proxy/handlers/multipart/upload.go#L87)) and
   before the session lookup
   ([upload.go:125](../../internal/proxy/handlers/multipart/upload.go#L125)):
   an unknown upload or an out-of-range part number still buffers the full body
   first. Only a *non-numeric* part number is refused early, and that happens one
   layer up ([handler.go:151-164](../../internal/proxy/handlers/object/handler.go#L151))
3. Nothing bounds one part: `readAllSized` caps the *pre-allocation* at 32 MiB
   ([parser.go:16](../../internal/proxy/request/parser.go#L16)) but the buffer
   still grows to whatever the client sends
4. **New with the exit provider** ([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)):
   a second consumer of the same buffered part. Under `exit` the handler branches
   to `uploadPassThroughPart` with the same `bodyData`
   ([upload.go:121-124](../../internal/proxy/handlers/multipart/upload.go#L121)),
   and that branch has nothing to seal — the body could go to the backend as it
   arrives, with `DecodedContentLength(r)` as the length. Whatever entry point
   this item builds has to serve both branches, and the pass-through one is the
   cheaper of the two to convert

- [ ] Move the uploadId/partNumber validation and the `SegmentedSession` lookup
      **before** any body read
- [ ] Give the session a reader-based entry point and feed it
      `requestParser.StreamingReader(r)` with `DecodedContentLength(r)` as the
      length; keep the exact-size single read for the short-last-part case, which
      has to be retained anyway (ADR 0011)
- [ ] Cap what one request may buffer, from the same bound the short-part buffer
      uses (`multipart_short_part_buffer_size`), so a client-supplied
      `X-Amz-Decoded-Content-Length` cannot size the allocation on its own
- [ ] Re-verify peak RSS with 8 concurrent part uploads afterwards

### 2.2 The HTTP `Transfer-Encoding` decoder, second half

**Done half**: aws-chunked detection is header-based
([parser.go:49](../../internal/proxy/request/parser.go#L49), `isAWSChunkedRequest`),
`aws_chunked_decoder.go` and its destructive 1 KiB body sniff are deleted, and
`readAllSized` pre-sizes from the decoded length. The latent corruption bug the
sniff carried — `STREAMING-UNSIGNED-PAYLOAD-TRAILER` bodies have no
`;chunk-signature=`, so the sniff missed them and raw framing would have been
stored as object data — went with it.

**Open half, re-verified 2026-09-10 — neither of the two changes touched a line of
it.** `clean_http_transfer_chunked` (default **true**,
[config.go:246](../../internal/config/config.go#L246)) still routes every
non-aws-chunked body through `HTTPChunkedDecoder` when `RequiresChunkedDecoding`
says so ([parser.go:56-66](../../internal/proxy/request/parser.go#L56)) — a branch
that `io.ReadAll`s the body and re-parses the framing by hand, byte-at-a-time
`readLine` included. Who sets it today: `config/aes-example.yaml:90` and
`config/aes-tls-example.yaml:99` set `false`, `config/exit-example.yaml:98` (the
renamed pass-through example) sets `true`, `config/multi-example.yaml` does not
carry the key at all, and `test/e2e/velero/values-proxy.yaml:147` sets `false`.

**That branch is dead, and it is dead for a reason the audit did not name.**
`RequiresChunkedDecoding` tests `r.Header.Get("Transfer-Encoding")`
([http_chunked_decoder.go:27-29](../../internal/proxy/request/http_chunked_decoder.go#L27),
unchanged), and `net/http` moves that header into `r.TransferEncoding` and deletes
it from the map before a handler runs — verified against Go 1.27 with a chunked
request into
an `httptest` server: `r.Header.Get("Transfer-Encoding")` is `""` while
`r.TransferEncoding` is `[chunked]`. The predicate can therefore never be true on
a server-side request, whatever the setting says, and net/http has already
de-chunked the body anyway.

- [ ] Delete `RequiresChunkedDecoding`, `ProcessChunkedData`, `readLine`,
      `HTTPChunkedDecoder` ([http_chunked_decoder.go](../../internal/proxy/request/http_chunked_decoder.go))
      and `ChunkedDecoderBase` ([chunked_decoder.go](../../internal/proxy/request/chunked_decoder.go)),
      whose only user it is
- [ ] Remove `clean_http_transfer_chunked` from the config struct
      ([config.go:81](../../internal/config/config.go#L81)), the defaults
      ([config.go:246](../../internal/config/config.go#L246)) and the example
      configs that carry it. The deletion is already decided and names this key:
      [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)
      D9, whose own status block records it as the one key of that round still
      standing in the tree
- [ ] Integration: aws-chunked **signed** and **unsigned-trailer** variants
      end-to-end (the TLS suite is the only one that reaches the trailer decoder)

### 2.3 The last redundant part copy: `readAllSized` allocates twice

(a) and (c) of this item are closed — no oversized 12 MiB pre-size survives, and
the producer seals straight out of its own buffer with no `bufio` re-copy. **(b)
is still live and is now measured.**

`readAllSized` ([parser.go:73-87](../../internal/proxy/request/parser.go#L73))
pre-sizes a `bytes.Buffer` to the hint and then uses `Buffer.ReadFrom`, which
needs `MinRead` (512 B) of spare capacity before each read. A body that exactly
fills the hint therefore triggers one `grow()` on the final EOF-probing
iteration. Measured directly against `bytes.Buffer` (Go 1.27, hint 5 MiB, reader
returning exactly 5 MiB then EOF): **initial cap 5 242 880 → final cap
10 485 760** — a second, doubled allocation plus a full-body `memmove`, for every
`ReadBody` caller. A 5 MiB `UploadPart` costs 15 MiB of allocation.

- [ ] Replace the `bytes.Buffer` with `make([]byte, n)` + `io.ReadFull` when the
      hint is exact, keeping the growth path only for an absent hint (this is a
      few lines and is worth doing even if 2.1 lands: eight bucket XML handlers
      keep calling `ReadBody` — acl, cors, lifecycle, logging, notification,
      policy, tagging and versioning)
- [ ] Check the same shape in the aws-chunked branch, which passes
      `DecodedContentLength` as the hint

### 4.1 Stop discarding the SDK transport defaults on the `insecure_skip_verify` path

**File**: [server.go:160-169](../../internal/proxy/server.go#L160) — unchanged
since the audit.

When `insecure_skip_verify` is set (every shipped example config), the code swaps
in a bare `&http.Client{Transport: &http.Transport{TLSClientConfig: …}}`,
discarding the SDK's `BuildableClient` tuning and inheriting Go zero values:
`MaxIdleConnsPerHost = 2` while the producer runs `multipart_upload_concurrency`
(default 4) concurrent backend requests — surplus connections are closed when
idle and re-dialed with a full TLS handshake, no session cache — no
`IdleConnTimeout`, **no dial or TLS-handshake timeout at all**, 4 KiB transport
buffers.

- [ ] Build via `awshttp.NewBuildableClient().WithTransportOptions(...)`:
      **mutate** the existing `t.TLSClientConfig` (do not replace it — that keeps
      the SDK's `MinVersion=TLS1.2`), set `InsecureSkipVerify: true` and
      `ClientSessionCache: tls.NewLRUClientSessionCache(32)`
- [ ] `t.MaxIdleConnsPerHost = max(16, multipart_upload_concurrency)`,
      `t.MaxIdleConns = 64`, `t.IdleConnTimeout = 90s`,
      `t.ReadBufferSize = t.WriteBufferSize = 128 << 10`
- [ ] Decide `ForceAttemptHTTP2` explicitly (SDK default true; the current bare
      transport is HTTP/1.1-only, and HTTP/1.1 is what the backend leg keeps —
      set false to preserve it)
- [ ] Apply the same pooling values on the verified-TLS path
- [ ] Restores dial (30 s) and TLS-handshake (10 s) timeouts — a reliability fix
      as much as a performance one; both are unbounded today

**Expected impact:** zero on loopback (handshake CPU was 0.07 % there). On a real
networked TLS backend: no repeated TCP+TLS reconnects and slow-start restarts per
part batch, better tail latency.

### 4.2 Fill the 128 KiB pooled buffer before writing to the client (GET)

**File**: [helpers.go:73-83](../../internal/proxy/handlers/object/helpers.go#L73)

**The premise moved twice; the item is still open and the win is smaller than the
audit claimed.** The original reading was that the proxy→MinIO leg is TLS, so each
`body.Read` returned one ~16 KiB TLS record and `io.CopyBuffer` issued ~65k client
writes per GB. The segmented reader absorbed that: it fills its own
`SegmentSize + overhead` buffer with `io.ReadFull`
([segmented_gcm_io.go:189-196](../../pkg/encryption/dataencryption/segmented_gcm_io.go#L189)).
But it then hands back **at most one 64 KiB segment per `Read`** regardless of
`len(p)` ([segmented_gcm_io.go:171-186](../../pkg/encryption/dataencryption/segmented_gcm_io.go#L171)),
so the 128 KiB pooled buffer is only ever half filled: ~16k client writes per GiB
where 8k would do.

**Re-verified 2026-09-10 after the exit provider
([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)): the read path branches
per object, so this copy now sees two body shapes, not one.** Both reach the same
`copyWithPooledBuffer` — one whole-object call
([operations.go:186](../../internal/proxy/handlers/object/operations.go#L186)) and
one ranged call ([range.go:405](../../internal/proxy/handlers/object/range.go#L405)):

- an object this proxy encrypted → the segmented reader above, 64 KiB per `Read`,
  buffer half filled
- an object stored as the client sent it, served under `exit` → the backend body
  passed through unchanged
  ([operations.go:66-73](../../internal/proxy/handlers/object/operations.go#L66),
  [range.go:172](../../internal/proxy/handlers/object/range.go#L172)), which is
  the audit's *original* shape: each `Read` returns whatever the backend transport
  hands over, well under half the buffer

Fill-then-write therefore helps both branches, and the pass-through one more than
the encrypted one. The decision is still a measurement, and the benchmark has to
cover both shapes — a reader that returns 64 KiB chunks and one that returns
transport-sized chunks — or it measures only half the tree.

- [ ] Replace `io.CopyBuffer` in `copyWithPooledBuffer` with fill-then-write:
      keep reading `buf[filled:]` until at least half full (or EOF/error), then
      one `dst.Write`
- [ ] Preserve `io.Copy` semantics exactly: `(n>0, io.EOF)`, `n==0,err==nil`
      reads, and write already-filled bytes before propagating a read error —
      the tamper suite is the test that matters
      ([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)),
      because a short write on a corrupt object must still cut the body off at a
      segment boundary
- [ ] Measure it, on both body shapes. At 8k versus 16k syscalls per GiB the
      encrypted branch may not clear the noise; the pass-through branch starts
      from the ~65k writes per GB the audit measured. `BenchmarkGetResponseCopy`
      ([copy_bench_test.go](../../internal/proxy/handlers/object/copy_bench_test.go))
      is the instrument and its decision rule from 1.4 applies unchanged

The audit's two other sub-items are gone: `hmacValidatingReader` and the `bufio`
wrap in `singlepart.go` no longer exist.

### 4.3 `GOMEMLIMIT`

**Decided 2026-09-07** ([023](023-major-v5.md) decision 8), **not implemented**:
`grep -rn GOMEMLIMIT` over the compose file, the chart and the `Containerfile`
returns nothing.

Ship `GOMEMLIMIT` only: an explicit chart value (`runtime.goMemLimit`, rendered
as the container's `GOMEMLIMIT` env) and a compose env, default 80 % of the
memory limit — `400MiB` for the shipped 512 Mi
([values.yaml:85-87](../../deploy/helm/s3-encryption-proxy/values.yaml#L85),
[docker-compose.demo.yml:89](../../docker-compose.demo.yml#L89) and
[:134](../../docker-compose.demo.yml#L134), both proxy containers). `GOGC` stays at its default; `GOGC=off` is excluded while any
client-controlled full-body allocation exists (see 2.1). The `GOMAXPROCS` /
automaxprocs sub-item is **void**: the tree builds with Go 1.27 and since Go 1.25
the Linux runtime derives `GOMAXPROCS` from the cgroup CPU limit itself
(`GODEBUG=containermaxprocs`).

- [ ] Chart value + compose env, 80 % of the limit, documented next to it
- [ ] Gate: the memory instrument (`test/perf/memory_test.go`) and a benchmark
      re-run under the new value, on `feat/major-v5`, as the last step before the
      merge. No gain means the value is dropped rather than shipped

### 6.1 One-time baseline without backend TLS

**Half closed**: `s3_backend.use_tls` was dead config and is deleted (ADR 0013 D4);
the backend scheme comes solely from `target_endpoint`. The baseline itself was
never run, so ~10-16 % of proxy CPU in every recorded profile is still TLS
re-encryption towards a loopback MinIO with `insecure_skip_verify` — zero
endpoint-authentication value, and it is misread as object crypto.

- [ ] Compose override/profile with `target_endpoint: http://minio:9000` and a
      MinIO without `--certs-dir` (MinIO cannot serve both schemes from one
      process); fix the healthcheck and `MinIOEndpoint` in
      [minio_test_helper.go](../../test/integration/minio_test_helper.go)
- [ ] Run the baseline suite once on it and record the true data-crypto floor
- [ ] Keep TLS the default everywhere else; document the plaintext backend as a
      co-located-deployment option (SigV4 headers and bucket/key names travel in
      the clear on that hop)

Note the interaction: refusing an `http://` backend under an encrypting provider
is decided (ADR 0013 D5) but not implemented — the only endpoint check in
[config.go:262](../../internal/config/config.go#L262) is that the key is set —
and once it is, the **exit provider**
([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md), the type formerly called
`none`) is the only configuration that could still reach a plain-HTTP backend —
and it is the one leg that cannot answer this question, because under `exit`
nothing is sealed and the run would report transport cost with no object crypto in
it. So this measurement has to be taken before D5 is implemented; after that it
needs a decision of its own, which belongs in an ADR and not in this list. (ADR
0013 D5 still writes "pass-through provider" for what is now `exit`.)

### 6.2 Parallel-stream benchmark

**Partly instrumented.** The local baseline suite measures three concurrency
levels against a direct-to-backend leg in the same run, which answers the
*request-rate* question (that is 6.3). The *bulk* parallel variant is still open,
and so is the compose profile it needs.

- [ ] N = 4-8 objects concurrently, aggregate MiB/s reported, ~100-200 MiB each
- [ ] Bench-only compose profile that lifts the MinIO 2-CPU cap
      ([docker-compose.demo.yml:39-42](../../docker-compose.demo.yml#L39)) and the
      512 MiB proxy memory limit on **both** proxy containers — the cap is
      deliberate for reproducibility, so the default profile stays unchanged and
      the existing number series stays comparable
- [ ] Optional: run the client inside the compose network, removing Docker
      Desktop's host→VM forwarding from the measurement

### 6.3 Small-object / high-QPS benchmark — instrument done, and it found a ceiling

- [x] Benchmark at 1 / 16 / 64 KiB and concurrency 1, 8 and 32 with a
      direct-to-backend leg in the same run
      ([smallobject_test.go](../../test/perf/smallobject_test.go))
- [x] CPU and heap profiles captured during a run
- [ ] **Attribute the ceiling in those profiles.** The June hypothesis — fixed
      per-request cost (SigV4 canonicalisation in
      [s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go), the
      middleware stack, per-PUT DEK generation and KEK wrap), not bulk crypto —
      is supported by the shape of the numbers but has not been read off a profile

**Measured 2026-09-09** (Apple M5 Pro, 18 cores, demo stack, `aes` provider,
median of 7 repetitions; full record under `perf-baseline/`). **The proxy does not
get faster when the client asks for more at once**, while the backend behind it
scales 2.6×:

| 1 KiB GET, plain HTTP | c1 | c8 | c32 |
|---|---:|---:|---:|
| proxy | 1778 ops/s | 2357 ops/s | 1930 ops/s |
| direct MinIO | 2974 ops/s | 8304 ops/s | 7835 ops/s |
| ratio | 60 % | 28 % | 25 % |

TLS behaves identically (1766 / 2108 / 1952 against 2957 / 8363 / 7548), so it is
not a transport effect. At 64 KiB the proxy runs 1100-1176 ops/s at c1 and
1539-1761 at c8/c32 — 69 to 110 MiB/s, far below what the same proxy sustains on
one large stream and far below the crypto floor. **It is a per-request
serialisation, not a throughput limit.** The PUT rows are noisy in exactly the
cells that would carry a shape, so nothing is claimed from them; the GET rows
scatter 2.6-8.4 % at c1 and c8, and the widening gap is the finding.

This measurement was taken on the format that has since been replaced, and the
listing rewrite and the exit provider have landed since as well. It is the number
the remaining per-request items are about, and it needs re-taking on the current
tree before it is used as a before-column.

### 6.4 Block/mutex profiles

`runtime.futex` 5.28 % flat and `findRunnable` 9.18 % cum were unattributed in the
010 profiles. `SetBlockProfileRate` / `SetMutexProfileFraction` are still called
nowhere, so `/debug/pprof/block|mutex` return empty profiles, and the baseline
harness captures only CPU and heap
([memory_test.go:228-231](../../test/perf/memory_test.go#L228)).

- [ ] Config-gated `runtime.SetBlockProfileRate` / `SetMutexProfileFraction`,
      at `monitoring.NewPprofServer`
      ([main.go:202](../../cmd/s3-encryption-proxy/main.go#L202)) — the
      profiling listener is loopback-only, which is where this belongs (ADR 0013),
      not beside the monitoring port
- [ ] Capture block+mutex plus a 5-10 s `go tool trace` under the producer load;
      suspects: the logrus shared mutex, the segmented-session map, upload workers
      idling behind the producer's per-part read
- [ ] This is what answers item 2.0's remaining question with data instead of a
      substitution argument

### 6.5 Part-size × concurrency sweep

Defaults (12 MiB `streaming_segment_size`, 4 `multipart_upload_concurrency`) were
never swept; both knobs exist and the producer's in-flight memory is
`(concurrency + 1) × part size` by construction
([operations.go:702-705](../../internal/proxy/handlers/object/operations.go#L702)),
on top of `multipart_short_part_buffer_size` per client-driven session.

- [ ] Sweep {8, 16, 32, 64 MiB} × concurrency {4, 8, 16} on loopback AND against
      a latency-injected backend (tc netem or real S3)
- [ ] Record the throughput/RSS curve; update the defaults and the README sizing
      formula from it

---

## Closed — the record

**1.1 SDK flexible checksums — `1e6c017` (F-4), 2026-09-05.** The comment said
"disable" while the code set `…WhenSupported`, which *enables* CRC32 over every
uploaded body and forces `ChecksumMode` on every GET (CRC64-NVME, ~8000 rebuilds
of a 16 KiB slicing-by-8 table per GB, because that polynomial is not
stdlib-cached): `crc64.update` 3.90 % + `makeSlicingBy8Table` 1.16 % +
`crc32.ieeeUpdate` 0.8 % ≈ **5.9 % flat proxy CPU**, a third integrity pass over
data the format already authenticates. Both are `WhenRequired` today
([server.go:147-148](../../internal/proxy/server.go#L147)). It landed for a
correctness reason rather than this one — the SDK failed outright against a
plain-HTTP backend on an unseekable ciphertext stream — and the predicted CPU
saving was never measured. The optional knob to put SDK CRC back was dropped:
the mode it served does not exist any more.

**The "related bug" underneath this item was refuted, not fixed. Do not re-open
it.** No response path ever emitted a `Checksum*` header on any backend:
responses are composed from an allowlist, asserted by
`TestWriteGetObjectResponse_EmitsOnlyTheAllowlist` and `assertNoChecksumHeaders`
([object_test.go:398-473](../../internal/proxy/handlers/object/object_test.go#L398)).
The trap that produced it: an SDK output struct carrying `Checksum*` fields is
not evidence that a header reaches the wire.

**1.3 Dead code and per-GET Info logs — closed by the format change and the
2026-09-10 deletion round.** Every subject is gone: the five Info-level entries
per HMAC-validated CTR GET, the constant-false `%T` sniff in
`writeGetObjectResponse`, `shouldValidateHMACEarly` / `validateHMACEarly`, and
the ~250 unreachable lines of `DecryptMultipartWithHMACVerification`,
`createStreamingDecryptionReader` and `hmacGatedDecryptionReader`. Grep for any
of those names returns nothing; the `.Info(` calls left in `internal/orchestration`
are provider registration, startup and shutdown.

**1.4 D-29, the pooled copy buffer — done 2026-09-07, and the premise it was
filed under was wrong.** 024 P-2 reported that the pooled 128 KiB buffer was used
only with monitoring enabled, because `io.copyBuffer` prefers `dst.ReadFrom`.
`s3Router.Use(s.loggingMiddleware)` is unconditional and that middleware wraps
every S3 response in its own `responseWriter`, so `dst` hid `io.ReaderFrom` in
both monitoring modes and the pooled buffer was always used. The flag-dependence
did not exist. What was real, and twice as broad: both wrappers dropped `Unwrap`,
`Flush` and `Hijack` on **every** S3 route, so `http.NewResponseController` had
never worked on this proxy — the thing that blocks item 1.2's per-transfer write
deadline. (One smaller correction: `io.copyBuffer` checks `src.(io.WriterTo)`
*before* `dst.(io.ReaderFrom)`; the item had the order backwards. No type here
implements `WriteTo`, so the source side is not live — a future body type that
grows one bypasses the pooled buffer from the other direction.)

What was done: `copyWithPooledBuffer` wraps `dst` in an unexported `writerOnly`
so the pooled buffer is the copy path by construction rather than by accident of
middleware composition; `Unwrap`, `FlushError`, `Flush` and `Hijack` were added to
both wrappers (`FlushError` as well as `Flush`, because `http.ResponseController`
prefers it and a bare `Flush` would swallow the error); neither wrapper declares
`ReadFrom`, and a test asserts that it stays undeclared.
`BenchmarkGetResponseCopy` had to be written — no benchmark could resolve a
response-buffer change, and after the wrapper the `ReadFrom` path is unreachable
through the server in every configuration, so the A/B does not exist as a
deployment. Apple M1 Ultra, `-benchtime 20x -count 6`, 64 MiB body, `httptest`
over loopback, mean MB/s ± sd:

| cell | MB/s | ±sd | B/op | allocs/op |
|---|---|---|---|---|
| `h1/readfrom/no-wrapper` | 4204 | 222 | 48 304 | 83.0 |
| `h1/readfrom/forwarding-wrapper` | 4348 | 174 | 48 693 | 83.8 |
| `h1/pooled32k/wrapper` | 4381 | 224 | 15 373 | 79.2 |
| **`h1/pooled128k/wrapper`** | **4585** | 177 | 31 863 | 79.2 |
| `h1/pooled512k/wrapper` | 4283 | 276 | 102 084 | 79.2 |
| `tls/readfrom/no-wrapper` | 1593 | 38 | 33 142 | 121.5 |
| `tls/pooled128k/wrapper` | 1525 | 48 | 59 729 | 123.2 |

The decision rule was fixed before the run: keep the pooled buffer unless a
`ReadFrom` cell beats the 128 KiB pooled cell by more than 3 % in MB/s *and* does
not lose on allocations, in the plain-HTTP/1 cell — the only cell where `ReadFrom`
can differ at all. It does not: the pooled 128 KiB buffer is **8.3 % faster and
allocates a third less**, and the shipped size is the right one (32 KiB is 4.4 %
slower, 512 KiB 6.6 % slower and allocates three times as much). `httptest` over
loopback exaggerates syscall cost, which is the right bias for this question and
the wrong instrument for absolute MB/s. The ranged-read response that this work
reported as the one GET copy still using a bare `io.Copy` now uses the pooled
buffer too ([range.go:405](../../internal/proxy/handlers/object/range.go#L405)).

**3.1 Multipart completion — closed by the format change, and without the scheme
this ticket proposed.** Both completion paths used to issue a self-`CopyObject`
with `MetadataDirective=REPLACE` after `CompleteMultipartUpload`: a full
server-side rewrite, write amplification ×2, and a hard 5 GiB cap that made every
multipart upload above 5 GiB fail *after* all bytes had been transferred and the
upload committed, leaving an object no client could decrypt. All of it is gone:
the object's encryption metadata is complete before the backend is asked to open
the upload, so it travels in `CreateMultipartUploadInput.Metadata`
([operations.go:651](../../internal/proxy/handlers/object/operations.go#L651),
[create.go:105-118](../../internal/proxy/handlers/multipart/create.go#L105)), and
`CopyObject` is not called anywhere in `internal/` — it is not even in
`S3BackendInterface` any more. The `PutObjectTagging` scheme this item designed
for the late-bound HMAC is **not needed and was not built**: there is no
late-bound HMAC under the segment chain, the trailer rides on the last part.

**3.2 Range GET — `df12c84` (F-6), 2026-09-05, then reimplemented.** Any GET with
a `Range` header used to answer 501 before metadata was fetched, breaking
boto3/aws-cli parallel downloads, s5cmd, mountpoint-s3 and kopia's pack-blob
reads — which is why every Velero volume restore failed. The CTR counter-seek
that closed it carried a security consequence this ticket never weighed: a ranged
AES-CTR read was not covered by the whole-object HMAC. The segment chain removed
both the ceiling and the gap — a ranged read is verified like any other read
(ADR 0003) — and phase 2, parallel ranged GETs, is gated on that format rather
than on item 6.2.

**3.3 HEAD and List size — HEAD `646932b` (F-7), List `d696763`, 2026-09-10.**
`handleHeadObject` wrote the backend's stored length verbatim, so every small
object HEADed as plaintext+28 and `aws s3 sync` / rclone re-transferred it
forever. HEAD converts with `PlaintextSize`
([operations.go:360](../../internal/proxy/handlers/object/operations.go#L360)),
and both object listings now state the same plaintext length, computed from the
stored length by the same arithmetic — no metadata read, no extra request
([listing.go:31-39](../../internal/proxy/handlers/bucket/listing.go#L31),
[ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)). Under the
exit provider the listing reports the **stored** size instead
([listing.go:44-46](../../internal/proxy/handlers/bucket/listing.go#L44)), which is
a decision, not an omission:
[ADR 0025](../adr/0025-leaving-is-a-supported-mode.md) D8. The one listing number
still unrecorded — the
wall time of a 2500-key paginated listing against the same listing issued straight
to MinIO — belongs to [018](018-listobjectsv2-document.md), not here.

**5.1 GCM GET unwraps the DEK twice — obsolete.** `DecryptGCMStream` fed one
cached unwrap into a dead HMAC branch while the real decrypt went through
`envelope.DecryptDataStream`, which called `keyEncryptor.DecryptDEK` raw and
bypassed the DEK cache — a full KEK operation per GET, and a billable KMS call
per GET once a network KMS lands. `pkg/encryption/envelope` no longer exists;
there is exactly one unwrap on the read path and it is the cached one
([segmented.go:257](../../internal/orchestration/segmented.go#L257)). The
cache-ownership warning the item carried survives in the code
([providers.go:251](../../internal/orchestration/providers.go#L251)): a cached DEK
is read-only, and zeroing it would corrupt later cache hits.

**5.2 GCM `[]byte` fast path — obsolete.** `dataencryption/aes_gcm.go` and its
~3× object-size allocation chain are gone. The segment codec seals and opens one
64 KiB segment in one buffer by construction, and the mutex-guarded
`lastNonce`/`GetLastIV` side channel the item warned about not inheriting went
with the file.

**6.3's config finding — filed and closed elsewhere.** The `s3_security`
rate-limiting/IP-blocking block that was parsed and referenced nowhere is N-5;
the decision was taken 2026-09-06 and the keys, the unbounded failed-attempt map
and the brute-force branch are deleted (ADR 0013, ADR 0014). `s3_security` now
carries one key, `max_clock_skew_seconds`.

---

## Explicitly not doing (rejected by adversarial review — do not re-propose without new evidence)

1. **Segmented AEAD / per-part MAC format change. Reversed 2026-09-07, and
   shipped 2026-09-10.** The audit rejected it on performance grounds ("the win
   today is ~0.05 cores on a 0.55-core load"). It was adopted on *integrity*
   grounds instead ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)),
   with performance as a constraint to hold rather than a benefit to claim. The
   activation condition this ticket wrote is void.
2. **GET read-ahead goroutine (overlap backend read with client write).**
   Structure verified serial, but the premise fails: the identical chain measured
   218 MB/s on other hardware, so the chain was not the ~120 MB/s ceiling, and
   kernel socket buffers already overlap the legs for a continuous stream. Not
   worth a concurrency change on the integrity-critical path.
3. **KEK `Fingerprint()` memoization — moot.** It is a stored field today
   ([aes.go:149-151](../../pkg/encryption/keyencryption/aes.go#L149)), not a
   SHA-256 per call.
4. **Auto-multipart producer double-buffering — superseded, and it was
   implemented.** The audit rejected it as worth ≤ ~6 % against a producer chain
   capping at ~1.3-1.4 GB/s. The measurement in ADR 0024 put the auto-multipart
   path at 57-70 % of the backend it writes to, which is a different regime; the
   overlap landed with the format change. What has not been measured is whether it
   helped — item 2.0.

---

## Done criteria

- [ ] Every remaining item merged or explicitly deferred with a note
- [ ] `make test-integration`, `make test-integration-tls` and
      `make test-e2e-velero` green on a fresh stack
- [ ] An *after* baseline run recorded under `perf-baseline/`, on the same machine
      and power source as its before-column, covering at least the three-leg
      upload comparison (2.0) and the small-object rates (6.3)
- [ ] No increase in peak resident memory during a 1 GB upload/download; the bound
      stated as the formula the code enforces —
      `(multipart_upload_concurrency + 1) × streaming_segment_size` in flight,
      plus `multipart_short_part_buffer_size` per client-driven session
- [ ] The parallel-stream aggregate number from 6.2 recorded as the capacity
      yardstick
