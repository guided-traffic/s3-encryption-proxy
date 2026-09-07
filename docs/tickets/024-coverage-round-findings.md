# Ticket 024: The coverage round — what raising coverage found

## Status (2026-09-06)

**Open.** This is the record of the unit-coverage round run on
`feat/improve-test-coverage` on the night of 2026-09-06. It is a findings ticket, not a
work plan: the coverage itself is done and committed, and what is left here is the defect
list the exercise produced. Items that belong to an existing ticket are marked as such and
are **not** re-opened here — see [Ownership](#ownership-which-ticket-actually-fixes-what).

**Decisions taken 2026-09-07 by the repository owner**, recorded as D-20 to D-30 in the
[label index](README.md#decisions-d-1-to-d-30) and written into the owning tickets:

| Finding | Decision | Lives in |
|---|---|---|
| H-1, H-2 | D-20 — documentation only until v2; README and `SECURITY_ARCHITECTURE.md` H-5 stop presenting `strict` as CTR protection | [013](013-storage-format-v2.md) q.12 |
| S-1 | D-21 — remove the raw-string KEK fallback, base64 of 32 bytes only, in the 5.0.0 major release (not in the accidental 4.0.0) | [013](013-storage-format-v2.md) q.13, [023](023-major-v5.md) |
| S-3 | D-22 — pprof on its own `127.0.0.1` listener | [015](015-configuration-hygiene.md) Part 5 |
| Tink | D-23 — complete it, Vault first, AWS/GCP alongside, after v2 | [025](025-tink-kms-hcvault.md) |
| S-4 | D-24 — keep the map, trusted-proxy CIDRs, eviction; reverses 015 Part 1.2 | [015](015-configuration-hygiene.md) Part 5 |
| A-1, A-2 | D-25 — fix the deadlock; reject a token without `exp` | [020](020-dev-license-expiry.md) |
| X-2 | D-26 — backend 2xx-with-error becomes 500, code kept | [022](022-s3-surface-fidelity.md) item 19 |
| H-4 follow-up | D-27 — `InvalidArgument` for the malformed part PUT | [022](022-s3-surface-fidelity.md) item 20 |
| P-1 | D-28 — no interim fix, v2 rewrites it, measure after | [013](013-storage-format-v2.md) q.14 |
| P-2 | D-29 — pooled path in both modes, then measure and delete the loser | [012](012-performance-audit-round2.md) item 1.4 |
| H-5 | D-30 — validate the prefix at startup | [015](015-configuration-hygiene.md) Part 5 |

**Worked off 2026-09-07 on `feat/improve-test-coverage`**, in the order of the table above,
one commit per decision. That branch merged into `main` as PR #331 with a merge commit
(`46ae5fd`), so semantic-release read the two `feat!` commits (D-22, D-30) and cut
**4.0.0** the same day; the hashes below are the rebased ones that `v3.8.57..v4.0.0`
carries. **D-24 is the only one not done**: it is held until the owner
confirms the consequence flagged in [015](015-configuration-hygiene.md) Part 5.2 — keeping
the failure map only earns its trusted-proxy machinery if `max_failed_attempts` and
`unblock_ip_seconds` become live controls, which reverses Part 1 for those two knobs.

| Decision | Landed as | State |
|---|---|---|
| D-20 | `f0e83be` | Done. Docs only, as decided |
| D-21 | `9c25efb` | Recorded. Ships with 5.0.0 — it is not in 4.0.0, `aes.go:61-66` still accepts a raw 32-character string; it had **no work item** in 013 and was **absent from 023 entirely** until now |
| D-22 | `1d48669` | Done, verified against the running demo stack; released in 4.0.0 as a breaking change |
| D-23 | — | Already fully recorded in [025](025-tink-kms-hcvault.md); nothing to do |
| D-24 | — | **Reverted the next day** by [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md): the failure map and its keys go after all, as [015](015-configuration-hygiene.md) Part 1 wrote it. Nothing is deleted in the tree yet - `logSecurityEvent` still logs `client_ip` and `failed_count` |
| D-25 | `4b86b2a` | Done, released in 4.0.0 |
| D-26 | `052e1a9` | Done, with a 304 carve-out the decision did not have; released in 4.0.0 |
| D-27 | `04856f8` | Done, released in 4.0.0 |
| D-28 | `9c25efb` | Recorded. It had no success criterion and **no benchmark to measure with** |
| D-29 | `6f9a8b8` | Done and measured. **Its premise was wrong about this tree**; released in 4.0.0 |
| D-30 | `ab8618d` | Done, released in 4.0.0 as a breaking change |

Five of the eleven turned out to rest on a claim this document or its owning ticket got
wrong, and in each case the tree won. They are written out in the owning tickets; the
short list, because it is the useful part of the exercise:

- **D-29's defect does not exist.** The pooled copy buffer was never switched by the
  monitoring flag: `s3Router.Use(s.loggingMiddleware)` is unconditional and that wrapper
  hides `ReadFrom` too. What is real is the capability loss, and it is on **every** S3
  route in **both** modes, not only with monitoring on.
- **D-26's justification does not hold.** aws-sdk-go-v2 already rewrites the S3
  200-with-`<Error>` answer to 500 for the three operations that produce it. The change is
  still right, for shapes neither ticket named — a 1xx above all, which `net/http` turns
  into a real implicit 200 carrying the error document.
- **D-30's mechanism is not the one recorded here.** `isNoneProviderData` *does* guard the
  empty prefix; the shredder comes from it disagreeing with every writer.
- **D-25's "one line" fix panics** against the suite in this tree.
- **P-1's benchmark was never committed**, so D-28's "measure after" had no instrument.

Two live defects were found while doing the work and deliberately **not** fixed, because
each needs a decision of its own:

- **A semicolon in the query string reopens H-4.** `PUT /b/k?partNumber=abc;uploadId=u`
  arrives at the handler with an **empty** parsed query — Go discards such segments while
  gorilla/mux splits on them — passes every refusal and runs the base PUT, and it
  authenticates cleanly because SigV4 canonicalisation reads the same empty query.
  Recorded in [022](022-s3-surface-fidelity.md) item 20.
- **A missing `s3ep-hmac` is skipped silently in every mode**, `strict` included, so H-5's
  "only `hybrid` downgrades" was wrong. A fourth route to the H-1 outcome, recorded in
  [013](013-storage-format-v2.md) q.12 together with the fact that a **correct** verifying
  reader already exists in the tree with no production caller.

One performance item is reported rather than changed: the ranged-read response still uses a
bare `io.Copy` and is the one GET body copy without the pooled buffer — the path every
ranged GET takes, kopia's small ranged reads on a Velero volume restore among them
([012](012-performance-audit-round2.md) item 1.4).

Every claim below carries its verification state:

- **Verified** — I read the code and confirmed it, or reproduced it with a test or a
  benchmark in this tree.
- **Reported** — a subagent reported it and I have not independently confirmed it. Treat
  these as leads, not as facts. One agent claim in this round was **wrong about severity**
  and is recorded in [Re-scoped](#re-scoped-claims-that-did-not-survive-checking) as a
  warning against taking the rest on trust.

---

## Before you start

Confirmed against the tree on 2026-09-07. Corrections marked *in place* are already
applied below; the reasoning around them is untouched.

- Five findings still read as open although their fix shipped in 4.0.0: the metadata
  prefix (`validateEncryption` refuses anything but `^[a-z0-9-]+$`), pprof (own loopback
  listener, a non-loopback bind address is a startup error), the malformed part `PUT`
  (`400 InvalidArgument`), the backend 2xx-with-error mapping (anything below 400 except
  304, and anything above 599, becomes 500) and both license paths. Marked in place.
- The sub-resource guard no longer allowlists literal `X-Amz-*` names — that list refused
  every pre-signed download over `X-Amz-Checksum-Mode`. It admits the whole `x-amz-*`
  namespace through `request.IsAWSProtocolQueryParam`. In place.
- Two "not written down anywhere" claims are wrong: `SECURITY_ARCHITECTURE.md` already
  states that CTR ciphertext is not bound to its object key while GCM is, and that there
  is no nonce store so a signed request replays inside the window. Both predate this
  ticket. In place, ownership row included.
- The prescribed response-writer fix is half wrong: the wrapper declares `Unwrap`,
  `FlushError`, `Flush` and `Hijack`, and `ReadFrom` deliberately not — `copyWithPooledBuffer`
  hides it behind a `writerOnly` so the pooled path is taken on every route in both modes
  (ADR 0020). In place.
- `CLAUDE.md` no longer advertises Tink as a working KMS integration; it calls it an
  unreachable stub, and completing it against a real KMS is decided (ADR 0005). The stub
  itself is unchanged. In place.
- "Neither is covered by an existing ticket" for the two license paths is wrong:
  [020](020-dev-license-expiry.md) owns them, its scope amended. In place.
- Success criterion 1 quoted wave 1's 77.8 % alone; it now carries wave 2's 96.2 % as well.
  The index in [README.md](README.md) still says "63.1 to 77.8 percent", and neither number
  has been re-measured since 2026-09-06. In place.
- The handler-round preamble "every item is reproduced by a test" is contradicted by the
  SigV4 canonicalisation observations below it, which say they are not. In place.

## Settled

- Rows that ask for work the tree already has are corrected rather than left standing: the
  associated-data asymmetry sentence and the two license findings.
- The commit identifiers in the "landed as" table are the rebased ones the 4.0.0 release
  carries.

---

## What the round did

Coverage of statements, unit tests only, `go test -short`:

| | Before | After wave 1 |
|---|---|---|
| Repository total | 63.1 % | 77.8 % after wave 1, **96.2 % after wave 2** |

The measurement changed as well as the number, and the change is the more important half.
Two commits removed 1765 statements of test-shaped code from the *production* build before
a single test was written:

- `internal/proxy/mock_s3_backend.go`, 533 lines and 180 statements, a mock of the S3
  backend in package `proxy` with **no reference anywhere in the repository**, not even
  from a test. Deleted. `internal/proxy` 81.0 → 97.7 %.
- `handlers/{bucket,object,root}/test_helpers.go`, 1585 statements of testify mocks that
  were ordinary package members because the files lacked the `_test.go` suffix. Renamed.
  This also removed `github.com/stretchr/testify/mock` from the dependency graph of
  `cmd/s3-encryption-proxy`: `go list -deps` now finds no testify package in the binary.

`root` went 13.1 → 81.0 % purely from that rename, because 248 of its 290 statements were
the mock. `bucket` went **down**, 83.2 → 81.7 %, because its mock was better covered than
its handlers (921 of 1089 statements) and had been holding the package average up. 81.7 %
is the honest number for the handler code.

The lesson worth keeping: 628 uncovered statements, a quarter of every uncovered statement
in the repository, were mock code being measured as product code. A coverage percentage is
only as meaningful as its denominator.

### Why these packages and not the handlers

[Ticket 019](019-handler-unit-coverage.md) blocks handler-level unit coverage on
[ticket 013](013-storage-format-v2.md), per D-17: v2 deletes the GCM/CTR split, the
early-HMAC machinery, the ranged-read fork and the `integrity_verification` branches, so
handler tests written now would be rewritten line for line.

That constraint was respected, not ignored. Wave 1 covered only packages v2 does not
rewrite. Where later waves must touch v2-doomed code to reach a statement, the rule given
to every agent was: **test the client-visible contract, not the internal mechanism**, and
mark anything that pins v1 behaviour with

```go
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
```

so the churn v2 causes is localised and greppable instead of spread through the suite.

---

## Critical

### C-1 The security counters were a remote kill switch — **verified, fixed**

`logSecurityEvent` incremented `securityMetrics.FailedAttempts[clientIP]` with no
synchronisation, from the request goroutine
([s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go)).

Concurrent writes to a Go map are not a lost update. The runtime detects them and calls
`fatal("concurrent map writes")`, which terminates the process. It is not a panic, so
`net/http`'s per-connection recover cannot catch it.

The path that does it is the authentication **failure** path — bad signature, bad
timestamp, unknown access key — so it needs no credentials. Two parallel requests with a
forged signature were enough to end the process, and an attacker who wanted the proxy down
only had to keep sending them.

Fixed in `036301b`: every counter access goes through `metricsMu`, and
`GetSecurityMetrics` returns a deep copy rather than the live struct. `clientCache` was
checked and left alone — it is filled once in the constructor and only read afterwards,
and concurrent map reads are safe.

### C-2 A forged chunk header could allocate gigabytes, or panic — **verified, fixed**

`HTTPChunkedDecoder.ProcessChunkedData` sized its buffer from the client:
`make([]byte, chunkSize)` where `chunkSize` came from `ParseInt(line, 16, 64)`. The chunk
header is about twenty bytes and the value ranges to 2^63-1, so a tiny request body could
ask for a multi-gigabyte allocation before a byte of payload was read. `ParseInt` also
accepts a leading minus, and a negative length reaches `make()` in one decoder and
`p[:toRead]` in the other; both panic the request goroutine.

What makes this an oversight rather than a house style: `readAllSized` in
[parser.go](../../internal/proxy/request/parser.go) right next door already clamps its
length hint to `maxBodyPrealloc`.

Fixed in `4279275` with `io.CopyN` plus explicit negative guards in both decoders.

---

## The handler round: what covering the S3 surface found

Wave 2 took the handler and orchestration packages from 77.8 % to **96.2 %** and produced
about 130 findings. The full per-agent detail is in the workflow journal; what follows is
the set I verified myself, plus the ones severe enough that they must not be lost in a list.

**Every item in this section is reproduced by a test that is now in the tree**, except
the SigV4 canonicalisation observations, which say themselves that they are not.

### H-1 `integrity_verification: strict` does not protect an AES-CTR download — **verified, critical, open**

This is the most serious finding of the round. `strict` is documented as *"aborts if
verification fails (maximum security)"*. On the AES-CTR read path it does not abort — it
logs.

`hmacValidatingReader` is written to withhold the final chunk until the HMAC verifies. It
cannot: its "near end of stream" branch returns the bytes to the caller (`return n, nil`)
and buffers nothing, and the withholding in the EOF branch only has something to withhold
when the terminating read carries bytes. A `bufio.Reader` — the reader type the
`DataEncryptor` interface is written in terms of — signals EOF in a *separate zero-byte
read*, so by the time `VerifyIntegrity` runs the entire plaintext has already been written
to the `ResponseWriter` behind a `200` and a matching `Content-Length`.

The log from the regression test says it exactly:

```
last_chunk_size=0 ... total_read=8192
⏳ Validating HMAC before releasing last chunk...
❌ HMAC validation FAILED  error="HMAC verification failed: data integrity compromised"
```

`last_chunk_size=0`: there was nothing left to withhold. The client already had all 8192
tampered bytes. Reproduced by
`TestObjGetGetObjectTamperedCTRIsServedDespiteStrictMode/content_length_known`.

Scope: every object above `optimizations.streaming_threshold` and every multipart object,
in every integrity mode. AES-GCM is unaffected — its tag is inside the cipher, so tampering
fails decryption and the client gets a 500.

Under the threat model this is rule 1 broken: integrity is supposed to mean *the proxy*
verifies, and the proxy does not — it narrates.

### H-2 The backend can switch integrity checking off with one header — **verified, critical, open**

`createDecryptionReaderWithSizeInternal` builds the verifying reader only under

```go
if m.hmacManager.IsEnabled() && expectedSize > 0 {
```

`expectedSize` is the backend response's `Content-Length`, forwarded as `-1` when it is nil
([operations.go](../../internal/proxy/handlers/object/operations.go)). So a backend that
answers chunked, or any intermediary that drops the header, disables HMAC verification for
that object — no error, no log line, no configuration change.

The backend is the adversary in this model, and it chooses that header. Reproduced by the
`content_length_absent` subtest of the same test.

H-1 and H-2 are independent routes to the same outcome, which is worth stating plainly:
**there is currently no configuration in which a tampered AES-CTR object is refused.**

### H-3 Unrouted object sub-resources still delete the object — **verified, critical, FIXED**

The exact bug ticket 022 recorded as fixed for buckets (`DELETE /bucket?encryption` deleted
the bucket), never fixed on the object side.

`?acl`, `?legal-hold` and `?retention` are registered for `GET` and `PUT` only, `?torrent`
for `GET` only, `?select` for `POST` only
([router.go](../../internal/proxy/router.go)). gorilla/mux does not match the method, so the
request falls through to the catch-all object route and executes the **base operation for
its verb**:

```
DELETE /bucket/key?legal-hold   ->  deletes the object
DELETE /bucket/key?retention    ->  deletes the object
DELETE /bucket/key?acl          ->  deletes the object
DELETE /bucket/key?torrent      ->  deletes the object
```

A client asking to remove a legal hold destroys the object instead. AWS answers these with
an error. Reproduced by
`TestObjMiscHandleFallsThroughUnknownSubResourcesToTheBaseOperation`.

Fixed in `568db10`. `Handler.Handle` now refuses in two steps, mirroring the bucket
handler: a parameter naming a routed sub-resource is answered `MethodNotAllowed`, and any
other unrecognised parameter is answered `NotImplemented`. The guard is bounded the other
way as well — `versionId`, `x-id` and the six `response-*` overrides are
allowlisted and the whole `x-amz-*` namespace is admitted through
`request.IsAWSProtocolQueryParam`, because a guard that is too broad is an outage rather
than a fix, and both directions are asserted. Naming the pre-signed parameters literally,
as this first did, refused every pre-signed download over `X-Amz-Checksum-Mode`.

The two unit tests that pinned the destructive behaviour were rewritten to assert the
refusal: they were the proof the bug existed and are now the proof it is gone. New
integration tests in
[object_subresource_refusal_test.go](../../test/integration/s3-methods/object_subresource_refusal_test.go)
drive the real proxy over HTTP, because the defect lives in the interaction between the
router and the handler and no handler-level test can see it: each writes an object, sends
the request that used to destroy it, and asserts the object is still byte-identical by
sha256.

**Still open:** the README documents the bucket refusals and says nothing about the object
ones. That belongs with [022](022-s3-surface-fidelity.md).

### H-4 A malformed `partNumber` overwrites the whole object — **verified, critical, FIXED**

The multipart upload route requires `partNumber` to match `[0-9]+`
([router.go](../../internal/proxy/router.go)). A non-numeric value simply does not match, so
`PUT /bucket/key?partNumber=abc&uploadId=...` falls through to the catch-all object route
and is executed as an ordinary `PutObject`: **the part body replaces the entire object.**

A client retrying an upload with a corrupted query string destroys the object it was
uploading into. AWS answers `InvalidArgument`. Reproduced by
`TestRtPxMalformedPartUploadReachesTheObjectHandler` — which, contrary to what this
paragraph said when it was written, only ever asserted *which route matches*. It passed
unchanged across `568db10`, so it never reproduced the data loss; the handler-level
`TestObjMiscHandleRefusesSubResourcesThatReachTheBaseOperation` is what does. Renamed and
its comment corrected with D-27.

Fixed in `568db10` together with H-3, and answered `NotImplemented` rather than
`MethodNotAllowed`: on a `GET`, `partNumber` is a legitimate S3 read of one part that this
proxy does not implement, and `MethodNotAllowed` would be the wrong thing to say about a
GET. `NotImplemented` is honest for every verb and destroys nothing. **AWS answers
`InvalidArgument` for the malformed-PUT case specifically**, and that is what the handler
answers now: a `PUT` carrying `partNumber` and `uploadId` with a non-numeric part number is
refused `400 InvalidArgument`, while `GET ?partNumber` stays `NotImplemented`.

### H-5 A client can write into the proxy's own metadata namespace — **prefix validation fixed, shared namespace open**

Two reports, same root: the encryption metadata and client user-metadata share one map and
the prefix check is case-sensitive.

- `x-amz-meta-s3ep-*` sent by a client reaches the same map the proxy writes
  `encrypted-dek` and friends into, and which one wins is not deterministic.
- A `metadata_key_prefix` that is not lowercase silently disables decryption *and* leaks the
  encryption metadata to clients, because S3 lower-cases metadata keys in transit while the
  comparison here does not.
- `metadata_key_prefix: ""` makes `isNoneProviderData` treat every object as unencrypted, so
  **every GET serves the ciphertext as plaintext**, and separately strips all user metadata
  in both directions.

The empty-prefix case is the sharp one: a single empty string in the config turns the proxy
into a shredder that returns ciphertext with a 200. Config validation now refuses it —
`validateEncryption` rejects any `metadata_key_prefix` that does not match `^[a-z0-9-]+$`,
released in 4.0.0 as a breaking change. The shared namespace and the case-sensitive filter
are still open.

### H-6 Multipart correctness

Worth naming individually because they are reachable by ordinary clients:

- **A repeated or retried part number parks the request goroutine forever.** Re-uploading a
  part — which is what every S3 client does on a network hiccup — never returns. A duplicate
  pending part also overwrites its predecessor and orphans that goroutine.
- **A failed part strands every part already buffered behind it**, and `FinalizeSession` is
  not idempotent and can return metadata with no HMAC.
- **`ListParts` always reports an empty list** and never asks the backend.
- **Completing with a subset of the uploaded parts stores an object whose own HMAC can never
  match it** — the object is committed and is then permanently unreadable.
- **Every malformed `CompleteMultipartUpload` is answered `500 InternalError`** instead of a
  400-class S3 code, and an unknown upload id is never answered `NoSuchUpload`.
- The post-Complete self-`CopyObject` is still present, so a multipart upload over 5 GiB
  fails *after* the data is committed (ticket 012 item 3.1, confirmed).

### H-6b SigV4 canonicalisation rejects requests AWS accepts — **open**

Two observations, one root area, both worth checking together before anyone touches the
signature code.

Reported by the header-fidelity agent: **SigV4 verification does not collapse sequential
whitespace in header values**, so a correctly signed request whose header contains repeated
spaces is answered 403. AWS's canonicalisation explicitly trims and collapses sequential
spaces in header values, so a client that follows the specification is refused.

Observed by me while writing the sub-resource regression test: a signed
`GET ...?response-content-disposition=attachment%3B%20filename%3D%22a.txt%22` is answered
**403**, while the same request with a value containing no encoded space is answered 200.
That points at query-string canonicalisation — SigV4 requires RFC 3986 encoding, where a
space is `%20` and not `+` — but I did not isolate whether the mismatch is in the proxy's
canonical query construction or in the test's. It is recorded as an observation, not a
verified proxy defect, and the regression test deliberately avoids the case rather than
asserting either answer.

Both matter for the same reason: `Content-Disposition` with a filename is exactly what a
presigned download URL carries, and filenames contain spaces.

### H-7 The S3 documents are not S3 documents — **open**

Reported consistently across the bucket and listing agents, and it is one finding, not
several: **every bucket sub-resource GET returns the marshalled aws-sdk-go-v2 output
struct** rather than the S3 XML document. `ListObjectsV2` is not a `ListBucketResult`, the
listing `<Size>` is the stored ciphertext size, `start-after` is dropped so paging with it
loops forever, `encoding-type` is dropped, V1 `ListObjects` drops `max-keys` entirely, and
`HeadBucket` is implemented as a `ListObjectsV2` call.

[Ticket 018](018-listobjectsv2-document.md) owns the listing document and already carries
D-11/P-4. The sub-resource documents are the same defect one level out and should join it.
`PUT /{bucket}?acl` silently dropping every `<Grant>` and answering 200, and `?cors`
discarding every rule, belong with 022's silent-200 class.

---

## Integrity

### I-1 A truncated aws-chunked upload was stored as a complete object — **verified, fixed**

`consumeCRLF` in
[streaming_aws_decoder.go](../../internal/proxy/request/streaming_aws_decoder.go) returned
a bare `io.EOF` when the stream ended where the chunk terminator belongs. `Read` passes
that out unchanged, and to `io.Copy` a bare `io.EOF` means *the stream ended cleanly*. A
client that hung up mid-upload therefore had its short body committed as a whole object —
and the HMAC verified, because the HMAC was computed over the bytes that actually arrived.

The body read immediately below it already converted this condition to
`io.ErrUnexpectedEOF`; only the terminator read was missing it. Fixed in `4279275`.

This is the same family as the truncated auto-multipart commit the pre-merge sweep found
(F-16 era), which is worth noting: it is the second instance of the same mistake, so the
class deserves a test rather than another point fix. The regression test is in
`internal/proxy/request/streaming_decoder_coverage_test.go`.

### I-2 The wrapped DEK aliased the buffer being zeroized — **verified, fixed, latent**

`EncryptDataStream` defers a loop that overwrites the plaintext DEK and returns whatever
`keyEncryptor.EncryptDEK` returned. `NoneProvider.EncryptDEK` returns its **input slice
unchanged**, so under the none provider the returned wrapped DEK aliased the buffer the
defer wipes.

Latent rather than live: both call sites in
[singlepart.go](../../internal/orchestration/singlepart.go) discard that return value, and
the base64 metadata string is built before the function returns, so the defer cannot reach
it. Fixed in `59ae8f0` with one `append` before it can become real.

---

## Security

### S-1 The AES KEK fingerprint is a crackable hash of a possibly human-chosen key — **verified, open**

Two facts that are each defensible alone and dangerous together.

`AESProvider.Fingerprint()` is `hex(SHA-256(kek))` over the **raw master KEK**, unsalted
([aes.go](../../pkg/encryption/keyencryption/aes.go)), and it is published in every
object's `s3ep-kek-fingerprint` metadata — which under this threat model the adversary
reads by definition.

`NewAESProvider` falls back to `kek = []byte(keyStr)` when the value does not base64-decode
to 32 bytes. So **any 32-character string is accepted as the AES-256 master key**:
`aes_key: "correct-horse-battery-staple-123"` starts the proxy.

Against a 32-byte random key, publishing SHA-256 of it is harmless. Against a 32-character
passphrase it is an offline dictionary attack with a free verification oracle, and
recovering the KEK unwraps every DEK and therefore every object.

[Ticket 013](013-storage-format-v2.md) already decided the fingerprint half — H-8, the
`aes` fingerprint becomes `HMAC-SHA256(KEK, "s3ep-kek-fingerprint")`. **The passphrase half
is not covered anywhere and is what turns H-8 from theoretical into practical.** The
options are to require base64 of 32 random bytes and reject the raw-string fallback, or to
run a passphrase through a KDF with a real work factor. That decision belongs to 013 with
the rest of the format change.

### S-2 The AES KEK wraps the DEK with unauthenticated AES-CTR — **verified, open**

`EncryptDEK` wraps with `cipher.NewCTR` and no MAC. A hostile backend can flip any bit of
`s3ep-encrypted-dek` and `DecryptDEK` returns a *different* DEK with no error — under CTR
the modification is bit-for-bit controlled.

Bounded today rather than exploitable: GCM objects fail their tag check, and for CTR
objects the HMAC key is HKDF-derived from the DEK, so a modified DEK produces a mismatching
HMAC. The exposure is the configurations where that check is absent — `integrity_verification`
`off` and `lax`, and `hybrid` against an object whose HMAC the backend simply removed,
which is N-2 exactly. Belongs to 013: an authenticated wrap (AES-GCM or AES-KW) is the fix,
and 013 is already rewriting the format.

### S-3 The monitoring port is unauthenticated, and pprof there exposed plaintext and keys — **pprof fixed, the open port remains**

The monitoring mux has no authentication and defaults to `:9090`, every interface. With
`PprofEnabled`, `/debug/pprof/heap` is registered on that same open port. On an encryption
proxy the heap holds DEKs, KEK-decrypted key material and plaintext object buffers, so
anyone who can reach the port can pull a heap profile and recover plaintext — defeating
encryption-at-rest from outside S3 entirely. The code logs a warning telling the operator
to restrict access; nothing enforces it, and rule 2 of the threat model says a control that
exists only in documentation is worse than none.

I have not reproduced the key recovery, hence *reported*. The pprof half is fixed: it is
served by `PprofServer` ([pprof.go](../../internal/monitoring/pprof.go)) on
`monitoring.pprof_bind_address`, default `127.0.0.1:6060`, the monitoring mux registers
nothing under `/debug/pprof`, and a non-loopback address is a startup error. The mux itself
is still unauthenticated on `:9090`.

### S-4 Client IP is attacker-controlled and the failure map never shrinks — **verified, open**

`getClientIP` trusts `X-Forwarded-For`, then `X-Real-IP`, with no trusted-proxy allowlist,
and `securityMetrics.FailedAttempts` is never evicted. An unauthenticated client varying a
forged header on failing requests inserts an unbounded number of distinct map keys:
memory grows without bound. Independently, every security log line attributes the event to
an attacker-chosen address.

Related to N-5 / [ticket 015](015-configuration-hygiene.md): because `max_failed_attempts`
and `unblock_ip_seconds` are read by no code, there is no IP blocking to evade today. The
map growth and the log forgery are the live parts.

### S-5 AES-CTR silently discards the object key it is handed — **verified, open**

`AESGCMDataEncryptor.EncryptStream` takes `associatedData` and feeds it to GCM.
`AESCTRDataEncryptor.EncryptStream` and `DecryptStream` declare the same parameter as
`_ []byte` and **discard it**
([aes_ctr.go](../../pkg/encryption/dataencryption/aes_ctr.go)).

The caller passes the object key: `provider.EncryptDataStream(ctx, dataReader, []byte(objectKey))`
in [singlepart.go](../../internal/orchestration/singlepart.go). So the intent to bind an
object to its own key is in the code, and for GCM objects it holds. For CTR objects — which
is every object above `streaming_threshold` and every multipart upload — nothing binds the
ciphertext to the key it is stored under.

Under the hostile-backend model that is a live gap, not a theoretical one: the backend can
move a ciphertext object, its `s3ep-*` metadata included, from key A to key B and the proxy
serves it as B. The whole-object HMAC does not object, because the DEK travels with the
object and the HMAC key is derived from that DEK. For any S3 client this means a GET
can return the wrong object with every integrity check passing; for a backup tool,
that is a restore of the wrong data.

[Ticket 013](013-storage-format-v2.md) already designs the fix and gives the reason
verbatim — `AAD = formatID ‖ clientObjectKey ‖ index`, *"it stops a hostile backend from
serving object A's ciphertext under B's name"*. `SECURITY_ARCHITECTURE.md` already states the
asymmetry — GCM objects are bound to their object key, CTR objects are not — in the
per-algorithm table and again in the hardening list, and that text predates this ticket.
What is left here is the format-change design.

### S-6 `max_clock_skew_seconds` is a no-op on the path every SDK uses — **verified, open**

Both halves confirmed in
[s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go).

**The knob is ignored where it matters.** `validateTimestamp`, the header-signed path,
compares against the package constant `MaxClockSkewSeconds = 900`. The *presigned* path has
a proper accessor that reads `s.config.S3Security.MaxClockSkewSeconds` and falls back to the
constant ([s3auth_presigned.go](../../internal/proxy/middleware/s3auth_presigned.go)). So
the setting works for presigned URLs and does nothing for header-signed requests — which is
what every AWS SDK client sends.

The default is 900 either way ([config.go](../../internal/config/config.go)), so a stock
install behaves as documented. It bites the operator who *changes* it: tightening the window
to 60 seconds to narrow replay exposure leaves the real path accepting 900. A security
control that silently does nothing is rule 2 of the threat model.

**The replay branch cannot execute.** The two checks are

```go
timeDiff := now.Sub(requestTime).Abs()
if timeDiff > MaxClockSkewSeconds*time.Second { return ... }        // returns here
if now.Sub(requestTime) > MaxClockSkewSeconds*time.Second { ... }   // unreachable
```

`now.Sub(requestTime) <= |now.Sub(requestTime)| = timeDiff`, and the first check already
returned for every `timeDiff` above the threshold. So the second is never true,
`ReplayAttempts` is always 0, and the metric reads as *no replays observed* rather than
*not measured*.

The substantive point behind the dead branch: there is **no replay defence at all**, only a
freshness window. A captured signed request can be replayed as often as the attacker likes
within 900 seconds, because nothing records which signatures have already been seen. `SECURITY_ARCHITECTURE.md` says
this already — no nonce store, a captured signed request replays until its timestamp ages
out of the window. The ignored knob and the dead branch themselves are unchanged.

---

## Performance

Both of these are on a hot path, and MAIN GOAL 2 makes them worth their own section.

### P-1 The DEK is unwrapped twice on every GCM GET — **verified, measured, open**

[singlepart.go](../../internal/orchestration/singlepart.go) unwraps the DEK through the
ProviderManager (which caches, per [ticket 011](011-dek-cache-stale-on-reupload.md)), uses
it to derive the HMAC key, and then calls
`envelopeEncryptor.DecryptDataStream(ctx, reader, encryptedDEK, ...)`, which unwraps **the
same encrypted DEK a second time** inside
[envelope.go](../../pkg/encryption/envelope/envelope.go). The envelope layer does not go
through the ProviderManager, so the cache does not cover the second unwrap.

Measured in this tree, Apple M1 Ultra, `go test -bench`:

| KEK provider | one unwrap |
|---|---|
| `aes` | 392 ns |
| `rsa` (2048) | **936 613 ns ≈ 0.94 ms** |

So the redundant unwrap costs 0.4 µs under AES — noise — and **0.94 ms under RSA**, paid
serially before the first plaintext byte is delivered. One core does roughly 1067
RSA-2048 private-key operations per second, so the duplicate roughly **halves the ceiling
on GET throughput for the RSA provider**, from about 1067 to about 533 GETs per second per
core.

The fix is to pass the already-unwrapped DEK into the envelope layer instead of the wrapped
one, or to route the envelope layer through the ProviderManager cache. Ticket 013 rewrites
this path, so it should land there rather than as a separate change — but it must land,
and it should be measured after.

### P-2 The pooled read buffer is disabled unless monitoring is on — **premise wrong, fixed**

`copyWithPooledBuffer` ([helpers.go](../../internal/proxy/handlers/object/helpers.go)) uses
`io.CopyBuffer` with a pooled 128 KiB buffer, which ticket 010 introduced deliberately.
`io.copyBuffer` checks `dst.(io.ReaderFrom)` **first** and, when it matches, calls
`dst.ReadFrom(src)` and ignores the supplied buffer entirely.

`monitoring.responseWriter` ([middleware.go](../../internal/monitoring/middleware.go))
embeds `http.ResponseWriter` and overrides only `WriteHeader`. It therefore *hides*
`ReadFrom`. And `router.Use(monitoring.HTTPMiddleware)` is applied to the whole router when
monitoring is enabled ([router.go](../../internal/proxy/router.go)).

The result is backwards:

| `monitoring.enabled` | `dst` | pooled 128 KiB buffer |
|---|---|---|
| false | `*http.response` (a `ReaderFrom`) | **ignored** |
| true | `*responseWriter` (hides it) | used |

A deliberate performance optimisation is switched on and off by a monitoring flag, and it
is *off* in the configuration that has one less wrapper. Worth re-checking which
configuration the ticket 010 measurements were taken under.

The same wrapper also drops `http.Flusher`, `http.Hijacker` and `Unwrap()`, so
`http.NewResponseController` did not work on a streaming proxy while monitoring was on.
Fixed asymmetrically: the wrapper declares `Unwrap`, `FlushError`, `Flush` and `Hijack`,
and `ReadFrom` deliberately **not** — `io.copyBuffer` prefers `dst.ReadFrom` over the
buffer it is handed, so `copyWithPooledBuffer` hides the writer behind a `writerOnly` and
the pooled path is taken on every route in both modes (ADR 0020).

### P-3 The two headline HTTP metrics are never exported — **reported, open**

`RequestsTotal` and `RequestDuration` are registered into a private
`prometheus.NewRegistry()`, while `/metrics` serves `promhttp.Handler()`, which gathers
`prometheus.DefaultGatherer`. Nothing ever gathers the private registry, so request rate
and request latency — the two metrics the middleware exists to produce — are invisible to
Prometheus, and the Kubernetes and Helm labels attached through that same wrapper appear on
no exported metric. Not a runtime cost, but it means there is currently no production
latency signal to detect P-1 or P-2 with.

---

## S3 surface

These belong with [ticket 022](022-s3-surface-fidelity.md), which owns the "silent 200"
class. They are recorded here because they were found here; **022 is where they get
fixed**, and none of them duplicates an existing 022 item.

### X-1 Conditional read headers are dropped — **verified, open**

`handleGetObject` forwards only `If-Match` and `If-None-Match`
([operations.go](../../internal/proxy/handlers/object/operations.go)). It drops
`If-Modified-Since` and `If-Unmodified-Since`, so a conditional GET that AWS answers with
`304 Not Modified` returns `200` and the whole body — fetched from the backend, decrypted,
and transferred.

`handleHeadObject` forwards **no** conditional header at all, so even `If-None-Match` is
ignored on HEAD, where GET honours it. The two verbs disagree about the same request.

This is 022's defect class exactly, and it is distinct from 022 item 1, which is about
request headers dropped on **PUT**.

### X-2 An error can be answered behind HTTP 200 — **verified, narrower than reported**

Real, but the reported framing overstated the reach, so here is the precise version.

`MapError` ([error_mapping.go](../../internal/proxy/response/error_mapping.go)) ends with

```go
if status < 100 || status > 599 { status = http.StatusInternalServerError }
```

which clamps only nonsense values. A 2xx or 3xx passes through untouched. Walking the
sources of `status`: the internal markers carry their own, the `codeStatus` lookup carries a
sane one, and the no-code-no-status case is forced to 500. **The only way in is
`respErr.HTTPStatusCode()`** — an SDK `ResponseError` whose status really was 2xx.

That is not hypothetical: S3 answers `CompleteMultipartUpload` and `CopyObject` with
`200 OK` and an `<Error>` document in the body, and the SDK surfaces those as errors
carrying status 200. So the proxy forwarded a backend 200-with-error as a 200-with-error — though not for those
two operations, where aws-sdk-go-v2 rewrites the answer to 500 itself. `MapError` now
forces any status above 599, and any status below 400 other than 304, to 500 before the
code and message fallbacks.

Whether that is a bug depends on the reading. As faithful proxying it is arguably correct.
Under this repository's threat model it is not, and that is the reading that should win: a
hostile backend can answer 200 with an error document, and any client that branches on the
status code alone reads the operation as successful. The proxy is the component that is
supposed to turn the backend's answer into something trustworthy, so it should map a failed
operation onto a failure status regardless of what the backend chose.

The two neighbouring claims from the same report are **not verified** and stay leads:
that `WriteXML` commits 200 before marshalling can fail, leaving a truncated document behind
a success status, and that bucket handlers marshal raw AWS SDK output structs through
`WriteXML`, producing XML no S3 client can parse. The second would be the more serious of
the two if it holds.

---

## Availability: two license paths that stop the proxy

Both **verified** by reading
[validator.go](../../internal/license/validator.go) and
[main.go](../../cmd/s3-encryption-proxy/main.go). Neither is covered by an existing ticket.
Both are owned by [020](020-dev-license-expiry.md), whose scope was amended to admit them,
and both are fixed and released.

### A-1 Every unlicensed shutdown hangs forever — **fixed**

`StartRuntimeMonitoring` returns early when there is no valid license — *"No valid license
- skipping runtime monitoring"* — **before** starting the goroutine whose
`defer close(v.doneChan)` is the only thing that ever closes that channel.

`Stop()` is

```go
close(v.stopChan)
<-v.doneChan     // nothing will ever close this
```

`doneChan` is a real open channel from `NewValidator`, so the receive blocks forever, and
`main.go` calls `licenseValidator.Stop()` on the shutdown path. Without a valid license the
process therefore never exits on SIGTERM and has to be killed.

Under Kubernetes that is every rollout, every scale-down and every node drain waiting out
`terminationGracePeriodSeconds` and then taking a SIGKILL — which is also the least good
moment to be killed, because in-flight multipart uploads are then left dangling on the
backend. Fixed, but not in the one line this predicted, which panicked against the suite:
`Stop` closes `stopChan` through a `sync.Once` and waits on `doneChan` only when the
monitoring goroutine actually exists.

### A-3 `/health` never reported the shutdown state, and fixing that exposed a dead timeout — **verified, fixed**

Two bugs that hid each other, which is why neither had been noticed.

**The wiring.** `setupRoutes` passed the server's handlers to the health handler by value:

```go
healthHandler.SetShutdownStateHandler(s.shutdownStateHandler)
healthHandler.SetRequestTracker(s.requestStartHandler, s.requestEndHandler)
```

`setupRoutes` runs inside `NewServer` ([server.go](../../internal/proxy/server.go)), and
`main` installs those handlers *after* `NewServer` returns
([main.go](../../cmd/s3-encryption-proxy/main.go)). So the health handler captured three
nils and kept them. `Health` guards every use with `if h.shutdownStateHandler != nil`, so it
silently did nothing.

Consequence: **`/health` answered 200 for the entire graceful shutdown.** A Kubernetes
readiness probe therefore kept the pod in the Service endpoints while it drained, so every
rollout, scale-down and node drain routed requests to a proxy that was shutting down. The
second call to `setupRoutes` in `GetHandler` does not save it — that one builds a throwaway
router and is documented as being for tests.

Fixed by binding late: the health handler now gets closures that read the server fields at
call time.

**The bug that fix uncovers.** Because the tracker was nil, `activeRequests` was never
incremented, so it was always zero, so the drain loop's `active == 0` branch fired on the
first tick and shutdown always finished within a second. That masked this:

```go
for {
    select {
    case <-ticker.C:                      // every 1 second
    case <-time.After(shutdownTimeout):   // rebuilt on every pass
    }
}
```

A `select` re-evaluates its channel operands each time round, so every tick created a new
timer and discarded the old one. The timeout could only fire after a full `shutdownTimeout`
with no tick, and the ticker made that impossible — the forced-shutdown branch was
unreachable.

With the counter working, any in-flight request holds the loop in the non-zero branch, and
on a streaming proxy one large transfer holds it there for minutes. The wiring fix alone
would have turned *always shuts down in a second* into *can wait forever*. Fixed in
`a0c6054` by creating the deadline once before the loop.

The pairing is the lesson: a dead code path can be load-bearing, and repairing the thing
that made it dead is what makes its bugs reachable.

### A-2 A license with no `exp` claim kills the proxy after exactly 60 minutes — **fixed**

Validation only checks expiry when the claim is present:

```go
if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time) { ... reject ... }
```

so a token **without** `exp` is accepted as valid. `expiresAt` then keeps its zero value,
`time.Time{}`, which is year 1. The runtime monitor ticks once an hour and asks

```go
if now.After(v.info.ExpiresAt) {   // now.After(year 1) is always true
    v.gracefulShutdown()           // logs "License has expired", then os.Exit(1)
}
```

So a perpetual license starts the proxy cleanly and terminates it one hour later, logging
*"License has expired during runtime"* about a license that has no expiry at all. In a
container that is a permanent one-hour crash loop with a log line pointing at the wrong
cause. Fixed the second way: `checkClaims` rejects a token whose `exp` claim is absent, because a
perpetual license is a business decision and must not be the consequence of an omission.

---

## Correctness, smaller

**Verified:**

- `ComputeCiphertextSize` returns `-1` for the empty algorithm while `ComputePlaintextSize`
  accepts it. `putObjectDirect` sends `ComputeCiphertextSize` as `Content-Length` while the
  body comes from the encryptor, so a `-1` would reach the SDK as a negative length. The
  arithmetic itself is correct and is now pinned against the real encryptors for every
  algorithm and eleven payload sizes in
  [ciphertext_size_invariant_test.go](../../pkg/encryption/ciphertext_size_invariant_test.go).
- `GetSecurityMetrics` and `ResetSecurityMetrics` have no callers anywhere.

**Reported, not verified** — leads for whoever works the owning ticket:

- `internal/config`: the legacy migration of `region`, `use_tls` and
  `skip_ssl_verification` is dead code — **verified**, and pinned by a test the round added
  (`TestCfgMigrateLegacyConfigWithoutDefaults` in
  [loading_coverage_test.go](../../internal/config/loading_coverage_test.go)). The guard is
  `... && viper.IsSet("use_tls") && !viper.IsSet("s3_backend.use_tls")`, and both keys have
  a `viper.SetDefault`, so `IsSet` is true for the new key as well and the branch never
  runs. Reported as major; **the severity is lower than that, because the direction is
  fail-safe in both cases**: a legacy `use_tls: false` is ignored and TLS stays on, and a
  legacy `skip_ssl_verification: true` is ignored and certificate verification stays on. The
  defect is that a legacy config is silently not honoured, not that it weakens anything.
  Belongs to [015](015-configuration-hygiene.md) with the rest of the config hygiene.
- `keyencryption`: `EncryptDEK`'s `keyID` return is discarded by every production caller,
  and `DecryptDataStream` passes the KEK its *own* fingerprint as the key id, which makes
  the identity check vacuous.

---

## Re-scoped: claims that did not survive checking

Recorded because it is the reason the rest of the *reported* items carry a caveat.

**"Tink `loadKEKHandle` ignores its KMS URI and mints a fresh random keyset on every call,
so data is unrecoverable after a restart."** The code does exactly that —
`loadKEKHandle(_ string, _ string)` discards both parameters and calls
`keyset.NewHandle(aead.AES256GCMKeyTemplate())`
([tink.go](../../pkg/encryption/keyencryption/tink.go)). But the severity is wrong, because
**the provider cannot be configured**: `validateProvider` refuses `type: "tink"` with
*"tink encryption is not yet implemented with the new architecture"*
([config.go](../../internal/config/config.go)), and there is no `config/tink-example.yaml`.
It is dead code, not a data-loss path.

The documentation half is repaired: `CLAUDE.md` now calls it an unreachable stub instead of
advertising a working KMS integration. The owner's decision is to complete it against a real
KMS rather than delete it (ADR 0005), so the unreachable code stays until then.

---

## Ownership: which ticket actually fixes what

Nothing here opens a competing ticket. The mapping:

| Finding | Owner |
|---|---|
| **H-1, H-2** | **Decided, D-20**: documentation only until v2. [013](013-storage-format-v2.md) dissolves both by construction; until then the README and H-5 in `SECURITY_ARCHITECTURE.md` must say that no mode refuses a tampered AES-CTR object |
| **H-3, H-4** | **Closed on this branch** (`568db10`). Follow-ups in [022](022-s3-surface-fidelity.md): item 20 answers the malformed-`partNumber` PUT with `InvalidArgument` (D-27), item 21 documents the object refusals in the README |
| **H-5** | **Decided, D-30**: validate the prefix at startup, [015](015-configuration-hygiene.md) Part 5; the shared-namespace half belongs to [013](013-storage-format-v2.md) |
| H-6 | [012](012-performance-audit-round2.md) item 3.1 already owns the multipart rework and the >5 GiB failure; the hang and the non-idempotent finalize are new and should join it |
| H-7 | [018](018-listobjectsv2-document.md) for the listing, [022](022-s3-surface-fidelity.md) for the sub-resource documents and the silent-200 PUTs |
| C-1, C-2, I-1, I-2 | **Closed on this branch**, no further work |
| S-1 (fingerprint half), S-2 | [013](013-storage-format-v2.md) — it is already changing the fingerprint (H-8) and the format |
| S-1 (passphrase half) | **Decided, D-21**: remove the raw-string fallback, [013](013-storage-format-v2.md) open question 13, bundled in [023](023-major-v5.md) for 5.0.0 (not shipped in 4.0.0) |
| S-4 | **Decided, D-24**: keep the map, trusted-proxy CIDR list, eviction — [015](015-configuration-hygiene.md) Part 5, which reverses its own Part 1.2 and flags the consequence |
| S-6 | [015](015-configuration-hygiene.md) Part 4, already owned there as its E-1 |
| S-3 | **Decided, D-22**: pprof on its own loopback listener, [015](015-configuration-hygiene.md) Part 5 |
| A-3 | **Closed on this branch** |
| A-1, A-2 | **Decided, D-25**: fix the deadlock, reject a token without `exp` — [020](020-dev-license-expiry.md), whose scope is amended to admit it. Both fixed and released in 4.0.0 |
| P-1 | **Decided, D-28**: no interim fix; [013](013-storage-format-v2.md) open question 14, measured after |
| P-2 | **Decided, D-29**: pooled path in both modes, then measure — [012](012-performance-audit-round2.md) item 1.4 |
| P-3 | [012](012-performance-audit-round2.md), the performance audit |
| X-1 | [022](022-s3-surface-fidelity.md), the silent-200 ticket |
| X-2 | **Decided, D-26**: map to 500 keeping the code — [022](022-s3-surface-fidelity.md) item 19 |
| S-5 | [013](013-storage-format-v2.md) designs the fix; the interim exposure is already stated in `SECURITY_ARCHITECTURE.md`, nothing to write |
| Tink | **Decided, D-23**: complete it rather than delete it — [025](025-tink-kms-hcvault.md) |

## Success criteria

1. Repository statement coverage above 90 %, unit tests only, with the mock code out of the
   denominator. Wave 1 reached 77.8 %, wave 2 96.2 %, both measured 2026-09-06 and neither
   re-measured since; the ticket index still quotes the wave-1 number.
2. Every item above is either fixed, assigned to the ticket named in the table, or
   explicitly declined by the owner.
3. No test in this round depends on `config/license.jwt`, which expires 2026-10-05 per
   [ticket 020](020-dev-license-expiry.md). Held: the license tests mint their own keys.
4. `golangci-lint run` reports 0 issues and the suites pass under `-race`.
