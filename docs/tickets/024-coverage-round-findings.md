# Ticket 024: The coverage round — what raising coverage found

## Status (2026-09-10, second pass)

**Eight rows still open; two of them lost half their subject.** This is a
findings ticket from the unit-coverage round of 2026-09-06: the coverage work
itself is long done, and what remains here is the defect list it produced. The
decisions it produced (D-20 to D-30) are ADRs now, and the fixes shipped in
4.0.0. The deletion round and the segment chain closed or dissolved most of the
rest.

Two changes landed on `feat/major-v5` since the first pass and this file absorbs
them:

1. **The listing document** (`d696763`, [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)).
   Both object listings and `ListBuckets` build an S3 document instead of
   marshalling the SDK output struct. **H-7's listing half is closed**; its
   sub-resource half is not. **X-3 is half closed**: the writer that marshals
   before it commits exists and the listings use it, `WriteXML` does not and 21
   call sites still do.
2. **The exit provider** (`0ccface`, [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)).
   `none` is gone as a provider type. No open item here rested on it; one
   *obsolete* row cited `NoneProvider.EncryptDEK` as evidence and that evidence
   was wrong — the row is corrected below.

Every state below was re-verified on 2026-09-10 against `6eea6c3` and carries the
file and line it was read at; treat a line number as an anchor to find the code,
not as an address. Nothing here opens a competing ticket; the open items name
their owner.

| Open | One line | Owner |
|---|---|---|
| H-6 residue | `ListParts` is a constant empty document; a malformed `CompleteMultipartUpload` is answered `500 InternalError` | [013](013-storage-format-v2.md) item 10 (P-7) for `ListParts`, [022](022-s3-surface-fidelity.md) for the status codes |
| H-6b | SigV4 canonicalisation does not collapse sequential whitespace in header values | [022](022-s3-surface-fidelity.md) |
| H-7 residue | The 21 bucket **sub-resource** `GET`s still return the marshalled SDK output struct, and `PUT ?acl` / `?cors` parse into a tagless SDK **input** struct | [022](022-s3-surface-fidelity.md) |
| S-3 | The monitoring listener is unauthenticated on `:9090` | **unassigned**; the natural home is [015](015-configuration-hygiene.md), which today carries only the pprof half (done) |
| S-6 | `max_clock_skew_seconds` is a no-op on the header-signed path, and there is no replay defence | [015](015-configuration-hygiene.md) item 2 (ADR 0013 D3) |
| P-3 | The two headline HTTP metrics never reach `/metrics` — **still reproduces** | **unassigned**; belongs with [012](012-performance-audit-round2.md), which carries no item for it yet |
| X-1 | `If-Modified-Since` / `If-Unmodified-Since` are dropped on `GET`, every conditional header on `HEAD` | [022](022-s3-surface-fidelity.md) |
| X-3 residue | `WriteXML` still commits `200` before it marshals, and 21 sub-resource `GET`s still call it | [022](022-s3-surface-fidelity.md) |

---

## The open items

### H-6 residue — multipart, what the format change did not close

The segment chain closed most of H-6 (see [Obsolete](#obsolete--the-subject-no-longer-exists)).
Two things did not:

- **`ListParts` never asks the backend.** It answers a constant document —
  `Bucket`, `Key`, `UploadId`, `StorageClass: STANDARD`, `MaxParts: 1000` and no
  parts — with a `TODO` next to it
  ([list.go:64-71](../../internal/proxy/handlers/multipart/list.go#L64)). A client
  that lists parts to decide what to re-upload is told the upload is empty.
- **A malformed `CompleteMultipartUpload` is answered `500 InternalError`.**
  Missing `uploadId`, an unparseable body, an empty part list, a part number out
  of range, a missing ETag and a duplicate part number all go through
  `WriteS3Error` with a plain `fmt.Errorf`
  ([complete.go:85, :114, :127, :132, :138](../../internal/proxy/handlers/multipart/complete.go#L85)),
  and an error carrying neither an `APIError` nor an HTTP status is internal by
  definition to the mapper
  ([error_mapping.go:157-160](../../internal/proxy/response/error_mapping.go#L157)).
  So a client error is reported as a proxy failure, with a generic message that
  says nothing about what was wrong. Same shape in
  [abort.go:67](../../internal/proxy/handlers/multipart/abort.go#L67) and
  [list.go:60](../../internal/proxy/handlers/multipart/list.go#L60).

The parts of H-6 that a client would hit first are gone: an unknown upload id is
`404 NoSuchUpload` ([complete.go:188](../../internal/proxy/handlers/multipart/complete.go#L188),
[upload.go:126](../../internal/proxy/handlers/multipart/upload.go#L126)), a part
number out of range is `400 InvalidPartNumber`
([complete.go:159](../../internal/proxy/handlers/multipart/complete.go#L159)),
and a completion list that does not describe the upload is `400 InvalidPart`
([complete.go:199, :214](../../internal/proxy/handlers/multipart/complete.go#L199)).

### H-6b SigV4 canonicalisation rejects requests AWS accepts

`buildCanonicalHeaders` trims each value and joins multiple values with commas
([s3auth_robust.go:334-369](../../internal/proxy/middleware/s3auth_robust.go#L334)).
It does **not** collapse sequential whitespace inside a value, which AWS's
canonicalisation does, so a correctly signed request whose header carries
repeated spaces is answered 403.

The second half is still an observation, not a verified proxy defect: a signed
`GET ...?response-content-disposition=attachment%3B%20filename%3D%22a.txt%22` was
answered **403** while the same request without an encoded space was answered 200.
That points at query-string canonicalisation — SigV4 requires RFC 3986, where a
space is `%20` and never `+` — but it was never isolated whether the mismatch is
in the proxy or in the test that produced it. The sub-resource regression test
deliberately avoids the case rather than asserting either answer.

Both matter for the same reason: `Content-Disposition` with a filename is exactly
what a pre-signed download URL carries, and filenames contain spaces.

### H-7 residue — the *sub-resource* documents are not S3 documents

**The listing half is closed** (`d696763`, ADR 0010): both object listings and
`ListBuckets` build an explicit document — `listBucketResultV2` /
`listBucketResultV1` under the S3 namespace
([listing_document.go](../../internal/proxy/handlers/bucket/listing_document.go)),
written with `WriteS3Document`
([listing.go:144, :215](../../internal/proxy/handlers/bucket/listing.go#L144),
[root/handler.go:138](../../internal/proxy/handlers/root/handler.go#L138)).
`start-after`, `fetch-owner` and `encoding-type` are forwarded,
`max-keys` is parsed and clamped
([listing_params.go:24-36](../../internal/proxy/handlers/bucket/listing_params.go#L24)),
`<Size>` is the plaintext length by arithmetic
([listing.go:32-38](../../internal/proxy/handlers/bucket/listing.go#L32)),
`<Owner>` is the caller
([listing.go:52-58](../../internal/proxy/handlers/bucket/listing.go#L52)), and
`HeadBucket` calls `HeadBucket`
([operations.go:112-140](../../internal/proxy/handlers/bucket/operations.go#L112)).

**What is left is the same root one level out, in both directions.**

On the way **out**: every bucket sub-resource `GET` hands the `aws-sdk-go-v2`
output struct to `WriteXML` — **21 call sites**, `grep -c "XMLWriter.WriteXML(w,"`
over `internal/proxy/handlers/bucket/` excluding tests, e.g.
[acl.go:60](../../internal/proxy/handlers/bucket/acl.go#L60),
[cors.go:62](../../internal/proxy/handlers/bucket/cors.go#L62),
[versioning.go:56](../../internal/proxy/handlers/bucket/versioning.go#L56). Two
mock arms write a literal document with `WriteRawXML`
([acl.go:126](../../internal/proxy/handlers/bucket/acl.go#L126),
[cors.go:137](../../internal/proxy/handlers/bucket/cors.go#L137)).

On the way **in** — this was a correction of what this ticket said before, and it
still holds: `PUT /{bucket}?acl` and `?cors` do read and parse the body
([acl.go:74-91](../../internal/proxy/handlers/bucket/acl.go#L74),
[cors.go:67-88](../../internal/proxy/handlers/bucket/cors.go#L67)) — they parse it
into the SDK **input** types, which carry no XML struct tags. `encoding/xml` then
matches by field name, so `<AccessControlList><Grant>` never binds to
`Grants []Grant` and `<CORSRule>` never binds to `CORSRules []CORSRule`.
Unmarshalling succeeds, the list is empty, and the backend is told to set an ACL
with an owner and no grants, or a CORS configuration with no rules — answered
`200`. `<Owner>` binds, because that element name happens to equal its field name.
Reproduced 2026-09-10 with a standalone `encoding/xml` program over the same
shapes; the SDK types are still tagless at
`service/s3@v1.113.0/types/types.go:52-61` and `:844-853`, and `go.mod:10` still
pins `v1.113.0`.

So the listing rewrite proved the shape of the fix and left the 21 sub-resources
untouched. They belong with [022](022-s3-surface-fidelity.md).

### S-3 The monitoring port is unauthenticated

The monitoring mux has no authentication and defaults to `:9090`, every interface
([server.go:26-69](../../internal/monitoring/server.go#L26),
[config.go:235](../../internal/config/config.go#L235)).

The sharp half is fixed and released: pprof is no longer registered on that mux
but on `PprofServer` ([pprof.go](../../internal/monitoring/pprof.go)) bound to
`monitoring.pprof_bind_address`, default `127.0.0.1:6060`, and a non-loopback
address is a startup error
([config.go:309-317](../../internal/config/config.go#L309), with
`requireLoopbackAddress` at [:328-357](../../internal/config/config.go#L328)).
That mattered because a heap profile of this process contains DEKs and plaintext
buffers.

What is left is the open port itself, and **one thing this ticket claimed is now
false**: it said the code logs a warning telling the operator to restrict access.
It does not — `grep -rn "Warn" --include="*.go" internal/monitoring/` (tests
excluded) returns nothing. The listener starts with an `Info` line naming its
address ([server.go:73](../../internal/monitoring/server.go#L73)) and says nothing
about exposure. So the control exists neither in code nor in a log line, only in
documentation, which is worse than none
([ADR 0001](../adr/0001-the-backend-is-hostile.md)).
Note that P-3 below means the two metrics an operator would actually want are
not on that port either.

### S-6 `max_clock_skew_seconds` is a no-op on the path every SDK uses

**The knob is ignored where it matters.** `validateTimestamp`, the header-signed
path, compares against the package constant `MaxClockSkewSeconds = 900`
([s3auth_robust.go:40](../../internal/proxy/middleware/s3auth_robust.go#L40),
[:232-241](../../internal/proxy/middleware/s3auth_robust.go#L232)). The pre-signed
path has a proper accessor that reads `s.config.S3Security.MaxClockSkewSeconds`
and falls back to the constant
([s3auth_presigned.go:163-167](../../internal/proxy/middleware/s3auth_presigned.go#L163)).
So the setting works for pre-signed URLs and does nothing for header-signed
requests — which is what every AWS SDK client sends.

The default is 900 either way, so a stock install behaves as documented. It bites
the operator who *changes* it: tightening the window to 60 seconds to narrow
replay exposure leaves the real path accepting 900. Since the deletion round
`max_clock_skew_seconds` is the **only** key left under `s3_security` —
`validateS3Security` checks that one and nothing else
([config.go:716-726](../../internal/config/config.go#L716)), the six dead ones are
gone ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)) —
which makes a key that silently does nothing on the main path harder to excuse,
not easier.

**The replay branch cannot execute.**

```go
timeDiff := now.Sub(requestTime).Abs()
if timeDiff > MaxClockSkewSeconds*time.Second { return ... }        // returns here
if now.Sub(requestTime) > MaxClockSkewSeconds*time.Second { ... }   // unreachable
```

`now.Sub(requestTime) <= |now.Sub(requestTime)| = timeDiff`, and the first check
already returned for every `timeDiff` above the threshold
([s3auth_robust.go:233-241](../../internal/proxy/middleware/s3auth_robust.go#L233)).
The `ReplayAttempts` counter this used to feed is gone with the rest of the
security-metrics machinery, so the dead branch is now only dead code — but the
substantive point behind it stands: there is **no replay defence at all**, only a
freshness window. A captured signed request replays as often as the attacker
likes within 900 seconds, because nothing records which signatures have been
seen. `SECURITY_ARCHITECTURE.md` states this already.

### P-3 The two headline HTTP metrics are never exported — re-verified 2026-09-10

Unchanged by either of the two changes; it still reproduces exactly as reported.

`RequestsTotal` and `RequestDuration` are created through `factory`, which is
`promauto.With(...)` over a **private** `prometheus.NewRegistry()` wrapped with
the Kubernetes and Helm labels
([metrics.go:39-63](../../internal/monitoring/metrics.go#L39)). `/metrics` serves
`promhttp.Handler()`, which gathers `prometheus.DefaultGatherer`
([server.go:32](../../internal/monitoring/server.go#L32)). Nothing in the
production tree ever gathers `registry` — `grep -rn "\bregistry\b" --include="*.go"
internal/ cmd/ pkg/` excluding tests returns exactly two hits, both at its own
definition ([metrics.go:41, :43](../../internal/monitoring/metrics.go#L41)); the
third hit is an unrelated word in a comment — so the two series the middleware
exists to produce
([middleware.go:93-94](../../internal/monitoring/middleware.go#L93)) reach no
scrape.

The mechanism cuts both ways, which is the part worth stating: the collectors
that *are* exported (`LicenseInfo`, `LicenseExpiryTime`, `LicenseDaysRemaining`,
`ServerInfo`, `ActiveConnections`) use plain `promauto.New*` against the default
registerer, so they carry **none** of the Kubernetes and Helm labels — those are
attached only by the wrapper around the private registry. Labelled series are not
exported; exported series are not labelled.

Why no test catches it: the unit test gathers the private registry directly
([middleware_coverage_test.go:19-23](../../internal/monitoring/middleware_coverage_test.go#L19)),
and the integration test only asserts that `/metrics` answers 200 without looking
for a series
([auth_test.go:431-449](../../test/integration/authentication/auth_test.go#L431)).

Consequence: there is no production latency or request-rate signal, on a proxy
whose second main goal is throughput. Any performance work that wants an
after-column from a running system needs this first
([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)).

### X-1 Conditional read headers are dropped

`serveWholeObject` forwards only `If-Match` and `If-None-Match`
([operations.go:43-53](../../internal/proxy/handlers/object/operations.go#L43));
the ranged path does the same
([range.go:236-247](../../internal/proxy/handlers/object/range.go#L236)). It drops
`If-Modified-Since` and `If-Unmodified-Since`, so a conditional GET that AWS
answers `304 Not Modified` returns `200` and the whole body — fetched from the
backend, decrypted and transferred.

`handleHeadObject` forwards **no** conditional header at all: its
`HeadObjectInput` carries `Bucket`, `Key` and `VersionId` and nothing else
([operations.go:322-332](../../internal/proxy/handlers/object/operations.go#L322)),
so even `If-None-Match` is ignored on HEAD, where GET honours it. The two verbs
disagree about the same request.

This is 022's defect class exactly and it is distinct from 022 item 1, which is
about request headers dropped on **PUT**.

### X-3 residue — `WriteXML` still commits 200 before it marshals

**Half closed** (`d696763`): `WriteS3Document` marshals into a buffer, answers
`500` if that fails, and only then commits `200` and writes the declaration plus
the body ([xml.go:41-62](../../internal/proxy/response/xml.go#L41)). The three
listing call sites use it (`listing.go:144`, `:215`, `root/handler.go:138`).

**`WriteXML` is untouched and still has every other caller.** It sets the status
and only then encodes ([xml.go:22-30](../../internal/proxy/response/xml.go#L22)),
so a marshalling failure leaves a truncated document behind a success status,
with the error visible only in the proxy's log. `WriteRawXML` has the same shape
without the marshalling risk ([xml.go:32-39](../../internal/proxy/response/xml.go#L32)).
The failure is reachable wherever the marshalled value is not a proxy-controlled
struct — which is every one of the 21 sub-resource call sites under H-7 residue.
X-3 closes when those call sites move to a document of the proxy's own, which is
the same work as H-7 residue seen from the writer's end.

---

## Closed

| Item | What closed it |
|---|---|
| C-1 The security counters were a remote kill switch | Fixed in `036301b` (mutex, deep copy), then the whole machinery was deleted with [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md); no `SecurityMetrics`, no failure map, no `getClientIP` in the tree |
| C-2 A forged chunk header could allocate gigabytes | `io.CopyN` plus an explicit negative guard, still in place ([http_chunked_decoder.go:56-62](../../internal/proxy/request/http_chunked_decoder.go#L56)) |
| H-3 Unrouted object sub-resources still delete the object | `Handler.Handle` refuses in two steps ([handler.go:105-207](../../internal/proxy/handlers/object/handler.go#L105)), pinned by [object_subresource_refusal_test.go](../../test/integration/s3-methods/object_subresource_refusal_test.go). The README residue is closed too: it documents the object refusals (README.md, *Operations the proxy does not implement*) |
| H-4 A malformed `partNumber` overwrites the whole object | A `PUT` carrying `partNumber` and `uploadId` with a non-numeric part number is `400 InvalidArgument`, `GET ?partNumber` stays `NotImplemented` ([handler.go:145-174](../../internal/proxy/handlers/object/handler.go#L145)) |
| H-5 A client can write into the proxy's own metadata namespace | All three halves. The prefix is validated `^[a-z0-9-]+$` at startup ([config.go:490](../../internal/config/config.go#L490), enforced at [:504-508](../../internal/config/config.go#L504)); the namespace check lowercases the key ([helpers.go:103-111](../../internal/proxy/handlers/object/helpers.go#L103)); a client `x-amz-meta-<prefix>*` header is dropped before it reaches the map ([helpers.go:156-171](../../internal/proxy/handlers/object/helpers.go#L156), [ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)) |
| I-1 A truncated aws-chunked upload was stored as complete | `consumeCRLF` returns `io.ErrUnexpectedEOF`, still in place ([streaming_aws_decoder.go:122-138](../../internal/proxy/request/streaming_aws_decoder.go#L122)) |
| S-1 The AES KEK fingerprint is a crackable hash of a possibly human-chosen key | Both halves. `aes_key` is base64 of exactly 32 bytes or a configuration error ([aes.go:72-90](../../pkg/encryption/keyencryption/aes.go#L72)) — D-21, shipped — and the fingerprint is `HKDF-Expand(prk, "s3ep-kek-fingerprint")`, not a hash of the master key ([aes.go:56-61](../../pkg/encryption/keyencryption/aes.go#L56), label at [:27](../../pkg/encryption/keyencryption/aes.go#L27)) |
| S-2 The AES KEK wraps the DEK with unauthenticated AES-CTR | The wrap is AES-256-GCM over `salt ‖ nonce ‖ ciphertext ‖ tag` with a fixed AAD, and a tampered wrap fails with `ErrWrappedDEKAuth` ([aes.go:93-127](../../pkg/encryption/keyencryption/aes.go#L93), [ADR 0004](../adr/0004-one-local-key-provider.md)) |
| S-4 Client IP is attacker-controlled and the failure map never shrinks | The map, `getClientIP` and the brute-force branch are deleted; `logSecurityEvent` logs `remote_addr` and `x_forwarded_for` as two separate raw fields ([s3auth_robust.go:405-419](../../internal/proxy/middleware/s3auth_robust.go#L405), [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md)) |
| S-5 AES-CTR silently discards the object key it is handed | The segment chain binds every segment: `AAD = FormatID ‖ objectKey ‖ index` ([segmented_gcm.go:114-121](../../pkg/encryption/dataencryption/segmented_gcm.go#L114), [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)). A backend that moves a ciphertext from key A to key B now fails the tag on the first segment |
| P-1 The DEK is unwrapped twice on every GCM GET | One unwrap left, through the caching `ProviderManager` ([segmented.go:257](../../internal/orchestration/segmented.go#L257)); the envelope layer that did the second one is deleted. D-28's "measure after" is moot |
| P-2 The pooled read buffer is disabled unless monitoring is on | Premise was wrong; the pooled path is taken on every route in both modes, `copyWithPooledBuffer` hiding the writer behind a `writerOnly` ([helpers.go:63-83](../../internal/proxy/handlers/object/helpers.go#L63), [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)) |
| X-2 An error can be answered behind HTTP 200 | `MapError` forces any status above 599, and any status below 400 other than 304, to 500 before the code and message fallbacks ([error_mapping.go:185-216](../../internal/proxy/response/error_mapping.go#L185)) |
| A-1 Every unlicensed shutdown hangs forever | `Stop` closes `stopChan` through a `sync.Once` and waits on `doneChan` only when the monitoring goroutine exists ([validator.go:223](../../internal/license/validator.go#L223)) |
| A-2 A license with no `exp` claim kills the proxy after 60 minutes | `checkClaims` rejects a token whose `exp` is absent ([validator.go:123](../../internal/license/validator.go#L123), [ADR 0016](../adr/0016-the-license-is-a-startup-gate.md) D5) |
| A-3 `/health` never reported the shutdown state, and its timeout was dead | The health handler is bound late, through closures that read the server fields at call time ([router.go:23-50](../../internal/proxy/router.go#L23)), and the drain deadline is created once before the loop ([main.go:250](../../cmd/s3-encryption-proxy/main.go#L250)) |
| H-7, the listing half | `d696763`, [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md): explicit `ListBucketResult` documents, forwarded parameters, `max-keys` honoured, plaintext `<Size>`, caller `<Owner>`, real `HeadBucket`. Detailed under [H-7 residue](#h-7-residue--the-sub-resource-documents-are-not-s3-documents) |
| X-3, the listing half | Same commit: `WriteS3Document` marshals before it commits ([xml.go:41-62](../../internal/proxy/response/xml.go#L41)) and the three listing call sites use it |
| The legacy config migration is dead code | `migrateLegacyConfig` and the whole legacy top-level backend block are deleted ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)) |
| `GetSecurityMetrics` / `ResetSecurityMetrics` have no callers | Deleted with the security-metrics machinery |

## Obsolete — the subject no longer exists

| Item | Why |
|---|---|
| H-1 `strict` does not protect an AES-CTR download | `encryption.integrity_verification`, its four modes and the whole HMAC layer are deleted. Every object is an authenticated segment chain: a segment's GCM tag is checked in `openInto` before its plaintext is handed to the caller ([segmented_gcm_io.go:235](../../pkg/encryption/dataencryption/segmented_gcm_io.go#L235)), and the trailer authenticates the object's length and checksum. Tampering is refused by construction, not narrated. What that does not do is un-send bytes already streamed before a later segment fails — the read-side sealed-checksum work is [013](013-storage-format-v2.md)'s |
| H-2 The backend can switch integrity checking off with one header | Same: there is no `expectedSize > 0` gate any more, because there is no separable HMAC to gate. Integrity travels inside the ciphertext |
| I-2 The wrapped DEK aliased the buffer being zeroized | `envelope.EncryptDataStream` and its zeroizing defer are deleted, and no caller in `internal/orchestration` wipes a DEK buffer today, so nothing aliases anything. **Correction:** this row used to cite `NoneProvider.EncryptDEK` returning its input slice as the surviving instance of the shape. That provider is gone with [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md) — `grep -rn "NoneProvider" --include="*.go" .` excluding tests returns nothing — and its successor returns no key material at all: `ExitProvider.EncryptDEK` and `DecryptDEK` both return `ErrExitProviderKeyUse` ([exit.go:33-46](../../pkg/encryption/keyencryption/exit.go#L33)) |
| `ComputeCiphertextSize` returns `-1` for the empty algorithm | The per-algorithm size arithmetic is deleted. `PlaintextSize` returns an error, never a sentinel ([segmented_gcm.go:208](../../pkg/encryption/dataencryption/segmented_gcm.go#L208), wrapped for the orchestration layer at [segmented.go:277](../../internal/orchestration/segmented.go#L277)), and every caller handles it — the listing takes the error as "report the stored size verbatim" ([listing.go:32-38](../../internal/proxy/handlers/bucket/listing.go#L32)) |
| `EncryptDEK`'s `keyID` return is discarded; `DecryptDataStream` passes the KEK its own fingerprint as the key id | The interface has no `keyID` any more — `EncryptDEK(ctx, dek) ([]byte, error)` ([interfaces.go:7-23](../../pkg/encryption/interfaces.go#L7)) — and `DecryptDataStream` is deleted with the envelope layer |
| Tink `loadKEKHandle` mints a fresh random keyset on every call | `keyencryption/tink.go` and `github.com/google/tink/go` are deleted. `validateProvider` still refuses `type: "tink"` by name ([config.go:568-569](../../internal/config/config.go#L568)). The KMS work is [025](025-tink-kms-hcvault.md), and the decision that a KMS key is a provider type of its own is [ADR 0005](../adr/0005-a-kms-key-is-a-provider.md) |
| H-6, the parts the format change dissolved | The out-of-order part buffer, the goroutine that parked on a repeated part number, the non-idempotent `FinalizeSession`, the subset-completion that stored an unreadable object, and the post-Complete self-`CopyObject` that failed above 5 GiB *after* the data was committed. Parts are sealed synchronously, the proxy's own part table is the authority at Complete, and the metadata goes into `CreateMultipartUpload` ([segmented_session.go](../../internal/orchestration/segmented_session.go), [ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)). `CopyObject` is not even in the backend interface any more |

---

## What the round taught — keep this, the work is gone

**A coverage percentage is only as meaningful as its denominator.** Two commits
removed 1765 statements of test-shaped code from the *production* build before a
single test was written: `internal/proxy/mock_s3_backend.go`, 533 lines with no
reference anywhere in the repository, and
`handlers/{bucket,object,root}/test_helpers.go`, 1585 statements of testify mocks
that were ordinary package members because the files lacked the `_test.go`
suffix. Renaming them also removed `github.com/stretchr/testify/mock` from the
dependency graph of the binary. `root` went 13.1 → 81.0 % purely from the rename;
`bucket` went **down**, 83.2 → 81.7 %, because its mock was better covered than
its handlers and had been holding the average up. 628 uncovered statements — a
quarter of every uncovered statement in the repository — were mock code being
measured as product code.

**Five of the eleven decisions rested on a claim this ticket or its owning ticket
got wrong, and in each case the tree won.** Worth remembering as a method, not
just as history:

- **D-29's defect did not exist.** The pooled copy buffer was never switched by
  the monitoring flag; `s3Router.Use(s.loggingMiddleware)` is unconditional and
  that wrapper hides `ReadFrom` too. What was real was the capability loss, on
  every S3 route in both modes.
- **D-26's justification did not hold.** aws-sdk-go-v2 already rewrites the S3
  200-with-`<Error>` answer to 500 for the operations that register the
  customization. The change was still right, for the shapes neither ticket named
  — a 1xx above all, which `net/http` turns into a real implicit 200 carrying the
  error document.
- **D-30's mechanism was not the one recorded.** `isNoneProviderData` *did* guard
  the empty prefix; the shredder came from it disagreeing with every writer. Both
  the function and the provider it named are gone with
  [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md); the lesson survives the
  symbol.
- **D-25's "one line" fix panicked** against the suite in this tree.
- **P-1's benchmark was never committed**, so D-28's "measure after" had no
  instrument. The item then dissolved with the envelope layer, and the `rsa` row
  of its measurement table names a provider that no longer exists — the local key
  provider is `aes` alone ([ADR 0004](../adr/0004-one-local-key-provider.md)).

A sixth, from the listing rewrite that closed H-7's larger half: **three of its
planning assumptions were wrong and were caught only because a real backend
response was captured before the assertions were written** — the element order
differs in three places, the development backend does not clamp `max-keys` above
1000 (the clamp is the proxy's own, deliberate deviation), and `max-keys=0`
answers `IsTruncated` false rather than true. Same method, same result: measure,
then assert.

**Reported is not verified.** Findings the round marked *reported* came from
subagents; one of them ("Tink is a data-loss path") was wrong about severity
because the provider could not be configured at all. That is why every state
claim in this file carries a file and a line.

## Success criteria

1. **Met and re-measured.** Repository statement coverage above 90 %, unit tests
   only, with the mock code out of the denominator: **93.8 %**, measured on
   2026-09-10 with `go test -short -coverprofile` over `./...`. Not re-measured in
   this pass; the two changes since add production statements in
   `internal/proxy/handlers/bucket` and remove some in `pkg/encryption/keyencryption`,
   so the number will have moved.
2. **Met for six of the eight rows.** Every row above is fixed, dissolved, halved
   by the two changes, or assigned to the ticket named in the table at the top —
   except **S-3** (the unauthenticated `:9090` listener) and **P-3** (the two
   unexported metrics), which no other ticket carries. They stay here until they
   are assigned, and they are the only reason this file cannot be deleted once
   the other six move.
3. **Held.** No test in this round depends on `config/license.jwt`; the license
   tests mint their own keys.
4. **Gates.** `go build ./...`, `go vet ./...` and `gofmt -l .` re-run clean on
   `6eea6c3` for this pass. `go test -short`, `make test-integration` and
   `make test-integration-tls` were green on the same tip when the two changes
   landed (132 integration tests) and `gosec` reported 0 issues over 79 files;
   not re-run here. `golangci-lint` is not installed on this workstation, the
   suite has not been run under `-race`, and the **Velero e2e suite has not been
   run since the storage format landed**.
