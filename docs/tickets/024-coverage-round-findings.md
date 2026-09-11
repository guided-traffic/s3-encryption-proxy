# Ticket 024: The coverage round — what raising coverage found

## Status (2026-09-11, after wave 2)

**One row left: S-3, and it is a decision, not work.** Everything else this
findings ticket carried is shipped or belongs to a ticket that owns it. The
coverage work itself was done in 2026-09; the decisions it produced (D-20 to
D-30) are ADRs; the fixes shipped in 4.0.0 and, for the rest, in 5.0.0's wave 2.

| Open | One line | State |
|---|---|---|
| S-3 | The monitoring listener is unauthenticated on `:9090` | **open, needs a decision** — see below. It is the only reason this file still exists |
| H-6, the `ListParts` half | `ListParts` answered a constant empty document without asking the backend | **Closed 2026-09-11** by [013](013-storage-format-v2.md) item 10: it is answered from the session part table |

Closed in wave 2, 2026-09-11:

| Was open | What closed it |
|---|---|
| H-6 residue, the status codes | Eight multipart client mistakes answered `500 InternalError` with the generic message, so every SDK retried them to the end of its budget. Each has the code that says what happened now, and the six bare plain-text refusals went with them (ADR 0007 D8) |
| H-6b | The canonical request collapses sequential whitespace inside a header value, mirroring `aws-sdk-go-v2`'s own canonicalisation byte for byte. A correctly signed request was answered `SignatureDoesNotMatch` while the backend accepted it — a false negative throughout, never a false positive |
| H-7 residue | All twenty-one bucket sub-resource `GET`s answer a document of the proxy's own. **It was worse than this file recorded**: they handed the `aws-sdk-go-v2` *output* struct to the XML writer, so the root element was its Go type name, the element names were its field names, there was no S3 namespace and the SDK's internal `<ResultMetadata>` was inside every one. No S3 client could parse any of them. `PUT ?acl` and `?cors` parse into the same documents and carry every grant and rule (ADR 0007 D5) |
| X-1 | All four preconditions on `GET`, ranged `GET` and `HEAD`, the two entity-tag ones on `PUT` and `CompleteMultipartUpload` (ADR 0007 D7) |
| X-3 residue | `WriteXML` is deleted. It committed `200` before it marshalled, so a marshalling failure left a truncated document behind a success status; `WriteS3Document` is the only writer left |
| P-3 | One registry, gathered by the listener. The two headline metrics reached no scrape at all, and the collectors that *were* served carried none of the Kubernetes labels — labelled series were not exported, exported series were not labelled |
| S-6 | Wave 1: `max_clock_skew_seconds` is read on the header-signed path, which is the one every SDK uses |

---

## The open item

### S-3 The monitoring port is unauthenticated — a decision, not work

The monitoring mux has no authentication and binds every interface when it is on.
What is verified about the exposure, 2026-09-11:

- It is **off by default** (`monitoring.enabled: false`), and the chart's
  monitoring `Service` is off by default and `ClusterIP` when on.
- The sharp half was already fixed and released: pprof is not on this mux but on
  `PprofServer`, bound to a loopback address that a non-loopback value refuses at
  startup. That mattered because a heap profile of this process contains DEKs and
  plaintext buffers.
- The `endpoint` label is the **route template** (`/{bucket}/{key:.*}`), not the
  request path, so no bucket or key name reaches a scrape.
- What a scrape does carry: request rate and latency by route template, build
  version and commit, active connections, and
  `s3ep_license_info{licensed_to, company, expires_at}`.
- One thing this ticket claimed that is still false: it said the code logs a
  warning telling the operator to restrict access. It does not. The listener
  starts with an `Info` line naming its address and says nothing about exposure.

So the sensitive part is narrow: the licensee's name and company, plus a
deployment fingerprint. Two answers were put to the owner and neither is taken
yet:

1. **Leave it unauthenticated and drop the two identifying labels.** That is what
   every Prometheus exporter is, it is what makes a Kubernetes scrape work at
   all, and it removes the only business-identifying data while keeping the
   expiry gauges an operator alarms on. The control stays where it belongs, in a
   NetworkPolicy, and the documentation says so.
2. **Give it real authentication.** A configuration key, its validation, its
   README row, and a ServiceMonitor that has to carry the credential.

This file is deleted the moment that is decided and written down — as an ADR if
the answer is a rule, as a README paragraph if it is a documented posture.

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

1. **Met.** Repository statement coverage above 90 %, unit tests only, with the
   mock code out of the denominator: **93.8 %**, measured on 2026-09-10. Not
   re-measured since; wave 2 adds production statements in
   `internal/proxy/handlers/bucket` and `internal/proxy/handlers/object` and
   removes some in `internal/proxy/response` and `internal/proxy/utils`, so the
   number will have moved.
2. **Met for seven of the eight rows.** Only **S-3** is left, and it is a
   decision rather than work. It is the one reason this file still exists;
   `ListParts` was named here for continuity and closed 2026-09-11 by
   [013](013-storage-format-v2.md) item 10, from the part table it now answers
   from.
3. **Held.** No test in this round depends on `config/license.jwt`; the license
   tests mint their own keys.
4. **Gates, re-run 2026-09-11 for wave 2.** `go build ./...`, `go vet ./...`,
   `gofmt -l .`, `make test-unit`, `make lint` (0 issues, golangci-lint v2.13.1),
   `make quality` end to end, `make test-integration` and
   `make test-integration-tls` all green, with no new error or warning line in
   `docker logs proxy` across either run, and zero test buckets left behind. The
   suite has still not been run under `-race`.
