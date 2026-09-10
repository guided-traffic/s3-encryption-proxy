# Ticket 022: S3 surface fidelity: the headers still dropped, the code still dead, the decisions still open

## Status (2026-09-10, after the listing rewrite and the exit provider)

**Open, and the error-writer half shrank again.** Every claim below was re-verified
against the working tree on `feat/major-v5` at `6eea6c3`; where the tree
contradicted what this file said, the text was corrected and the contradiction is
named. Line numbers are to that commit.

Two changes landed after the last pass, and both touch code this ticket owns:

1. **The listing rewrite (ADR 0010, `d696763`).** Three consequences here.
   `response.XMLWriter.WriteS3Document` ([xml.go:45](../../internal/proxy/response/xml.go#L45))
   is no longer uncommitted work — it landed, so the tree now holds **three**
   production XML *document* writers, not two. Both `utils.HandleS3Error` call
   sites in the bucket handler moved onto `h.errorWriter.WriteS3Error`, so item 13
   is down to **one** production call site. And `HeadBucket` joined
   `S3BackendInterface` ([s3_backend.go:65](../../internal/proxy/interfaces/s3_backend.go#L65)),
   which is the precedent item 22's passthrough half needs — see item 1.
2. **The exit provider (ADR 0025, `0ccface`, `6eea6c3`).** The provider type `none`
   is gone. Two consequences here, both cosmetic to the work: `config/none-example.yaml`
   became [config/exit-example.yaml](../../config/exit-example.yaml#L82) and carries
   the same literal AES key as the other three, so item 5 gains a fourth config row;
   and `pkg/encryption/keyencryption/` now holds `aes.go` and `exit.go`, which
   corrects one sentence in item 8. Nothing in the storage-header work changes:
   `addRequestHeaders` runs on both provider branches of `putObjectSegmented`
   ([operations.go:277](../../internal/proxy/handlers/object/operations.go#L277)),
   and the multipart producer sets its headers outside the pass-through branch
   ([operations.go:657-670](../../internal/proxy/handlers/object/operations.go#L657)).

Three earlier changes this file already absorbed, kept because the items still cite
them: the dead-code round (`7606158`) closed items 9 and 11 and took the early-HMAC
entry of item 2; the segment chain (ADR 0003) replaced the whole PUT path, leaving
**three** upload paths instead of four and removing the self-copy item 6 was aimed
at; the `rsa` key provider was deleted with ADR 0004, which is what made items 8
and 18 obsolete.

| Item | State |
|---|---|
| 1 / 22 — storage headers, D-35 | **open**, decided, not started; the path table below is rewritten to `6eea6c3`, and the passthrough half still has to put seven `S3BackendInterface` methods back — `HeadBucket` shows the interface already grew back by one |
| 2 — dead code | **partly closed**: `isRealMultipartObject`, `WriteXMLWithStatus`, `ReadRequestBody` and the early-HMAC pair are gone; the two mock handlers, `WriteRawXML` and the test helper's `contains` are still in the tree, at unchanged lines |
| 3 / 13 — two error writers | **open and smaller**: one production `HandleS3Error` call site left ([create.go:128](../../internal/proxy/handlers/multipart/create.go#L128)), down from three. The XML half grew instead: three writers now |
| 4 — `<Location>` | **open**, decided (D-36); the code moved to `complete.go:280-284` and is otherwise identical |
| 5 — key material in examples | **partly closed**: the RSA half is obsolete, `config/license.jwt` is excluded from the build context (`f9d0de1`); `gen-keys.sh` and the env-var-only examples are still open, now across **four** config files |
| 6 — missing integration coverage | **partly closed**: the copy tests exist; the self-copy case is re-aimed; versioned buckets are still untested |
| 7 — assert-nothing tests, lint leftovers | **open**: three Makefile leftovers, the README `staticcheck` line and both assert-nothing test files all still reproduce |
| 8 / 18 — RSA fingerprint | **obsolete**: the provider it fixes does not exist |
| 19, 20, 21, 22 (pre-signed) | **done**; item 21 re-verified — the README section it wrote survived the documentation rewrite and now sits at [README.md:912-957](../../README.md#L912) |
| 23 — `;` in the raw query | **open**, decided (ADR 0007 D13), nothing in the tree refuses it — `grep -rn RawQuery internal/proxy` still has no production hit |

## Before you start

- **The deletion round already took what items 9 and 11 asked for, including
  their tests.** `grep -rn "WriteXMLWithStatus\|ReadRequestBody\|isRealMultipartObject"
  --include="*.go" .` returns nothing, and there is no `//nolint:unused` left
  anywhere in the tree. What the same grep still finds is `WriteRawXML`
  ([xml.go:32](../../internal/proxy/response/xml.go#L32)) with two live callers and
  four test call sites in
  [response/xml_coverage_test.go](../../internal/proxy/response/xml_coverage_test.go)
  (`:135`, `:150`, `:176`, `:197`), and `HandleS3Error` / `S3ErrorResponse` with
  **one** production call site ([create.go:128](../../internal/proxy/handlers/multipart/create.go#L128))
  and twelve test call sites — the listing rewrite (`d696763`) moved the bucket
  handler's two onto `errorWriter`. The success criterion's grep only passes when
  items 10 and 13 land.
- **The copy tests item 6 asks for mostly exist.** `TestEncCopyObjectNeverStoresPlaintext`
  ([encryption_at_rest_test.go:728](../../test/integration/s3-methods/encryption_at_rest_test.go#L728))
  and `TestEncUploadPartCopyNeverStoresPlaintext`
  ([:797](../../test/integration/s3-methods/encryption_at_rest_test.go#L797)) drive both
  over the wire and assert the `422` and the `NotSupportedWithEncryption` code; the
  `CopyObject` one also checks on MinIO that the destination key is absent. Left: the
  bucket-to-bucket variant, and the assertion that the refused `UploadPartCopy` left no
  part on the upload.
- **The entity headers are covered for small objects, not for the multipart
  producer.** [object_headers_conformance_test.go:260](../../test/integration/s3-methods/object_headers_conformance_test.go#L260)
  asserts `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`
  and `Content-Type` on GET and HEAD against the backend's own answer, and PUT/HEAD ETag
  agreement — on a 57-byte payload. Nothing in `test/` uploads past
  `optimizations.streaming_segment_size`, so `putObjectAutoMultipart` sets those four
  headers ([operations.go:657-670](../../internal/proxy/handlers/object/operations.go#L657))
  under no test but a mock.
- **The storage-header probe is automated.** `TestHdrStorageHeadersAreAcceptedAndSilentlyDropped`
  ([:706](../../test/integration/s3-methods/object_headers_conformance_test.go#L706)) sends
  SSE, storage class, tagging, ACL, website-redirect and the three object-lock headers
  through the proxy and asserts the 200 plus the backend showing nothing. The forwarding
  work inverts that test per header; there is no aws-cli probe to re-run.
- **A versioned-bucket teardown already exists, in one file.** `HdrCleanupBucket`
  ([:212](../../test/integration/s3-methods/object_headers_conformance_test.go#L212))
  removes versions, delete markers, legal holds and governance retention. The shared
  `CleanupTestBucket`
  ([minio_test_helper.go:433](../../test/integration/minio_test_helper.go#L433)) still
  cannot. Lift that one into the helper or call it; do not write a third.
- **`gosec` and `govulncheck` are pinned** and run through `go run` with the module
  toolchain (`GOSEC_VERSION := v2.29.0` at [Makefile:277](../../Makefile#L277),
  `GOVULNCHECK_VERSION := v1.7.0` at [:288](../../Makefile#L288)). What is left unpinned is
  `air@latest` ([Makefile:60](../../Makefile#L60), [:267](../../Makefile#L267)) and the
  v1 golangci-lint coordinate item 7 fixes.

## Settled

- The bucket versioning sub-resource keeps answering `501 NotImplemented`. No client in
  scope sets it, and implementing the body parsing is a feature, not a fidelity fix; the
  versioning test enables versioning with the MinIO client, as item 6 already says.
- The static-analysis target ordering, the formatting guard and the routing-test rewrite
  (items 7 and 16) land on the bundle branch like everything else — [023](023-major-v5.md)
  stopped splitting work off to `main` on 2026-09-10.
- Turning on the `ST*` and `QF*` families is a separate, mechanical ticket, not part of
  item 7.
- The conditional read headers on GET and HEAD are not this ticket's. They land with the
  write side in one change — all four headers across GET, HEAD and PUT — in the
  conditional-request work recorded in the
  [coverage-round findings](024-coverage-round-findings.md).

---

## Context

The round that landed on `feat/velero-support-and-tests` closed the sweep findings that
were data loss or a silent wrong answer: an unrouted bucket sub-resource executing the
base operation for its method (`DELETE /bucket?encryption` deleted the bucket), the
self-copy destroying every entity header on large objects, `PUT` returning an ETag the
stored object no longer had, `?legal-hold` always setting the hold on, `?attributes`
returning the object bytes, and a truncated auto-multipart upload committing a short
object whose HMAC verified. Those are gone, and the segment chain has since removed the
self-copy that two of them were patches for.

What is left is one class of defect and three kinds of debt.

The defect class is **the silent 200**: the proxy accepts a request that asks for
something it does not do, does something else, and answers success. Rule 2 of the
threat model in
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#12-three-rules) — *a control
that exists only in configuration or documentation is worse than no control,
because it gets relied upon* — is what makes this a security item rather than a
compatibility one. Every instance closed so far was closed by answering honestly,
usually `501 NotImplemented`. Item 1 is the last instance.

The debt is code that cannot execute, two implementations of the same error document,
and example configuration files carrying live key material by design.

---

## Scope

**In**

1. **S-8**, the dropped storage headers on PUT and CreateMultipartUpload
   (items 1 and 22; decided, not implemented).
2. **Dead code** the sweep exposed and the deletion round did not reach: the two
   bucket mock handlers with `WriteRawXML`, and the test helper's hand-rolled
   `contains`.
3. **The two error writers**: `utils.HandleS3Error` and `response.ErrorWriter`
   render the same document from two implementations.
4. **`<Location>`** in `CompleteMultipartUploadResult`, currently built from
   client-controlled request data.
5. **The example configs' key material** — the decision is taken (ADR 0021), the
   generator is not written.
6. **Integration coverage that does not exist**: the copy variants that are still
   missing, the multipart producer's entity headers over the wire, and the
   versioned-bucket behaviour the README promises.
7. **Two test files that assert nothing**, and the three leftovers of the lint
   toolchain repair.
8. **Refusing a `;` in the raw query** (item 23, ADR 0007 D13).

**Out**

- Upload checksum verification ([ticket 014](014-upload-checksum-verification.md)),
  the configuration keys ([ticket 015](015-configuration-hygiene.md)), the chart
  ([ticket 016](016-helm-chart-fixes.md)), handler unit coverage
  ([ticket 019](019-handler-unit-coverage.md)), SSE-C on every verb
  ([ticket 026](026-sse-c-passthrough.md)).
- The listing document, which **landed** on 2026-09-10 (ADR 0010, `d696763`). It is
  out of scope here as before, but it is no longer pending work somewhere else: the
  only thing it leaves for this ticket is the `<StorageClass>` consequence in
  item 1's header table and the third XML writer in item 3.
- Object tagging as a *feature*. `PUT/GET/DELETE /bucket/key?tagging` answers
  `501 NotImplemented` today
  ([tagging.go:64-76](../../internal/proxy/handlers/object/tagging.go#L64)); item 22
  turns it into passthrough, but the proxy still does not encrypt tags.

---

## Item 1 — S-8: PUT drops the storage headers and answers 200

**Decided 2026-09-07 (owner, D-35; [023](023-major-v5.md) decision 5).** The
table below stays as the analysis; the answer is **forward everything except
SSE-C**. The finding is the silent drop with 200, the proxy's job is the
confidentiality of the content, and none of these headers touches it — ACLs and
tags act on the ciphertext object and are the client's business. SSE-C is the
one header where forwarding creates a trap: no read path forwards the customer
key, so an SSE-C object written through the proxy could never be read back; it
answers `501 NotImplemented` naming the header until
[026](026-sse-c-passthrough.md) carries it on every verb. Consequences beyond
the table: `?tagging` (GET/PUT/DELETE), `?retention` and `?legal-hold` (GET/PUT)
become passthrough instead of `501`
([tagging.go:64-76](../../internal/proxy/handlers/object/tagging.go#L64),
[operations.go:555-569](../../internal/proxy/handlers/object/operations.go#L555));
`PUT ?acl` and `PUT ?cors` (024 H-7, assigned here as item 22) get XML structs
with tags so the grants and rules reach the backend instead of being discarded
([acl.go](../../internal/proxy/handlers/bucket/acl.go),
[cors.go](../../internal/proxy/handlers/bucket/cors.go)); the README
and `SECURITY_ARCHITECTURE.md` say that tags and `x-amz-meta-*` reach the
backend in plaintext, that ACLs apply to the ciphertext object, and that object
lock defends against a compromised credential, not a compromised backend.

**Stale premise corrected 2026-09-10.** The deletion round removed seventeen
methods from `S3BackendInterface`
([s3_backend.go](../../internal/proxy/interfaces/s3_backend.go)), among them
`GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`,
`GetObjectLegalHold`, `PutObjectLegalHold`, `GetObjectRetention` and
`PutObjectRetention` — exactly the calls the passthrough half of item 22 needs.
They have to be put back with the handlers that use them. That is correct, not a
regression: ADR 0013's rule is that a thing exists only if code reads it, and
nothing read them.

**The interface has already grown back once, 2026-09-10.** `HeadBucket`
([s3_backend.go:65](../../internal/proxy/interfaces/s3_backend.go#L65)) was added
by the listing rewrite because `handleHeadBucket` calls it
([operations.go:119](../../internal/proxy/handlers/bucket/operations.go#L119));
it was never one of the seventeen the deletion round removed. The interface is 42
methods today. So re-adding the seven is the same move, not a reversal of
ADR 0013 — a method arrives with the caller that needs it. ADR 0007's amendment
about the cost of D4 is unaffected: `HeadBucket` is not one of the eight it names.

**The original analysis, kept as written:**

### What the code does, verified 2026-09-10

Exactly four request headers reach the backend on a PUT, plus `Content-Type`
and the `x-amz-meta-*` user metadata, which every path forwards
(`h.userMetadataFromRequest(r)` at
[helpers.go:159](../../internal/proxy/handlers/object/helpers.go#L159), called from
[operations.go:264](../../internal/proxy/handlers/object/operations.go#L264),
[:266](../../internal/proxy/handlers/object/operations.go#L266) and
[:637](../../internal/proxy/handlers/object/operations.go#L637); `h.userMetadata(r)`
at [create.go:104](../../internal/proxy/handlers/multipart/create.go#L104)).

**There are three PUT paths now, not four.** `handlePutObject`
([operations.go:202](../../internal/proxy/handlers/object/operations.go#L202))
routes on the plaintext length alone: `plaintextLen < 0 ||
plaintextLen > optimizations.streaming_segment_size` goes to the multipart
producer ([:237-240](../../internal/proxy/handlers/object/operations.go#L237)),
everything else to the single-request path. The old `putObjectDirect` /
`putObjectStreamingReader` split, the 5 MiB threshold and the HMAC condition are
all gone with the segment chain.

| Path | Function | Where the headers are set |
|---|---|---|
| one request, up to one segment | `putObjectSegmented` ([operations.go:248](../../internal/proxy/handlers/object/operations.go#L248)) | `h.addRequestHeaders(r, putInput)` at [:277](../../internal/proxy/handlers/object/operations.go#L277) → [helpers.go:113-134](../../internal/proxy/handlers/object/helpers.go#L113) |
| multipart producer (unknown length, or above one segment) | `putObjectAutoMultipart` ([operations.go:618](../../internal/proxy/handlers/object/operations.go#L618)) | `CreateMultipartUploadInput` at [:651](../../internal/proxy/handlers/object/operations.go#L651), headers inline at [:657-670](../../internal/proxy/handlers/object/operations.go#L657) |
| client-driven multipart | `CreateHandler.Handle` ([create.go:49](../../internal/proxy/handlers/multipart/create.go#L49)) | `CreateMultipartUploadInput` at [:61](../../internal/proxy/handlers/multipart/create.go#L61), headers at [:67-93](../../internal/proxy/handlers/multipart/create.go#L67) |

**The exit provider does not split this work.** Both branches of `putObjectSegmented`
build the same `PutObjectInput` and `addRequestHeaders` runs after the branch
([operations.go:277](../../internal/proxy/handlers/object/operations.go#L277)); in
the producer the header block sits outside the pass-through condition
([:657-670](../../internal/proxy/handlers/object/operations.go#L657)). One helper
per input type still covers every provider.

The four are `Cache-Control`, `Content-Disposition`, `Content-Encoding` (through
`StripAWSChunked`) and `Content-Language`. They describe the plaintext, which is
why they are correct to forward.

Everything else a client can ask for on a PUT is read by nothing.
`grep -rn "ServerSideEncryption\|StorageClass\|ObjectCannedACL\|Tagging" internal/proxy`
finds no assignment to a `PutObjectInput` or `CreateMultipartUploadInput` field
outside the mock backends, the `CompleteMultipartUpload` *response* echo at
[complete.go:270-275](../../internal/proxy/handlers/multipart/complete.go#L270), and
the listing's `<StorageClass>`, which reports what the backend stored
([listing.go:129](../../internal/proxy/handlers/bucket/listing.go#L129),
[:204](../../internal/proxy/handlers/bucket/listing.go#L204)). The dropped set:

`x-amz-server-side-encryption`, `x-amz-server-side-encryption-aws-kms-key-id`,
`x-amz-server-side-encryption-customer-*` (SSE-C), `x-amz-storage-class`,
`x-amz-tagging`, `x-amz-acl` and the canned-grant headers,
`x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`,
`x-amz-object-lock-legal-hold`, `x-amz-website-redirect-location`.

### Probe

Probed 2026-09-06 against the running demo stack (proxy `:8080`, MinIO `:9000`);
the probe bucket was removed afterwards. Not re-run since; the automated probe
`TestHdrStorageHeadersAreAcceptedAndSilentlyDropped` covers the same ground and
is green.

```
aws --endpoint-url http://127.0.0.1:8080 s3api put-object --bucket <probe> --key sse.txt \
    --body f --server-side-encryption AES256 --storage-class STANDARD_IA \
    --tagging 'k=v' --acl private
```

answers `200` with an ETag and nothing else. Directly against MinIO the stored
object has no SSE marker, `get-object-tagging` returns `"TagSet": []`, and
`list-objects-v2` reports `"StorageClass": "STANDARD"`. Four requests the client
made, four silent drops, one success.

### The decision, per header

There is no single right answer for the whole set, because the headers do
different things and the threat model treats them differently. The tension:

- **Forwarding `x-amz-server-side-encryption` asks a hostile backend to
  encrypt.** Under the model recorded in
  [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#11-the-s3-backend-is-hostile), the backend
  can read every byte anyway; its at-rest encryption is a control the adversary
  operates over its own copy. It buys nothing the proxy has not already done, and
  the response header it produces reads to the client like a guarantee.
- **Refusing breaks a client that set it harmlessly.** A Terraform module, a
  bucket-default helper, or an operator copying an example sets
  `--server-side-encryption AES256` reflexively. Answering `501` turns a working
  upload into a failed one over a header that changes nothing.

Suggested framing, one row per header. The last column was the starting point for
the argument; D-35 settled every row as "forward" except SSE-C:

| Header | Forwarding costs | Refusing costs | Leaning at the time |
|---|---|---|---|
| `x-amz-server-side-encryption`, `...-aws-kms-key-id` | asks the adversary to encrypt its own copy; the echoed response header reads as a guarantee the proxy did not make | breaks reflexive callers over a no-op | decide |
| `x-amz-server-side-encryption-customer-*` (SSE-C) | the client key would travel to the backend in a header, and the proxy would hold plaintext key material it does not manage | almost nothing — no known caller | refuse |
| `x-amz-tagging` | tag keys and values are stored **as plaintext** on the ciphertext object, so they leak to the adversary exactly what the object is | a client that tags loses tagging | refuse |
| `x-amz-storage-class` | none for confidentiality: it names a tier the operator chose. A Glacier-class object would list as readable and then fail on GET — still unverified. The listing document has since landed (ADR 0010) and passes `<StorageClass>` through verbatim ([listing.go:129](../../internal/proxy/handlers/bucket/listing.go#L129)), so a forwarded tier becomes visible to every client that lists | an operator cannot pick a tier through the proxy | forward |
| `x-amz-acl` and the grant headers | a canned ACL grants backend access to principals the proxy does not control; `public-read` would expose the ciphertext object, its size, its timing and its `s3ep-*` metadata to anyone | a client that sets `private` (the default anyway) gets an error | refuse |
| object-lock: `-mode`, `-retain-until-date`, `-legal-hold` | a hostile backend can ignore a lock, so it is not a control under the model — but against a *credential* compromise rather than a backend compromise, WORM on the ciphertext is a real anti-ransomware control for backups | consistent with the `?legal-hold` and `?retention` sub-resources | decide |
| `x-amz-website-redirect-location` | meaningless for encrypted objects | none | refuse |

The same answer has to hold on all three paths above, and a shared helper is the
place for it: extend `addRequestHeaders`
([helpers.go:113](../../internal/proxy/handlers/object/helpers.go#L113)) for the
`PutObjectInput` path, and add a matching helper for the two
`CreateMultipartUploadInput` sites — they take a different input type, so they
cannot share the `PutObjectInput` one, and both currently repeat the same four
`if` blocks by hand.

### Velero relevance

- **Verified in this tree (re-checked 2026-09-10):** the e2e BackupStorageLocation
  sets exactly one config key beyond endpoints and credentials —
  `checksumAlgorithm: "CRC32"`
  ([values-velero.yaml:50](../../test/e2e/velero/values-velero.yaml#L50)). It sets no
  `serverSideEncryption`, no `kmsKeyId`, no `tagging`. So **none of the S-8
  headers are load-bearing for the 13 scenarios**, and refusing them would not have
  shown up in the e2e. The e2e covers one client; any other S3 client that sets one
  of these headers meets the same decision.
- **Unverified:** that `velero-plugin-for-aws` maps BSL config keys
  (`serverSideEncryption`, `kmsKeyId`, `tagging`, `customerKeyEncryptionFile`)
  onto exactly these request headers. That is from memory of the plugin's object
  store; the plugin source is not vendored here. It matters less now that D-35
  forwards rather than refuses — but it still matters for the SSE-C refusal.
- Also unverified: whether kopia sets a storage class through the Velero
  node-agent path. It has such an option; nothing in this tree sets it.

---

## Item 2 — Dead code

### Closed by the deletion round (`7606158`), 2026-09-10

`isRealMultipartObject`, `XMLWriter.WriteXMLWithStatus` and `utils.ReadRequestBody`
are gone, together with the coverage tests that were their only callers. So are
`shouldValidateHMACEarly` and `validateHMACEarly`, which this ticket had parked
with [013](013-storage-format-v2.md): the segment chain removed the HMAC machinery
entirely, so there was nothing left to park.

### Still in the tree

Re-verified 2026-09-10 by grep for callers.

| What | Where | Why it is dead |
|---|---|---|
| `handleMockACL` | [acl.go:106-133](../../internal/proxy/handlers/bucket/acl.go#L106) | reachable only through `if h.S3Backend == nil` at [acl.go:35](../../internal/proxy/handlers/bucket/acl.go#L35). Production always has a backend: the router passes `s.s3Backend`, the `*s3.Client` the server builds. It fabricates an `AccessControlPolicy` granting `FULL_CONTROL` to a `mock-owner-id` |
| `handleMockCORS` | [cors.go:120-147](../../internal/proxy/handlers/bucket/cors.go#L120) | same nil branch at [cors.go:35](../../internal/proxy/handlers/bucket/cors.go#L35); fabricates a `CORSConfiguration` with `AllowedOrigin: *`, all five methods and `AllowedHeader: *` |
| `XMLWriter.WriteRawXML` | [xml.go:32-39](../../internal/proxy/response/xml.go#L32) | exactly two production callers, both the mocks above ([acl.go:126](../../internal/proxy/handlers/bucket/acl.go#L126), [cors.go:137](../../internal/proxy/handlers/bucket/cors.go#L137)). It goes when they go — and it is still the only place in the proxy that writes a hand-built XML *document* from a string. **Correction to the earlier note in this file: it is not dead today**, and it cannot be deleted before the mock handlers are, nor before item 22 rewrites `PUT ?acl` / `PUT ?cors`. Four coverage tests call it as well ([xml_coverage_test.go:135](../../internal/proxy/response/xml_coverage_test.go#L135), [:150](../../internal/proxy/response/xml_coverage_test.go#L150), [:176](../../internal/proxy/response/xml_coverage_test.go#L176), [:197](../../internal/proxy/response/xml_coverage_test.go#L197)). **The collision this file warned about did not happen:** `WriteS3Document` landed beside it in `d696763` and touches neither `WriteRawXML` nor `WriteXML` |
| `contains` / `findInString` | [minio_test_helper.go:478-492](../../test/integration/minio_test_helper.go#L478) | a hand-rolled `strings.Contains` with a redundant prefix/suffix short-circuit, called three times from `IsAlreadyExistsError` at [:467-469](../../test/integration/minio_test_helper.go#L467). Its doc comment claims "case-insensitive helper"; it is case-sensitive. **Location confirmed 2026-09-10:** this is the only copy left in the tree — the pair in `middleware_setup.go` was replaced by `strings.Contains` earlier |

**Correction to the sweep, still current.** It recorded the two mock handlers as
"reachable only when `S3Backend == nil`, which the server never constructs",
implying nothing executes them. Half right: production never reaches them, but two
tests do, on purpose — [acl_test.go:19](../../internal/proxy/handlers/bucket/acl_test.go#L19)
(`TestHandleBucketACL_GET_NoClient`) and
[cors_test.go:18](../../internal/proxy/handlers/bucket/cors_test.go#L18)
(`TestHandleBucketCORS_GET_NoClient`) both construct the handler with a nil backend
— since the listing rewrite the call reads `NewHandler(nil, nil, logger, cfg)`
([acl_test.go:22](../../internal/proxy/handlers/bucket/acl_test.go#L22),
[cors_test.go:21](../../internal/proxy/handlers/bucket/cors_test.go#L21)), because
`bucket.NewHandler` now takes the encryption manager as its second argument. Those
tests are the reason this code survived — they made it look covered. So the deletion
is five things: both handlers, both nil branches, both tests, `WriteRawXML`, and its
four coverage tests.

---

## Item 3 — Two implementations of one error document

[`utils.HandleS3Error`](../../internal/proxy/utils/utils.go#L27) routes through
`response.MapError` and marshals with `xml.MarshalIndent` before `WriteHeader`,
which is exactly what
[`ErrorWriter.writeErrorDocument`](../../internal/proxy/response/errors.go#L73)
does. Same element order, same four-space indent, same `xml.Header` prefix, same
`RequestId: proxy-request` — re-read side by side on 2026-09-10. **The documents
are identical; the implementations are still two**, and `utils.S3ErrorResponse`
([utils.go:15-21](../../internal/proxy/utils/utils.go#L15)) is a second, exported
copy of the unexported `s3Error`
([errors.go:15-21](../../internal/proxy/response/errors.go#L15)).

Two implementations of one document is how they diverged in the first place.
Consolidate onto `ErrorWriter`; delete `HandleS3Error` and `S3ErrorResponse`.

**The obstacle is now one line of work.** `HandleS3Error` takes a
`logrus.FieldLogger`; `response.NewErrorWriter` takes a `*logrus.Entry`. There were
four production call sites, then three; the listing rewrite (`d696763`) moved the
bucket handler's two onto `errorWriter` while it was rewriting those functions, so
**one** is left, and it already holds both an `*logrus.Entry` and a constructed
`*response.ErrorWriter`:

| Call site | Logger field | ErrorWriter field |
|---|---|---|
| [multipart/create.go:128](../../internal/proxy/handlers/multipart/create.go#L128) | `h.logger` — [create.go:23](../../internal/proxy/handlers/multipart/create.go#L23) | `h.errorWriter` — [create.go:25](../../internal/proxy/handlers/multipart/create.go#L25) |

It becomes `h.errorWriter.WriteS3Error(w, err, bucket, key)`. The only thing lost is
`HandleS3Error`'s `message` log field, a static string per call site that is already
implied by `error_code` and the operation — and at this one site the same text is
already logged by the `WithError(...).Error("Failed to create multipart upload with
S3")` immediately above it
([create.go:124-127](../../internal/proxy/handlers/multipart/create.go#L124)). The
pattern for a caller that genuinely only has a `FieldLogger` is in the tree:
[root/handler.go:53-58](../../internal/proxy/handlers/root/handler.go#L53) builds its
`ErrorWriter` from `logger.WithField("component", "root-handler")`. The bucket
handler's three converted sites are the worked example
([operations.go:67](../../internal/proxy/handlers/bucket/operations.go#L67),
[:100](../../internal/proxy/handlers/bucket/operations.go#L100),
[:123](../../internal/proxy/handlers/bucket/operations.go#L123)).

Test call sites that move with it — twelve, not five, because the coverage round
added seven:
[server_test.go:266](../../internal/proxy/server_test.go#L266),
[:468](../../internal/proxy/server_test.go#L468),
[:520](../../internal/proxy/server_test.go#L520) (all pass `server.logger`, an
`*logrus.Entry`),
[utils_test.go:20](../../internal/proxy/utils/utils_test.go#L20),
[:35](../../internal/proxy/utils/utils_test.go#L35), and seven in
[utils_coverage_test.go](../../internal/proxy/utils/utils_coverage_test.go)
(`:163`, `:196`, `:224`, `:246`, `:314`, `:337`, `:357`) plus `UtlParseErrorBody`
at [:119](../../internal/proxy/utils/utils_coverage_test.go#L119), which decodes
into `S3ErrorResponse`. The body assertions should be **kept and re-pointed** at
`ErrorWriter` rather than deleted — several of them (no backend detail leaks, the
resource is escaped, the status drives the log level) are the only tests that
assert those properties at all.

**Named but not folded in, and it grew instead of shrinking.** The XML *response*
writers were two; since `d696763` they are **three**, and each produces different
bytes for the same struct:

| Writer | Shape | Production call sites |
|---|---|---|
| [multipart/xml.go:45-58](../../internal/proxy/handlers/multipart/xml.go#L45) `writeXMLDocument` | `MarshalIndent` + `xml.Header`, marshals before the status | 3 — [complete.go:286](../../internal/proxy/handlers/multipart/complete.go#L286), [create.go:145](../../internal/proxy/handlers/multipart/create.go#L145), [list.go:66](../../internal/proxy/handlers/multipart/list.go#L66) |
| [response/xml.go:23-30](../../internal/proxy/response/xml.go#L23) `XMLWriter.WriteXML` | `Encoder.Encode`, no declaration, no indent, status committed first | 21, all bucket sub-resource handlers |
| [response/xml.go:45-59](../../internal/proxy/response/xml.go#L45) `XMLWriter.WriteS3Document` | `Marshal` + `xml.Header`, no indent, marshals before the status | 3 — [listing.go:144](../../internal/proxy/handlers/bucket/listing.go#L144), [:215](../../internal/proxy/handlers/bucket/listing.go#L215), [root/handler.go:158](../../internal/proxy/handlers/root/handler.go#L158) |

`WriteS3Document` is the one that is right: it is the shape ADR 0008 and ADR 0010
describe — declaration, S3 namespace on the document struct, and no status
committed until the body marshals. `WriteXML` is the one that is wrong on both
counts, and it is the one with 21 callers. **This is not this ticket's work** —
converging them is a change to every bucket sub-resource response and needs its own
ticket and its own byte-level assertions — but it is no longer "somebody is already
doing it": the rewrite landed and stopped at the two listings. Item 10's
`WriteRawXML` deletion does **not** collide with it; they are independent
functions.

---

## Item 4 — `<Location>` is built from client-controlled request data

[complete.go:280-284](../../internal/proxy/handlers/multipart/complete.go#L280) —
the code is unchanged, only moved again:

```go
scheme := "http"
if r.TLS != nil {
    scheme = "https"
}
location := scheme + "://" + r.Host + r.URL.EscapedPath()
```

This is a deliberate improvement on what it replaced — the backend's own
`result.Location`, which leaked the internal endpoint (`https://minio:9000/...`)
to the client and is attacker-controlled text under the threat model. But
`r.Host` is whatever the client put in the `Host` header, and `r.TLS` describes
the *last* hop, so behind a TLS-terminating load balancer or an ingress the proxy
reports `http://` for a connection the client made over `https://`, with whatever
hostname the client sent.

**Decided 2026-09-07 (owner, D-36; [023](023-major-v5.md) decision 6): option 1.**
The owner wants ingress deployments to get a correct value even without a
concrete consumer today. No trusted-proxy list is added for it: the element is
reflected only to the sender of the request and drives no decision in the
proxy, so a client forging the headers misleads only itself. The README says
the element mirrors the forwarded headers as received. Work item: read
`X-Forwarded-Proto` and `X-Forwarded-Host` (first value of each) where `location`
is built, fall back to `r.TLS` / `r.Host`; one unit test per source and one for
the fallback.

The three options, kept as the analysis:

1. **Honour `X-Forwarded-Proto` / `X-Forwarded-Host` when present**, falling back
   to `r.TLS` / `r.Host`. Correct behind a proxy; both headers are client-settable
   when this proxy is exposed directly, so it trades one spoofable source for
   another unless a trusted-proxy list is added — which the config has no concept
   of today.
2. **A configured public URL** (`server.public_url` or similar), used verbatim.
   Unspoofable and explicit; costs a config key, its validation, its README row,
   and a defined behaviour when it is unset. ADR 0013's rule applies to any new
   key: it must be read on every path that needs it, or not exist — and since
   2026-09-10 (ADR 0013 D11) an unknown key refuses the start, so adding one is
   also a compatibility event.
3. **Drop the element.** `<Location>` is informational; aws-sdk-go-v2 exposes it,
   and `<Bucket>`, `<Key>` and `<ETag>` carry the load. **Unverified:** which S3
   clients read `<Location>` — neither `velero-plugin-for-aws` nor kopia is
   vendored here; what is verified is only that the 13 Velero e2e scenarios pass
   with the value the proxy produces today.

`completeMultipartUploadResult`
([xml.go:32-38](../../internal/proxy/handlers/multipart/xml.go#L32)) is the only
place the element is produced, and `writeXMLDocument`
([xml.go:45](../../internal/proxy/handlers/multipart/xml.go#L45)) the only writer
that emits it.

---

## Item 5 — The example configs still carry working key material

**Decided 2026-09-07 (owner, D-37; [023](023-major-v5.md) decision 7), and the
decision now lives permanently in
[ADR 0021](../adr/0021-key-material-is-generated-never-committed.md).** Option 1,
generate on demand: `gen-keys.sh --if-needed` next to
[gen-certs.sh](../../test/ssl-setup/gen-certs.sh), called from
[start-demo.sh](../../start-demo.sh), `e2e-up.sh` and the CI bring-up, writes a
fresh AES key and exports `S3EP_AES_KEY`; the example configs carry
`aes_key: "${S3EP_AES_KEY}"` and nothing else;
[test/e2e/velero/values-proxy.yaml](../../test/e2e/velero/values-proxy.yaml) loses
its literal key; `start-demo.sh` exports `S3EP_LICENSE_TOKEN` from
`config/license.jwt` the way `e2e-up.sh` does
([e2e-up.sh:36-45](../../test/e2e/velero/e2e-up.sh#L36)).

**What has landed (verified 2026-09-10)**

- `config/license.jwt` is excluded from the container build context
  ([.dockerignore:18](../../.dockerignore#L18), commit `f9d0de1`), so a locally
  built image no longer carries a token that happens to be on disk.
- The Helm chart carries no working key: `values.yaml`, `values-monitoring.yaml`
  and `values-production.yaml` all reference `${S3EP_AES_KEY}`.

**The RSA half is obsolete.** `config/rsa-example.yaml`,
`pkg/encryption/keyencryption/rsa.go` and the five RSA integration tests are all
gone with the provider (ADR 0004). There are **no RSA private keys in this
repository** — `grep -rln "BEGIN .*PRIVATE KEY" config/ deploy/ test/` matches only
the generated, untracked test PKI under `test/ssl-setup/`. ADR 0021 carries the
same correction so an auditor does not go looking.

**What is still open**

| File | Line | Material |
|---|---|---|
| [config/aes-example.yaml](../../config/aes-example.yaml#L76) | 76 | a real AES-256 KEK (`XZmcGLpO...`, base64-decodes to 32 bytes); the env-var form sits commented at [:78](../../config/aes-example.yaml#L78) |
| [config/aes-tls-example.yaml](../../config/aes-tls-example.yaml#L85) | 85 | the same key; env-var form at [:87](../../config/aes-tls-example.yaml#L87) |
| [config/multi-example.yaml](../../config/multi-example.yaml#L50) | 50, 56 | the same key plus a second AES-256 key |
| [config/exit-example.yaml](../../config/exit-example.yaml#L82) | 82 | the same key again; env-var form at [:84](../../config/exit-example.yaml#L84) |
| [test/e2e/velero/values-proxy.yaml](../../test/e2e/velero/values-proxy.yaml#L142) | 142 | the same key again |

**New since the exit provider (ADR 0025), 2026-09-10.** `config/none-example.yaml`
became `config/exit-example.yaml`, and it grew a key: under the exit provider the
`aes` provider stays configured so objects this proxy encrypted earlier still read
back, so the example that used to need no key material now carries the same literal
one as the other three. Four files, not three.

**Why they were left.** They are working fixtures, not deployment artifacts:
[docker-compose.demo.yml:65](../../docker-compose.demo.yml#L65) and
[:113](../../docker-compose.demo.yml#L113) bind-mount `aes-example.yaml` and
`aes-tls-example.yaml` as the two demo proxies' configuration, and
`make run-monitoring` ([Makefile:361](../../Makefile#L361)) and
`make test-monitoring` ([:368](../../Makefile#L368)) pass
`--config config/aes-example.yaml`. `make run` ([Makefile:54](../../Makefile#L54))
does **not**: it starts the binary with no `--config` at all. Replacing a literal
with `${S3EP_AES_KEY}` makes config loading fail with
`environment variable ... is not set or empty`
([envexpand.go](../../internal/config/envexpand.go)) unless the variable is
exported first, so the generator and the bring-up calls have to land in the same
change — otherwise `docker compose -f docker-compose.demo.yml up` stops working
from a clean clone.

**One open detail ADR 0021 names and this work has to settle:** the generator, the
chart and the example comment currently use three different variable names
(`S3EP_AES_KEY`, `AES_ENCRYPTION_KEY`, and whatever the generator prints). Pick
one — `S3EP_AES_KEY`, the one the chart already uses — and make every file say it.

---

## Item 6 — Integration coverage that does not exist

Two and a half gaps. All are behaviour the repository states in the README or in a
code comment and proves nowhere against a real backend.

### The copy operations — mostly closed

Both copy paths answer `422 NotSupportedWithEncryption`
([errors.go:108](../../internal/proxy/response/errors.go#L108)):

- `CopyObject` (`PUT` with `x-amz-copy-source`) at
  [operations.go:208-222](../../internal/proxy/handlers/object/operations.go#L208),
  pinned by [object/copy_test.go](../../internal/proxy/handlers/object/copy_test.go)
  and, over the wire, by `TestEncCopyObjectNeverStoresPlaintext`.
- `UploadPartCopy` at
  [copy.go:35-44](../../internal/proxy/handlers/multipart/copy.go#L35), routed at
  [router.go:88-92](../../internal/proxy/router.go#L88) — the registration that had
  to be moved ahead of `UploadPart`, with a `Headers("x-amz-copy-source", "")`
  matcher that used to compare against the literal string `{source}`. Pinned at
  route level by [server_test.go:547](../../internal/proxy/server_test.go#L547)
  and over the wire by `TestEncUploadPartCopyNeverStoresPlaintext`.

Left to write:

1. On the refused `UploadPartCopy`, assert that the upload has **no** part — not a
   part of size 0. That is what the original bug produced, and no test looks for it.
   Check the backend directly.
2. The bucket-to-bucket variant of the `CopyObject` refusal, so a future
   implementation cannot pass by handling only the same-bucket case.

### The multipart producer's entity headers over the wire — re-aimed 2026-09-10

**The self-copy is gone.** `putObjectAutoMultipart` now sets the object's metadata
on `CreateMultipartUpload` ([operations.go:651-656](../../internal/proxy/handlers/object/operations.go#L651))
because every value exists before the first byte is sent, and there is no
`CopyObject` in `S3BackendInterface` any more. `restateStoredAttributes` and the
ETag correction went with it. So the *defect* this test was written against
(S-4: the self-copy destroying every entity header, S-10: the PUT ETag the stored
object no longer had) can no longer occur by that mechanism.

**Write the test anyway, and write it now.** The entity headers and the PUT/HEAD
ETag agreement are a contract with the client, not an artefact of the copy. Today
nothing proves that contract on the producer path against a real backend: every
payload in `object_headers_conformance_test.go` is a few dozen bytes and takes
`putObjectSegmented`. The test is the check that the segment chain did not lose
what the self-copy was patched to keep, and it is the check that catches anyone
reintroducing a post-completion rewrite.

Wanted, in `test/integration/s3-methods/`:

- PUT an object **larger than `optimizations.streaming_segment_size`** with a
  `Content-Type`, a `Cache-Control` and a `Content-Disposition`, HEAD it back,
  assert all three survived, and assert that the ETag the PUT returned is the one
  HEAD reports. The size is load-bearing and the threshold changed: the demo stack
  configures 12 MiB ([config/aes-example.yaml:85](../../config/aes-example.yaml#L85)),
  and the routing condition is now purely `plaintextLen < 0 || plaintextLen >
  streaming_segment_size` ([operations.go:237](../../internal/proxy/handlers/object/operations.go#L237)) —
  no 5 MiB threshold, no HMAC condition. 16 MiB is a safe choice; 8 MiB is **not**
  and would prove nothing.
- Add the client-driven variant if it is cheap (`create-multipart-upload` with the
  same three headers, one part, complete, HEAD): it is a third code path
  ([create.go:67-93](../../internal/proxy/handlers/multipart/create.go#L67)) with
  its own copy of the same four `if` blocks, and item 22 is about to touch all
  three.

### Versioned buckets, which nothing in this repository ever creates

`grep -rni versioning test/` still matches exactly one file, and it is the dead one
item 7 deletes: `bucket_subresource_test.go` names `versioning` in a list literal
it never sends anywhere
([:49](../../test/integration/s3-methods/bucket_subresource_test.go#L49)).
Nothing else in the tree calls `PutBucketVersioning` outside a mock, and
`TestContext` creates a plain bucket that no test changes.

So the whole versioned-object path is asserted at handler level against mocks
and never once against a backend that keeps versions:

| Behaviour | Production code |
|---|---|
| `versionId` forwarded on GET and HEAD | `objectVersionID` ([helpers.go:17](../../internal/proxy/handlers/object/helpers.go#L17)) |
| `versionId` on a ranged GET, on both backend GETs | [range.go](../../internal/proxy/handlers/object/range.go) |
| `versionId` forwarded on DELETE | [operations.go:305-317](../../internal/proxy/handlers/object/operations.go#L305) |
| `x-amz-version-id` on the way back | `writeVersionHeaders` ([helpers.go:29-39](../../internal/proxy/handlers/object/helpers.go#L29)) |
| `x-amz-delete-marker` on a DELETE that created one | [operations.go](../../internal/proxy/handlers/object/operations.go) |
| a multipart upload writes exactly **one** version | the metadata is set on `CreateMultipartUpload` ([create.go:104-119](../../internal/proxy/handlers/multipart/create.go#L104), [operations.go:651-656](../../internal/proxy/handlers/object/operations.go#L651)) and no `CopyObject` follows — the method is not on `S3BackendInterface` any more |

A mock returns the version id the test told it to return, so those prove the
plumbing and nothing about the backend.

**The last row inverted on 2026-09-10 and the test has to follow.** The README
used to promise that a multipart upload writes a *second* version carrying the
encryption metadata; [README.md:969-978](../../README.md#L969) now states the
opposite — "An encrypted multipart upload writes exactly one version: every
metadata value exists before the first backend byte is sent, so nothing rewrites
the finished object to attach it." That is a stronger claim and a better test: it
fails if anyone reintroduces a post-completion rewrite.

Wanted, in the same package, on a bucket the test versions itself:

1. Two PUTs to the same key, then GET and HEAD each `versionId` through the
   proxy, comparing the SHA-256 of each body against what was uploaded. A
   dropped `versionId` serves the current version, which only a second version
   can expose. One ranged GET on the older version as well, because
   `handleGetObjectRange` passes the parameter on two separate backend GETs.
2. DELETE without `versionId`: assert `x-amz-delete-marker: true`, assert the
   previous version still reads by id, then DELETE that id and assert it is
   gone.
3. A multipart upload above the segment size: assert the bucket holds **exactly
   one** version afterwards, that `x-amz-version-id` returned by
   `CompleteMultipartUpload` names it, and that the `s3ep-*` metadata sits on it.
   It pairs with the entity-header case above: the same 16 MiB PUT answers both.

Three things to know before writing it.

- **Enable versioning with the MinIO client, not through the proxy.**
  `PUT /bucket?versioning` refuses every non-empty body: `if len(body) > 0` at
  [versioning.go:77](../../internal/proxy/handlers/bucket/versioning.go#L77)
  answers `501 NotImplemented` at
  [:79](../../internal/proxy/handlers/bucket/versioning.go#L79), and every real
  client sends `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`.
  What gets past that branch forwards a `PutBucketVersioningInput` carrying no
  configuration at all ([:70](../../internal/proxy/handlers/bucket/versioning.go#L70)).
  The README says so too, and tells operators to version the bucket at the backend.
- **The shared teardown cannot delete a versioned bucket.** `CleanupTestBucket`
  lists with `ListObjectsV2` and deletes without a `versionId`
  ([minio_test_helper.go:433-458](../../test/integration/minio_test_helper.go#L433)),
  which on a versioned bucket writes delete markers instead of removing
  versions. The `DeleteBucket` that follows fails with `BucketNotEmpty` and its
  error is only logged, so the bucket would pile up in MinIO from run to run with
  nothing failing. Use `HdrCleanupBucket`
  ([object_headers_conformance_test.go:212](../../test/integration/s3-methods/object_headers_conformance_test.go#L212)),
  which already walks `ListObjectVersions` and clears holds and retention, or lift
  it into the helper. Do not write a third.
- **Unverified: that the demo MinIO accepts versioning at all.** It runs
  single-drive (`server /data` in
  [docker-compose.demo.yml](../../docker-compose.demo.yml)), and no
  `put-bucket-versioning` has been issued against it. Check it first: if the
  backend refuses, the test needs a different backend shape, and that is a larger
  decision than the test.

---

## Item 7 — Two tests that assert nothing, and three leftovers from the lint repair

### The lint toolchain: what is already fixed

Recorded because the remaining items only make sense against it:

- [.golangci.yml](../../.golangci.yml) declares `version: "2"`, drops `gosimple`
  (merged into `staticcheck` in v2), re-enables the v1 default exclusion presets,
  and turns the new `ST*` and `QF*` families off with the reason written next to
  them.
- CI is pinned to `github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1`
  ([release.yml:172](../../.github/workflows/release.yml#L172)). It used to install
  the **v1 module path** via `@latest`, whose newest version is `v1.64.8`, because
  v2 lives under `/v2/`.
- `make lint` ([Makefile:239-250](../../Makefile#L239)) now fails on an
  unformatted file instead of printing the list and exiting 0.

### What is left, all three re-verified 2026-09-10

- **`make tools` still installs the v1 path.**
  [Makefile:268](../../Makefile#L268) is
  `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`, the
  exact line CI moved away from. A developer who follows the documented setup gets
  v1.64.8, which refuses the migrated config with
  `you are using a configuration file for golangci-lint v2 with golangci-lint v1`.
  Point it at the same pinned v2 coordinate CI uses, and keep the two in sync from
  one place if that is cheap.
- **`make static` still has the non-failing copy of the fmt check.**
  [Makefile:295-298](../../Makefile#L295) is `go vet` plus a bare `$(GOFMT) -l .`.
  It is the weaker duplicate of what `lint` does properly. Either give it the same
  guard or drop the line; two checks with the same name and different strictness is
  how the first one got trusted.
- **`quality` runs the formatter after the check that fails without it.**
  `quality: static lint fmt` ([Makefile:301](../../Makefile#L301)) — make runs
  prerequisites in order and stops at the first failure, so on an unformatted tree
  `lint` exits 1 and `fmt`, the target that would have fixed it, never runs.
  Reorder to `fmt static lint`, or drop `fmt` from the aggregate.
- **`ST*` and `QF*` stay off**, deliberately, so that a tooling migration did not
  become a repo-wide restyle. Measured 2026-09-06 with the two exclusions removed:
  **18 findings** — 12 `ST1003` (naming), 3 `QF1008`, and one each of `ST1023`,
  `QF1006`, `QF1003`. The count predates the deletion round and will have shrunk;
  re-measure before opening that ticket.
- **The standalone `staticcheck` binary is not what the repository means by
  staticcheck.** `staticcheck` in [.golangci.yml](../../.golangci.yml) is the linter
  inside golangci-lint. A separately installed binary must be built with the
  module's Go version or it cannot analyze the tree at all. One line in the README
  Development section ([README.md:1054](../../README.md#L1054)) saves the next person
  the detour — `grep -n staticcheck README.md` still returns nothing.

### Two test files that assert nothing

Neither can fail when the code is wrong, and one costs integration-suite time to
prove it. Both re-verified present 2026-09-10.

- [test/integration/s3-methods/bucket_subresource_test.go](../../test/integration/s3-methods/bucket_subresource_test.go)
  — 94 lines behind the `integration` build tag, containing
  `assert.True(t, true, ...)` ([:29](../../test/integration/s3-methods/bucket_subresource_test.go#L29)),
  `assert.Equal(t, 200, http.StatusOK)` ([:39](../../test/integration/s3-methods/bucket_subresource_test.go#L39)),
  `assert.Contains(t, "application/xml", "application/xml")` ([:40](../../test/integration/s3-methods/bucket_subresource_test.go#L40)),
  and a `supportedSubResources` list literal defined at
  [:46](../../test/integration/s3-methods/bucket_subresource_test.go#L46) inside the
  test itself. It builds an `httptest` request at
  [:34](../../test/integration/s3-methods/bucket_subresource_test.go#L34) and never
  sends it. Delete the file.
- [internal/proxy/handlers/bucket/routing_test.go:87-136](../../internal/proxy/handlers/bucket/routing_test.go#L87)
  — `testTrackingHandler.handleBucket` ([:93](../../internal/proxy/handlers/bucket/routing_test.go#L93))
  re-implements the routing rule, including its own 14-entry sub-resource list at
  [:102-106](../../internal/proxy/handlers/bucket/routing_test.go#L102), instead of
  calling `Handler.Handle`. It asserted its own copy of the logic and therefore
  could not catch the bucket-deleting fall-through. The real coverage now lives in
  [bucket_crud_test.go](../../internal/proxy/handlers/bucket/bucket_crud_test.go)
  (`TestBucketHandle_UnroutedSubResourceIsNotABaseOperation` and neighbours), all of
  which call the real `Handle`. Rewrite the routing test against the real handler or
  delete it; do not leave a second implementation of the routing rule in the tree,
  because the next person to change the rule will change only one of them.

---

## Item 8 — Obsolete: the RSA provider fingerprint

**Obsolete 2026-09-10.** The defect was `keyData := append(p.publicKey.N.Bytes(),
byte(p.publicKey.E))` in the `rsa` key provider: `byte(E)` keeps the low 8 bits, so
for the near-universal exponent 65537 the fingerprint was effectively
`SHA-256(N)`. The provider was deleted with ADR 0004 ("one local key provider") —
`pkg/encryption/keyencryption/` holds only `aes.go` and `exit.go` (ADR 0025 renamed
the pass-through provider) — so there is no
fingerprint to fix and no stored object to break. The `#nosec G115` and the comment
that named this ticket went with the file.

What survives the deletion is the shape worth remembering: a provider-selection key
that silently dropped most of one of its two inputs. The `aes` provider derives its
fingerprint with HKDF-SHA256 over the whole key, so it is not in that class.

---

## Work breakdown

**Blocked on nothing — the decisions are taken**

- [ ] 1. ~~Take the per-header decision.~~ **Done 2026-09-07: D-35, forward
      everything except SSE-C.** Item 22 is the implementation.
- [ ] 2. Implement it on all **three** PUT paths through shared helpers: extend
      `addRequestHeaders`
      ([helpers.go:113](../../internal/proxy/handlers/object/helpers.go#L113)) for
      `PutObjectInput`, and add one helper for the two `CreateMultipartUploadInput`
      sites ([operations.go:651](../../internal/proxy/handlers/object/operations.go#L651),
      [create.go:61](../../internal/proxy/handlers/multipart/create.go#L61)), which
      today repeat the same four `if` blocks by hand. Restore the object tagging,
      retention and legal-hold methods on `S3BackendInterface` — the deletion round
      removed them because nothing called them.
- [ ] 3. Unit tests: a table over the decided headers asserting either the
      forwarded input field or the refusal status, on each of the three paths. One
      integration test for each of the three refused SSE-C headers, so the refusal
      is proven over the wire.
- [ ] 4. README: a row per header under
      [Operations the proxy does not implement](../../README.md#L912), and move the
      `?tagging` / `?retention` / `?legal-hold` rows from refused to forwarded.
      State plainly that the proxy's own encryption is unaffected either way.
- [x] ~~5. Implement ADR 0021's generator.~~ **Done 2026-09-11.**
      [scripts/gen-keys.sh](../../scripts/gen-keys.sh) writes `S3EP_AES_KEY` and
      `S3EP_AES_KEY_RETIRED` into the ignored `.env`, refuses to replace a key that
      is already there under `--if-needed`, and is called by
      [start-demo.sh](../../start-demo.sh), `e2e-up.sh`, CI and the two monitoring
      make targets. All six literal keys are gone — four example configurations,
      the end-to-end deployment values and five blocks of `README.md` — and
      `S3EP_AES_KEY` is the only variable name left. `start-demo.sh` exports
      `S3EP_LICENSE_TOKEN` from `config/license.jwt`. Two things the ticket did not
      list: the chart had never wired the variable its own values referenced, so a
      default install could not start, and the integration suites that build a
      proxy in-process load `.env` themselves. `make run-monitoring` and
      `make test-monitoring` were the open question here; both now generate the key
      the way the demo does.

- [ ] 6. Implement D-36 at
      [complete.go:280-284](../../internal/proxy/handlers/multipart/complete.go#L280):
      `X-Forwarded-Proto` / `X-Forwarded-Host` first value each, falling back to
      `r.TLS` / `r.Host`; one unit test per source and one for the fallback.

**Unblocked**

- [x] ~~7. Point `make tools` at the pinned v2 golangci-lint coordinate CI uses.~~
      **Done 2026-09-11.** `GOLANGCI_LINT_VERSION := v2.13.1` on the `/v2` module
      path, with the reason and the requirement that it match
      `.github/workflows/release.yml` written beside it, and the target now says
      where it installed the binary. This is why the red lint went unnoticed:
      `make tools` handed out a v1 binary that refuses this repository's
      configuration, so nobody could run the gate locally at all.
- [ ] 8. Give `make static` the same failing fmt guard as `lint`, or drop the
      `$(GOFMT) -l .` line ([Makefile:295-298](../../Makefile#L295)), and reorder
      `quality` ([Makefile:301](../../Makefile#L301)) so the formatter runs before
      the check that fails without it.
- [x] ~~9. Delete `isRealMultipartObject`.~~ **Done 2026-09-10** in the dead-code
      round (`7606158`), with its coverage test.
- [ ] 10. Delete `handleMockACL`
      ([acl.go:106](../../internal/proxy/handlers/bucket/acl.go#L106)),
      `handleMockCORS` ([cors.go:120](../../internal/proxy/handlers/bucket/cors.go#L120)),
      both `S3Backend == nil` branches
      ([acl.go:35](../../internal/proxy/handlers/bucket/acl.go#L35),
      [cors.go:35](../../internal/proxy/handlers/bucket/cors.go#L35)), both tests
      that exercise them
      ([acl_test.go:19](../../internal/proxy/handlers/bucket/acl_test.go#L19),
      [cors_test.go:18](../../internal/proxy/handlers/bucket/cors_test.go#L18) — both
      now build the handler as `NewHandler(nil, nil, logger, cfg)`), and
      then `WriteRawXML` ([xml.go:32](../../internal/proxy/response/xml.go#L32)) with
      its four coverage tests. **Order matters and the earlier note here was wrong:**
      `WriteRawXML` is not dead today — it has two live callers — so it goes last,
      and only after item 22 has settled whether `PUT ?acl` / `PUT ?cors` need a
      raw-XML writer of their own (they do not: they marshal structs).
- [x] ~~11. Delete `XMLWriter.WriteXMLWithStatus` and `utils.ReadRequestBody`.~~
      **Done 2026-09-10** in the dead-code round (`7606158`), with their tests.
- [ ] 12. Replace `contains` / `findInString`
      ([minio_test_helper.go:478-492](../../test/integration/minio_test_helper.go#L478))
      with `strings.Contains` at the three call sites in `IsAlreadyExistsError`
      ([:467-469](../../test/integration/minio_test_helper.go#L467)). Verified
      2026-09-10: this is the last copy in the tree.
- [ ] 13. Consolidate the error writers: move the **one** remaining production call
      site ([multipart/create.go:128](../../internal/proxy/handlers/multipart/create.go#L128))
      onto `h.errorWriter.WriteS3Error` — the bucket handler's two went that way in
      the listing rewrite (`d696763`) and are the worked example
      ([bucket/operations.go:67](../../internal/proxy/handlers/bucket/operations.go#L67),
      [:100](../../internal/proxy/handlers/bucket/operations.go#L100)) — delete
      `utils.HandleS3Error` and
      `utils.S3ErrorResponse`, and re-point the twelve test call sites — three in
      [server_test.go](../../internal/proxy/server_test.go#L266), two in
      [utils_test.go](../../internal/proxy/utils/utils_test.go#L20), seven plus
      `UtlParseErrorBody` in
      [utils_coverage_test.go](../../internal/proxy/utils/utils_coverage_test.go#L119)
      — at `ErrorWriter` rather than deleting them.
- [ ] 14. Finish the copy coverage: assert the refused `UploadPartCopy` leaves no
      part on the backend upload, and add the bucket-to-bucket `CopyObject`
      refusal. The two `422` tests themselves already exist.
- [ ] 15. Add the versioned-bucket integration test: a bucket versioned through the
      MinIO client, `versionId` on GET, ranged GET, HEAD and DELETE compared by
      SHA-256, the delete marker, and the **single** version a multipart upload
      leaves behind — with `HdrCleanupBucket` as the teardown, because
      [CleanupTestBucket](../../test/integration/minio_test_helper.go#L433) cannot
      remove versions or delete markers.
- [ ] 16. Delete
      [bucket_subresource_test.go](../../test/integration/s3-methods/bucket_subresource_test.go),
      and rewrite or delete
      [routing_test.go:87-136](../../internal/proxy/handlers/bucket/routing_test.go#L87).
- [ ] 17. One line in the README Development section
      ([README.md:1054](../../README.md#L1054)) about `staticcheck` being a linter
      inside golangci-lint rather than a separate tool.
- [x] ~~18. Schedule the RSA fingerprint fix with the storage format change.~~
      **Obsolete 2026-09-10:** the `rsa` provider was deleted with ADR 0004. See
      item 8.
- [ ] 24. Add the entity-header and ETag test for the multipart producer: one PUT
      above `optimizations.streaming_segment_size` (16 MiB against the demo stack's
      12 MiB) carrying `Content-Type`, `Cache-Control` and `Content-Disposition`,
      HEAD it back, assert all three survived and that the PUT's ETag is the one
      HEAD reports. Add the client-driven multipart variant if cheap. Re-aimed
      2026-09-10: this no longer guards a self-copy, it guards the contract the
      self-copy used to break.

**Assigned 2026-09-07 from [024](024-coverage-round-findings.md), decided**

- [x] ~~19. **D-26 — an error behind HTTP 200 becomes 500.**~~ **Done 2026-09-07.**
      Implemented as `status > 599 || (status < 400 && status != 304) -> 500`, placed
      before the code and message fallbacks so a forced 500 also derives
      `InternalError` / `Internal Server Error` instead of keeping a `<Message>` of
      `OK`; the old trailing 100-599 clamp is subsumed and deleted. Two corrections
      to the item as written, both because the tree contradicted it:
      - **The 304 carve-out is mandatory and was not in the decision.**
        `handleGetObject` forwards `If-None-Match`, so a matching ETag makes the
        backend answer 304 and the SDK surfaces it as a `ResponseError` carrying that
        status. The rule as worded — *any* status below 400 — turns every cache
        revalidation into a 500, and two integration tests assert the 304 today
        (`TestConditionalRequestErrors`, `TestCondGetAndHeadPreconditions`). No other
        3xx is produced by this proxy.
      - **The stated justification does not hold against the pinned SDK, and the
        first correction of it was also wrong.** aws-sdk-go-v2 `service/s3` v1.111.0
        rewrites a 2xx carrying an `<Error>` root to 500 before deserializing
        (`internal/customizations/handle_200_error.go`), so the proxy never did
        forward the S3 `CompleteMultipartUpload` 200-error this item cites. But that
        customization is **not limited to three operations** — 88 `api_op_*.go` files
        in that module register it. The fact worth building on is the inverse, and it
        is stronger: **`GetObject`, `PutObject`, `UploadPart`, `HeadObject`,
        `DeleteObject`, `ListObjectsV2` and `CreateMultipartUpload` register
        nothing**, so for this proxy's entire data plane a backend 2xx carrying an
        error still reaches `MapError` untouched. Verified by grepping the module
        cache. On top of that: a deserialization failure on an otherwise successful
        2xx, any 1xx, any 3xx other than 304, and any backend that is not AWS S3. A
        **1xx is the sharpest case and neither ticket named it** — net/http answers
        100-199 as informational without committing the status, so the body write
        then commits an implicit 200 carrying the `<Error>` document, which is
        literally the bug D-26 describes.
      `TestRespMapErrorNonErrorStatusesAreRenderedAsErrors`, which existed to pin the
      defect, is replaced by `TestRespMapErrorNonErrorStatusesBecome500`; new
      `TestMapError_ErrorBehindANonErrorStatusBecomes500`,
      `TestMapError_ConditionalGetKeepsIts304` and
      `TestRespMapErrorNotModifiedIsForwarded`.
- [x] ~~20. **D-27 — `InvalidArgument` for the malformed part upload.**~~ **Done
      2026-09-07.** One branch in `Handler.Handle`, placed *after* the
      `knownObjectSubResources` loop rather than before it: placed before, a request
      carrying both `partNumber` and a routed sub-resource would flip from 405 to 400,
      an answer nobody decided to change. Only requests that got 501 from the
      unknown-parameter branch become 400. It does not re-parse the part number — the
      router has already proved it is not `[0-9]+`, and the range check for numeric
      values lives in `multipart/upload.go` and must not be duplicated. Scope stayed at
      PUT-with-both: `PUT ?partNumber` alone, `PUT ?uploadId` alone and every non-PUT
      verb keep their 501, because nothing decided them and AWS's answer for those
      shapes was not verified.

      **Found while doing it, NOT fixed here.** The whole guard reads
      `r.URL.Query()`. Go's `net/url.parseQuery` discards any `&`-separated segment
      containing a `;` and `Query()` swallows that error, while gorilla/mux splits on
      both. So `PUT /b/k?partNumber=abc;uploadId=u` fails the mux part route, reaches
      `Handle` with an **empty** parsed query, passes both refusal loops and the new
      branch, and executes the base PUT — H-4's data loss through a different door. It
      authenticates cleanly, because the SigV4 canonical query string is built from
      the same `r.URL.Query()`, so the client signs the empty query it sends. Verified
      by reading `net/url` and gorilla/mux, **not reproduced over the wire**.
      **Decided 2026-09-09 (owner): refuse — ADR 0007 D13, item 23 below.**
- [x] ~~21. **README: the object sub-resource refusals.**~~ **Done 2026-09-10** in
      the documentation rewrite (`d2981ef`).
      [README.md:912-957](../../README.md#L912) now carries the object refusals next
      to the bucket ones: a bullet naming `?acl`, `?tagging`, `?attributes`,
      `?legal-hold`, `?retention` and S3 Select with `?torrent` as the one forwarded
      exception, a table of the four that used to answer `200` for work they did
      wrongly, the `CopyObject` / `UploadPartCopy` `422`, and the sentence that only
      allowlisted query parameters reach a base operation. `?restore` and an unrouted
      `?uploads` are covered by "object sub-resources are all refused" rather than by
      name; item 22 rewrites this section anyway when tagging, retention and
      legal-hold move to forwarded.
- [x] ~~22. **The sub-resource guard refused every pre-signed download.**~~ **Found by
      the Velero e2e and fixed 2026-09-07.** `568db10` allowlisted the pre-signed SigV4
      parameters by literal name, and aws-sdk-go-v2 puts **`X-Amz-Checksum-Mode=ENABLED`
      into every pre-signed `GetObject` URL**, which was not among them. The
      unknown-parameter branch therefore answered `501 NotImplemented` to every
      pre-signed download. `TestV10_PresignedLogAccess` had been red since `568db10`
      with `<error getting backup resource list>`: Velero fetches backup logs, the
      resource list, the volume info and restore logs exactly that way, so
      `velero backup logs`, `velero backup describe --details` and
      `velero restore logs` were all broken against this proxy. Velero was where
      it showed; every client that pre-signs through aws-sdk-go-v2 was refused
      the same way.
      Fixed by admitting the **namespace** rather than a list of names:
      `request.IsAWSProtocolQueryParam`
      ([queryparams.go:32](../../internal/proxy/request/queryparams.go#L32)) treats any
      `x-amz-*` parameter as protocol rather than sub-resource, in the bucket guard
      ([bucket/handler.go:115](../../internal/proxy/handlers/bucket/handler.go#L115)) as
      well as the object one
      ([object/handler.go:169](../../internal/proxy/handlers/object/handler.go#L169)),
      because a literal list goes stale the next time the SDK adds a parameter. Safe on
      both counts: no S3 sub-resource is named `x-amz-*`, and every query parameter
      except `X-Amz-Signature` itself goes into the canonical query string the
      signature covers, so nobody who cannot already sign the request can add one.
      Covered by a unit test over the namespace boundary including the near misses
      (`xamz-acl`, `x-amz`, `ax-amz-acl`) and by
      `TestSubrefPresignedGetIsNotRefusedAsASubResource`
      ([object_subresource_refusal_test.go:215](../../test/integration/s3-methods/object_subresource_refusal_test.go#L215)),
      which presigns through the SDK and fetches over the wire.

- [ ] 22. **D-35: forward the storage headers, SSE-C refused, three sub-resources
      passthrough, two bucket bodies carried.** One request-header helper shared by
      `putObjectSegmented` and `putObjectAutoMultipart`, and a second for the two
      `CreateMultipartUploadInput` sites, setting `ServerSideEncryption`,
      `SSEKMSKeyId`, `Tagging`, `StorageClass`, `ACL` and the grant fields,
      `ObjectLockMode`, `ObjectLockRetainUntilDate`, `ObjectLockLegalHoldStatus` and
      `WebsiteRedirectLocation` from the request; the three SSE-C headers answer
      `501 NotImplemented` naming the header ([026](026-sse-c-passthrough.md) lifts
      that). `?tagging` GET/PUT/DELETE, `?retention` GET/PUT and `?legal-hold`
      GET/PUT become passthrough to the matching SDK calls with the S3 document
      echoed as the backend returns it — **which means putting those seven methods
      back on `S3BackendInterface`, where the deletion round removed them for having
      no caller.** The listing rewrite already did that once for `HeadBucket`
      ([s3_backend.go:65](../../internal/proxy/interfaces/s3_backend.go#L65)), so the
      shape of that change is settled: the method lands in the same commit as the
      handler arm that calls it, and the handler mocks in the unit tests grow with
      it. `PUT ?acl` and `PUT ?cors` parse their body into structs with
      `xml` tags that match `AccessControlPolicy/AccessControlList/Grant` and
      `CORSConfiguration/CORSRule`, map them onto the SDK types and forward; a body
      that does not parse answers `MalformedXML` through `ErrorWriter`, not
      `http.Error`. Tests: `TestHdrStorageHeadersAreAcceptedAndSilentlyDropped`
      inverts per header into "forwarded and visible on the direct MinIO leg"; a
      unit test per PUT path asserts the helper populates every field; an
      integration test each for tagging, retention and legal hold round trips;
      `PUT ?acl` with one grant and `PUT ?cors` with one rule are read back directly
      from MinIO. Docs: README storage-header table (forwarded / refused per
      header, and that tags and `x-amz-meta-*` reach the backend in plaintext),
      `SECURITY_ARCHITECTURE.md` gains user metadata and tags in its data-flow
      section, the object-lock sentence names the credential-compromise adversary.

---

- [x] ~~23. **ADR 0007 D13: refuse a `;` in the raw query.**~~ **Done 2026-09-11.**
      A middleware between authentication and the handlers answers
      `400 InvalidArgument` for any raw query containing a `;`; a percent-encoded
      `%3B` is a value byte and passes. Two integration tests in
      [object_subresource_refusal_test.go](../../test/integration/s3-methods/object_subresource_refusal_test.go)
      pin both sides: three bypass shapes refused with the object asserted
      byte-identical by SHA-256 afterwards, and an encoded semicolon in a listing
      prefix still answered `200`. The bypass was reproduced over the wire before
      the fix — a signed `PUT /b/k?partNumber=abc;uploadId=u` answered `200` and
      replaced the object. ADR 0007's Status records it as shipped. **Still owed
      by this item: the README row under the refusals**, which lands with the rest
      of the ADR 0007 documentation in item 4.

## Success criteria

- [ ] `go build ./... && go vet ./...` clean; `make test-unit` green;
      `make lint` green — it reports 0 issues today and must still do so, with the
      same golangci-lint major version from `make tools` and from CI.
- [ ] `make quality` runs to completion on a deliberately unformatted tree
      instead of stopping before the formatter.
- [ ] `grep -rn "HandleS3Error\|S3ErrorResponse\|WriteRawXML\|handleMock" --include="*.go" .`
      returns nothing. (`WriteXMLWithStatus`, `ReadRequestBody` and
      `isRealMultipartObject` already return nothing.)
- [ ] The deletions build with **no new `//nolint:unused`** anywhere — the
      `unused` linter is enabled, the tree currently has zero, and that is the check
      that keeps this from regrowing.
- [ ] For each header of item 22: a unit test per PUT path asserting the forwarded
      input field, and for each refused SSE-C header an integration test showing the
      refusal over the wire with the documented code.
- [ ] `TestHdrStorageHeadersAreAcceptedAndSilentlyDropped` is inverted per header:
      each header either fails with the documented code or succeeds with the
      forwarded property visible on the backend object, instead of the silent 200
      it pins today.
- [ ] `UploadPartCopy` integration test: no part exists on the backend upload after
      the `422`. `CopyObject` bucket-to-bucket: `422`, and the destination key does
      not exist.
- [ ] Versioned-bucket integration test green, and the bucket it created is gone
      afterwards — no `test-bucket-*` survives the run. It has to fail if
      `versionId` stops being forwarded, and if a multipart upload ever leaves more
      than one version behind again.
- [ ] The over-segment PUT of item 24: HEAD returns the `Content-Type`,
      `Cache-Control` and `Content-Disposition` the PUT sent, and its ETag equals
      the one the PUT returned.
- [ ] `make test-integration` **and** `make test-integration-tls` green — both,
      because item 5 touches the configs the TLS suite loads.
- [ ] `make e2e-up && make test-e2e-velero && make e2e-down`: all 13 scenarios
      green. This is the Velero gate for the SSE-C refusal and for item 5, which
      takes the literal key out of `values-proxy.yaml`.
- [ ] `docker logs proxy | tail -50` shows no new error or warning lines during
      the integration run.
- [ ] README states what a PUT does with each storage header, and the
      `<Location>` decision is visible in the response body or documented as
      removed.

---

## Risks and open questions

- **"Forward" is not free, and the cost is not symmetric.** A refusal fails loudly
  and gets fixed in minutes. A forward that succeeds teaches the client that the
  proxy honours the header, and every later assumption builds on that — including,
  for `x-amz-acl`, an assumption about who can read the ciphertext. D-35 chose
  forward for every row but SSE-C; the documentation has to carry the weight the
  refusal would have carried.
- **`x-amz-tagging` versus tagging as a feature.** Item 22 makes tags reach the
  backend in plaintext on a ciphertext object, which hands an adversary a labelled
  index. That is the accepted tradeoff of D-35, and it is why the README and
  `SECURITY_ARCHITECTURE.md` rows are part of the work item and not a follow-up.
- **The object-lock row is where the threat model may argue against itself.**
  "The backend is hostile, so its WORM is meaningless" is right for a compromised
  *backend* and wrong for a compromised *credential*, which is the more common
  ransomware path for a backup bucket. D-35 forwards; the docs must say which
  adversary that is for.
- **The versioning test is the first test whose bucket outlives the shared
  teardown.** Every other test can rely on `CleanupTestBucket`; this one cannot,
  and the failure is silent — a logged-and-discarded `DeleteBucket` error and a
  bucket that stays. Use `HdrCleanupBucket`, run the test twice in a row, and check
  that MinIO is clean before believing either run.
- **Deleting the two mock handlers deletes two passing tests.** That will look
  like a coverage regression in the bucket package, and it is — of a code path
  that cannot execute. Say so in the commit message, or the next coverage review
  will restore it.
- **Item 3 is a refactor with no test that can prove it.** The two *error* writers
  produce identical bytes today — unlike the three XML document writers, which do
  not — so consolidating cannot be observed by any assertion
  except the ones being re-pointed. Do it in its own commit, moving the
  `utils_test.go` and `utils_coverage_test.go` body assertions rather than deleting
  them, so a byte-level difference would surface.
- **Item 5 changes what a clean clone can do.** Today
  `docker compose -f docker-compose.demo.yml up` works with no preparation because
  the key is in the file. After the generator lands it does not, unless
  `start-demo.sh` is the only documented entry point. Decide that explicitly rather
  than discovering it.
- **This ticket keeps being overtaken by the tree.** The `.golangci.yml` migration,
  the CI pin and the `make lint` fmt guard landed mid-ticket; the deletion round and
  the segment chain landed after that and closed four more items outright; the
  listing rewrite (`d696763`) and the exit provider (`0ccface`, `6eea6c3`) landed
  after *that* and moved most of the object-handler line numbers again. Re-verify
  every file:line before starting an item — most of them have moved at least twice.
  Two of those overtakes were help, not damage: item 13 lost two of its three call
  sites for free, and `HeadBucket` settled the shape of item 22's interface work.
- **`go install ...@latest` is a moving target beyond golangci-lint.** Largely
  closed: `gosec` and `govulncheck` are pinned and invoked through `go run` with the
  module toolchain, and the pinned golangci-lint at
  [release.yml:172](../../.github/workflows/release.yml#L172) is the only
  `go install` in any workflow file. What is left is `air@latest`, in `tools`
  ([Makefile:267](../../Makefile#L267)) and in `dev` ([:60](../../Makefile#L60)), and
  the v1 golangci-lint coordinate item 7 fixes.
