# Ticket 022: S3 surface fidelity: the headers still dropped, the code still dead, the decisions still open

## Status (2026-09-06)

**Open.** This is the residue of the before-merge sweep on
`feat/velero-support-and-tests`: everything the sweep found that was not a
before-merge fix, plus everything that needs a decision from the repository owner
before any code can be written. The sweep itself is not in the repository; its
findings are reproduced here with the file and line they were verified at, and
**every claim below was re-verified against the working tree on 2026-09-06** —
branch tip `bc6a37a` plus the uncommitted before-merge work. Where
re-verification contradicted the sweep, the correction is in the text and marked
as such.

A second pass on the same day re-checked every file:line, command and number in
this file against the tree and corrected the claims that did not hold, among
them: the `make run` attribution in item 5 (it passes no `--config` at all), the
workflow-versus-Makefile mix-up in the risks, the `ST*`/`QF*` count in item 7
(18, not 6), the four-headers sentence in item 1 (user metadata is forwarded
too), the placement of the commented env-var forms in item 5, and two over-broad
statements — what the README documents, and what reads `<Location>`. Item 7's
scope line said two lint leftovers where the item lists three. The S-8 probe,
the `handleMock*` coverage numbers, the golangci-lint v1 refusal and the four
unformatted files at `bc6a37a` were all reproduced independently.

Two cautions about the line numbers. First, the before-merge work is
**uncommitted** while this is written, so a reference is to the working tree, not
to `bc6a37a`. Second, `internal/proxy/handlers/object/operations.go` is the file
[ticket 013](013-storage-format-v2.md) rewrites most; check the function name,
not only the line.

It depends on nothing and blocks nothing. One item (item 2's early-HMAC entry) is
explicitly **not** in this ticket because ticket 013 already owns it. Three items
(1, 4, 5) are blocked on a decision, not on other work. One item (8) was assigned
to this ticket from the code itself: `pkg/encryption/keyencryption/rsa.go` now
carries a comment naming this file.

---

## Context

The round that just landed closed the sweep findings that were data loss or a
silent wrong answer: an unrouted bucket sub-resource executing the base operation
for its method (`DELETE /bucket?encryption` deleted the bucket), the self-copy
destroying every entity header on objects at or above 5 MiB, `PUT` returning an
ETag the stored object no longer had, `?legal-hold` always setting the hold on,
`?attributes` returning the object bytes, and a truncated auto-multipart upload
committing a short object whose HMAC verified. Those are gone. The README
documents the part of it a client can see — the sub-resource refusals and the
copy `422` at [README.md:636-659](../../README.md#L636); the ETag fix and the
entity headers the self-copy now preserves are recorded only in the commit that
made them, `c359091`, and as F-16 in the
[label index](README.md#fixes-f-1-to-f-25).

What is left is one class of defect and three kinds of debt.

The defect class is **the silent 200**: the proxy accepts a request that asks for
something it does not do, does something else, and answers success. Rule 2 of the
threat model in
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#12-three-rules) — *a control
that exists only in configuration or documentation is worse than no control,
because it gets relied upon* — is what makes this a security item rather than a
compatibility one. Every instance closed this round was closed by answering
honestly, usually `501 NotImplemented`. Item 1 is the last instance, and the only
one where the honest answer is not obvious, because "forward it to a backend we
treat as hostile" and "refuse it" are both defensible, and they are defensible
per header.

The debt is code that cannot execute, two implementations of the same error
document, a fingerprint that discards most of an RSA exponent, and example
configuration files carrying live key material by design.

---

## Scope

**In**

1. **S-8**, the dropped storage headers on PUT and CreateMultipartUpload. Needs a
   decision first.
2. **Dead code** the sweep exposed, minus what ticket 013 already owns.
3. **The two error writers**: `utils.HandleS3Error` and `response.ErrorWriter`
   now render the same document from two implementations.
4. **`<Location>`** in `CompleteMultipartUploadResult`, currently built from
   client-controlled request data.
5. **The example configs' key material** — a decision, not a fix.
6. **Integration coverage that does not exist**: none for the copy operations,
   and none for the versioned-bucket behaviour the README already promises.
7. **Two test files that assert nothing**, and the three leftovers of the lint
   toolchain repair that landed in this round.
8. **The RSA provider fingerprint**, which keeps one byte of the public exponent
   — **moved to [ticket 013](013-storage-format-v2.md) item 2 on 2026-09-06**;
   item 8 below keeps the analysis.

**Out**

- The early-HMAC dead code (`shouldValidateHMACEarly` / `validateHMACEarly`) and
  the post-Complete self-copy. [Ticket 013](013-storage-format-v2.md) deletes both
  by name in its "In scope — deletions" list. Deleting them here would create a
  conflict in the file v2 rewrites most.
- Upload checksum verification ([ticket 014](014-upload-checksum-verification.md)),
  the dead `s3_security` knobs and the presign lifetime
  ([ticket 015](015-configuration-hygiene.md)), the chart
  ([ticket 016](016-helm-chart-fixes.md)), the `ListObjectsV2` document
  ([ticket 018](018-listobjectsv2-document.md)), handler unit coverage
  ([ticket 019](019-handler-unit-coverage.md)).
- Object tagging as a *feature*. `PUT/GET/DELETE /bucket/key?tagging` answers
  `501 NotImplemented` today
  ([tagging.go:64-76](../../internal/proxy/handlers/object/tagging.go#L64)) and this
  ticket does not change that. It only decides what the `x-amz-tagging` header on
  a PUT should answer.

---

## Item 1 — S-8: PUT drops the storage headers and answers 200

**This item needs a decision before it can be implemented. It is presented as
options, not as a plan.**

### What the code does, verified

Exactly four request headers reach the backend on a PUT, plus `Content-Type`
and the `x-amz-meta-*` user metadata, which every path forwards
([helpers.go:128-139](../../internal/proxy/handlers/object/helpers.go#L128) for the
two single-part paths,
[operations.go:1048-1058](../../internal/proxy/handlers/object/operations.go#L1048)
for auto-multipart, `h.userMetadata(r)` at
[create.go:97](../../internal/proxy/handlers/multipart/create.go#L97) for the
client-driven one):

| Path | Function | Where the headers are set |
|---|---|---|
| small objects | `putObjectDirect` ([operations.go:501](../../internal/proxy/handlers/object/operations.go#L501)) | `h.addRequestHeaders(r, input)` at [:537](../../internal/proxy/handlers/object/operations.go#L537) → [helpers.go:150-169](../../internal/proxy/handlers/object/helpers.go#L150) |
| streaming single-part | `putObjectStreamingReader` ([operations.go:574](../../internal/proxy/handlers/object/operations.go#L574)) | an inline copy of the same four at [:655-669](../../internal/proxy/handlers/object/operations.go#L655) |
| auto-multipart (≥ 5 MiB with HMAC on) | `putObjectAutoMultipart` ([operations.go:1017](../../internal/proxy/handlers/object/operations.go#L1017)) | `CreateMultipartUploadInput` at [:1029](../../internal/proxy/handlers/object/operations.go#L1029), headers at [:1034-1046](../../internal/proxy/handlers/object/operations.go#L1034) |
| client-driven multipart | `CreateHandler.Handle` ([create.go:49](../../internal/proxy/handlers/multipart/create.go#L49)) | `CreateMultipartUploadInput` at [:61](../../internal/proxy/handlers/multipart/create.go#L61), headers at [:66-93](../../internal/proxy/handlers/multipart/create.go#L66) |

The four are `Cache-Control`, `Content-Disposition`, `Content-Encoding` (through
`StripAWSChunked`) and `Content-Language`. They describe the plaintext, which is
why they are correct to forward.

Everything else a client can ask for on a PUT is read by nothing.
`grep -rn "ServerSideEncryption\|StorageClass\|ObjectCannedACL\|Tagging" internal/proxy`
finds no assignment to a `PutObjectInput` or `CreateMultipartUploadInput` field
outside the mock backends. The dropped set:

`x-amz-server-side-encryption`, `x-amz-server-side-encryption-aws-kms-key-id`,
`x-amz-server-side-encryption-customer-*` (SSE-C), `x-amz-storage-class`,
`x-amz-tagging`, `x-amz-acl` and the canned-grant headers,
`x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`,
`x-amz-object-lock-legal-hold`, `x-amz-website-redirect-location`.

### Probe

Re-probed on 2026-09-06 against the running demo stack (proxy `:8080`, MinIO
`:9000`); the probe bucket was removed afterwards.

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
  backup into a failed one over a header that changes nothing.

Suggested framing, one row per header. The last column is a starting point for
the argument, not a conclusion:

| Header | Forwarding costs | Refusing costs | Leaning |
|---|---|---|---|
| `x-amz-server-side-encryption`, `...-aws-kms-key-id` | asks the adversary to encrypt its own copy; the echoed response header reads as a guarantee the proxy did not make | breaks reflexive callers over a no-op | **decide**: refuse and document, or forward and document that it is backend-side and not the proxy's encryption |
| `x-amz-server-side-encryption-customer-*` (SSE-C) | the client key would travel to the backend in a header, and the proxy would hold plaintext key material it does not manage | almost nothing — no known caller | refuse |
| `x-amz-tagging` | tag keys and values are stored **as plaintext** on the ciphertext object, so they leak to the adversary exactly what the object is | a client that tags loses tagging | refuse, consistent with `?tagging` already answering `501` at [tagging.go:64-76](../../internal/proxy/handlers/object/tagging.go#L64) |
| `x-amz-storage-class` | none for confidentiality: it names a tier the operator chose. A Glacier-class object would list as readable and then fail on GET — recorded, and explicitly marked unverified, in [ticket 018](018-listobjectsv2-document.md) | an operator cannot pick a tier through the proxy | forward |
| `x-amz-acl` and the grant headers | a canned ACL grants backend access to principals the proxy does not control; `public-read` would expose the ciphertext object, its size, its timing and its `s3ep-*` metadata to anyone | a client that sets `private` (the default anyway) gets an error | refuse |
| object-lock: `-mode`, `-retain-until-date`, `-legal-hold` | a hostile backend can ignore a lock, so it is not a control under the model — but against a *credential* compromise rather than a backend compromise, WORM on the ciphertext is a real anti-ransomware control for backups | consistent with the `?legal-hold` and `?retention` sub-resources, which this round made `501` | **decide**: the one row where refusing may be the weaker security answer |
| `x-amz-website-redirect-location` | meaningless for encrypted objects | none | refuse |

Whatever is decided, the same answer has to hold on all four paths above, and the
shared helper is the place for it: move `putObjectStreamingReader`'s inline copy
([operations.go:655-669](../../internal/proxy/handlers/object/operations.go#L655))
onto `addRequestHeaders`, and give the two `CreateMultipartUploadInput` sites a
matching helper — they take a different input type, so they cannot share the
`PutObjectInput` one.

### Velero relevance

- **Verified in this tree:** the e2e BackupStorageLocation sets exactly one
  config key beyond endpoints and credentials — `checksumAlgorithm: "CRC32"`
  ([values-velero.yaml:50](../../test/e2e/velero/values-velero.yaml#L50)). It sets no
  `serverSideEncryption`, no `kmsKeyId`, no `tagging`. So **none of the S-8
  headers are load-bearing for the 13 scenarios that are green today**, and
  refusing them would not have shown up in the e2e.
- **Unverified:** that `velero-plugin-for-aws` maps BSL config keys
  (`serverSideEncryption`, `kmsKeyId`, `tagging`, `customerKeyEncryptionFile`)
  onto exactly these request headers. That is from memory of the plugin's object
  store; the plugin source is not vendored here and was not fetched in this
  session. **Check it before choosing "refuse" for any of them**, because
  "refuse" turns a BSL setting an operator can legitimately want into a hard
  backup failure, and the failure surfaces as a BSL that never goes Available
  rather than as a message naming the header.
- Also unverified: whether kopia sets a storage class through the Velero
  node-agent path. It has such an option; nothing in this tree sets it.

---

## Item 2 — Dead code

Each entry re-verified on 2026-09-06 by grep for callers, plus a coverage profile
where that changed the answer.

### Owned by ticket 013, not by this one

`shouldValidateHMACEarly`
([operations.go:186-204](../../internal/proxy/handlers/object/operations.go#L186))
returns `false` unconditionally at
[:203](../../internal/proxy/handlers/object/operations.go#L203) — the only other
return, at [:197](../../internal/proxy/handlers/object/operations.go#L197), is also
`false`. Its single caller is the branch at
[:165-181](../../internal/proxy/handlers/object/operations.go#L165), which is
therefore unreachable, and with it `validateHMACEarly`
([:206-242](../../internal/proxy/handlers/object/operations.go#L206)) and its
whole-object `io.ReadAll` at
[:211](../../internal/proxy/handlers/object/operations.go#L211). About 60 lines.

[Ticket 013](013-storage-format-v2.md) lists both functions by name in its
deletions. **Leave them here.** If 013 slips past two releases, move this entry
into whatever ticket is landing in `operations.go` at that time — but do not open
a second edit of that file in parallel with v2.

### In scope here

| What | Where | Why it is dead |
|---|---|---|
| `isRealMultipartObject` | [operations.go:1403-1426](../../internal/proxy/handlers/object/operations.go#L1403) | no caller; carries `//nolint:unused` at [:1402](../../internal/proxy/handlers/object/operations.go#L1402), which is the marker that it was known dead and kept anyway |
| `handleMockACL` | [acl.go:106-133](../../internal/proxy/handlers/bucket/acl.go#L106) | reachable only through `if h.S3Backend == nil` at [acl.go:35](../../internal/proxy/handlers/bucket/acl.go#L35). Production always has a backend: [router.go:40](../../internal/proxy/router.go#L40) passes `s.s3Backend`, the `*s3.Client` built at [server.go:120](../../internal/proxy/server.go#L120) and stored at [:125](../../internal/proxy/server.go#L125). It fabricates an `AccessControlPolicy` granting `FULL_CONTROL` to a `mock-owner-id` |
| `handleMockCORS` | [cors.go:120-147](../../internal/proxy/handlers/bucket/cors.go#L120) | same nil branch at [cors.go:35](../../internal/proxy/handlers/bucket/cors.go#L35); fabricates a `CORSConfiguration` with `AllowedOrigin: *`, all five methods and `AllowedHeader: *` |
| `XMLWriter.WriteXMLWithStatus` | [xml.go:33-40](../../internal/proxy/response/xml.go#L33) | no caller anywhere; 0.0 % covered |
| `XMLWriter.WriteRawXML` | [xml.go:43-49](../../internal/proxy/response/xml.go#L43) | exactly two callers, both the mocks above ([acl.go:126](../../internal/proxy/handlers/bucket/acl.go#L126), [cors.go:137](../../internal/proxy/handlers/bucket/cors.go#L137)). It goes when they go — and it is the last place in the proxy that writes a hand-built XML *document*. The only hand-built XML string left after that is the bare declaration at [root/handler.go:105](../../internal/proxy/handlers/root/handler.go#L105), which interpolates nothing |
| `utils.ReadRequestBody` | [utils.go:107-117](../../internal/proxy/utils/utils.go#L107) | no production caller; only [utils_test.go:200](../../internal/proxy/utils/utils_test.go#L200) and [:219](../../internal/proxy/utils/utils_test.go#L219). Body reading goes through `request.Parser` |
| `contains` / `findInString` | [minio_test_helper.go:478-492](../../test/integration/minio_test_helper.go#L478) | a hand-rolled `strings.Contains` with a redundant prefix/suffix short-circuit, called three times at [:467-469](../../test/integration/minio_test_helper.go#L467). Its doc comment claims "case-insensitive helper"; it is case-sensitive. The identical pair in `middleware_setup.go` was replaced by `strings.Contains` in the round that just landed — this is the copy that was missed |

**Correction to the sweep.** It records the two mock handlers as "reachable only
when `S3Backend == nil`, which the server never constructs", implying nothing
executes them. Half right: production never reaches them, but two tests do, on
purpose — [acl_test.go:19-35](../../internal/proxy/handlers/bucket/acl_test.go#L19)
(`TestHandleBucketACL_GET_NoClient`) and
[cors_test.go:18-34](../../internal/proxy/handlers/bucket/cors_test.go#L18)
(`TestHandleBucketCORS_GET_NoClient`) both call `NewHandler(nil, ...)`. A coverage
profile confirms it: `handleMockACL` 60.0 %, `handleMockCORS` 50.0 %. So the
deletion is five things, not two: both handlers, both nil branches, both tests,
and `WriteRawXML`. Those tests are the reason this code survived — they made it
look covered.

---

## Item 3 — Two implementations of one error document

The round that just landed made
[`utils.HandleS3Error`](../../internal/proxy/utils/utils.go#L50) route through
`response.MapError` and marshal with `xml.MarshalIndent` before `WriteHeader`,
which is exactly what
[`ErrorWriter.writeErrorDocument`](../../internal/proxy/response/errors.go#L73)
does. Same element order, same four-space indent, same `xml.Header` prefix, same
`RequestId: proxy-request`. **The documents are now identical; the
implementations are still two**, and `utils.S3ErrorResponse`
([utils.go:38-43](../../internal/proxy/utils/utils.go#L38)) is a second, exported
copy of the unexported `s3Error`
([errors.go:15-21](../../internal/proxy/response/errors.go#L15)).

Two implementations of one document is how they diverged in the first place.
Consolidate onto `ErrorWriter`; delete `HandleS3Error` and `S3ErrorResponse`.

**The obstacle, and why it is smaller than it looks.** `HandleS3Error` takes a
`logrus.FieldLogger`; `response.NewErrorWriter` takes a `*logrus.Entry`. But all
four production call sites already hold both an `*logrus.Entry` and a constructed
`*response.ErrorWriter`:

| Call site | Logger field | ErrorWriter field |
|---|---|---|
| [bucket/operations.go:47](../../internal/proxy/handlers/bucket/operations.go#L47) | `h.logger` — [handler.go:17](../../internal/proxy/handlers/bucket/handler.go#L17) | `h.errorWriter` — [handler.go:19](../../internal/proxy/handlers/bucket/handler.go#L19) |
| [bucket/operations.go:74](../../internal/proxy/handlers/bucket/operations.go#L74) | same | same |
| [multipart/create.go:108](../../internal/proxy/handlers/multipart/create.go#L108) | `h.logger` — [create.go:23](../../internal/proxy/handlers/multipart/create.go#L23) | `h.errorWriter` — [create.go:25](../../internal/proxy/handlers/multipart/create.go#L25) |
| [multipart/create.go:137](../../internal/proxy/handlers/multipart/create.go#L137) | same | same |

So each becomes `h.errorWriter.WriteS3Error(w, err, bucket, key)`. The only thing
lost is `HandleS3Error`'s `message` log field, a static string per call site that
is already implied by `error_code` and the operation. Where a caller genuinely
only has a `FieldLogger`, the pattern is already in the tree:
[root/handler.go:47](../../internal/proxy/handlers/root/handler.go#L47) builds its
`ErrorWriter` with `logger.WithField("component", "root-handler")`.

Test call sites that move with it:
[server_test.go:263](../../internal/proxy/server_test.go#L263),
[:521](../../internal/proxy/server_test.go#L521),
[:573](../../internal/proxy/server_test.go#L573) (all pass `server.logger`, an
`*logrus.Entry` — [server.go:26](../../internal/proxy/server.go#L26)), and
[utils_test.go:143](../../internal/proxy/utils/utils_test.go#L143),
[:158](../../internal/proxy/utils/utils_test.go#L158), whose assertions on the
document body should be **kept and re-pointed** at `ErrorWriter` rather than
deleted — they are the only tests that assert the error body from the `utils`
side.

**Named but not folded in:** the XML *response* writers are also two now.
[multipart/xml.go:45-58](../../internal/proxy/handlers/multipart/xml.go#L45)
(`writeXMLDocument`, added this round: `MarshalIndent` plus `xml.Header`) and
[response/xml.go:23-30](../../internal/proxy/response/xml.go#L23)
(`XMLWriter.WriteXML`: `Encoder.Encode`, no declaration, no indent), the latter
used by 20-odd bucket sub-resource handlers. They produce different bytes for the
same struct. Unifying them is a bigger change than this ticket wants and it
touches every bucket handler; record it, do not start it here.

---

## Item 4 — `<Location>` is built from client-controlled request data

[complete.go:295-309](../../internal/proxy/handlers/multipart/complete.go#L295):

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

Three options, to be decided:

1. **Honour `X-Forwarded-Proto` / `X-Forwarded-Host` when present**, falling back
   to `r.TLS` / `r.Host`. Correct behind a proxy; both headers are client-settable
   when this proxy is exposed directly, so it trades one spoofable source for
   another unless a trusted-proxy list is added — which the config has no concept
   of today.
2. **A configured public URL** (`server.public_url` or similar), used verbatim.
   Unspoofable and explicit; costs a config key, its validation, its README row,
   and a defined behaviour when it is unset. Note that
   [ticket 015](015-configuration-hygiene.md) is deleting config keys, so adding
   one wants that ticket's rule applied: it must be read on every path that needs
   it, or not exist.
3. **Drop the element.** `<Location>` is informational; aws-sdk-go-v2 exposes it,
   and `<Bucket>`, `<Key>` and `<ETag>` carry the load. **Unverified:** that no
   client on the Velero path reads `<Location>` — neither the plugin nor kopia is
   vendored here, and neither was read in this session; what is verified is only
   that the 13 e2e scenarios pass with the value the proxy produces today.
   Smallest change, and it removes a class of question rather than answering it.

Whichever is chosen, `completeMultipartUploadResult`
([xml.go:32-38](../../internal/proxy/handlers/multipart/xml.go#L32)) is the only
place the element is produced.

---

## Item 5 — The example configs still carry working key material

**A decision, not a defect report.** The round that just landed removed the
working AES-256 KEK from the Helm chart, because the chart is the deployment
artifact: a `helm install` that did not override
`aes_key: "0123456789abcdef0123456789abcdef"` encrypted every object with a key
published in this repository. Both values files now reference `${S3EP_AES_KEY}`
([values.yaml:213](../../deploy/helm/s3-encryption-proxy/values.yaml#L213),
[values-monitoring.yaml:106](../../deploy/helm/s3-encryption-proxy/values-monitoring.yaml#L106)),
matching what `values-production.yaml` already did
([:127-130](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L127),
[:179](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L179)).

The example configs were **deliberately left alone**:

| File | Line | Material |
|---|---|---|
| [config/aes-example.yaml](../../config/aes-example.yaml#L113) | 113 | a real AES-256 KEK (`XZmcGLpO...`, base64-decodes to 32 bytes) |
| [config/aes-tls-example.yaml](../../config/aes-tls-example.yaml#L122) | 122 | the same key |
| [config/multi-example.yaml](../../config/multi-example.yaml#L72) | 72, 88 | the same key, plus a complete RSA private key |
| [config/rsa-example.yaml](../../config/rsa-example.yaml#L94) | 94 | a complete RSA private key |

Both PEM blocks parse as valid 2048-bit RSA private keys (`openssl pkey -noout
-text`, re-checked 2026-09-06). Each file carries a commented-out
environment-variable form next to the literal — two lines *below* it in
[aes-example.yaml:114-115](../../config/aes-example.yaml#L114), and *above* both
literals in [rsa-example.yaml:81-83](../../config/rsa-example.yaml#L81) — so the
safe shape is already written beside the unsafe one.

**Why they were left.** They are working fixtures, not deployment artifacts, and
the test suite loads them as such:

- [rsa_provider_test.go:62](../../test/integration/encryption-modes/rsa_provider_test.go#L62)
  loads `config/rsa-example.yaml` **directly** and starts a proxy instance from
  it. Five test functions depend on it
  ([:201](../../test/integration/encryption-modes/rsa_provider_test.go#L201),
  [:321](../../test/integration/encryption-modes/rsa_provider_test.go#L321),
  [:446](../../test/integration/encryption-modes/rsa_provider_test.go#L446),
  [:574](../../test/integration/encryption-modes/rsa_provider_test.go#L574),
  [:684](../../test/integration/encryption-modes/rsa_provider_test.go#L684)).
  Replacing the key with `${RSA_PRIVATE_KEY}` makes config loading fail with
  `environment variable ${RSA_PRIVATE_KEY} is not set or empty`
  ([envexpand.go:32](../../internal/config/envexpand.go#L32)) unless the variable is
  exported first.
- [docker-compose.demo.yml:60](../../docker-compose.demo.yml#L60) and
  [:102](../../docker-compose.demo.yml#L102) bind-mount `aes-example.yaml` and
  `aes-tls-example.yaml` as the two demo proxies' configuration, and
  `make run-monitoring` ([Makefile:266](../../Makefile#L266)) and
  `make test-monitoring` ([:273](../../Makefile#L273)) pass
  `--config config/aes-example.yaml`. `make run`
  ([Makefile:52-54](../../Makefile#L52)) does **not**: it starts the binary with no
  `--config` at all, so it searches for `.s3-encryption-proxy` in `$HOME`, `.`
  and `./config` ([config.go:197-201](../../internal/config/config.go#L197)) and
  never loads an example file.

**The decision this ticket asks for:** should the examples become env-var-only,
with the fixture keys generated on demand — the same move
[D-3](README.md#decisions-d-1-to-d-19) made for the test PKI, which is now
untracked and produced by
[gen-certs.sh](../../test/ssl-setup/gen-certs.sh) with `--if-needed`? The honest
accounting:

- *For.* A published key in a file called `example` gets copied. The AES key is
  identical across three files, so one copy-paste puts the same
  repository-public key on three deployments. Rule 2 again: the comment two lines
  above saying "use an environment variable" is documentation, not a control.
- *Against.* The suite currently gets a working RSA provider for free. Generating
  one means a `gen-keys.sh --if-needed` on the model of `gen-certs.sh`, a call to
  it in [start-demo.sh](../../start-demo.sh) and in the CI job before compose comes
  up (the same shape as the PKI step added at
  [release.yml:213-214](../../.github/workflows/release.yml#L213)), and a decision
  about what `make run-monitoring` does on a fresh checkout. It also removes the property
  that `docker compose -f docker-compose.demo.yml up` works from a clean clone
  with no preparation.
- *Middle option.* Leave the AES demo keys — the demo stack is local and
  throwaway, and its MinIO credentials are `minioadmin` anyway — and move only the
  RSA private keys out, since a private key in a repository is the artifact that
  reads as a real leak in a scan. Costs the five RSA integration tests a generated
  fixture, nothing else.

Do not implement any of the three before the decision.

---

## Item 6 — Integration coverage that does not exist

Two gaps. Both are behaviour the repository states in the README or in a code
comment and proves nowhere against a real backend.

### The copy operations

```
grep -rn UploadPartCopy test/   →  no matches
grep -rln CopyObject test/      →  no matches
```

Both copy paths answer `422 NotSupportedWithEncryption`
([errors.go:108-117](../../internal/proxy/response/errors.go#L108)):

- `CopyObject` (`PUT` with `x-amz-copy-source`) at
  [operations.go:372-387](../../internal/proxy/handlers/object/operations.go#L372),
  pinned by the unit test in
  [object/copy_test.go](../../internal/proxy/handlers/object/copy_test.go).
- `UploadPartCopy` at
  [copy.go:35-44](../../internal/proxy/handlers/multipart/copy.go#L35), routed at
  [router.go:66-70](../../internal/proxy/router.go#L66) — the registration that had
  to be moved ahead of `UploadPart`, with a `Headers("x-amz-copy-source", "")`
  matcher that used to compare against the literal string `{source}`.

`UploadPartCopy` is pinned by exactly one test,
[server_test.go:601-635](../../internal/proxy/server_test.go#L601). It is a good test
— it asserts the matched route by handler name, then executes the handler and
checks the 422 and the `<Resource>` element — but it invokes
`match.Route.GetHandler()` directly, so it bypasses the middleware chain and the
real server. Nothing proves the request behaves that way over the wire, and
nothing proves the thing the bug actually produced is gone: a `ListParts` that
shows a 0-byte part.

There is a third copy, and it is the one that actually runs. The metadata
self-copy on both multipart paths — [operations.go:1344](../../internal/proxy/handlers/object/operations.go#L1344)
for auto-multipart, [complete.go:234](../../internal/proxy/handlers/multipart/complete.go#L234)
for the client-driven one — is a `CopyObject` with `MetadataDirective: REPLACE`,
which replaces the entity headers along with the user metadata. The round that
just landed made it restate them (from `createInput` on the auto-multipart path,
from a `HeadObject` on the stored object in `restateStoredAttributes`,
[complete.go:323](../../internal/proxy/handlers/multipart/complete.go#L323)) and
made the copy's ETag the one the client is told
([operations.go:1374](../../internal/proxy/handlers/object/operations.go#L1374),
[complete.go:258](../../internal/proxy/handlers/multipart/complete.go#L258)).
Both are asserted **against a mock only** —
[object_test.go:602](../../internal/proxy/handlers/object/object_test.go#L602) and
[multipart_test.go:1178](../../internal/proxy/handlers/multipart/multipart_test.go#L1178),
the second feeding back a `HeadObjectOutput` the test wrote itself. Whether a
real backend reports those headers on HEAD, and honours them on the copy the way
`restateStoredAttributes` assumes, is unverified on MinIO and everywhere else:
`grep -rn "Cache-Control\|Content-Disposition" test/` matches nothing, and the
only place a PUT ETag is reused over the wire today is
[error_mapping_test.go:146-175](../../test/integration/s3-methods/error_mapping_test.go#L146),
on a 23-byte object that never reaches the self-copy.

Wanted, in `test/integration/s3-methods/`:

1. `UploadPartCopy` through the proxy: create a multipart upload, issue
   `upload-part-copy`, assert `422` and the `NotSupportedWithEncryption` code,
   then assert that the upload has **no** part — not a part of size 0. Check the
   backend directly, because `ListParts` fabricates its answer until
   [ticket 013](013-storage-format-v2.md).
2. `CopyObject` through the proxy: `422`, and the destination key does not exist
   afterwards.
3. The bucket-to-bucket variant of (2), so a future implementation cannot pass by
   handling only the same-bucket case.
4. **The self-copy over the wire, in one case.** PUT 8 MiB with a
   `Content-Type`, a `Cache-Control` and a `Content-Disposition`, HEAD it back,
   assert all three survived, and assert that the ETag the PUT returned is the
   one HEAD reports. This is the cheapest test in the item: it closes S-4 (the
   self-copy destroying every entity header at or above 5 MiB), S-10 (the PUT
   ETag the stored object no longer had) and F-16 in a single case. The size is
   load-bearing — the auto-multipart branch is taken when the length is unknown
   or HMAC is on and the object is at least 5 MiB
   ([operations.go:446-450](../../internal/proxy/handlers/object/operations.go#L446),
   with `integrity_verification: "strict"` at
   [config/aes-example.yaml:100](../../config/aes-example.yaml#L100) for the demo
   stack) — so a 1 KiB object keeps its headers either way and proves nothing.
   Add the client-driven variant if it is cheap (`create-multipart-upload` with
   the same three headers, one part, complete, HEAD): that path does not
   remember what the client sent, it reads it back from the backend, which is
   exactly the half a mock cannot speak for.

**Write (4) before [ticket 013](013-storage-format-v2.md), not after.** v2
removes the self-copy and with it `restateStoredAttributes` and the ETag
correction, so it is tempting to wait. Do not: the entity headers and the
PUT/HEAD ETag agreement are a contract with the client, not an artefact of the
copy, so the same assertions survive the rewrite unchanged and become the check
that v2 did not lose what the self-copy was patched to keep. Written after v2,
the test never runs against the code it was written for, and the only evidence
that F-16 ever worked on a real backend stays a mock.

### Versioned buckets, which nothing in this repository ever creates

`grep -rni versioning test/` matches exactly one file, and it is the dead one
item 7 deletes: `bucket_subresource_test.go` names `versioning` in a list
literal it never sends anywhere
([:49](../../test/integration/s3-methods/bucket_subresource_test.go#L49)).
Nothing else in the tree calls `PutBucketVersioning` outside a mock — not a
helper, not a compose file, not a shell script — and `TestContext` creates a
plain bucket
([minio_test_helper.go:145-157](../../test/integration/minio_test_helper.go#L145))
that no test changes.

So the whole versioned-object path is asserted at handler level against mocks
and never once against a backend that keeps versions:

| Behaviour | Production code | Its only tests |
|---|---|---|
| `versionId` forwarded on GET and HEAD | `objectVersionID` ([helpers.go:22](../../internal/proxy/handlers/object/helpers.go#L22)) at [operations.go:43](../../internal/proxy/handlers/object/operations.go#L43) and [:731](../../internal/proxy/handlers/object/operations.go#L731) | [object_test.go:293](../../internal/proxy/handlers/object/object_test.go#L293), [:382](../../internal/proxy/handlers/object/object_test.go#L382) |
| `versionId` on a ranged GET, on both backend GETs | [range.go:126](../../internal/proxy/handlers/object/range.go#L126), [:205](../../internal/proxy/handlers/object/range.go#L205) | [range_test.go:152](../../internal/proxy/handlers/object/range_test.go#L152) |
| `versionId` forwarded on DELETE | [operations.go:708](../../internal/proxy/handlers/object/operations.go#L708) | [delete_object_test.go:205](../../internal/proxy/handlers/object/delete_object_test.go#L205) |
| `x-amz-version-id` on the way back | `writeVersionHeaders` ([helpers.go:33-40](../../internal/proxy/handlers/object/helpers.go#L33)) at [operations.go:311](../../internal/proxy/handlers/object/operations.go#L311), [:565](../../internal/proxy/handlers/object/operations.go#L565), [:694](../../internal/proxy/handlers/object/operations.go#L694), [:768](../../internal/proxy/handlers/object/operations.go#L768), [range.go:269](../../internal/proxy/handlers/object/range.go#L269), [complete.go:285](../../internal/proxy/handlers/multipart/complete.go#L285) | [object_test.go:293](../../internal/proxy/handlers/object/object_test.go#L293), [range_test.go:118](../../internal/proxy/handlers/object/range_test.go#L118) |
| `x-amz-delete-marker` on a DELETE that created one | [operations.go:717](../../internal/proxy/handlers/object/operations.go#L717) | [delete_object_test.go:205](../../internal/proxy/handlers/object/delete_object_test.go#L205) |
| the self-copy, not the completion, owns the version the client is told | [complete.go:255-262](../../internal/proxy/handlers/multipart/complete.go#L255), [operations.go:1374-1378](../../internal/proxy/handlers/object/operations.go#L1374) | [object_test.go:602](../../internal/proxy/handlers/object/object_test.go#L602) |

A mock returns the version id the test told it to return, so those prove the
plumbing and nothing about the backend — the same objection the entity-header
case above makes, one row further out. The last row is the one that matters:
[README.md:674-683](../../README.md#L674) now tells users that an encrypted
multipart or auto-multipart upload writes a **second** version, and that it is
that version — the one whose id the proxy returns — which carries the encryption
metadata. That is a claim about a real versioned bucket, and no test has ever
made one.

Wanted, in the same package, on a bucket the test versions itself:

1. Two PUTs to the same key, then GET and HEAD each `versionId` through the
   proxy, comparing the SHA-256 of each body against what was uploaded. A
   dropped `versionId` serves the current version, which only a second version
   can expose. One ranged GET on the older version as well, because
   `handleGetObjectRange` passes the parameter on two separate backend GETs.
2. DELETE without `versionId`: assert `x-amz-delete-marker: true`, assert the
   previous version still reads by id, then DELETE that id and assert it is
   gone.
3. A multipart upload above the streaming threshold: assert the bucket holds two
   versions afterwards, that the `x-amz-version-id` returned by
   `CompleteMultipartUpload` is the later one, and that the `s3ep-*` metadata
   sits on that version. That is the README promise, and it is what a broken or
   removed self-copy would take away silently. It pairs with (4) of the copy
   subsection above: the same upload can carry the entity headers, so one 8 MiB
   PUT answers both.

Three things to know before writing it.

- **Enable versioning with the MinIO client, not through the proxy.**
  `PUT /bucket?versioning` refuses every non-empty body: `if len(body) > 0` at
  [versioning.go:77](../../internal/proxy/handlers/bucket/versioning.go#L77)
  answers `501 NotImplemented`
  ([:79](../../internal/proxy/handlers/bucket/versioning.go#L79)), and every real
  client sends `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`.
  What gets past that branch forwards a `PutBucketVersioningInput` carrying no
  configuration at all
  ([:83](../../internal/proxy/handlers/bucket/versioning.go#L83)). So the proxy
  cannot turn versioning on today, and the README section describes how it
  behaves on a bucket somebody else versioned. Whether to implement the body
  parsing is a decision this item does not take; it is recorded here because it
  is the reason the test needs the direct client.
- **The shared teardown cannot delete a versioned bucket.** `CleanupTestBucket`
  lists with `ListObjectsV2` and deletes without a `versionId`
  ([minio_test_helper.go:162-181](../../test/integration/minio_test_helper.go#L162)),
  which on a versioned bucket writes delete markers instead of removing
  versions. The `DeleteBucket` that follows fails with `BucketNotEmpty` and its
  error is discarded
  ([:179](../../test/integration/minio_test_helper.go#L179)), so the bucket would
  pile up in MinIO from run to run with nothing failing. Give the versioning
  test a teardown over `ListObjectVersions` covering versions **and** delete
  markers, or give the helper one.
- **Unverified: that the demo MinIO accepts versioning at all.** It runs
  single-drive (`server /data`,
  [docker-compose.demo.yml:16](../../docker-compose.demo.yml#L16)), and no
  `put-bucket-versioning` was issued against it while this was written. Check it
  first: if the backend refuses, the test needs a different backend shape, and
  that is a larger decision than the test.

---

## Item 7 — Two tests that assert nothing, and two leftovers from the lint repair

### The lint toolchain: what this round already fixed

Recorded because it moved while this ticket was written, and because the
remaining items only make sense against it. Verified by running both binaries:

- [.golangci.yml](../../.golangci.yml) was a v1 file; under the v2 binary the whole
  run failed with `unsupported version of the configuration`. It now declares
  `version: "2"`, drops `gosimple` (merged into `staticcheck` in v2), re-enables
  the v1 default exclusion presets, and turns the new `ST*` and `QF*` families
  off with the reason written next to them.
- CI installed the linter from `github.com/golangci/golangci-lint/cmd/golangci-lint@latest`
  — the **v1 module path**, whose newest version is `v1.64.8`
  (`go list -m -versions`), because v2 lives at `.../v2/cmd/golangci-lint`. So CI
  ran a different major version than any developer with a current install. Now
  pinned to `.../v2/cmd/golangci-lint@v2.13.1`
  ([release.yml:175-183](../../.github/workflows/release.yml#L175)).
- `make lint` ran `gofmt -l .`, which **prints and exits 0**, so an unformatted
  file passed. It now fails ([Makefile:153-160](../../Makefile#L153)), and the four
  files that were unformatted at `bc6a37a` were formatted.
- `make lint` ([Makefile:161](../../Makefile#L161) runs
  `golangci-lint run --timeout=5m`) now reports **0 issues** and exits 0;
  so does `golangci-lint run --timeout=10m ./...`. Both re-verified 2026-09-06,
  as was `make static` (exit 0).

### What is left

- **`make tools` still installs the v1 path.**
  [Makefile:179](../../Makefile#L179) is
  `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`, the
  exact line CI just moved away from. A developer who follows the documented
  setup gets v1.64.8, which refuses the migrated config with
  `you are using a configuration file for golangci-lint v2 with golangci-lint v1`
  — verified by installing that version and running it against this tree. Point it
  at the same pinned v2 coordinate CI uses, and keep the two in sync from one
  place if that is cheap.
- **`make static` still has the non-failing copy of the fmt check.**
  [Makefile:194-197](../../Makefile#L194) is `go vet` plus a bare `gofmt -l .`. It
  is now the weaker duplicate of what `lint` does properly. Either give it the
  same guard or drop the line; two checks with the same name and different
  strictness is how the first one got trusted.
- **`quality` runs the formatter after the check that fails without it.**
  `quality: static lint fmt` ([Makefile:200](../../Makefile#L200)) — make runs
  prerequisites in order and stops at the first failure, so on an unformatted
  tree `lint` now exits 1 and `fmt`, the target that would have fixed it, never
  runs. Reorder to `fmt static lint`, or drop `fmt` from the aggregate.
- **`ST*` and `QF*` stay off**, deliberately, so that a tooling migration did not
  become a repo-wide restyle. Turning them on is a separate, mechanical ticket if
  anyone wants it. Measured 2026-09-06 by running the same config with the two
  exclusions removed: **18 findings** — 12 `ST1003` (naming), 3 `QF1008`, and one
  each of `ST1023`, `QF1006`, `QF1003`.
- **The standalone `staticcheck` binary is not what the repository means by
  staticcheck.** `staticcheck` in [.golangci.yml](../../.golangci.yml) is the linter
  inside golangci-lint. A separately installed binary must be built with the
  module's Go version or it cannot analyze the tree at all — the copy on this
  workstation is `2025.1.1` built with go1.25 and fails with `file requires newer
  Go version go1.26 (application built with go1.25)`. One line in the README
  Development section ([README.md:760](../../README.md#L760)) saves the next person
  the detour. Note that the documentation standard's `DEVELOPER.md` does not exist
  in this repository yet, so the README is the place until it does.

### Two test files that assert nothing

Neither can fail when the code is wrong, and one costs integration-suite time to
prove it.

- [test/integration/s3-methods/bucket_subresource_test.go](../../test/integration/s3-methods/bucket_subresource_test.go)
  — 94 lines behind the `integration` build tag, containing
  `assert.True(t, true, ...)` ([:29](../../test/integration/s3-methods/bucket_subresource_test.go#L29)),
  `assert.Equal(t, 200, http.StatusOK)` ([:39](../../test/integration/s3-methods/bucket_subresource_test.go#L39)),
  `assert.Contains(t, "application/xml", "application/xml")` ([:40](../../test/integration/s3-methods/bucket_subresource_test.go#L40)),
  and `assert.Len(t, supportedSubResources, 14)` over a list literal defined at
  [:46](../../test/integration/s3-methods/bucket_subresource_test.go#L46) inside the
  test itself. It builds an `httptest` request at
  [:34](../../test/integration/s3-methods/bucket_subresource_test.go#L34) and never
  sends it. Delete the file.
- [internal/proxy/handlers/bucket/routing_test.go:87-136](../../internal/proxy/handlers/bucket/routing_test.go#L87)
  — `testTrackingHandler.handleBucket` re-implements the routing rule, including
  its own 14-entry sub-resource list at
  [:102-106](../../internal/proxy/handlers/bucket/routing_test.go#L102), instead of
  calling `Handler.Handle`. It asserted its own copy of the logic and therefore
  could not catch the bucket-deleting fall-through. The real coverage now lives in
  [bucket_crud_test.go:227](../../internal/proxy/handlers/bucket/bucket_crud_test.go#L227)
  (`TestBucketHandle_UnroutedSubResourceIsNotABaseOperation`),
  [:295](../../internal/proxy/handlers/bucket/bucket_crud_test.go#L295) and
  [:341](../../internal/proxy/handlers/bucket/bucket_crud_test.go#L341), all of which
  call the real `Handle`. Rewrite the routing test against the real handler or
  delete it; do not leave a second implementation of the routing rule in the tree,
  because the next person to change the rule will change only one of them.

---

## Item 8 — The RSA provider fingerprint keeps one byte of the exponent

**Moved to [ticket 013](013-storage-format-v2.md) item 2 on 2026-09-06 (owner
decision).** The fix changes every RSA fingerprint, and 013 is the one release
in which that is free; done afterwards it would be a second format break. The
analysis below stays as the record; the work is tracked there.

Assigned to this ticket by the code itself: the round that just landed annotated
the defect rather than fixing it, and the comment names this file.

[rsa.go:124-137](../../pkg/encryption/keyencryption/rsa.go#L124):

```go
keyData := append(p.publicKey.N.Bytes(), byte(p.publicKey.E))
hash := sha256.Sum256(keyData)
```

`E` is an `int`; `byte(E)` keeps its low 8 bits. For the near-universal exponent
65537 (`0x010001`) that byte is `0x01`, so the exponent contributes one constant
byte and the fingerprint is effectively `SHA-256(N)`. Two keys sharing a modulus
but differing in the upper bytes of `E` fingerprint identically.

**Why it is not a "just fix it" change.** The fingerprint is written into object
metadata as `s3ep-kek-fingerprint`
([metadata.go:52](../../internal/orchestration/metadata.go#L52)) and is what selects
the KEK provider on decryption
([providers.go:305](../../internal/orchestration/providers.go#L305), reading the
value back at [metadata.go:162](../../internal/orchestration/metadata.go#L162)).
Changing the input to the hash changes every RSA fingerprint, so every object
written by an RSA provider stops matching its provider and fails to decrypt
until it is rewritten. That is a stored-format change, which is why it belongs
next to [ticket 013](013-storage-format-v2.md) rather than in a lint pass.

**Severity, honestly.** Sharing a modulus across two keys is not something that
happens by accident, and the modulus alone identifies the key in every realistic
configuration. This is a correctness and clarity defect, not a break in the
encryption. What makes it worth carrying is the shape: a provider-selection key
that silently drops most of one of its two inputs, in a function whose comment
says it hashes "public key components".

**Options:** hash the DER-encoded `SubjectPublicKeyInfo` (one call, canonical,
covers both components and matches what every other tool calls an RSA key
fingerprint), or keep the hand-built form and use `E`'s full big-endian bytes.
The first is preferable and no more expensive. Either way it lands with the
format change, and the AES provider's fingerprint should be checked for the same
class of truncation at the same time.

---

## Work breakdown

**Blocked on a decision — do not start before it is taken**

- [ ] 1. Take the per-header decision in
      [Item 1](#item-1--s-8-put-drops-the-storage-headers-and-answers-200). Before
      deciding "refuse" for `serverSideEncryption`, `kmsKeyId` or `tagging`, check
      the `velero-plugin-for-aws` BSL key to header mapping against the plugin
      source; it is unverified here.
- [ ] 2. Implement it on all four paths through the shared helper: extend
      `addRequestHeaders`
      ([helpers.go:150](../../internal/proxy/handlers/object/helpers.go#L150)),
      replace the inline copy at
      [operations.go:655-669](../../internal/proxy/handlers/object/operations.go#L655)
      with a call to it, and add the matching helper for the two
      `CreateMultipartUploadInput` sites
      ([operations.go:1029](../../internal/proxy/handlers/object/operations.go#L1029),
      [create.go:61](../../internal/proxy/handlers/multipart/create.go#L61)).
- [ ] 3. Unit tests: a table over the decided headers asserting either the
      forwarded input field or the refusal status, on each of the four paths. One
      integration test per refused header, so the refusal is proven over the wire.
- [ ] 4. README: a row per header under
      [Operations the proxy does not implement](../../README.md#L636), or
      Checksums-style prose if the answer is "forwarded". State plainly that the
      proxy's own encryption is unaffected either way.
- [ ] 5. Take the decision in
      [Item 5](#item-5--the-example-configs-still-carry-working-key-material). If
      "generate": a `gen-keys.sh --if-needed` on the model of
      [gen-certs.sh](../../test/ssl-setup/gen-certs.sh), called from
      [start-demo.sh](../../start-demo.sh) and from CI before compose comes up, plus
      the five RSA integration tests re-pointed at the generated fixture.
- [ ] 6. Take the decision in
      [Item 4](#item-4--location-is-built-from-client-controlled-request-data) and
      implement it at
      [complete.go:295-309](../../internal/proxy/handlers/multipart/complete.go#L295).

**Unblocked**

- [ ] 7. Point [Makefile:179](../../Makefile#L179) at the pinned v2 golangci-lint
      coordinate CI uses, so `make tools` cannot hand a developer the binary that
      refuses this repository's own configuration.
- [ ] 8. Give `make static` the same failing fmt guard as `lint`, or drop the
      `gofmt -l .` line ([Makefile:194-197](../../Makefile#L194)), and reorder
      `quality` ([Makefile:200](../../Makefile#L200)) so the formatter runs before
      the check that fails without it.
- [ ] 9. Delete `isRealMultipartObject`
      ([operations.go:1403](../../internal/proxy/handlers/object/operations.go#L1403)).
- [ ] 10. Delete `handleMockACL`, `handleMockCORS`, both `S3Backend == nil`
      branches ([acl.go:35](../../internal/proxy/handlers/bucket/acl.go#L35),
      [cors.go:35](../../internal/proxy/handlers/bucket/cors.go#L35)), both tests
      that exercise them
      ([acl_test.go:19](../../internal/proxy/handlers/bucket/acl_test.go#L19),
      [cors_test.go:18](../../internal/proxy/handlers/bucket/cors_test.go#L18)), and
      `WriteRawXML`, which then has no callers.
- [ ] 11. Delete `XMLWriter.WriteXMLWithStatus`
      ([xml.go:33](../../internal/proxy/response/xml.go#L33)) and
      `utils.ReadRequestBody`
      ([utils.go:107](../../internal/proxy/utils/utils.go#L107)) with its two tests.
- [ ] 12. Replace `contains` / `findInString`
      ([minio_test_helper.go:478](../../test/integration/minio_test_helper.go#L478))
      with `strings.Contains` at the three call sites.
- [ ] 13. Consolidate the error writers: move the four production call sites onto
      `h.errorWriter.WriteS3Error`, delete `utils.HandleS3Error` and
      `utils.S3ErrorResponse`, and re-point the body assertions in
      [utils_test.go:143](../../internal/proxy/utils/utils_test.go#L143),
      [:158](../../internal/proxy/utils/utils_test.go#L158) and the three in
      [server_test.go](../../internal/proxy/server_test.go#L263) at `ErrorWriter`.
- [ ] 14. Add the copy-operation integration tests from
      [Item 6](#item-6--integration-coverage-that-does-not-exist).
- [ ] 15. Add the versioned-bucket integration test from the same item: a bucket
      versioned through the MinIO client, `versionId` on GET, ranged GET, HEAD
      and DELETE compared by SHA-256, the delete marker, and the two versions a
      multipart upload leaves behind — with a teardown that removes versions and
      delete markers, which
      [CleanupTestBucket](../../test/integration/minio_test_helper.go#L162)
      does not.
- [ ] 16. Delete
      [bucket_subresource_test.go](../../test/integration/s3-methods/bucket_subresource_test.go),
      and rewrite or delete
      [routing_test.go:87-136](../../internal/proxy/handlers/bucket/routing_test.go#L87).
- [ ] 17. One line in the README Development section
      ([README.md:760](../../README.md#L760)) about `staticcheck` being a linter
      inside golangci-lint rather than a separate tool.
- [ ] 18. **Schedule item 8 with, not before, the storage format change.** Switch
      the RSA fingerprint to a DER `SubjectPublicKeyInfo` hash
      ([rsa.go:124-137](../../pkg/encryption/keyencryption/rsa.go#L124)), check the
      AES provider for the same truncation class, and remove the `#nosec G115`
      and the deferral comment when it lands.

**Assigned 2026-09-07 from [024](024-coverage-round-findings.md), decided**

- [x] ~~19. **D-26 — an error behind HTTP 200 becomes 500.**~~ **Done 2026-09-07.**
      Implemented as `status > 599 || (status < 400 && status != 304) -> 500`, placed
      before the code and message fallbacks so a forced 500 also derives
      `InternalError` / `Internal Server Error` instead of keeping a `<Message>` of
      `OK`; the old trailing 100-599 clamp is subsumed and deleted. Two corrections
      to the item as written below, both because the tree contradicted it:
      - **The 304 carve-out is mandatory and was not in the decision.**
        `handleGetObject` forwards `If-None-Match`
        ([operations.go:50](../../internal/proxy/handlers/object/operations.go#L50)),
        so a matching ETag makes the backend answer 304 and the SDK surfaces it as a
        `ResponseError` carrying that status. The rule as worded — *any* status below
        400 — turns every cache revalidation into a 500, and two integration tests
        assert the 304 today (`TestConditionalRequestErrors`,
        `TestCondGetAndHeadPreconditions`). No other 3xx is produced by this proxy.
      - **The stated justification does not hold against the pinned SDK.**
        aws-sdk-go-v2 `service/s3` v1.111.0 already rewrites a 2xx carrying an
        `<Error>` root to 500 before deserializing, for exactly `CopyObject`,
        `CompleteMultipartUpload` and `UploadPartCopy`
        (`internal/customizations/handle_200_error.go`). So the proxy never did
        forward an S3 `CompleteMultipartUpload` 200-error. What is genuinely
        reachable, and what the change is for: a deserialization failure on an
        otherwise successful 2xx, any 1xx, any 3xx other than 304, and any backend
        that is not AWS S3. A **1xx is the strongest case and neither ticket named
        it** — net/http answers 100-199 as informational without committing the
        status, so the body write then commits an implicit 200 carrying the `<Error>`
        document, which is literally the bug D-26 describes.
      `TestRespMapErrorNonErrorStatusesAreRenderedAsErrors`, which existed to pin the
      defect, is replaced by `TestRespMapErrorNonErrorStatusesBecome500`; new
      `TestMapError_ErrorBehindANonErrorStatusBecomes500`,
      `TestMapError_ConditionalGetKeepsIts304` and
      `TestRespMapErrorNotModifiedIsForwarded`.

      Original item: `MapError`
      ([error_mapping.go](../../internal/proxy/response/error_mapping.go)) clamps only
      statuses outside 100-599, so a backend `ResponseError` carrying status 200 with an
      S3 error code — which S3 itself produces for `CompleteMultipartUpload` and
      `CopyObject` — is forwarded as a 200 with an `<Error>` body. A status-only client
      reads success. Map any status below 400 that carries an error code to 500, keep the
      code and message. Unit test with a fabricated `ResponseError{StatusCode: 200}`.
- [ ] 20. **D-27 — `InvalidArgument` for the malformed part upload.** `568db10` made
      `PUT /bucket/key?partNumber=abc&uploadId=...` answer `NotImplemented` instead of
      overwriting the object. AWS answers `InvalidArgument` (400). In `Handler.Handle`
      ([handler.go](../../internal/proxy/handlers/object/handler.go)) answer
      `InvalidArgument` when the method is PUT and both `partNumber` and `uploadId` are
      present; leave `GET ?partNumber` at `NotImplemented`, because the proxy genuinely
      does not implement a part read. Adjust
      `TestObjMiscHandleRefusesSubResourcesThatReachTheBaseOperation` and
      `TestSubrefMalformedPartNumberDoesNotOverwriteTheObject` to the new code.
- [ ] 21. **README: the object sub-resource refusals.** The README documents the bucket
      refusals from this ticket's first round and says nothing about the object ones that
      `568db10` added (`?acl`, `?legal-hold`, `?retention`, `?torrent`, `?restore`,
      `?select`, `?uploads` on an unrouted method; unknown parameters). One table next to
      the bucket one, same shape.

---

## Success criteria

- [ ] `go build ./... && go vet ./...` clean; `make test-unit` green;
      `make lint` green — it reports 0 issues today and must still do so, with the
      same golangci-lint major version from `make tools` and from CI.
- [ ] `make quality` runs to completion on a deliberately unformatted tree
      instead of stopping before the formatter.
- [ ] `grep -rn "HandleS3Error\|S3ErrorResponse\|WriteXMLWithStatus\|WriteRawXML\|ReadRequestBody\|isRealMultipartObject\|handleMock" --include="*.go" .`
      returns nothing.
- [ ] The deletions build with **no new `//nolint:unused`** anywhere — the
      `unused` linter is enabled, and it is the check that keeps this from
      regrowing.
- [ ] For each header decided in item 1: a unit test per PUT path asserting the
      decided behaviour, and for each refused header an integration test showing
      the refusal over the wire with the documented code.
- [ ] The S-8 probe re-run gives the decided answer rather than a silent 200:
      `put-object --server-side-encryption AES256 --storage-class STANDARD_IA
      --tagging k=v --acl private` either fails with the documented code, or
      succeeds with the forwarded properties visible on the backend object.
- [ ] `UploadPartCopy` integration test: `422`, and no part exists on the backend
      upload afterwards. `CopyObject` integration test: `422`, and the destination
      key does not exist.
- [ ] Versioned-bucket integration test green, and the bucket it created is gone
      afterwards — no `test-bucket-*` survives the run. It has to fail if
      `versionId` stops being forwarded, and if the multipart self-copy stops
      writing the version that carries the metadata.
- [ ] The 8 MiB PUT of item 6 (4): HEAD returns the `Content-Type`,
      `Cache-Control` and `Content-Disposition` the PUT sent, and its ETag equals
      the one the PUT returned.
- [ ] `make test-integration` **and** `make test-integration-tls` green — both,
      because item 5 touches the configs the TLS suite loads.
- [ ] `make e2e-up && make test-e2e-velero && make e2e-down`: all 13 scenarios
      green. This is the gate for item 1: if a refusal breaks Velero, it breaks
      here.
- [ ] `docker logs proxy | tail -50` shows no new error or warning lines during
      the integration run.
- [ ] README states what a PUT does with each storage header, and the
      `<Location>` decision is visible in the response body or documented as
      removed.
- [ ] Item 8 only: an RSA round trip through a re-fingerprinted provider, and an
      explicit statement in the format ticket that objects written under the old
      fingerprint are not readable — the same "no backward compatibility"
      accounting v2 makes.

---

## Risks and open questions

- **Item 1 is the only item that can break a working client, and it is the one
  with the least evidence.** The e2e proves that refusing does not break *the
  configuration the e2e uses*, which sets none of these headers. It proves nothing
  about a BSL that sets `serverSideEncryption` or `tagging`, because no such BSL
  is tested. If "refuse" is chosen for those two, add an e2e scenario with them
  set, or the first evidence will come from an operator.
- **"Forward" is not free either, and the cost is not symmetric.** A refusal fails
  loudly and gets fixed in minutes. A forward that succeeds teaches the client
  that the proxy honours the header, and every later assumption builds on that —
  including, for `x-amz-acl`, an assumption about who can read the ciphertext.
  Prefer refuse where the header grants access or leaks plaintext metadata; prefer
  forward where it only picks a storage tier.
- **`x-amz-tagging` versus tagging as a feature.** Refusing the header while
  `?tagging` also answers `501` is consistent. But if object tagging is ever
  implemented, the tags must be encrypted or the decision is silently reversed —
  plaintext tags on ciphertext objects hand the adversary a labelled index. Note
  it wherever the tagging feature is eventually specified.
- **The object-lock row is where the threat model may argue against itself.**
  "The backend is hostile, so its WORM is meaningless" is right for a compromised
  *backend* and wrong for a compromised *credential*, which is the more common
  ransomware path for a backup bucket. This ticket does not resolve it; whoever
  decides should say which adversary the answer is for.
- **The versioning test is the first test whose bucket outlives the shared
  teardown.** Every other test can rely on `CleanupTestBucket`; this one cannot,
  and the failure is silent — a discarded `DeleteBucket` error and a bucket that
  stays. Write the teardown first, run the test twice in a row, and check that
  MinIO is clean before believing either run.
- **Deleting the two mock handlers deletes two passing tests.** That will look
  like a coverage regression in the bucket package, and it is — of a code path
  that cannot execute. Say so in the commit message, or the next coverage review
  will restore it.
- **Item 3 is a refactor with no test that can prove it.** The two writers produce
  identical bytes today, so consolidating cannot be observed by any assertion
  except the ones being re-pointed. Do it in its own commit, moving the
  `utils_test.go` body assertions rather than deleting them, so a byte-level
  difference would surface.
- **Item 8 is a stored-format change wearing a lint finding's clothes.** It is
  small, it is tempting to do alone, and doing it alone makes every existing
  RSA-encrypted object undecryptable with a fingerprint mismatch that reads like a
  configuration error. It goes with the format change or not at all.
- **This ticket was written while the tree was moving.** Several claims were
  overtaken between verification and writing: the `.golangci.yml` migration, the
  CI pin and the `make lint` fmt guard all landed mid-ticket, and item 7 is what
  survived that. Re-verify the two Makefile leftovers before starting them; they
  were true at the time of writing and are exactly the kind of thing a parallel
  edit closes.
- **`go install ...@latest` is a moving target beyond golangci-lint.** Not in
  the workflow — the pinned golangci-lint at
  [release.yml:182](../../.github/workflows/release.yml#L182) is the only
  `go install` in any workflow file — but in the Makefile, which installs
  `gosec@v2.22.8` (pinned, [Makefile:184](../../Makefile#L184)) and
  `govulncheck@latest` (not, [Makefile:190](../../Makefile#L190)), and `air@latest`
  next to the linter in `tools` ([Makefile:178](../../Makefile#L178)). Pinning the
  lint version fixed this ticket's instance; a pass over the rest is worth doing
  at some point and is not in scope here.
