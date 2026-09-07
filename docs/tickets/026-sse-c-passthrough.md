# Ticket 026: SSE-C on every verb, or not at all

## Status (2026-09-07)

**Open, after [013](013-storage-format-v2.md).** Created on the owner's request
during the v5 decision round ([023](023-major-v5.md) decision 5, D-35). D-35
makes the proxy forward every storage header a PUT carries — except the three
SSE-C headers, which it **refuses** with `501 NotImplemented` until this ticket
lands. The reason is a trap, not a policy: today no read path forwards the
customer key (`grep -rn SSECustomer internal/proxy` finds nothing in production
code), so an object written with SSE-C through the proxy would be one the proxy
can never read back — the backend answers every GET, HEAD and ranged GET without
the key with `400 InvalidRequest`. Forwarding SSE-C on PUT alone would turn a
silent drop into a silent time bomb. Either every verb carries the key, or none
does. Nothing here is started.

Sequencing: after 013, because 013 deletes the two backend calls that would
otherwise need SSE-C copy-source plumbing — the post-Complete self-`CopyObject`
([operations.go:1344](../../internal/proxy/handlers/object/operations.go#L1344),
[complete.go:234](../../internal/proxy/handlers/multipart/complete.go#L234)) and
the `HeadObject` that restates stored attributes before it
([complete.go:324](../../internal/proxy/handlers/multipart/complete.go#L324)).
Also after the D-35 forwarding helper in [022](022-s3-surface-fidelity.md) item
1, which this ticket extends rather than duplicates.

---

## Context: what SSE-C is, and what it is not under this threat model

SSE-C (server-side encryption with customer-provided keys) is three request
headers the client sends on every request that touches the object:

| Header | Value |
|---|---|
| `x-amz-server-side-encryption-customer-algorithm` | `AES256` |
| `x-amz-server-side-encryption-customer-key` | base64 of a 256-bit key |
| `x-amz-server-side-encryption-customer-key-MD5` | base64 of MD5 over the raw key, checked by the backend |

The backend encrypts the object with that key and discards it; the response
echoes `-algorithm` and `-key-MD5`. S3 requires the headers on `PutObject`,
`GetObject` (including ranged), `HeadObject`, `CreateMultipartUpload` and every
`UploadPart`; `CompleteMultipartUpload` takes none; `CopyObject` and
`UploadPartCopy` take a second set with a `copy-source-` prefix for the source
object. The proxy refuses both copy operations under an encrypting provider
(`NotSupportedWithEncryption`), so the copy variants are out of scope.

**What SSE-C buys here: compatibility, not security.** The S3 model hands the
key to the backend on every request; the backend holds it in memory while it
encrypts or decrypts. Under the threat model of this proxy the backend is the
adversary, so SSE-C adds no confidentiality against it — the proxy's own
envelope encryption is what protects the content, and SSE-C wraps the
ciphertext a second time with a key the adversary sees. The feature exists so
that a client or a bucket policy that *requires* SSE-C (some organisations
enforce `s3:x-amz-server-side-encryption-customer-algorithm` in bucket
policies) works through the proxy. The README says exactly that, and
`SECURITY_ARCHITECTURE.md` says it next to the storage-header table D-35 adds.

What the proxy must do with the key: forward it on the backend leg and echo the
two response headers; **never** log it (the request logger logs headers?
verify — [logging.go](../../internal/proxy/middleware/logging.go)), never store
it, never let it into object metadata, never cache it. The proxy's own DEK cache
and metadata are unaffected: SSE-C is a property of the backend leg only.

## Context: the sites, verified at `ed2e964`

Every backend input the proxy builds for an object, and whether it needs the
key:

| Site | Input | SSE-C |
|---|---|---|
| [operations.go:40](../../internal/proxy/handlers/object/operations.go#L40) `handleGetObject` | `GetObjectInput` | yes |
| [range.go:122](../../internal/proxy/handlers/object/range.go#L122) ranged GET, [range.go:202](../../internal/proxy/handlers/object/range.go#L202) full-decrypt range | `GetObjectInput` | yes |
| [operations.go:728](../../internal/proxy/handlers/object/operations.go#L728) `handleHeadObject` | `HeadObjectInput` | yes |
| [operations.go:528](../../internal/proxy/handlers/object/operations.go#L528) `putObjectDirect`, [:621](../../internal/proxy/handlers/object/operations.go#L621) `putObjectStreamingReader` | `PutObjectInput` | yes, through the D-35 helper ([helpers.go:164](../../internal/proxy/handlers/object/helpers.go#L164)) |
| [operations.go:1029](../../internal/proxy/handlers/object/operations.go#L1029) auto-multipart create, [:1136](../../internal/proxy/handlers/object/operations.go#L1136) its parts, [:1307](../../internal/proxy/handlers/object/operations.go#L1307) its complete | `CreateMultipartUploadInput`, `UploadPartInput`, `CompleteMultipartUploadInput` | create and parts yes, complete no |
| [create.go:61](../../internal/proxy/handlers/multipart/create.go#L61), [upload.go:225](../../internal/proxy/handlers/multipart/upload.go#L225), [complete.go:193](../../internal/proxy/handlers/multipart/complete.go#L193) client-driven multipart | same three | create and parts yes, complete no |
| `DeleteObject`, `DeleteObjects`, listings | — | no |

Response side: [writeGetObjectResponse](../../internal/proxy/handlers/object/operations.go#L295)
and [writeRangeResponse](../../internal/proxy/handlers/object/range.go#L248)
emit an allowlist of headers, pinned by
[`TestWriteGetObjectResponse_EmitsOnlyTheAllowlist`](../../internal/proxy/handlers/object/object_test.go#L338);
the two SSE-C echo headers join it. The multipart handlers already echo
`x-amz-server-side-encryption` ([upload.go:263](../../internal/proxy/handlers/multipart/upload.go#L263),
[complete.go:288](../../internal/proxy/handlers/multipart/complete.go#L288));
the SSE-C pair joins them.

Client-driven multipart has one wrinkle: the key arrives on `CreateMultipartUpload`
and again on every `UploadPart`. The proxy forwards whatever each request
carries and does not remember the key between requests — S3 semantics, and the
only behaviour that keeps the key out of the session state.

Pre-signed URLs: SSE-C headers travel as headers, not query parameters, and
must be in `SignedHeaders`; the pre-signed validator
([s3auth_presigned.go](../../internal/proxy/middleware/s3auth_presigned.go))
signs whatever headers the URL names, so nothing changes there — verify with
one test.

MinIO, the integration backend, accepts SSE-C **only over TLS** and rejects it
over plain HTTP. The proxy's backend leg is TLS in every shipped config (D-6
refuses plain HTTP under an encrypting provider), so the backend side is fine;
the *client* leg of the integration suite must use the TLS listener
(`make test-integration-tls`, `proxy-tls` on :8443) for the SSE-C tests, or
MinIO's own SSE-C refusal — which the proxy would map and forward — is what the
test sees. Say so in the test file.

---

## Scope

**In**

- The three request headers forwarded on the sites above; the two response
  headers echoed on GET, ranged GET, HEAD, PUT, UploadPart and Complete.
- A `501 NotImplemented` with a message naming the header on any site that
  cannot carry the key (there should be none after this ticket; the branch
  stays as the guard).
- README: SSE-C row in the storage-header table, the sentence that it is
  compatibility and not protection against the backend, the TLS requirement.
- `SECURITY_ARCHITECTURE.md`: the same sentence, and "the key transits the
  proxy and is never logged, stored or cached".
- Integration tests in the TLS suite.

**Out**

- `CopyObject` / `UploadPartCopy` with SSE-C source keys — the operations are
  refused under encryption ([022](022-s3-surface-fidelity.md) item 6 records why).
- SSE-C as the proxy's *own* encryption mechanism. It is not one.
- Any caching or session storage of the customer key.

---

## Work breakdown

- [ ] **1. One helper.** `sseCustomerHeaders(r) (alg, key, md5 string, ok bool)`
      in [helpers.go](../../internal/proxy/handlers/object/helpers.go), shared
      with the multipart package (the D-35 forwarding helper lives there too);
      applied to each input type (`PutObjectInput`, `GetObjectInput`,
      `HeadObjectInput`, `CreateMultipartUploadInput`, `UploadPartInput`) through
      the SDK's `SSECustomerAlgorithm` / `SSECustomerKey` / `SSECustomerKeyMD5`
      fields. Remove the D-35 `501` for SSE-C on PUT.
- [ ] **2. Response echo.** Add `x-amz-server-side-encryption-customer-algorithm`
      and `-key-MD5` to the GET / ranged GET / HEAD allowlists and to the PUT,
      UploadPart and Complete responses; update
      `TestWriteGetObjectResponse_EmitsOnlyTheAllowlist`.
- [ ] **3. No leak.** Verify the request logger and every `logrus` field on the
      object and multipart paths never carry the key header; add a unit test
      that captures the log output of a PUT and a GET with SSE-C and asserts the
      key is absent. Verify no metadata key can carry it (the D-34 prefix
      refusal and `cleanMetadata` are unrelated; the key never enters metadata by
      construction — assert it anyway on the stored object in the integration
      test).
- [ ] **4. Error mapping.** A GET/HEAD without the key on an SSE-C object, or
      with the wrong key, answers what the backend answers (`400 InvalidRequest`
      from MinIO; verify the code) through the existing mapper; a wrong `-key-MD5`
      likewise. No proxy-side check of the MD5 — the backend does it.
- [ ] **5. Integration tests**, TLS suite, differential against MinIO: PUT →
      GET → HEAD → ranged GET round trip with SSE-C, plaintext SHA-256 equal on
      both legs; multipart create + parts + complete with SSE-C; GET without key
      fails as MinIO fails; GET with a wrong key fails as MinIO fails; the stored
      object read directly from MinIO with the key is ciphertext (the proxy's,
      entropy check) and its metadata carries no customer key; a pre-signed GET
      with SSE-C headers in `SignedHeaders` succeeds.
- [ ] **6. Docs.** README storage-header table and the compatibility sentence;
      `SECURITY_ARCHITECTURE.md` next to the D-35 table; the TLS requirement of
      MinIO in the test file header.

## Success criteria

- [ ] `grep -rn SSECustomer internal/proxy --include='*.go' | grep -v _test`
      hits every site in the table above and nothing else.
- [ ] The TLS integration suite carries the six cases of item 5 and they are
      green against the demo MinIO; the plain-HTTP suite skips them with a
      message naming MinIO's TLS requirement.
- [ ] A log capture of an SSE-C PUT and GET at `log_level: debug` does not
      contain the key.
- [ ] README and `SECURITY_ARCHITECTURE.md` say in one sentence each that SSE-C
      through this proxy is compatibility, not protection against the backend.

## Risks and open questions

- **The key transits the proxy in plaintext headers on both legs.** TLS on the
  client leg is the operator's choice (`tls.enabled`); the README must say that
  SSE-C without TLS on the client leg sends the key in the clear, and the proxy
  could refuse SSE-C on a plain-HTTP listener the way MinIO does — decide when
  implementing; refusing is the consistent answer with D-6.
- **Bucket policies that require SSE-C** are the only known reason to want
  this. No client exercised in this repository (the integration suites, the Velero
  e2e) sends SSE-C; any S3 client can be configured to. If no such policy shows
  up before this ticket is picked, it can stay open indefinitely; the D-35
  refusal is honest.
- **MinIO's SSE-C TLS requirement** was stated from memory of MinIO's
  documentation, not verified against the demo instance; the first integration
  run settles it.
- **The self-copy and the restating `HeadObject`** must be gone (013) before
  this ticket, or both need the copy-source variants and the key in the
  proxy's multipart session, which this ticket refuses to do.
