# 035 — The pinned-defect sweep: 27 tests that asserted the bug

Raised 2026-09-13, out of the rclone/s3cmd suites shipping with every open defect
recorded as an *expected* refusal. Both suites were green, the release gate was
green, and the pipeline reported that a product two named clients can neither
upload to nor download from was ready to merge.

The rule that came out of it is now in `CLAUDE.md`: **a test asserts the target
behaviour of the software, never the behaviour it has today.** A red suite is a
correct suite, and it is committed red.

This ticket is the sweep of the rest of the tree against that rule: ~65 000 lines
of test code across the integration suites, the three end-to-end suites and every
unit test. 55 candidates were found; each was then put to an adversarial check
that tried to prove it was a **decided** behaviour backed by an ADR. 28 were
refuted that way and left alone — `CopyObject` answering 422, SSE-C answering
501, the `xxhash` family answering 501, an object with no proxy metadata answering
403, the conformance suite recording a difference between two backends, and
others. **27 survived.** Their tests now assert the target and are red.

**The unit-test half was built on 2026-09-13 and `make test-unit` is green.**
What landed:
the `tink` and licence-banner wordings, the cleanup-interval minimum, the
monitoring bind failure reaching its caller, `NoSuchBucketPolicy` and the policy
body bound, `InvalidPartOrder`, the four `DeleteObjects` refusals, `405` with an
`Allow` header on the object resource and at the router, the `?torrent` refusal,
the six `response-*` overrides, the absent `RequestId`, the uncleaned path, the
CORS preflight, and the probe matcher that stops `/health` shadowing a bucket.
The integration and end-to-end items below are untouched; so are the two bounds
noted under *What is left of the unit items*.

## How to see the list without this file

Run the suites. Every failure names the rule it wants and the ADR that rule
belongs to. The two client suites additionally write
`test-results/e2e-<client>-verdicts.md` with a *Still broken* section, and their
CI jobs put the same list in the step summary.

## What is red, and what each one wants


### `internal/config/validation_coverage_test.go`
- **line 87** — Keep the refusal and keep it on its own named arm — `type: "tink"` must fail at startup distinctly from the generic "unsupported encryption type" arm, so a configuration written for the deleted stub fails loudly (SECURITY_ARCHITECTURE.md:186-188, ADR 0005 Status). Change the message so it names the rule instead of promising an implementation: tink is not a provider type this product has (supported: aes, exit), in the shape ADR 0013 requires — the field plus the rule it broke — with no "not yet implemented" and no forward promise, since ADR 0005 D4 has already replaced that name with Vault Transit.
- **line 484** — Startup validation must refuse an out-of-range `optimizations.multipart_session_cleanup_interval` by name (ADR 0013 D7, ADR 0017 D8) — a minimum of 1 second checked where the idle-timeout minimum is checked (internal/config/config.go:251-257), so that 0 can no longer switch the sweeper off and strand short-part budget permanently; the never-evaluated `validate:"min=60"` tag at internal/config/config.go:88 is deleted with it. The test case at internal/config/validation_coverage_test.go:481-486 should then assert the refusal with an expectError naming the key (and lose the "are not enforced" name and the concession comment), and it should be red until the check exists.

### `internal/license/logger_coverage_test.go`
- **line 114** — Two acceptable targets; the second is the minimum change and matches the repo's precedent (ADR 0005's stub removal, and the project rule "WE DONT NEED BACKWARD COMPATIBILITY, remove unnecessary code"). A) Close the residual risk: validate `k8s_cluster_id` — a non-empty claim must be matched against the cluster the proxy actually runs in, and a mismatch must be a startup refusal on the same fatal path as every other license failure (ADR 0016 D1: "there is no degraded or grace-period mode").

### `internal/monitoring/server_coverage_test.go`
- **line 215** — internal/monitoring/server_coverage_test.go:178-219 should assert that a failed bind reaches the caller: keep the existing `require.Eventually` on the "Monitoring server error" log, then replace lines 214-215 with `require.Error(t, err)` plus a check that the error names the bind failure (e.g. it wraps `ListenAndServe`'s error / mentions the held address), and drop the concession comment.

### `internal/proxy/handlers/bucket/subresource_methods_coverage_test.go`
- **line 738** — GET /{bucket}?policy must answer 404 NoSuchBucketPolicy, as an S3 <Error> document composed by the proxy, whenever no policy is available — including the arm the test covers, where the backend returns success with no policy document. It must never answer 200 with a zero-byte body behind Content-Type: application/json.
- **line 851** — A bucket sub-resource write body is read under a bound and refused above it before the body has been read in full, instead of being buffered whole and forwarded. Concretely, PUT /{bucket}?policy (and the eight sibling handlers that call RequestParser.ReadBody: cors, logging, notification, lifecycle, versioning, tagging, acl, operations) reads through Parser.ReadBodyLimited with a bound the operator can size against the container limit, and a body above it answers a named S3 error with no backend call - the shape ADR 0011 D5 already uses for an oversized part ("400 EntityTooLarge .

### `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **line 1261** — A `CompleteMultipartUpload` whose `<Part>` elements are not in strictly ascending part-number order answers `400 InvalidPartOrder` ("The list of parts was not in ascending order. Parts must be ordered by part number."), before any part is forwarded and without aborting the session, as AWS and MinIO both do.

### `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **line 313** — A POST /{bucket}?delete whose body parses as a <Delete> document containing no <Object> element (<Delete></Delete>, <Delete/>, or <Delete><Quiet>true</Quiet></Delete>) is refused with 400 MalformedXML through the proxy's own S3 error document, before any backend call — the same answer AWS gives, and the same answer the adjacent unparseable-body cases already get. The test should assert http.StatusBadRequest, error code MalformedXML, Content-Type application/xml, and backend.AssertNotCalled(t, "DeleteObjects", …) for all three cases, replacing the current 200-OK/empty-object-list assertions and dropping the DEFECT comment.
- **line 351** — A `POST /{bucket}?delete` document containing an `<Object>` element with no `<Key>` is refused with `400 MalformedXML` through the proxy's own S3 error document, and `DeleteObjects` is never called on the backend — instead of today's `200 OK` with `Delete.Objects[0].Key == ""` forwarded as a delete of the empty key. Test rewrite: assert `http.StatusBadRequest`, `Code == "MalformedXML"`, and `backend.AssertNotCalled(t, "DeleteObjects", ...)`, mirroring the existing `TestObjMiscDeleteObjectsEmptyBodyIsMalformed` at :322 and the `MalformedXML` cases at :280-286.
- **line 379** — A POST /{bucket}?delete whose Delete document carries more than 1000 <Object> entries is refused with 400 MalformedXML, and the body read is bounded (Parser.ReadBodyLimited, the mechanism ADR 0011 D5 already established) so a client cannot make the proxy buffer an arbitrarily large document or turn one request into an unbounded backend DeleteObjects call. Until that lands, the test should assert the refusal rather than pin 200 OK with every key forwarded.
- **line 406** — A `DeleteObjects` request whose body cannot be read answers `400 IncompleteBody` with the message "The request body terminated before the declared number of bytes was read" — byte-identical to what `internal/proxy/handlers/object/operations.go:416` (PUT) and `internal/proxy/handlers/multipart/upload.go:199` (UploadPart) already emit for the same fault. It must not reuse `400 InvalidRequest` / "Failed to read request body", because ADR 0012 D14 reserves `InvalidRequest` on this very verb for a request that carries no digest at all; a client cannot currently tell "you sent no Content-MD5" from "your connection dropped mid-body", and the second is retryable while the first is not.

### `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **line 284** — A method the object resource does not carry must be answered `405 MethodNotAllowed` — S3 `<Error>` document with `Code=MethodNotAllowed`, `Content-Type: application/xml`, and an `Allow` header naming the methods the resource does carry (`GET, HEAD, PUT, DELETE`) — instead of `501 NotImplemented` with `Code=NotImplemented` and `Resource=Object_<METHOD>`. Concretely, in `internal/proxy/handlers/object/handler.go:205` the default arm of `handleBaseObjectOperations` changes from `h.errorWriter.WriteNotImplemented(w, "Object_"+r.Method)` to a 405 that sets `Allow` before writing the error document — the same shape the sub-resource-with-a-route arm already uses at handler.go:135-141, plus the `Allow` header.
- **line 747** — GET /{bucket}/{key}?torrent on an object this proxy encrypted must be refused with a named S3 error and its matching status — the project's own vocabulary for "encryption forecloses the operation" is 422 NotSupportedWithEncryption, with 501 NotImplemented naming ObjectTorrent as the alternative if the operation is dropped rather than foreclosed (ADR 0007 D8) — and the backend's torrent document must never reach the client. The test should assert the refusal status and code, an S3 <Error> body (ADR 0008 D7), that Content-Type is not application/x-bittorrent, and that GetObjectTorrent is never called on the backend under an encrypting provider.

### `internal/proxy/handlers/object/getobject_coverage_test.go`
- **line 794** — A GET carrying response-content-type, response-content-disposition, response-cache-control, response-content-encoding, response-content-language or response-expires must have those values honoured, per ADR 0007 D1/D2: each is set on the backend GetObjectInput (ResponseContentType, ResponseContentDisposition, ResponseCacheControl, ResponseContentEncoding, ResponseContentLanguage, ResponseExpires) and/or applied by the proxy when it composes the response, so the client's requested Content-Type and Content-Disposition appear on the 200 instead of the object's stored values. The test should therefore assert the requested values reach the backend and are served — e.g.

### `internal/proxy/middleware_setup_coverage_test.go`
- **line 183** — One of two, and the choice is the owner's: (a) Decide the status per code. `writeS3Error` already takes the status, so it is a table beside `authErrorMessage` in `internal/proxy/middleware_setup.go`: `InvalidRequest` and `AuthorizationHeaderMalformed` → 400; `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `RequestTimeTooSkewed`, `AccessDenied` → 403 (AWS's own statuses for those four).
- **line 230** — A failure to parse the `Authorization` header should answer `AuthorizationHeaderMalformed`, not `InvalidRequest`. Fix (one line, in `internal/proxy/middleware_setup.go:129-146`): move `case strings.Contains(errMsg, "malformed")` above `case strings.Contains(errMsg, "authorization header")`.

### `internal/proxy/response/errors_coverage_test.go`
- **line 174** — The error document must not carry an invented RequestId. Under ADR 0008 D12 ("the default is not to invent a value any more than to pass one through") and D1 ("values the proxy can state truthfully"), the two acceptable shapes are: omit the element entirely — the struct tag at internal/proxy/response/errors.go:20 is already `omitempty`, so this is a one-line change at errors.go:70 — or, if the project wants correlation, mint a per-request identifier once per request, carry it into the error document and emit the matching `x-amz-request-id` response header, so a client-visible failure can be matched against the proxy's own log line (the handle ADR 0028 and docs/developer/multipart.md say does not exist today).

### `internal/proxy/router_coverage_test.go`
- **line 282** — The router must serve the key the client asked for. "/bucket/a//b", "/bucket/a/../b" and "/bucket/a/./b" are three distinct, legal S3 keys and must reach the object handler with Vars["key"] equal to "a//b", "a/../b" and "a/./b" respectively — no 301, no Location header, no rewriting to a different key.
- **line 313** — A request whose method no route declares must be answered by the proxy's own S3 error surface, not by the gorilla/mux default handler: `405` with an S3 `<Error>` XML document carrying `Code=MethodNotAllowed` (per ADR 0008 D7 — no bare status, no empty body) and an `Allow` header listing the methods the path does declare. An `OPTIONS` preflight must reach the CORS middleware at internal/proxy/middleware/cors.go, which already has the preflight branch, so the response carries `Access-Control-Allow-Origin` and the usual preflight headers instead of a 405.
- **line 427** — A GET on /health or /version that is an S3 request — carrying SigV4 credentials and/or S3 listing parameters such as list-type=2&prefix= — must reach the authenticated S3 bucket handler and answer a ListBucketResult (or 403 when unsigned), exactly as it would against AWS S3; only an actual probe request (unsigned, no S3 query parameters) is answered by the health/version document, and it must keep being answered during the drain per ADR 0029 D1. Equivalently, per ADR 0006 D2, if the shadowing is kept deliberately it must be written down as a limit in README.md — today it is neither fixed nor documented, and the same test shows PUT /health already reaches the bucket handler, so the reservation is not even applied consistently across verbs.

### `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **line 253** — HEAD through the proxy must report exactly the plaintext length for a sub-part-size streamed object. Replace the whole isSmallFile/else construct at comprehensive_multipart_test.go:249-267 with the unconditional assertion the rest of the suite makes: require.Equal(t, tc.size, actualSize, "HEAD through the proxy must report the plaintext size for %s (ADR 0010 D1)", tc.name) The size-dependent branching goes away entirely - the large-file arm already asserts exact equality, and ADR 0010 D1 makes no distinction between the single-request and multipart paths.

### `test/integration/encryption-modes/exit_provider_test.go`
- **line 499** — Keep refusing `type: "tink"` by name — that part is deliberate and documented (README.md:167, SECURITY_ARCHITECTURE.md:182-190), so an operator with a pre-removal configuration gets a message about their actual type instead of the generic arm. Change only the wording: `internal/config/config.go:790` must stop promising an implementation that is neither in the tree nor planned under that name.

### `test/integration/s3-methods/delete_objects_batch_test.go`
- **line 651** — The proxy states its own correlation id on the responses it composes: an `x-amz-request-id` header (and `x-amz-id-2` only if the proxy can vouch for a value; otherwise omit it per ADR 0008 D12) generated per request, never the backend's, on every path that answers — batch delete included. The same real id should replace the hardcoded `RequestID: "proxy-request"` in the `<Error>` document (internal/proxy/response/errors.go:70) so the header and the body agree.

### `test/integration/s3-methods/multipart_conformance_test.go`
- **line 467** — CompleteMultipartUpload whose <Part> elements are not in ascending part-number order must be refused with 400 InvalidPartOrder ("The list of parts was not in ascending order. Parts must be ordered by part number."), the same answer AWS S3 and MinIO give, instead of being sorted into ascending order and accepted.

### `test/integration/s3-methods/object_headers_conformance_test.go`
- **line 358** — Once the entity-tag question of ADR 0010 D12 is decided, the `etag` arm of the skip at line 358 must stop being an unexplained carve-out. Note the claimed target is wrong in one respect: the proxy's ETag will still not equal MinIO's, because the accepted candidate (ticket 034) keeps the backend's MD5 of the ciphertext and only appends the `-0` marker inside the quotes.
- **line 656** — The test should assert the entity tag the proxy itself owns and states, not "it differs from MinIO's". Concretely, once ADR 0010 D12's open question is answered (ticket 034's accepted candidate): under an encrypting provider, the object-level ETag is quoted, identical across PUT, GET, HEAD and the listing, and is NOT in the 32-hex shape a client reads as a content MD5 — i.e.

### `test/integration/s3-methods/passthrough_operations_test.go`
- **line 181** — Delete TestPassthroughOperations_Retention — it is superseded by TestSubpassRetentionAndLegalHoldRoundTrip (test/integration/s3-methods/object_subresource_passthrough_test.go:82-129), which already asserts ADR 0007 D4 for both GET and PUT ?retention by reading the result straight from MinIO. If the test is kept instead, it must create the bucket with object lock enabled (HdrNewDirectBucket(t, ctx, tc.MinIOClient, true)), un-comment the PutObjectRetention call and require.NoError on it, and assert both the backend-side HeadObject (ObjectLockMode, ObjectLockRetainUntilDate) and the proxy's GetObjectRetention answer value for value — with no `if err != nil { t.Logf(...) }` arm left anywhere in it.

## The contradiction inside the list, and how it was decided

`internal/proxy/middleware_setup_coverage_test.go` wanted an unsigned request —
no `Authorization` header at all — answered `400 InvalidRequest`. Four tests in
`internal/proxy/router_coverage_test.go` wanted the identical request answered
`403`. One request cannot have two answers, so one of the five was wrong, and it
was a decision rather than a fix.

Measured against MinIO in the demo stack: an anonymous request is
`403 AccessDenied`, a `Basic` header is `400 InvalidRequest`. The proxy answered
`403 InvalidRequest` to all three shapes, so the cell asking for
`400 InvalidRequest` had carried that blanket code over and applied only the new
status to it.

**Decided and recorded as ADR 0014 D13** (2026-09-13): anonymous is
`403 AccessDenied`, an unimplemented scheme is `400 InvalidRequest`, an
unparseable header is `400 AuthorizationHeaderMalformed`, and the three
credential failures keep their `403`. The cell was corrected; all five tests now
say the same thing. The probe matcher that came with it is ADR 0014 D14.

## What the unit items left open, and how it was closed

All three were decided on 2026-09-13 and built the same day.

- **The document bound is one configured ceiling**, `optimizations.max_request_document_size`,
  default 2 MB, recorded as ADR 0024 D8. It covers the thirteen bodies the proxy
  parses whole — nine bucket sub-resource writes, three object ones and the
  `Delete` document — not `?policy` alone, and the fixed 20 KiB constant that
  briefly stood in for it is gone. The default is set so the proxy refuses
  nothing S3 itself accepts.
- **`DeleteObjects` reads under that ceiling**, so an oversized document is
  refused on what arrived rather than buffered and then judged. The thousand-key
  rule stays behind it: the two bounds answer different questions.
- **The proxy states its own `x-amz-request-id`**, in the header, in the
  `<RequestId>` element and in the access log line, recorded as ADR 0008 D12a.
  That closes the correlation gap the ticket named: until now a failure a client
  reported could not be found in this proxy's log.

## Grouped by what has to change

- **The entity tag** (ADR 0010 D12, open): the rclone and s3cmd suites, plus
  `object_headers_conformance_test.go`. The largest block, and the one whose
  answer is a decision rather than a fix.
- **The proxy's own correlation id** (ADR 0008 D12): `x-amz-request-id` is absent
  on every answer and the error document carries the constant `proxy-request`,
  which identifies nothing.
- **`DeleteObjects` input validation**: an empty document, an `<Object>` with no
  `<Key>`, and more than a thousand keys all reach the backend instead of being
  refused with `400 MalformedXML`; an unreadable body does not answer
  `IncompleteBody`.
- **Routing and method refusal**: a key containing `//`, `/../` or `/./` is
  rewritten by the mux path cleaner instead of being served; an unrouted method
  gets gorilla's bare 405 instead of an S3 `<Error>`; `/health` and `/version`
  shadow buckets of the same name; an unsupported object method answers 501 where
  S3 answers 405.
- **Bucket sub-resources**: `GET ?policy` with no policy answers 200 with an empty
  JSON body instead of `404 NoSuchBucketPolicy`; a sub-resource write body is
  buffered whole with no bound.
- **`CompleteMultipartUpload` part order**: a scrambled `<Part>` list is accepted
  where S3 answers `400 InvalidPartOrder`.
- **Response overrides** (ADR 0007 D1/D2): `response-content-type` and its five
  siblings are dropped instead of honoured.
- **`?torrent`**: forwarded undecrypted, which hands out a document derived from
  the stored bytes (ADR 0008 D1/D3/D11).
- **Startup validation**: `multipart_session_cleanup_interval` has a
  never-evaluated `validate:"min=60"` tag and no check, so `0` switches the
  sweeper off and strands the short-part budget permanently (ADR 0028 residual).
- **Two messages that promise an implementation**: the `tink` refusal says "not
  yet implemented" for a name ADR 0005 D4 replaced, and the licence logger emits
  "Kubernetes Cluster ID validation not yet implemented" for a claim nothing
  reads (ADR 0016 residual).
- **A monitoring bind failure** is logged and `Start` still reports success.

## Two decisions inside the list, not fixes

- **The authentication status per error code.** Decided 2026-09-13 and recorded
  as ADR 0014 D13; see *The contradiction inside the list* above.
- **The correlation id.** Either stay absent, which ADR 0008 D12 permits, or mint
  a real per-request id and echo it in `x-amz-request-id`. The constant that
  identifies nothing is the one answer that is wrong either way.

## Open, and not in the list above

Four things the sweep and its decision left outstanding. They are here because a
decision record is not a work list; the reasoning for each is in ADR 0031.

- [ ] **A red test does not name its rule where a reader sees it.** ADR 0031 D7
      asks for the rule and the record *in the failure message*. The two client
      suites do it; the twenty-seven tests above do not — their citation sits in
      a source comment and the failure is bare tool output (`Should be empty, but
      was proxy-request`). ADR 0031 D9 asks a suite to report what is open where
      its result is already read; the integration suites produce no such summary.
      **These two are named in ADR 0031 as the whole mitigation for the largest
      risk it accepts**, so until they are built that risk is unmitigated. The
      mechanical fix is to move each citation into the assertion's message.

- [ ] **There is no emergency release path, and it is undecided.** Every gate is
      a prerequisite of the release job, so a security fix in a dependency cannot
      ship while an unrelated target is red. ADR 0031's residual risks put the
      choice plainly: either a security release may cut past red gates under a
      named written procedure saying who may do it and what backfills afterwards,
      or it may not and an unbounded delay on security fixes is accepted. **Decide
      it before it is needed.**

- [ ] **Three required checks are not pinned to the app that reports them.** The
      thirteen checks that predate this work name GitHub Actions as the only app
      allowed to satisfy them; the three end-to-end checks added on 2026-09-13
      carry no such binding, so anything able to write a commit status can report
      them green. The endpoint that sets it answered HTTP 500 on every attempt,
      including an exact no-op, so this is a retry rather than a fix. Until then
      it is a real if modest weakening of three release gates, and it is the kind
      of inconsistency nobody finds by reading the repository, because the check
      list is configured outside it.

- [ ] **Revisit the enforced known-failure manifest** once the red set is about
      regressions rather than a backlog. ADR 0031 rejects it for now and says why,
      and names it as the alternative most likely to replace the decision: it
      cannot decay, and it preserves the regression signal that permanent red
      destroys.

The committed knowledge graph is also behind by this work and the two client
suites; it is rebuilt in its own approved change and never unprompted.

## Done when

- [ ] Each item above is either fixed, or decided and recorded in an ADR with its
      test updated to the decision.
- [ ] `make test-unit`, `make test-integration`, `make test-integration-tls`,
      `make test-e2e-rclone`, `make test-e2e-s3cmd` and `make test-e2e-velero`
      are green on the branch head.
- [ ] The four items under *Open, and not in the list above* are each done or
      decided and recorded.
- [ ] `git grep 035` is empty outside this directory, and this file is deleted.
