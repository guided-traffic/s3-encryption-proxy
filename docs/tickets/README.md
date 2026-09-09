# Tickets

One file per ticket, checked in, kept next to the code it changes. **A ticket is
a work list.** It holds what has to be done, what was verified and how, and what
was deliberately left out — and it is **deleted when the work lands**. Nothing
outside this directory may reference a ticket; decisions live in
[docs/adr/](../adr/) and may be referenced from anywhere. The rule and the
reasoning behind it are
[ADR 0022](../adr/0022-tickets-are-work-lists-that-get-deleted.md).

Before deleting a ticket: move anything durable out of it (the decision into an
ADR, the operator-visible consequence into `README.md` or
`SECURITY_ARCHITECTURE.md`), then `git grep` its number and clear whatever is
left.

This page carries the [index](#index) of what exists and the
[label index](#label-index) for the finding labels older ticket text still
cites.

## Index

| Ticket | State | What it covers | Labels it carries |
|---|---|---|---|
| [010](010-performance-improvements.md) | Complete (2026-04-25) | Streaming throughput, tiers 1 to 4.3: buffer pooling, allocation and log-level work on the GET path | — |
| [011](011-dek-cache-stale-on-reupload.md) | Closed | The DEK cache returned the previous DEK after a re-upload of the same key. The cache key now includes the encrypted DEK ([providers.go:220](../../internal/orchestration/providers.go#L220)), covered by [dek_cache_reupload_test.go](../../test/integration/360-degree-variants/dek_cache_reupload_test.go). The ticket file itself carries no status line | — |
| [012](012-performance-audit-round2.md) | Open (2026-06-11) | Round-2 performance audit after 010: 15 confirmed findings, 4 rejected with rationale, of which three (1.1, 3.2 and the HEAD half of 3.3) were closed by the Velero round for correctness reasons — see the dated update in its Status. The Velero work cites item 1.2 (the 30 s blanket HTTP timeouts) and item 3.1 (the multipart completion rework, which is also what removes the >5 GiB failure) | N-8 |
| [013](013-storage-format-v2.md) | Open | Storage format v2: one segmented AES-256-GCM chain per object, replacing the AES-GCM-whole / AES-CTR + whole-object-HMAC split. The central ticket of the Velero round; three others are scheduled after it | N-1, N-2, N-3, P-1, P-2, P-7 |
| [014](014-upload-checksum-verification.md) | Open | Verify the client upload checksums the proxy parses and throws away, and route the last three raw-body handlers through the parser | N-6 (a), P-5, P-13 |
| [015](015-configuration-hygiene.md) | Open | Delete the security knobs that no code reads, refuse to start on a plain-HTTP backend under an encrypting provider, and make the pre-signed URL lifetime configurable | N-5, P-11 |
| [016](016-helm-chart-fixes.md) | Open | Chart: `checksum/config` rollout, TLS-aware probes, the two values files that fail `helm template`, and the CI that would have caught them | P-10 |
| [017](017-filename-encryption.md) | Open, blocked on 013 | Filename encryption, directory segments only, leaf names in the clear, so prefix listings and exact lookups survive for every S3 client (kopia, the uploader Velero uses, relies on both) | the filename-encryption decision |
| [018](018-listobjectsv2-document.md) | Open, after 013 | A real `ListBucketResult` document, the dropped listing parameters, and plaintext sizes computed from the stored size | P-4 |
| [019](019-handler-unit-coverage.md) | Open, blocked on 013 | Handler-level unit coverage, written against the v2 handlers rather than the ones v2 deletes | — |
| [021](021-relative-performance-thresholds.md) | Open | Turn the measured proxy-versus-MinIO ratio into an enforced threshold and delete the skip knobs | — |
| [022](022-s3-surface-fidelity.md) | Open | The residue of the pre-merge sweep: the headers PUT still drops, the dead code the sweep exposed, and the decisions it needs before any code is written | S-8 and the sweep residue |
| [023](023-major-v5.md) | Open, umbrella | The minimum scope of release 5.0.0: what it contains at least, in what order it lands, what the operator has to do, and the release-note skeleton. Carries no decisions of its own — every line points at the ADR that decided it | — |
| [024](024-coverage-round-findings.md) | Open, decisions taken 2026-09-07 | The coverage round of 2026-09-06: unit coverage from 63.1 to 77.8 percent, 1765 statements of mock code taken out of the production build, and the defect list that raising coverage produced. A findings ticket - each item names the ticket that fixes it rather than opening a competing one | C-1, C-2, I-1, I-2, S-1 to S-6, A-1 to A-3, P-1 to P-3, X-1, X-2; the decisions it produced are ADRs now |
| [026](026-sse-c-passthrough.md) | Open, after 013 | SSE-C (customer-provided keys) forwarded on every verb — PUT, GET, ranged GET, HEAD, multipart create and parts — with the response echo, never logged or stored; until it lands the storage-header decision (ADR 0007) refuses SSE-C on PUT because forwarding it there alone would write objects the proxy can never read back. Compatibility, not protection against the backend | — |
| [025](025-tink-kms-hcvault.md) | Parked | Vault as a key provider: the five decisions still to make, the rotation findings worth keeping, and what must be verified against a running Vault before any code. Not in the next major release | — |

The `010-*` directories next to these files are the pprof profiles and captured
`top` output ticket 010 was argued from (`010-baseline`, `010-tier1`,
`010-tier1.3`, `010-tier2`, `010-tier4.1`); ticket 012 verifies its findings
against them.

## What runs first

Ticket 013 is the one that unblocks the rest. It deletes the GCM/CTR split, the
separable HMAC metadata, the ordered multipart pipeline and the post-Complete
self-`CopyObject`, so 017, 018 and 019 are scheduled after it — written now,
they would encode behaviour v2 removes. 014 does not technically depend on v2
(its choke point is the request parser) but is sequenced after it for the same
test-churn reason. 015, 016, 021 and 022 depend on nothing. 025 is after 013 as well, for a different reason: a
KMS-backed KEK turns the redundant second DEK unwrap, which is deliberately left
in place until the format change, into a network round-trip on every read.

The breaking tickets are collected on one branch and released together as one
major, now **5.0.0 on `feat/major-v5`**. [023](023-major-v5.md) is that release's
scope list: what it contains at least, what is still a candidate, and in what
order the work lands. 021 stays on `main`.

## Label index

The labels come from the Velero round on `feat/velero-support-and-tests`
(2026-09-06): the e2e suite was built against real Velero in a kind cluster, and
building it turned up defects in the proxy, which were then swept for siblings
against a live demo stack. Five series came out of that work and the tickets
cite them by label:

| Series | What it is |
|---|---|
| `N-` | A finding the threat model added — the backend is hostile, so what "integrity" means changed and new things became defects |
| `S-` | A finding of the pre-merge sweep over the proxy handlers, most of them reproduced by probe against a running stack |
| `P-` | A defect parked rather than fixed before merge, with enough detail to pick up without repeating the investigation |
| `F-` | A fix that landed on the branch. Closed history, listed so a label cited elsewhere resolves |

Priority marks in the `N-` series: **[S]** touches security, **[R]** touches the
release process, **[C]** cost or coverage only. The `D-` series is gone: decisions
live in [docs/adr/](../adr/).

The working notes these labels were written in are gone; every label that still
means work is owned by a ticket, and the security findings are written out from
the operator side as `H-1` to `H-8` in
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#8-residual-risks--hardening-checklist).
The tables below are the definition of each label and say where it lives now.

### Decisions — moved to `docs/adr/`

**The decision tables that used to sit here are gone.** A decision is durable and a
ticket is not, so every decision this project has taken now lives as an
architecture decision record in [docs/adr/](../adr/), which has its own index.
That is the rule of [ADR 0022](../adr/0022-tickets-are-work-lists-that-get-deleted.md):
tickets are work lists, they are deleted when the work lands, and nothing outside
this directory may reference one.

Older ticket text still cites decisions as `D-nn`. Those labels no longer resolve
anywhere. When you pick up a ticket, read the matching ADR from the index, and
delete the `D-nn` citation from the ticket text as you go — the ticket will be
deleted with the work anyway.


### Threat-model findings N-1 to N-10

Found by re-reading the proxy against the orientation in
[SECURITY_ARCHITECTURE.md section 1](../../SECURITY_ARCHITECTURE.md#1-threat-model):
the backend is hostile, integrity means the proxy verifies, and a control that
exists only in configuration or documentation is worse than no control.

| # | Finding | Where it lives now |
|---|---|---|
| N-1 | [S] GET, HEAD and ranged GET fall back to pass-through when an object carries no `s3ep-*` metadata, **even under an encrypting provider**, so a backend that strips the metadata and replaces the body has its substitute delivered as plaintext. Decided: fail closed, no opt-out knob, pre-existing plaintext migrated once through the proxy | Open, [013](013-storage-format-v2.md); [H-6](../../SECURITY_ARCHITECTURE.md#h-6-an-object-without-encryption-metadata-is-served-as-plaintext) |
| N-2 | [S] `integrity_verification: hybrid` accepts an object whose `s3ep-hmac` the backend simply removed, and `lax` delivers data whose verification failed. Dissolved by v2, where integrity is not separable from decryption and the knob goes away; until then no mode refuses a tampered `aes-ctr` object, which is what the documentation-only call makes the README and H-5 say | Open, [013](013-storage-format-v2.md); [H-5](../../SECURITY_ARCHITECTURE.md#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object) |
| N-3 | [S] Re-uploading a multipart part would encrypt at the same AES-CTR offset twice — a two-time pad. Latent today only because the retry hangs instead (P-2). Dissolved by v2 random per-segment nonces; any interim fix to P-2 must not encrypt twice at the same offset | Open, [013](013-storage-format-v2.md) |
| N-4 | [S] Velero creates its kopia repository with the published default password `static-passw0rd` unless `velero-repo-credentials` is set first, so kopia AES-GCM and its content HMACs are forgeable by anyone who can read the bucket. Velero's own objects are never encrypted by Velero at all | Half closed: the README carries the warning and the command, and [H-4](../../SECURITY_ARCHITECTURE.md#h-4-velero-kopia-repositories-default-to-a-published-password) states it from the operator side. The other half of the decision — the e2e setting one so the suite runs the documented configuration — was never built and is item 10 of [016](016-helm-chart-fixes.md) |
| N-5 | [S] Request rate limiting does not exist. `enable_rate_limiting`, `max_requests_per_minute`, `max_failed_attempts` and `unblock_ip_seconds` are parsed, validated and read by nothing; the failed-attempt map is keyed by an attacker-chosen `X-Forwarded-For` value and never expires. Decided: delete the knobs and the map, keep the security log line. Per-IP limiting is the wrong tool here anyway — any S3 client legitimately bursts from one address, Velero from one pod IP for example | Open, [015](015-configuration-hygiene.md); [H-7](../../SECURITY_ARCHITECTURE.md#h-7-dead-security-configuration-knobs) |
| N-6 | [S] Client checksums, four pieces. **(a)** A wrong `Content-MD5` is answered 200 on both the small-object and the auto-multipart path, so the integrity intent of every client that sends one is dropped, kopia's for every blob it writes — open, [014](014-upload-checksum-verification.md). **(b)** and **(c)** the client `Content-MD5` was forwarded with the *ciphertext* body on the streaming PUT and `UploadPart` paths — closed, F-20. **(d)** **Refuted**: no response path ever emitted an `x-amz-checksum-*` header. Responses are composed from an allowlist, and the backend client runs with `ResponseChecksumValidation = WhenRequired`; what was actually there was dead field copying, cut down in F-18. A refuted finding is a result — it is why the checksum decision lost its "strip backend checksum headers" half | (a) [014](014-upload-checksum-verification.md); (b), (c) closed, F-20; (d) refuted |
| N-7 | [C] kopia sets `DisableMultipart: true` and writes every ~20 MiB pack blob as one PutObject, so under Velero the proxy auto-multipart path carries all kopia data and the client-driven multipart path is exercised only by Velero's own uploader; other S3 clients drive multipart themselves, so both paths carry production data. Context rather than a work item: it is one input to the weighting of P-2 and the part-size rule in v2 | Context for [013](013-storage-format-v2.md) |
| N-8 | [C] `ReadTimeout` and `WriteTimeout` are 30 s on the listener, so any transfer slower than that is killed — `velero backup download` of a large tarball over a slow link, or a node-agent upload moving less than one part per 30 s | Item 1.2 of [012](012-performance-audit-round2.md) |
| N-9 | [S] A client that hung up mid-body made `io.ReadFull` return `io.ErrUnexpectedEOF`, which the producer loop read as a clean end of stream: the object was committed **short**, and because the HMAC covers what was actually uploaded, the truncated object then verified in `strict` mode on every later read. No adversary needed — a dropped connection or the 30 s timeout of N-8 is enough | Closed, F-24 |
| N-10 | [S] The Helm chart shipped a working AES-256 KEK as its default provider key, and `values-monitoring.yaml` a second one, so any `helm install` that did not override `config` encrypted every object with a key published in this repository. Both are to be treated as compromised wherever a deployment took the default | Closed, F-25; recorded in [SECURITY_ARCHITECTURE.md section 7.4](../../SECURITY_ARCHITECTURE.md#74-a-published-chart-default-that-was-a-working-key) |

### Sweep findings S-1 to S-15

A second pass over the proxy handlers, run against a live demo stack with the
AWS CLI as the probe. All but S-8 were fixed before merge; the residue is
[022](022-s3-surface-fidelity.md).

| # | Finding | Where it lives now |
|---|---|---|
| S-1, S-6 | [S] `DELETE /bucket?<any unrouted sub-resource>` deleted the whole bucket. A 13-entry denylist let every sub-resource without its own route fall through to the base operation for the method, so `delete-bucket-encryption` ran `handleDeleteBucket`, `put-bucket-encryption` ran `CreateBucket`, and `list-object-versions` answered an empty listing with 200. Reproduced end to end; it is also the shape Terraform sends on destroy. Unrecoverable data loss from one ordinary CLI call | Closed, F-11 |
| S-2 | [S] The encryption-metadata self-copy ran on the request context, so a disconnect between `CompleteMultipartUpload` and the copy left ciphertext in the bucket with no `s3ep-*` metadata — which N-1 then hands to the next reader as plaintext | Closed, F-14 |
| S-3 | [C] `InitiateMultipartUploadResult` was string-concatenated, so a key containing `&` or `<` produced a body the client cannot parse; the client retried, and every attempt leaked a real backend upload that can be neither completed nor aborted through the proxy | Closed, F-13 |
| S-4 | [S] The self-copy used `MetadataDirective: REPLACE` while restating nothing, so `Content-Type` and every entity header were destroyed on every object at or above 5 MiB — the whole kopia path. Not a header the proxy forgot to forward: one it set at `CreateMultipartUpload` and deleted again two calls later | Closed, F-16 |
| S-5 | [S] GET, HEAD and ranged GET dropped `versionId` as well, so a request naming one version was answered with the current object | Closed, F-15 |
| S-7 | [S] `PUT ?legal-hold` discarded the body and always sent `Status: ON`, so a client asking to **release** a hold applied one and was told it succeeded; `PUT ?retention` always sent `Governance` with no date; both GETs and `SelectObjectContent` answered 200 with an empty body | Closed, F-17 |
| S-8 | [S] PUT drops `x-amz-server-side-encryption`, `x-amz-tagging`, `x-amz-storage-class`, `x-amz-acl` and the object-lock headers, and answers 200. Not fixed and **blocked on a decision rather than on work**: backend SSE is close to pointless under the proxy's own envelope encryption, while tags, storage class and ACL are ordinary storage attributes, so the two halves probably want opposite answers | Open, item 1 of [022](022-s3-surface-fidelity.md) |
| S-9 | [C] GET and ranged GET dropped the entity headers HEAD returns for the same object. `Content-Encoding` is the dangerous one — a stored `gzip` was invisible to the GET caller | Closed, F-18 |
| S-10 | [C] PUT and `CompleteMultipartUpload` returned an ETag the object no longer had, because the self-copy rewrote it afterwards. A client that stores the PUT ETag to detect drift saw drift immediately | Closed, F-16 |
| S-11 | [C] Client-driven `CreateMultipartUpload` dropped `x-amz-meta-*` entirely, although every other write path preserves it | Closed, F-19 |
| S-12 | [C] `DeleteObjects` asked the SDK for a SHA-256 over a document the proxy re-serialises, because the client had sent a `Content-MD5` — a third variant of N-6 (b) and (c) | Closed, F-20 |
| S-13 | [C] `GET /bucket/key?attributes` had no route, so `GetObjectAttributes` returned the object bytes where an XML document belongs | Closed, F-17 |
| S-14 | [S] `<Location>` in `CompleteMultipartUploadResult` was the backend URL, unescaped: backend-controlled text reflected into an XML body, leaking the internal endpoint to every client that completes an upload | Closed, F-13 |
| S-15 | [C] The `ListBuckets` error path answered `http.Error(w, "Internal Server Error", 500)`, so every backend failure — `AccessDenied` included — reached the client as a `text/plain` internal error with no `<Error>` document | Closed, F-23 |

### Parked items P-1 to P-13

Defects that were found before merge and deliberately not fixed there.

| # | Item | Where it lives now |
|---|---|---|
| P-1 | Ranged reads cannot be verified against the whole-object HMAC; the option costed here was a per-segment or Merkle HMAC written at upload time | [013](013-storage-format-v2.md), with the ranged-read decision (ADR 0003) |
| P-2 | An `UploadPart` retry, or a part-number gap, blocks in `processPartOrdered` with no context case until the session ages out — confirmed by probe for a retried part 1, for part 3 without part 2, and for a cancelled caller. Every aws-sdk-go-v2 retry reuses the part number, so it is latent rather than absent. v2 makes parts independent and removes the ordering; an interim fix only if v2 slips a release, and it must not re-encrypt at the same offset (N-3) | [013](013-storage-format-v2.md) |
| P-3 | `UploadPartCopy` was shadowed by the plain `UploadPart` route, so a copy request was handled as a part upload of an empty body and answered 200 | Closed, F-12 |
| P-4 | `ListObjectsV2` drops `start-after`, `fetch-owner` and `encoding-type`, silently ignores an out-of-range `max-keys`, XML-encodes the raw SDK struct as `<ListObjectsV2Output>`, and reports the ciphertext size; `handleHeadBucket` is a `ListObjectsV2(MaxKeys=0)` without `x-amz-bucket-region` | [018](018-listobjectsv2-document.md), with the listing decision (ADR 0010) |
| P-5 | Three handlers read the body raw instead of through `Parser.ReadBody` — `handleDeleteObjects`, `CompleteHandler` and `handleCreateBucket` — so a trailer-framed body would break them. The `html.UnescapeString` half of the item, which turned escaped markup in a Complete body into real markup, is closed with F-13 | [014](014-upload-checksum-verification.md), with the checksum decision (ADR 0012) |
| P-6 | Response XML built by string concatenation with unescaped input, in four places; two of them reflected attacker-controlled text (the attempted access key id, the raw request URL). Escaping alone would not have been enough — the old code used `html.EscapeString`, which passes control characters through | Closed, F-13, including the two sites the item missed (S-3, S-14) |
| P-7 | `ListParts` returns a fabricated empty `<ListPartsResult>` at 200, so a client verifying an upload is told it has zero parts; `ListMultipartUploads` is 501. With P-8, orphaned uploads existed and could not be enumerated. Now marshalled from a struct (F-13) but still reporting zero parts | [013](013-storage-format-v2.md), with the v2 multipart rework |
| P-8 | The multipart abort ran on the already-cancelled request context, so the abort caused by a client disconnect could never reach the backend and the upload was orphaned | Closed, F-14. Two corrections to the item: the third abort site is `multipart/create.go`, not `complete.go`, and the self-copies (S-2) mattered more than the aborts |
| P-9 | `DeleteObject` built its input without `VersionId`, so on a versioned bucket `velero backup delete` left every version behind | Closed, F-15, together with the GET, HEAD and ranged-GET siblings S-5 named |
| P-10 | The chart has no `checksum/config` pod annotation, so `helm upgrade` with a changed config updates the ConfigMap without rolling the pods. Plus five related chart items found while wiring the e2e: two values files that fail `helm template`, probes that ignore `tls.enabled`, an unmounted cert-manager `Certificate`, a `Service` with no `nodePort`, and a stale helm-unittest file nothing runs | [016](016-helm-chart-fixes.md), all six items |
| P-11 | A plain-HTTP backend cannot take a streaming upload: aws-sdk-go-v2 signs by hashing the body, which needs a seekable stream, and only accepts `UNSIGNED-PAYLOAD` over TLS. Nothing in the repository says so, because every example config uses TLS | [015](015-configuration-hygiene.md), as the plain-HTTP refusal (ADR 0013) |
| P-12 | The test CA private key is committed | Closed, F-22 |
| P-13 | The aws-chunked checksum trailer is parsed and discarded, although the decoder already reads the trailer block. Verifying it would have caught the framing bug F-1 at upload time instead of at the next read | [014](014-upload-checksum-verification.md), under the checksum decision (ADR 0012) |

### Fixes F-1 to F-25

Closed history, and the reason several things in the code look the way they do.
F-1 to F-10 landed earlier on `feat/velero-support-and-tests`: F-1 and F-2 in
`11134a3`, F-4 and F-9 in `1e6c017`, F-5 and F-6 in `df12c84`, F-7 and F-8 in
`646932b`; F-3 and F-10 sit in that same run of commits and are not attributed
to one of them here. F-11 to F-21, F-23 and F-24 landed together in `c359091`;
F-22 and F-25 in `ae1c828`. After the last of
them: unit suite, integration suite against both the HTTP and the TLS proxy
endpoint, all 13 Velero e2e scenarios in a kind cluster, and `make lint` green
(2026-09-06).

Four of them were additionally re-probed by hand over the wire that day, against
the running demo stack rather than against a mock: `delete-bucket-encryption`
answered `501` and the bucket survived (F-11); an 8 MiB PUT kept `Content-Type`,
`Cache-Control` and `Content-Disposition`, and its ETag still matched the
following HEAD (F-16); `?attributes` and `put-object-legal-hold` answered `501`
(F-17); and a GET response carried no `x-amz-checksum-*` header (the N-6 (d)
refutation). Those were one-off manual probes — no automated test repeats three
of them, which is what item 6 of [022](022-s3-surface-fidelity.md) is for.

| # | What it fixed |
|---|---|
| F-1 | aws-chunked framing was stored as payload: detection sniffed for `;chunk-signature=`, which `STREAMING-UNSIGNED-PAYLOAD-TRAILER` does not carry. Detection is header-based now and `aws_chunked_decoder.go` is gone |
| F-2 | Every backend error surfaced as a 500 `InternalError`. Mapping lives in `response.MapError`, unwraps with `errors.As`, and is the only mapper in the proxy |
| F-3 | PutObject routed on the wire length rather than the plaintext length, so the GCM/CTR branch depended on how the client framed the request |
| F-4 | The backend SDK client computed checksums over an unseekable ciphertext stream — an outright failure against a plain-HTTP backend and a full extra pass otherwise. Now `WhenRequired` |
| F-5 | Pre-signed URLs were rejected with 403, which broke every `velero backup logs`, `restore logs`, `backup download` and `describe --details`. Query-string SigV4 is validated now, with a bounded `X-Amz-Expires`; the canonical builder also had to stop using `url.QueryEscape` |
| F-6 | Ranged GET was refused for every object, which failed **every kopia-based Velero restore**. This is where the the ranged-read decision (ADR 0003) tradeoff enters the code |
| F-7 | HEAD reported the ciphertext length, 28 bytes more than GET returned, and dropped the entity headers |
| F-8 | `Content-Encoding: aws-chunked` was written onto the stored object on three PUT paths |
| F-9 | The test certificates had expired the day the work started; `gen-certs.sh` issues a real CA and a 397-day leaf instead |
| F-10 | A dead `UploadPart` handler was removed |
| F-11 | Unrouted bucket sub-resources ran the base bucket operation (S-1, S-6). The denylist is replaced by an allowlist of the parameters the base operations actually take; anything else answers `NotImplemented` |
| F-12 | `UploadPartCopy` was unreachable (P-3) — two defects, the registration order *and* a header matcher comparing the literal `{source}`, so swapping the order alone would not have fixed it |
| F-13 | Every XML response body is built with `encoding/xml` (P-6, S-3, S-14, and the P-5 unescape). The two dead not-implemented writers were deleted rather than escaped, and `<Location>` names the proxy instead of echoing the backend |
| F-14 | Cleanup that must outlive the request runs on `utils.CleanupContext`, a detached context with its own timeout (P-8, S-2) |
| F-15 | `versionId` is forwarded on GET, HEAD, ranged GET and DELETE, and `x-amz-version-id` comes back (P-9, S-5) |
| F-16 | The metadata self-copy no longer destroys the entity headers or the ETag (S-4, S-10); the auto-multipart path restates them from the request, the client-driven path reads them back with a `HeadObject` |
| F-17 | Legal-hold, retention, select and `?attributes` answer `NotImplemented` instead of pretending (S-7, S-13), which deleted about 150 lines |
| F-18 | GET and ranged GET return the entity headers HEAD returns (S-9), and the dead `GetObjectOutput` field copying behind the N-6 (d) claim is gone |
| F-19 | Client-driven `CreateMultipartUpload` keeps user metadata (S-11) |
| F-20 | Client checksum headers no longer reach the backend (N-6 b and c, S-12) |
| F-21 | The error mapper substring fallback is deleted (ADR 0008) |
| F-22 | The test PKI is untracked and generated on demand (P-12); `--if-needed` checked only two of the six files and would have reported "still valid" on a fresh clone |
| F-23 | `ListBuckets` failures go through the error mapper (S-15) |
| F-24 | A truncated auto-multipart upload was committed and then verified (N-9). The byte count is checked against an authoritative declared length, and `Parser.PlaintextContentLength` exists so an aws-chunked body without `X-Amz-Decoded-Content-Length` is not rejected by mistake |
| F-25 | The Helm chart default KEK is gone (N-10); the values files reference `${S3EP_AES_KEY}`, so a release without a key fails at startup instead of encrypting with a published one |

Alongside these, the same round repaired the static analysis that had never run:
`golangci-lint` 2.13.1 refused the v1-schema `.golangci.yml`, and `make lint`
called `gofmt -l`, which only prints. The config is on the v2 schema, the CI
install is pinned to the v2 module path, and `make lint` exits non-zero on an
unformatted file (`d4553d4`). Three leftovers of that repair — the `make tools`
install path, the unguarded `gofmt` in `make static`, and the `quality` target
ordering — are item 7 of [022](022-s3-surface-fidelity.md).
