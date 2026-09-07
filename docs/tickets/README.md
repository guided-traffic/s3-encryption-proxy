# Tickets

One file per ticket, checked in, kept next to the code it changes. A ticket
holds the reasoning as well as the work: what was verified and how, what was
deliberately left out, and what still needs a decision from the repository
owner. Nothing here is a status board — read the ticket for the current state,
this page only says which one to open.

Two things live in this file because they have nowhere better to live:
the [index](#index) of what exists, and the [label index](#label-index) that
defines the `D-`, `N-`, `S-`, `P-` and `F-` labels the Velero-round tickets cite
in almost every paragraph.

## Index

| Ticket | State | What it covers | Labels it carries |
|---|---|---|---|
| [010](010-performance-improvements.md) | Complete (2026-04-25) | Streaming throughput, tiers 1 to 4.3: buffer pooling, allocation and log-level work on the GET path | — |
| [011](011-dek-cache-stale-on-reupload.md) | Closed | The DEK cache returned the previous DEK after a re-upload of the same key. The cache key now includes the encrypted DEK ([providers.go:220](../../internal/orchestration/providers.go#L220)), covered by [dek_cache_reupload_test.go](../../test/integration/360-degree-variants/dek_cache_reupload_test.go). The ticket file itself carries no status line | — |
| [012](012-performance-audit-round2.md) | Open (2026-06-11) | Round-2 performance audit after 010: 15 confirmed findings, 4 rejected with rationale, of which three (1.1, 3.2 and the HEAD half of 3.3) were closed by the Velero round for correctness reasons — see the dated update in its Status. The Velero work cites item 1.2 (the 30 s blanket HTTP timeouts) and item 3.1 (the multipart completion rework, which is also what removes the >5 GiB failure) | N-8 |
| [013](013-storage-format-v2.md) | Open | Storage format v2: one segmented AES-256-GCM chain per object, replacing the AES-GCM-whole / AES-CTR + whole-object-HMAC split. The central ticket of the Velero round; three others are scheduled after it | D-1, D-10, N-1, N-2, N-3, P-1, P-2, P-7 |
| [014](014-upload-checksum-verification.md) | Open | Verify the client upload checksums the proxy parses and throws away, and route the last three raw-body handlers through the parser | D-9, D-16, N-6 (a), P-5, P-13 |
| [015](015-configuration-hygiene.md) | Open | Delete the security knobs that no code reads, refuse to start on a plain-HTTP backend under an encrypting provider, and make the pre-signed URL lifetime configurable | D-5, D-6, D-7, N-5, P-11 |
| [016](016-helm-chart-fixes.md) | Open | Chart: `checksum/config` rollout, TLS-aware probes, the two values files that fail `helm template`, and the CI that would have caught them | P-10 |
| [017](017-filename-encryption.md) | Open, blocked on 013 | Filename encryption, directory segments only, leaf names in the clear, so kopia prefix listings and exact lookups survive | the filename-encryption decision |
| [018](018-listobjectsv2-document.md) | Open, after 013 | A real `ListBucketResult` document, the dropped listing parameters, and plaintext sizes computed from the stored size | D-11, P-4 |
| [019](019-handler-unit-coverage.md) | Open, blocked on 013 | Handler-level unit coverage, written against the v2 handlers rather than the ones v2 deletes | D-17 |
| [020](020-dev-license-expiry.md) | Open, deadline 2026-10-05 | `config/license.jwt` and its CI secret twin expire; reissue both and add a CI check that fails early | D-18 |
| [021](021-relative-performance-thresholds.md) | Open | Turn the measured proxy-versus-MinIO ratio into an enforced threshold and delete the skip knobs | D-14 |
| [022](022-s3-surface-fidelity.md) | Open | The residue of the pre-merge sweep: the headers PUT still drops, the dead code the sweep exposed, and the decisions it needs before any code is written | S-8 and the sweep residue |
| [023](023-major-v4.md) | Open, umbrella | Major release v4: the tickets that force a migration (013, 015, the config-facing remnants of 012, 022 item 5), the client-visible candidates that should ride along, what stays out, and the `feat/major-v4` branch everything is collected on | — |
| [024](024-coverage-round-findings.md) | Open, decisions taken 2026-09-07 | The coverage round of 2026-09-06: unit coverage from 63.1 to 77.8 percent, 1765 statements of mock code taken out of the production build, and the defect list that raising coverage produced. A findings ticket - each item names the ticket that fixes it rather than opening a competing one | C-1, C-2, I-1, I-2, S-1 to S-6, A-1 to A-3, P-1 to P-3, X-1, X-2 |
| [025](025-tink-kms-hcvault.md) | Open, after 013 | Complete the Tink KEK provider against a real KMS, HashiCorp Vault Transit first, AWS and GCP KMS alongside; today it is an unreachable stub that mints a random keyset | D-23 |

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
test-churn reason. 015, 016, 020, 021 and 022 depend on nothing; 020 is the only
one with a date on it.

Since 2026-09-06 the breaking tickets are collected on one branch,
`feat/major-v4`, and released together as 4.0.0; [ticket 023](023-major-v4.md)
says which tickets are members, which are candidates, which stay on `main`,
and in what order they land on the branch. 020 and 021 stay on `main`.

## Label index

The labels come from the Velero round on `feat/velero-support-and-tests`
(2026-09-06): the e2e suite was built against real Velero in a kind cluster, and
building it turned up defects in the proxy, which were then swept for siblings
against a live demo stack. Five series came out of that work and the tickets
cite them by label:

| Series | What it is |
|---|---|
| `D-` | A decision that was open, with the call taken on 2026-09-06 |
| `N-` | A finding the threat model added — the backend is hostile, so what "integrity" means changed and new things became defects |
| `S-` | A finding of the pre-merge sweep over the proxy handlers, most of them reproduced by probe against a running stack |
| `P-` | A defect parked rather than fixed before merge, with enough detail to pick up without repeating the investigation |
| `F-` | A fix that landed on the branch. Closed history, listed so a label cited elsewhere resolves |

Priority marks in the `D-` and `N-` series: **[S]** touches security,
**[R]** touches the release process, **[C]** cost or coverage only.

The working notes these labels were written in are gone; every label that still
means work is owned by a ticket, and the security findings are written out from
the operator side as `H-1` to `H-8` in
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#8-residual-risks--hardening-checklist).
The tables below are the definition of each label and say where it lives now.

### Decisions D-1 to D-30

| # | Decision, and what was decided on 2026-09-06 | Where it lives now |
|---|---|---|
| D-1 | [S] A ranged read cannot be verified against the whole-object HMAC. **Not accepted as shipped**: a format in which every byte at rest is authenticated at a granularity ranged reads can use | [013](013-storage-format-v2.md); stated as [H-1](../../SECURITY_ARCHITECTURE.md#h-1-ranged-reads-of-aes-ctr-objects-are-not-verified-by-the-proxy) until it ships |
| D-2 | [R] Does the `e2e-velero` job block `semantic-release`? **Keep it blocking** — a release cannot ship past a broken Velero path; revisit only if the job proves flaky, which it has not (13 of 13 twice, once from a freshly created cluster) | Closed: `semantic-release` needs `e2e-velero` in [release.yml:572](../../.github/workflows/release.yml#L572), with the reason in the comment above it |
| D-3 | [S] The test CA private key is committed. **Gitignore, delete, regenerate** — and further than that: only `gen-certs.sh` stays tracked, because a tracked certificate stops matching the key a fresh clone generates | Closed, F-22 |
| D-4 | [R] Renovate automerge for the "Velero e2e" group, which is `automerge: false` against a repository default of true because the Velero chart lags the Velero release, so a chart bump and an image bump must never land separately. **Keep manual** until the `e2e-velero` job has been green across a few Renovate cycles; the group already moves all pins together, which is what made separate merges dangerous | Closed: [renovate.json:154-155](../../renovate.json#L154) |
| D-5 | [C] Rate limiting is switched off in the e2e proxy config. **Moot** — the limiter does not exist (N-5); delete the knobs instead of raising them | [015](015-configuration-hygiene.md) |
| D-6 | [S] A plain-HTTP backend silently cannot take a streaming upload. **Refuse to start** when the active provider encrypts; warn and continue for `none` | [015](015-configuration-hygiene.md) |
| D-7 | [S] The pre-signed URL maximum lifetime is not configurable. **Add `s3_security.max_presign_expiry_seconds`**, default 3600 s, hard cap 604800 s. Velero needs 600 s; seven days of bearer capability is the wrong default | [015](015-configuration-hygiene.md) |
| D-8 | [C] The error mapper keeps a substring fallback. **Delete it**, so an internal error whose text happens to name an S3 code is no longer answered as that code | Closed, F-21 |
| D-9 | [S] The aws-chunked checksum trailer is discarded. **Verify it**: CRC32, CRC32C and CRC64NVME always; MD5, SHA-1 and SHA-256 behind `encryption.verify_upload_digests` (default false, because a second full pass costs upload throughput on the kopia path); mismatch answers `BadDigest`; never forwarded to the backend, never stored, because a plaintext checksum in cleartext metadata lets the backend confirm guesses about small files | [014](014-upload-checksum-verification.md) |
| D-10 | [C] A ranged GET of an AES-GCM object costs two backend requests. **Accept** until v2, which dissolves it | [013](013-storage-format-v2.md) |
| D-11 | [C] `ListObjectsV2` reports ciphertext sizes and a non-S3 document. **Own ticket after v2**, because only under v2 is the plaintext size a pure function of the stored size | [018](018-listobjectsv2-document.md) |
| D-12 | [C] The e2e health check reads the Backup CR rather than `velero backup describe`. **Keep**, deviation from the E2E-001 specification accepted; `describe --details` is covered by scenario V10 | Closed, in the e2e suite as built |
| D-13 | [C] Scenario V9 rotates between two AES providers rather than to a `none` provider. **Keep**, no `none` e2e scenario: `none` is a testing and end-of-life aid, not a production mode | Closed, in the e2e suite as built |
| D-14 | [C] Performance thresholds stay advisory in CI. **Relative baseline first, then enable** | [021](021-relative-performance-thresholds.md) |
| D-15 | [C] docker-compose runs two proxies (HTTP 8080, HTTPS 8443) and the integration suite runs against both, which roughly doubles that job. **Keep both**: aws-sdk-go-v2 emits `STREAMING-UNSIGNED-PAYLOAD-TRAILER` framing only over TLS, so the two runs cover different upload framing — measured on this branch, a full HTTPS run hits the buffered aws-chunked path 718 times and the HTTP run zero. If the CI time becomes a problem, split them into parallel jobs rather than dropping one | Closed: `proxy` and `proxy-tls` in [docker-compose.demo.yml](../../docker-compose.demo.yml) |
| D-16 | [C] Coverage gap 5, bucket configuration handlers with chunked bodies. **Fold into P-5**, with D-9 | [014](014-upload-checksum-verification.md) |
| D-17 | [C] Handler-level unit coverage is thin. **Own ticket, after v2** — handler tests written now would test code v2 deletes | [019](019-handler-unit-coverage.md) |
| D-18 | [R] The development license expires 2026-10-05. **Reissue before the date**, refresh the CI secret, and add a step that fails when the token expires within 14 days | [020](020-dev-license-expiry.md) |
| D-19 | [S] Per-chunk signatures in aws-chunked uploads are never verified. **Leave it, document it**: those signatures protect the client leg, which runs inside the cluster over TLS, and the adversary is on the other leg | Closed as documentation, [H-2](../../SECURITY_ARCHITECTURE.md#h-2-per-chunk-signatures-are-never-verified) |

D-20 to D-30 are the decisions taken on 2026-09-07 on the findings of the coverage round
([024](024-coverage-round-findings.md)); the finding labels in the second column are 024's.

| # | Decision, and what was decided on 2026-09-07 | Where it lives now |
|---|---|---|
| D-20 | [S] 024 H-1/H-2: `integrity_verification: strict` does not refuse a tampered AES-CTR download, and a backend answering without `Content-Length` disables the check. **Documentation only until v2**: the README stops presenting `strict` as protection on the CTR path, and `SECURITY_ARCHITECTURE.md` H-5 is rewritten to say so; the code is fixed by the format change, not patched | [013](013-storage-format-v2.md), open question 12 |
| D-21 | [S] 024 S-1: any 32-character string is accepted as the AES master KEK, and its unsalted SHA-256 is published in every object. **Remove the raw-string fallback**; `aes_key` is base64 of exactly 32 bytes and nothing else. Ships with the major release | [013](013-storage-format-v2.md), open question 13; bundled in [023](023-major-v4.md) |
| D-22 | [S] 024 S-3: pprof is served on the unauthenticated monitoring port and a heap profile contains DEKs and plaintext. **Own listener bound to `127.0.0.1`** for `/debug/pprof`; `/metrics` stays on the monitoring port | [015](015-configuration-hygiene.md), Part 5 |
| D-23 | [S] The Tink provider is a stub that mints a random keyset and is refused by config. **Complete it**, HashiCorp Vault Transit first, AWS KMS and GCP KMS alongside; sequenced after v2 because of P-1 | [025](025-tink-kms-hcvault.md) |
| D-24 | [S] 024 S-4: `X-Forwarded-For` is trusted unconditionally and the per-IP failure map is never evicted. **Keep the map, add a trusted-proxy CIDR list and eviction** — reversing the "delete the whole struct" plan in 015 Part 1.2; the consequence for the two blocking knobs is flagged there | [015](015-configuration-hygiene.md), Part 5 |
| D-25 | [S] 024 A-1/A-2: `Stop()` deadlocks without a license, and a token without `exp` terminates the proxy after 60 minutes. **Fix the deadlock; reject a token without `exp` at validation** — a perpetual license needs an explicit claim, not an omission. Amends 020's scope, which excluded validation changes | [020](020-dev-license-expiry.md), scope amendment |
| D-26 | [C] 024 X-2: a backend `200` carrying an `<Error>` document is forwarded as a 200. **Map it to 500**, keeping the S3 code, because a status-only client must not read a failed operation as success | [022](022-s3-surface-fidelity.md), item 19 |
| D-27 | [C] 024 H-4 follow-up: a `PUT` whose `partNumber` fails the route regex now answers 501. **Answer `InvalidArgument` (400) for PUT with `partNumber`+`uploadId`**, as AWS does; `GET ?partNumber` stays 501 because the proxy really does not implement it | [022](022-s3-surface-fidelity.md), item 20 |
| D-28 | [C] 024 P-1: the DEK is unwrapped twice per GCM GET, 0.94 ms under RSA-2048. **No interim fix**; v2 rewrites the path and must be measured after. This is also why 025 is sequenced after v2 | [013](013-storage-format-v2.md), open question 14 |
| D-29 | [C] 024 P-2: the pooled 128 KiB copy buffer is bypassed exactly when monitoring is off, because `io.CopyBuffer` prefers `dst.ReadFrom`. **Make the pooled path apply in both modes, add `Flush`/`Unwrap`/`Hijack`, then measure both copy paths and delete the loser** | [012](012-performance-audit-round2.md), item 1.4 |
| D-30 | [S] 024 H-5: `metadata_key_prefix` is not validated; an empty prefix serves ciphertext as plaintext and a non-lowercase one disables decryption. **Validate at startup**: non-empty, `[a-z0-9-]` only, error otherwise | [015](015-configuration-hygiene.md), Part 5 |

### Threat-model findings N-1 to N-10

Found by re-reading the proxy against the orientation in
[SECURITY_ARCHITECTURE.md section 1](../../SECURITY_ARCHITECTURE.md#1-threat-model):
the backend is hostile, integrity means the proxy verifies, and a control that
exists only in configuration or documentation is worse than no control.

| # | Finding | Where it lives now |
|---|---|---|
| N-1 | [S] GET, HEAD and ranged GET fall back to pass-through when an object carries no `s3ep-*` metadata, **even under an encrypting provider**, so a backend that strips the metadata and replaces the body has its substitute delivered as plaintext. Decided: fail closed, no opt-out knob, pre-existing plaintext migrated once through the proxy | Open, [013](013-storage-format-v2.md); [H-6](../../SECURITY_ARCHITECTURE.md#h-6-an-object-without-encryption-metadata-is-served-as-plaintext) |
| N-2 | [S] `integrity_verification: hybrid` accepts an object whose `s3ep-hmac` the backend simply removed, and `lax` delivers data whose verification failed. Dissolved by v2, where integrity is not separable from decryption and the knob goes away; until then `strict` is the only mode the README recommends | Open, [013](013-storage-format-v2.md); [H-5](../../SECURITY_ARCHITECTURE.md#h-5-integrity_verification-modes-only-strict-is-safe) |
| N-3 | [S] Re-uploading a multipart part would encrypt at the same AES-CTR offset twice — a two-time pad. Latent today only because the retry hangs instead (P-2). Dissolved by v2 random per-segment nonces; any interim fix to P-2 must not encrypt twice at the same offset | Open, [013](013-storage-format-v2.md) |
| N-4 | [S] Velero creates its kopia repository with the published default password `static-passw0rd` unless `velero-repo-credentials` is set first, so kopia AES-GCM and its content HMACs are forgeable by anyone who can read the bucket. Velero's own objects are never encrypted by Velero at all | Half closed: the README carries the warning and the command, and [H-4](../../SECURITY_ARCHITECTURE.md#h-4-velero-kopia-repositories-default-to-a-published-password) states it from the operator side. The other half of the decision — the e2e setting one so the suite runs the documented configuration — was never built and is item 10 of [016](016-helm-chart-fixes.md) |
| N-5 | [S] Request rate limiting does not exist. `enable_rate_limiting`, `max_requests_per_minute`, `max_failed_attempts` and `unblock_ip_seconds` are parsed, validated and read by nothing; the failed-attempt map is keyed by an attacker-chosen `X-Forwarded-For` value and never expires. Decided: delete the knobs and the map, keep the security log line. Per-IP limiting is the wrong tool here anyway — Velero legitimately bursts from one pod IP | Open, [015](015-configuration-hygiene.md); [H-7](../../SECURITY_ARCHITECTURE.md#h-7-dead-security-configuration-knobs) |
| N-6 | [S] Client checksums, four pieces. **(a)** A wrong `Content-MD5` is answered 200 on both the small-object and the auto-multipart path, so kopia's integrity intent is dropped for every blob it writes — open, [014](014-upload-checksum-verification.md). **(b)** and **(c)** the client `Content-MD5` was forwarded with the *ciphertext* body on the streaming PUT and `UploadPart` paths — closed, F-20. **(d)** **Refuted**: no response path ever emitted an `x-amz-checksum-*` header. Responses are composed from an allowlist, and the backend client runs with `ResponseChecksumValidation = WhenRequired`; what was actually there was dead field copying, cut down in F-18. A refuted finding is a result — it is why D-9 lost its "strip backend checksum headers" half | (a) [014](014-upload-checksum-verification.md); (b), (c) closed, F-20; (d) refuted |
| N-7 | [C] kopia sets `DisableMultipart: true` and writes every ~20 MiB pack blob as one PutObject, so the proxy auto-multipart path carries all kopia data and the client-driven multipart path is exercised only by Velero's own uploader. Context rather than a work item: it is what weights P-2 and settles the part-size rule in v2 | Context for [013](013-storage-format-v2.md) |
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
| P-1 | Ranged reads cannot be verified against the whole-object HMAC; the option costed here was a per-segment or Merkle HMAC written at upload time | [013](013-storage-format-v2.md), with D-1 |
| P-2 | An `UploadPart` retry, or a part-number gap, blocks in `processPartOrdered` with no context case until the session ages out — confirmed by probe for a retried part 1, for part 3 without part 2, and for a cancelled caller. Every aws-sdk-go-v2 retry reuses the part number, so it is latent rather than absent. v2 makes parts independent and removes the ordering; an interim fix only if v2 slips a release, and it must not re-encrypt at the same offset (N-3) | [013](013-storage-format-v2.md) |
| P-3 | `UploadPartCopy` was shadowed by the plain `UploadPart` route, so a copy request was handled as a part upload of an empty body and answered 200 | Closed, F-12 |
| P-4 | `ListObjectsV2` drops `start-after`, `fetch-owner` and `encoding-type`, silently ignores an out-of-range `max-keys`, XML-encodes the raw SDK struct as `<ListObjectsV2Output>`, and reports the ciphertext size; `handleHeadBucket` is a `ListObjectsV2(MaxKeys=0)` without `x-amz-bucket-region` | [018](018-listobjectsv2-document.md), with D-11 |
| P-5 | Three handlers read the body raw instead of through `Parser.ReadBody` — `handleDeleteObjects`, `CompleteHandler` and `handleCreateBucket` — so a trailer-framed body would break them. The `html.UnescapeString` half of the item, which turned escaped markup in a Complete body into real markup, is closed with F-13 | [014](014-upload-checksum-verification.md), with D-9 and D-16 |
| P-6 | Response XML built by string concatenation with unescaped input, in four places; two of them reflected attacker-controlled text (the attempted access key id, the raw request URL). Escaping alone would not have been enough — the old code used `html.EscapeString`, which passes control characters through | Closed, F-13, including the two sites the item missed (S-3, S-14) |
| P-7 | `ListParts` returns a fabricated empty `<ListPartsResult>` at 200, so a client verifying an upload is told it has zero parts; `ListMultipartUploads` is 501. With P-8, orphaned uploads existed and could not be enumerated. Now marshalled from a struct (F-13) but still reporting zero parts | [013](013-storage-format-v2.md), with the v2 multipart rework |
| P-8 | The multipart abort ran on the already-cancelled request context, so the abort caused by a client disconnect could never reach the backend and the upload was orphaned | Closed, F-14. Two corrections to the item: the third abort site is `multipart/create.go`, not `complete.go`, and the self-copies (S-2) mattered more than the aborts |
| P-9 | `DeleteObject` built its input without `VersionId`, so on a versioned bucket `velero backup delete` left every version behind | Closed, F-15, together with the GET, HEAD and ranged-GET siblings S-5 named |
| P-10 | The chart has no `checksum/config` pod annotation, so `helm upgrade` with a changed config updates the ConfigMap without rolling the pods. Plus five related chart items found while wiring the e2e: two values files that fail `helm template`, probes that ignore `tls.enabled`, an unmounted cert-manager `Certificate`, a `Service` with no `nodePort`, and a stale helm-unittest file nothing runs | [016](016-helm-chart-fixes.md), all six items |
| P-11 | A plain-HTTP backend cannot take a streaming upload: aws-sdk-go-v2 signs by hashing the body, which needs a seekable stream, and only accepts `UNSIGNED-PAYLOAD` over TLS. Nothing in the repository says so, because every example config uses TLS | [015](015-configuration-hygiene.md), as D-6 |
| P-12 | The test CA private key is committed | Closed, F-22, as D-3 |
| P-13 | The aws-chunked checksum trailer is parsed and discarded, although the decoder already reads the trailer block. Verifying it would have caught the framing bug F-1 at upload time instead of at the next read | [014](014-upload-checksum-verification.md), as D-9 |

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
| F-6 | Ranged GET was refused for every object, which failed **every kopia-based Velero restore**. This is where the D-1 tradeoff enters the code |
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
| F-21 | The error mapper substring fallback is deleted (D-8) |
| F-22 | The test PKI is untracked and generated on demand (D-3, P-12); `--if-needed` checked only two of the six files and would have reported "still valid" on a fresh clone |
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
