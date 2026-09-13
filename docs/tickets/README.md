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

**State (2026-09-12, `feat/major-v5`).** Twenty-one ticket files. Waves 0 to 7 of
the 5.0.0 bundle have landed, and so has the round after them
([028](028-upload-and-read-performance-round.md)); between them they deleted
three tickets (020, the development-license one, on 2026-09-09; 022, the
S3-surface one, with wave 2; and 014, the upload-checksum one, with wave 3).
**011, 013, 015, 016 and 024 are finished and awaiting deletion**, and the
work list in [023](023-major-v5.md) says what each still owes first; 010's
verdict — delete it, or state what is still wanted — is still open in that
list. [017](017-filename-encryption.md) and
[026](026-sse-c-passthrough.md) are unblocked, and their own status blocks still
say "blocked" and "after 013". Three files are not release work:
[025](025-tink-kms-hcvault.md), Vault as a key provider, parked by owner
decision; [027](027-whole-object-read-first-window.md), the evaluation of the
first read of a whole-object `GET`; and [029](029-multipart-idle-clock.md),
which the owner has decided not to schedule.

**The Velero e2e gate has run on the format**: 13 tests — the preflight plus the
twelve V1-V10 scenarios — green twice on 2026-09-11 after wave 4. **It has not
run since the audit wave of 2026-09-12**, which touched five product paths; that
run, and the integration, TLS and conformance suites with it, is owed before the
merge ([030](030-test-suite-audit.md)).

## Index

| Ticket | State | What it covers | Labels it carries |
|---|---|---|---|
| [010](010-performance-improvements.md) | **Complete (2026-04-25), verdict open in [023](023-major-v5.md)** | Streaming throughput, tiers 1 to 4.3: buffer pooling, allocation and log-level work on the GET path. It argues about a tree that no longer exists — the CTR path, whole-object HMAC and `processPartOrdered`. What is durable out of it is the measurement rule, which is already [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md); 010's numbers are history, not a baseline — [012](012-performance-audit-round2.md) says so itself and measures against `perf-baseline/` instead | — |
| [011](011-dek-cache-stale-on-reupload.md) | **Done, awaiting deletion** | The DEK cache returned the previous DEK after a re-upload of the same key. The cache key now includes the encrypted DEK (`buildDEKCacheKey`, [providers.go:345](../../internal/orchestration/providers.go#L345)), covered by [dek_cache_reupload_test.go](../../test/integration/360-degree-variants/dek_cache_reupload_test.go). Nothing durable is left in it: the rule is [ADR 0002](../adr/0002-one-data-key-per-object.md) and the regression is pinned by that test. The ticket file itself carries no status line | — |
| [012](012-performance-audit-round2.md) | Open (2026-09-10), **its own counts are behind the tree** | Round-2 performance audit after 010. Read its per-item table, not its summary: at least three of the items it counts as open have landed since, one of them in part — 1.2, the 30 s listener timeouts (N-8, [ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)); 2.1, the client-driven part the proxy can stream, now forwarded while it arrives ([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md) D1), while a short last part or an exit-provider part is still read whole; and 4.1, the bare backend `http.Transport`. What is certainly left is the five Tier 6 measurements. Everything it argued about the two-cipher tree is void: the stored format is one authenticated segment chain (ADR 0003) | — |
| [013](013-storage-format-v2.md) | **Done 2026-09-11, awaiting deletion** | Storage format v2: one segmented AES-256-GCM chain per object. The chain is live on every path and the format it replaced is out of the tree. Every row this ticket carried is closed — the write-side prefix refusal, the reserved trailer part number, `ListParts`, the sealed checksum on the read side, the configuration remainder, the performance after-column and the documentation. The forged pass-through fingerprint (its item 4b) is closed by the exit provider (ADR 0025). One question outlives it and is an ADR's, not a ticket's: [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D9's ranged-read request count | P-7; N-1, N-2, N-3, P-1 and P-2 closed with the format |
| [015](015-configuration-hygiene.md) | **Done 2026-09-11, deleted with the merge** | The dead knobs went with the deletion round (N-5) and every control it owed landed: `max_clock_skew_seconds` on both authentication forms, the pre-signed lifetime ceiling, the refusal to start on a plain-HTTP backend, the metadata-prefix shape, and an unknown configuration key refusing the start | P-11 |
| [016](016-helm-chart-fixes.md) | **Done 2026-09-11, awaiting deletion** | Chart: `checksum/config` rollout, TLS-aware probes, the two values files that failed `helm template`, and the CI that would have caught them — all twenty-one items done, plus the chart's own TLS listener ([ADR 0026](../adr/0026-the-proxy-terminates-tls-at-its-own-service.md)), which the ticket had put out of scope | P-10 |
| [017](017-filename-encryption.md) | Open, **unblocked 2026-09-10** | Filename encryption, directory segments only, leaf names in the clear, so prefix listings and exact lookups survive for every S3 client (kopia, the uploader Velero uses, relies on both). Both dependencies landed: the segment chain and the listing document, so `start-after`, `encoding-type` and a real `ListBucketResult` exist now. Its own status block still says "blocked" and still describes the SDK-struct listing — that paragraph is stale, and so is every `D-11` in it | the filename-encryption decision ([ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md)) |
| [018](018-listobjectsv2-document.md) | **Landed 2026-09-10**, one item left | A real `ListBucketResult` document, the dropped listing parameters, `max-keys` honoured or refused, `<Owner>` as the authenticated caller, `HeadBucket` as a real `HeadBucket`, and plaintext sizes computed from the stored size — all shipped ([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)); under the exit provider a listing reports the stored size ([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)). What remains is the listing benchmark; the Velero run went green on 2026-09-11 | P-4, closed with it |
| [019](019-handler-unit-coverage.md) | Open, **re-scoped 2026-09-10** | Was handler-level unit coverage; that landed with the pre-merge round and the format migration, so the ticket is now the suite's own quality: one shared backend mock, and the fact that the test tree is not linted at all. The four skips that asserted nothing are closed ([ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md) D4, 2026-09-12) | — |
| [021](021-relative-performance-thresholds.md) | Open, **rewritten 2026-09-09** | The threshold gate on the continuous-integration runner is cancelled, not deferred ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)): no performance number fails a build. The local baseline suite is built and has recorded the before-column the format change is judged against. What is left is five leftovers of the cancelled gate in continuous integration — the duplicated measurement run, the module-cache wipe, the un-paged listing in the comparison bucket's cleanup (the bucket itself is cleared now), the summary that is named for something it does not measure, and the rule that keeps the step from growing. The skip knobs and the dead threshold branch are gone ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) D11) | — |
| [023](023-major-v5.md) | Open, umbrella, **rewritten 2026-09-12** | The minimum scope of release 5.0.0: what it contains at least, in what order it lands, what the operator has to do, and the release-note skeleton. Carries no decisions of its own — every line points at the ADR that decided it. Waves 0 to 7 and the round after them are done; what it now carries is the follow-up before the merge, five items, the first being that the release job cannot build and so merging produces no tag. The five decisions the owner owed were taken on 2026-09-12 | — |
| [024](024-coverage-round-findings.md) | **Answered 2026-09-12, awaiting deletion** | The coverage round of 2026-09-06 and the defect list it produced. Wave 2 closed every open row but one: **S-3**, the unauthenticated monitoring listener. That is answered — [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) D11 is the rule, the owner decision of 2026-09-12 dropped `licensed_to` and `company` from the scrape and adds no `NetworkPolicy` as the answer (the chart's optional one stays off by default, `networkPolicy.enabled: false`, and the network boundary is the administrator's), and `SECURITY_ARCHITECTURE.md` states the posture. `ListParts` is named there for continuity and belongs to [013](013-storage-format-v2.md) | C-1, C-2, I-1, I-2, S-1 to S-6, A-1 to A-3, P-1 to P-3, X-1, X-2; the decisions it produced are ADRs now |
| [026](026-sse-c-passthrough.md) | Open, **additive since 2026-09-11** | SSE-C (customer-provided keys) forwarded on every verb — PUT, GET, ranged GET, HEAD, multipart create and parts — with the response echo, never logged or stored. Both preconditions are met: the format change removed the copy-source plumbing it would have owed, and the storage-header decision shipped, so the three customer-key headers are refused `501 NotImplemented` today ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D6). Until that refusal existed this ticket was a breaking change parked in an open ticket; it is now what it was written to be — lifting a refusal | — |
| [028](028-upload-and-read-performance-round.md) | Open, **work committed 2026-09-12** | The upload and read performance round after wave 7: the comparison stopped measuring its own harness, four costs came off the read and write paths, a client part is forwarded while it is received (ADR 0024 D1), and an upload that can no longer be finished is ended rather than abandoned (ADR 0028, ADR 0029). Its own status block still says nothing is committed; the work is on the branch and the file is deleted when 5.0.0 is cut | — |
| [029](029-multipart-idle-clock.md) | Open, **not scheduled (2026-09-12)** | The multipart idle clock moves only at part boundaries, so one part slower than `multipart_session_idle_timeout` is expired and ended at the backend while it is still arriving. Owner decision: rare enough to live with, and an operator can raise the timeout. The mitigation is usable now — a swept upload is logged at `Info` with the idle time, the configured timeout and the name of the knob. What is left is the real fix: an `atomic.Int64` clock the part body touches as bytes arrive | — |
| [025](025-tink-kms-hcvault.md) | Parked | Vault as a key provider: the five decisions still to make, the rotation findings worth keeping, and what must be verified against a running Vault before any code. Not in the next major release | — |
| [027](027-whole-object-read-first-window.md) | Open, **evaluation only (2026-09-11)** | How large the first read of a whole-object `GET` should be. The tail-first read of [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D14 costs a second backend request above 64 KiB. Five options are written down with what each costs; option C — issue the second request on the first answer's headers — shipped with [028](028-upload-and-read-performance-round.md), so the round trip now overlaps the first read and the 1.2 ms and 40 % this ticket measures predate it. The question, and the window, are unchanged. Explicitly **not** in 5.0.0 | — |
| [030](030-test-suite-audit.md) | Open, **every row worked (2026-09-12)** | The test suite read against what the product promises: 62 surviving findings, four of them mutation-proven to pass with the guard they exist for deleted. Five defects in the product came out of it, not in its tests. What is left before the file goes is the integration, TLS, conformance and Velero runs, because the wave touches paths every one of them exercises | — |
| [031](031-short-part-budget-starvation.md) | Open, **found 2026-09-12** | Since the global short-part bound of [ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md) D5 landed, one client-driven upload holding one part of `multipart_short_part_buffer_size` keeps every other upload in the process from holding its last part — `503 SlowDown` until that session ends, and the holder decides when. The cross-client consequence is recorded in no document | — |
| [033](033-out-of-band-recovery-path.md) | Open, **not scheduled (2026-09-12)** | A deliberate out-of-band tool that decrypts an object whose metadata or stored bytes are damaged, under the owner's explicit risk. The proxy must never do this — it may not serve an unauthenticated byte. Raised out of the discussion behind [ADR 0002](../adr/0002-one-data-key-per-object.md) D13; the requirement and what the format already gives it are recorded, the design is not started | — |

The `010-*` directories next to these files are the captured `top` output and
test logs ticket 010 was argued from (`010-baseline`, `010-tier1`,
`010-tier1.3`, `010-tier2`, `010-tier4.1`) — the profiles themselves were never
committed, only the tables read off them, and `010-tier1.3` and `010-tier4.1`
carry no README to say which run they are. They go with the ticket when it is
deleted; ticket 012 does not measure against them — it calls those numbers
history rather than a baseline and measures against `perf-baseline/` instead.

## What runs first

**Nothing is blocked any more (2026-09-10).** Ticket 013's format landed: the
GCM/CTR split, the separable HMAC metadata, the ordered multipart pipeline and the
post-Complete self-`CopyObject` are gone. 018 landed on top of it — the plaintext
size in a listing is arithmetic on the stored size — and the exit provider landed
beside it. That clears the last two waiting rooms: 017 waited for 013 *and* for the
listing document, and 026 waited for the self-copy to disappear. 019 was re-scoped
rather than started, because the coverage it asked for arrived by another route.
015 lost its deletion half to the same round. 016, 021 and 022 never depended on
anything.

Nothing is left in 013 but a decision: [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)
D9's ranged-read request count, which the ADR's own status block carries. One
backend request holds for an explicit `bytes=a-b`, not for a suffix or an
open-ended range, and what is missing is the decision, not the sentence.

The breaking tickets are collected on one branch and released together as one
major, now **5.0.0 on `feat/major-v5`**. [023](023-major-v5.md) is that release's
scope list: what it contains at least, what is still a candidate, and in what
order the work lands. Nothing is split off to `main` any more, 021 included: the
whole bundle is worked on the branch and merged once (recorded in
[023](023-major-v5.md), decided 2026-09-10).

## Label index

The labels come from the Velero round on `feat/velero-support-and-tests`
(2026-09-06): the e2e suite was built against real Velero in a kind cluster, and
building it turned up defects in the proxy, which were then swept for siblings
against a live demo stack. Four series came out of that work and the tickets cite
them by label — a fifth, `D-`, held the decisions and is gone
([below](#decisions--moved-to-docsadr)):

| Series | What it is |
|---|---|
| `N-` | A finding the threat model added — the backend is hostile, so what "integrity" means changed and new things became defects |
| `S-` | A finding of the pre-merge sweep over the proxy handlers, most of them reproduced by probe against a running stack |
| `P-` | A defect parked rather than fixed before merge, with enough detail to pick up without repeating the investigation |
| `F-` | A fix that landed on the branch. Closed history, listed so a label cited elsewhere resolves |

Priority marks in the `N-` series: **[S]** touches security, **[R]** touches the
release process, **[C]** cost or coverage only. The `D-` series is gone: decisions
live in [docs/adr/](../adr/).

**One word in these labels changed meaning on 2026-09-10: pass-through is no
longer a provider mode.** `type: "none"` is refused at startup by name
([config.go:760-764](../../internal/config/config.go#L760)) and the exit provider
replaced it ([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)): under `exit`
a read decides **per object** — one this proxy encrypted is still decrypted, one
it did not is delivered as stored — and under an encrypting provider a foreign
object is refused. No label below names the `none` provider; N-1 is the one whose
wording described that fail-open read path, and it is closed.

The working notes these labels were written in are gone; every label that still
means work is owned by a ticket, and the security findings are written out from
the operator side as `H-1` to `H-11` in
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

One of them is worth naming because ticket text still *schedules* against it.
**D-11 — the listing document and the plaintext size in a listing — is
[ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md), and it
landed on 2026-09-10** with [018](018-listobjectsv2-document.md) (`d696763`),
together with its parked twin P-4. Text that says work comes "after D-11" — the
seven occurrences in [017](017-filename-encryption.md) — is waiting for something
that has shipped.


### Threat-model findings N-1 to N-10

Found by re-reading the proxy against the orientation in
[SECURITY_ARCHITECTURE.md section 1](../../SECURITY_ARCHITECTURE.md#1-threat-model):
the backend is hostile, integrity means the proxy verifies, and a control that
exists only in configuration or documentation is worse than no control.

| # | Finding | Where it lives now |
|---|---|---|
| N-1 | [S] GET, HEAD and ranged GET fell back to pass-through when an object carried no `s3ep-*` metadata, **even under an encrypting provider**, so a backend that strips the metadata and replaces the body had its substitute delivered as plaintext. Decided: fail closed, no opt-out knob, pre-existing plaintext migrated once through the proxy | **Closed.** Fail-closed landed with the segment chain — a read of an object this proxy did not write answers `403 InvalidObjectState` ([operations.go:222-231](../../internal/proxy/handlers/object/operations.go#L222), [tail.go:81-88](../../internal/proxy/handlers/object/tail.go#L81), [range.go:287](../../internal/proxy/handlers/object/range.go#L287)) — and the last hole, a backend-supplied pass-through fingerprint, closed with the exit provider: `ExitProvider.DecryptDEK` returns an error and no fingerprint is special-cased on the read path ([providers.go:232-235](../../internal/orchestration/providers.go#L232)). [H-6](../../SECURITY_ARCHITECTURE.md#h-6-an-object-without-encryption-metadata-is-served-as-plaintext--closed) |
| N-2 | [S] `integrity_verification: hybrid` accepted an object whose `s3ep-hmac` the backend simply removed, and `lax` delivered data whose verification failed. It was to be dissolved by the new format, where integrity is not separable from decryption and the knob goes away | **Closed with the format.** The knob is gone: `git grep -n "integrity_verification\|IntegrityVerification" -- '*.go' ':!*_test.go'` is empty — the only hits left are in the unit test that asserts the key is refused by name at startup — and a segment that does not authenticate is never delivered ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)). [H-5](../../SECURITY_ARCHITECTURE.md#h-5-a-tampered-object-is-delivered-not-refused--closed) |
| N-3 | [S] Re-uploading a multipart part would encrypt at the same AES-CTR offset twice — a two-time pad. Latent at the time only because the retry hung instead (P-2) | **Obsolete.** AES-CTR is not in the production tree any more (`git grep -l "AESCTR\|aes-ctr" -- '*.go'` matches test files only); every segment carries its own nonce and tag ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)) |
| N-4 | [S] Velero creates its kopia repository with the published default password `static-passw0rd` unless `velero-repo-credentials` is set first, so kopia AES-GCM and its content HMACs are forgeable by anyone who can read the bucket. Velero's own objects are never encrypted by Velero at all | **Closed.** The README carries the warning and the command, [H-4](../../SECURITY_ARCHITECTURE.md#h-4-velero-kopia-repositories-default-to-a-published-password) states it from the operator side, and the other half landed too: `e2e-up.sh` generates `velero-repo-credentials` when it is absent, so the suite runs the documented configuration, and a subtest asserts the repository password is not the published default |
| N-5 | [S] Request rate limiting does not exist. `enable_rate_limiting`, `max_requests_per_minute`, `max_failed_attempts` and `unblock_ip_seconds` are parsed, validated and read by nothing; the failed-attempt map is keyed by an attacker-chosen `X-Forwarded-For` value and never expires. Decided: delete the knobs and the map, keep the security log line. Per-IP limiting is the wrong tool here anyway — any S3 client legitimately bursts from one address, Velero from one pod IP for example | **Closed** by the deletion round: `git grep -n "enable_rate_limiting\|max_requests_per_minute\|max_failed_attempts\|unblock_ip_seconds"` over the code and the shipped configuration is empty, and `S3SecurityConfig` keeps `max_clock_skew_seconds` and the pre-signed ceiling `max_presign_expiry_seconds`, nothing else ([config.go:68-79](../../internal/config/config.go#L68), [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) D9). Making the skew key reach the header-signed path too was item 2 of [015](015-configuration-hygiene.md), and it landed. [H-7](../../SECURITY_ARCHITECTURE.md#h-7-dead-security-configuration-knobs--closed) |
| N-6 | [S] Client checksums, four pieces. **(a)** A wrong `Content-MD5` was answered 200 on both the small-object and the auto-multipart path, so the integrity intent of every client that sent one was dropped, kopia's for every blob it writes — **closed 2026-09-11**: every declared checksum is verified against the plaintext (ADR 0012). **(b)** and **(c)** the client `Content-MD5` was forwarded with the *ciphertext* body on the streaming PUT and `UploadPart` paths — closed, F-20. **(d)** **Refuted**: no response path ever emitted an `x-amz-checksum-*` header. Responses are composed from an allowlist, and the backend client runs with `ResponseChecksumValidation = WhenRequired`; what was actually there was dead field copying, cut down in F-18. A refuted finding is a result — it is why the checksum decision lost its "strip backend checksum headers" half | (a) closed, ADR 0012; (b), (c) closed, F-20; (d) refuted |
| N-7 | [C] kopia sets `DisableMultipart: true` and writes every ~20 MiB pack blob as one PutObject, so under Velero the proxy auto-multipart path carries all kopia data and the client-driven multipart path is exercised only by Velero's own uploader; other S3 clients drive multipart themselves, so both paths carry production data. Context rather than a work item: it is one input to the weighting of P-2 and the part-size rule in v2 | Context for [013](013-storage-format-v2.md) |
| N-8 | [C] `ReadTimeout` and `WriteTimeout` were 30 s on the listener, so any transfer slower than that was killed — `velero backup download` of a large tarball over a slow link, or a node-agent upload moving less than one part per 30 s | **Closed 2026-09-11.** Both default to 0, Go's "no deadline"; a transfer is bounded by the client and by shutdown ([ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)). `read_header_timeout` and `idle_timeout` keep their own bounds and may not be 0 |
| N-9 | [S] A client that hung up mid-body made `io.ReadFull` return `io.ErrUnexpectedEOF`, which the producer loop read as a clean end of stream: the object was committed **short**, and because the HMAC covers what was actually uploaded, the truncated object then verified in `strict` mode on every later read. No adversary needed — a dropped connection or the 30 s timeout of N-8 is enough | Closed, F-24 |
| N-10 | [S] The Helm chart shipped a working AES-256 KEK as its default provider key, and `values-monitoring.yaml` a second one, so any `helm install` that did not override `config` encrypted every object with a key published in this repository. Both are to be treated as compromised wherever a deployment took the default | Closed, F-25; recorded in [SECURITY_ARCHITECTURE.md section 7.4](../../SECURITY_ARCHITECTURE.md#74-a-published-chart-default-that-was-a-working-key) |

### Sweep findings S-1 to S-15

A second pass over the proxy handlers, run against a live demo stack with the
AWS CLI as the probe. All but S-8 were fixed before merge, and S-8 closed with the storage-header
forwarding of [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) on 2026-09-11.

| # | Finding | Where it lives now |
|---|---|---|
| S-1, S-6 | [S] `DELETE /bucket?<any unrouted sub-resource>` deleted the whole bucket. A 13-entry denylist let every sub-resource without its own route fall through to the base operation for the method, so `delete-bucket-encryption` ran `handleDeleteBucket`, `put-bucket-encryption` ran `CreateBucket`, and `list-object-versions` answered an empty listing with 200. Reproduced end to end; it is also the shape Terraform sends on destroy. Unrecoverable data loss from one ordinary CLI call | Closed, F-11 |
| S-2 | [S] The encryption-metadata self-copy ran on the request context, so a disconnect between `CompleteMultipartUpload` and the copy left ciphertext in the bucket with no `s3ep-*` metadata — which N-1 then hands to the next reader as plaintext | Closed, F-14 |
| S-3 | [C] `InitiateMultipartUploadResult` was string-concatenated, so a key containing `&` or `<` produced a body the client cannot parse; the client retried, and every attempt leaked a real backend upload that can be neither completed nor aborted through the proxy | Closed, F-13 |
| S-4 | [S] The self-copy used `MetadataDirective: REPLACE` while restating nothing, so `Content-Type` and every entity header were destroyed on every object at or above 5 MiB — the whole kopia path. Not a header the proxy forgot to forward: one it set at `CreateMultipartUpload` and deleted again two calls later | Closed, F-16 |
| S-5 | [S] GET, HEAD and ranged GET dropped `versionId` as well, so a request naming one version was answered with the current object | Closed, F-15 |
| S-7 | [S] `PUT ?legal-hold` discarded the body and always sent `Status: ON`, so a client asking to **release** a hold applied one and was told it succeeded; `PUT ?retention` always sent `Governance` with no date; both GETs and `SelectObjectContent` answered 200 with an empty body | Closed, F-17 |
| S-8 | [S] PUT dropped `x-amz-server-side-encryption`, `x-amz-tagging`, `x-amz-storage-class`, `x-amz-acl` and the object-lock headers and answered 200 | **Closed 2026-09-11**: every one of them reaches the backend, SSE-C is refused by name ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D3, D6) |
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
| P-1 | Ranged reads cannot be verified against the whole-object HMAC; the option costed here was a per-segment or Merkle HMAC written at upload time | **Closed** by the segment chain, which is the per-segment option: a range opens only the segments its window covers, each under its own tag ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)); [H-1](../../SECURITY_ARCHITECTURE.md#h-1-ranged-reads-are-not-verified-by-the-proxy--closed) |
| P-2 | An `UploadPart` retry, or a part-number gap, blocked in `processPartOrdered` with no context case until the session aged out — confirmed by probe for a retried part 1, for part 3 without part 2, and for a cancelled caller. Every aws-sdk-go-v2 retry reuses the part number, so it was latent rather than absent | **Closed with the format**, which made the parts independent as planned: `git grep -n "processPartOrdered\|PendingParts" -- '*.go'` is empty, so there is no ordering left to block on. The remaining hits are in ticket text, the `010-*` capture directories and the committed knowledge graph under `graphify-out/`, which clears on the next rebuild |
| P-3 | `UploadPartCopy` was shadowed by the plain `UploadPart` route, so a copy request was handled as a part upload of an empty body and answered 200 | Closed, F-12 |
| P-4 | `ListObjectsV2` drops `start-after`, `fetch-owner` and `encoding-type`, silently ignores an out-of-range `max-keys`, XML-encodes the raw SDK struct as `<ListObjectsV2Output>`, and reports the ciphertext size; `handleHeadBucket` is a `ListObjectsV2(MaxKeys=0)` without `x-amz-bucket-region` | **Closed 2026-09-10** by the listing rewrite (`d696763`, [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)): the three parameters are forwarded, `max-keys` is honoured, clamped or refused with `400 InvalidArgument`, the body is a real `ListBucketResult` ([listing_document.go:31](../../internal/proxy/handlers/bucket/listing_document.go#L31)), `<Size>` is the plaintext length, and `handleHeadBucket` calls the backend's `HeadBucket` and sets `x-amz-bucket-region` ([operations.go:124-155](../../internal/proxy/handlers/bucket/operations.go#L124)). The listing benchmark left in [018](018-listobjectsv2-document.md) is not this item |
| P-5 | Three handlers read the body raw instead of through `Parser.ReadBody` — `handleDeleteObjects`, `CompleteHandler` and `handleCreateBucket` — so a trailer-framed body would break them. The `html.UnescapeString` half of the item, which turned escaped markup in a Complete body into real markup, is closed with F-13 | **Closed 2026-09-11**: all three read through the parser (ADR 0012) |
| P-6 | Response XML built by string concatenation with unescaped input, in four places; two of them reflected attacker-controlled text (the attempted access key id, the raw request URL). Escaping alone would not have been enough — the old code used `html.EscapeString`, which passes control characters through | Closed, F-13, including the two sites the item missed (S-3, S-14) |
| P-7 | `ListParts` returned a fabricated empty `<ListPartsResult>` at 200, so a client verifying an upload was told it had zero parts; `ListMultipartUploads` was 501 | **Closed 2026-09-11**, item 10 of [013](013-storage-format-v2.md): `ListParts` is answered from the session part table, `ListMultipartUploads` is forwarded |
| P-8 | The multipart abort ran on the already-cancelled request context, so the abort caused by a client disconnect could never reach the backend and the upload was orphaned | Closed, F-14. Two corrections to the item: the third abort site is `multipart/create.go`, not `complete.go`, and the self-copies (S-2) mattered more than the aborts |
| P-9 | `DeleteObject` built its input without `VersionId`, so on a versioned bucket `velero backup delete` left every version behind | Closed, F-15, together with the GET, HEAD and ranged-GET siblings S-5 named |
| P-10 | The chart has no `checksum/config` pod annotation, so `helm upgrade` with a changed config updates the ConfigMap without rolling the pods. Plus five related chart items found while wiring the e2e: two values files that fail `helm template`, probes that ignore `tls.enabled`, an unmounted cert-manager `Certificate`, a `Service` with no `nodePort`, and a stale helm-unittest file nothing runs | [016](016-helm-chart-fixes.md), all six items |
| P-11 | A plain-HTTP backend cannot take a streaming upload: aws-sdk-go-v2 signs by hashing the body, which needs a seekable stream, and only accepts `UNSIGNED-PAYLOAD` over TLS. Nothing in the repository says so, because every example config uses TLS | [015](015-configuration-hygiene.md), as the plain-HTTP refusal (ADR 0013) |
| P-12 | The test CA private key is committed | Closed, F-22 |
| P-13 | The aws-chunked checksum trailer is parsed and discarded, although the decoder already reads the trailer block. Verifying it would have caught the framing bug F-1 at upload time instead of at the next read | **Closed 2026-09-11**: the trailer is captured and verified (ADR 0012) |

### Fixes F-1 to F-25

Closed history, and the reason several things in the code look the way they do.
F-1 to F-10 landed earlier on `feat/velero-support-and-tests`; F-11 to F-21,
F-23 and F-24 landed together, and F-22 and F-25 with them. **The hashes are not
quoted any more: that branch is gone and none of them resolves in this
repository.** After the last of them: unit suite, integration suite against both
the HTTP and the TLS proxy endpoint, all 13 Velero e2e tests — the preflight and
the twelve V1-V10 scenarios — in a kind cluster, and `make lint` green
(2026-09-06).

Four of them were additionally re-probed by hand over the wire that day, against
the running demo stack rather than against a mock: `delete-bucket-encryption`
answered `501` and the bucket survived (F-11); an 8 MiB PUT kept `Content-Type`,
`Cache-Control` and `Content-Disposition`, and its ETag still matched the
following HEAD (F-16); `?attributes` and `put-object-legal-hold` answered `501`
(F-17); and a GET response carried no `x-amz-checksum-*` header (the N-6 (d)
refutation). Those were one-off manual probes. Automated tests repeat them since 2026-09-11:
the entity headers and the PUT/HEAD ETag are asserted on every upload path,
including one above `streaming_segment_size`, and the object sub-resource
refusals over the wire.

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
| F-16 | The metadata self-copy no longer destroys the entity headers or the ETag (S-4, S-10); the auto-multipart path restates them from the request, the client-driven path reads them back with a `HeadObject`. The self-copy itself is gone with the segment chain — do not go looking for it |
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
unformatted file. Three leftovers of that repair — the `make tools`
install path, the unguarded `gofmt` in `make static`, and the `quality` target
ordering — are closed as of 2026-09-11.
