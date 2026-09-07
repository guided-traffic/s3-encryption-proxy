# Major release 5.0.0 — the minimum scope

Work list for the next major release. It says what 5.0.0 contains **at least**, in
what order it lands, and what the operator has to do. The decisions behind every
line live in [docs/adr/](../adr/); this file adds no decisions of its own.

More may join the release when it makes sense. What must not join it is anything
that does not need it.

## Why 5 and not 4

`v4.0.0` was released on 2026-09-07 without this bundle: a pull request was merged
with a merge commit, the release automation saw the two honestly marked breaking
commits inside it, and cut a major nobody had planned. Nothing of the bundle is in
it. The current line is 4.0.x, the bundle is 5.0.0, and objects written by 3.x and
by 4.0.x are equally unreadable under the new format.

The guard that stops this happening again is [ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md):
a check on every pull request into `main` that fails on a breaking commit unless
the pull request carries the `release:major` label. **It lands on `main` before
the bundle branch forks.**

## Branch

`feat/major-v5`, forked from `main` at or after `ed2e964`. Not from the Velero
branch — that work is already in `main`, squashed, and the branch is not an
ancestor of it.

One pull request per unit of work into the bundle branch, squash-merged. Breaking
markers are used freely there; nothing releases from that branch. Rebase onto
`main` whenever `main` moves; the end-to-end suite is the gate on every rebase.
The final pull request into `main` carries the `release:major` label, and the
computed version is checked before the merge button.

## The minimum

Every row forces an operator to do something, or changes an answer a client gets.

| What ships | Decision | What the operator does |
|---|---|---|
| The segmented AES-256-GCM storage format | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Re-upload every object through the new proxy. There is no migration and no read path for the old format |
| `encryption.integrity_verification` and `optimizations.streaming_threshold` removed; `streaming_segment_size` must be a multiple of 64 KiB | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Drop the two keys; check the segment size or the proxy will not start |
| One local key provider: the `rsa` provider type is gone, `aes_key` must be base64 of 32 random bytes, the wrap becomes authenticated and the fingerprint derived | [ADR 0004](../adr/0004-one-local-key-provider.md) | Move any `rsa` provider to `aes` before re-uploading. Replace a key that is not 32 random bytes — including one delivered through `${S3EP_AES_KEY}`, which nothing in this repository can be grepped for |
| Client metadata inside the configured prefix is refused with `InvalidArgument` | [ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md) | Stop writing user metadata into the `s3ep-` namespace |
| The dead `s3_security` keys, `s3_backend.use_tls`, `clean_http_transfer_chunked` and the legacy top-level backend block are deleted; a plain-HTTP backend under an encrypting provider and a scheme-less endpoint refuse to start; the pre-signed ceiling drops to one hour; the configured clock skew applies to both authentication forms | [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md), [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) | Drop the keys from the configuration and the deployment values; switch the backend endpoint to `https://`; set `max_presign_expiry_seconds` if URLs above one hour are in use; check client clocks |
| The whole-request and whole-response wall clocks go; `shutdown_timeout` becomes the transfer budget and the chart derives its grace period from it | [ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) | Nothing, unless a deployment relied on a transfer being killed at 30 s |
| Storage headers on `PUT` are forwarded instead of silently dropped; the tagging, retention and legal-hold sub-resources become pass-through; `PUT ?acl` and `PUT ?cors` carry their documents to the backend; SSE-C is refused with a named error | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | Check that a client which sets these headers meant them: they now take effect on the backend object |
| The location element of a completed multipart upload honours `X-Forwarded-Proto` and `X-Forwarded-Host` | [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) | Nothing |
| The example configurations and the end-to-end values lose their literal keys; keys are generated at bring-up | [ADR 0021](../adr/0021-key-material-is-generated-never-committed.md) | Export the key variables, or run the bring-up script |
| `GOMEMLIMIT` ships in the chart and in compose | [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) | Re-size the pod limits if the deployment overrides them |

## Also in, and what stays out

Each of these changes an answer a client gets, so by the rule of
[ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) each belongs in
a major. Which major was left to judgement; the calls are below.

**In**, because the alternative is writing their tests twice or shipping a second
set of behaviour changes weeks later:

| Also in | Decision | Why here |
|---|---|---|
| Upload checksum verification ([014](014-upload-checksum-verification.md)) | [ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md) | Its tests are written against configuration keys the format change deletes; on the current line they would be written twice |
| The listing document and plaintext sizes ([018](018-listobjectsv2-document.md)) | [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md) | The plaintext size is only a pure function of the stored size under the new format; the document rewrite touches the same responses and lands as one change |
| Conditional request headers on writes and reads ([019](019-handler-unit-coverage.md) item 12) | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | A silent overwrite becoming a `412` is a behaviour change; it is blocked on the format change anyway |

**Out**, each for its own reason:

| Out | Where instead | Why |
|---|---|---|
| The Helm chart round ([016](016-helm-chart-fixes.md)) | `main`, now | It closes a live deployment defect and gives continuous integration a render of the values files this release edits. Squash-merged under a non-breaking title |
| Filename encryption ([017](017-filename-encryption.md)) | A later release | Depends on the listing work and on a client-behaviour check that has not started. Enabling it later is a rename pass, not a re-encryption, so it costs an operator nothing to wait |
| Vault as a key provider ([025](025-tink-kms-hcvault.md)) | A later release | Parked: its own five decisions are deferred and recorded on the ticket. Purely additive, and with the local provider kept there is no gap at 5.0.0 |
| SSE-C on every verb ([026](026-sse-c-passthrough.md)) | A later release | Purely additive: a request that answers `501` today starts working |

## Order

1. **On `main`, before or beside the branch:** the release guard, the Helm chart
   round, the metadata-prefix case fix, the pooled copy on the ranged read, the
   license reissue ([020](020-dev-license-expiry.md)), the performance baseline
   ([021](021-relative-performance-thresholds.md)) with pre-release numbers.
2. **[013](013-storage-format-v2.md)** first on the branch — it deletes the code
   the others would otherwise be written against, and it is the largest change.
3. **[015](015-configuration-hygiene.md)** — after 013, so the example
   configurations and values files are edited once for both.
4. The client-visible corrections, in dependency order.
5. **[022](022-s3-surface-fidelity.md)** — the storage headers and the location
   element.
6. The runtime memory limit last: the memory test of 013 is re-run under it, and
   if it shows no gain the value is dropped before the merge.

## Release notes — skeleton

Filled as each unit closes. Under a `BREAKING CHANGE:` footer.

**Stored data.** Objects written by 3.x and 4.0.x are not readable. Re-upload them
through the new proxy; there is no in-place migration. `s3ep-aes-iv` and
`s3ep-hmac` are no longer written, `s3ep-dek-algorithm` is `s3ep-gcm-seg-v2`, and
`s3ep-kek-fingerprint` values change.

**Configuration — removed.** `encryption.integrity_verification`,
`optimizations.streaming_threshold`, `optimizations.clean_http_transfer_chunked`,
`s3_backend.use_tls`, the dead `s3_security` keys, the legacy top-level backend
block, and the `rsa` provider type.

**Configuration — refuses to start.** A segment size that is not a multiple of
65536; a backend endpoint without a scheme, or `http://` under an encrypting
provider; an `aes_key` that is not base64 of 32 random bytes; a provider of type
`rsa`.

**Behaviour.** Whole-object `GET` and `HEAD` answer with an
`x-amz-checksum-crc32c` over the plaintext, recorded at upload;
`InvalidObjectState` for objects the proxy did not write;
`InvalidPart` for unaligned client multipart; `InvalidArgument` for client
metadata inside the proxy prefix; pre-signed URLs above the configured ceiling
refused; the configured clock skew applied to header authentication; storage
headers forwarded; SSE-C refused; no wall clock on a transfer.

**Deployment.** Values files lose the removed keys; pods carry `GOMEMLIMIT` and a
termination grace period derived from `shutdown_timeout`.

**Migration.** Stop writers, upgrade, re-upload, verify a sample by SHA-256,
resume. An `rsa` deployment configures an `aes` key first.

## Done when

- [ ] Every row of "the minimum" is closed on the branch, and every candidate is
      either closed there or moved out with a line saying why.
- [ ] On the branch head: `make test-unit`, `make test-integration`,
      `make test-integration-tls`, `make e2e-up && make test-e2e-velero` green.
- [ ] **Upgrade rehearsal**, documented here once: a 4.0.x stack with objects in
      the backend, upgraded in place; a read of an old object answers
      `InvalidObjectState`; re-upload; the round trip matches by SHA-256.
- [ ] `grep -rn` for every removed key and for `type: "rsa"` returns only
      `CHANGELOG.md`.
- [ ] The final pull request carries the `release:major` label and the computed
      version is verified as `5.0.0` before the merge.
- [ ] Every ADR this release touches has its `Status` updated from "decided, not
      implemented" to what actually shipped, in the same pull request.
- [ ] Each ticket listed here is **deleted** when its work lands, and
      `git grep` shows nothing outside `docs/tickets/` referencing it.
