# Ticket 023: Major release v4 — the breaking-change bundle

## Status (2026-09-06)

**Open. Umbrella ticket, no code of its own.** The current release line is
3.8.x (`v3.8.55`, 2026-09-05, semantic-release from `main`). The owner decided
on 2026-09-06 that storage format v2 ([ticket 013](013-storage-format-v2.md))
ships without a migration path, as a major release whose notes state the
incompatibility. Once one release forces every operator to re-upload their
objects and touch their configuration, every other change that forces the same
kind of work belongs in that release and not in the minor after it. This ticket
names those changes, names the candidates that should ride along, names what
stays out, and fixes the branch on which all of it is collected.

The inventory below comes from a sweep of tickets 012 and 014–022 on
2026-09-06, every hit verified at the cited ticket line. What "breaking" means
here: an upgrade makes stored data unreadable, makes an existing configuration
or Helm values file stop loading or change behaviour, or makes an S3 request
that succeeds today fail. Correctness fixes are still breaking under that
definition when a client can observe them; they are listed as candidates, not
members.

---

## Branch strategy

**Every member ticket is developed against `feat/major-v4` and merged there,
not into `main`.** `main` keeps releasing 3.8.x patches (dependency bumps,
fixes that do not break) for as long as the bundle takes.

- `feat/major-v4` is created from the head of `feat/velero-support-and-tests`,
  which is 16 commits ahead of `origin/main` today and carries the pre-merge
  fixes 013 assumes. If the Velero branch merges into `main` first,
  `feat/major-v4` is rebased onto `main` at that point; either way the base is
  the Velero work, never a `main` that lacks it.
- Each member ticket is its own PR into `feat/major-v4`, squash-merged with a
  conventional-commit title, so the branch history is one commit per ticket
  and a ticket can be reverted alone.
- `feat/major-v4` is rebased onto `main` whenever `main` moves (Renovate bumps
  land there continuously). The Velero e2e suite is the gate on every rebase,
  as it is on every ticket: `make e2e-up && make test-e2e-velero`.
- **The final merge into `main` is what cuts 4.0.0, and only if the commit
  says so.** `.releaserc` maps `feat!` / `fix!` and any `BREAKING CHANGE:`
  footer to a major release; a plain `feat:` cuts a minor. The squash commit of
  the final PR takes its message from the PR title and body, so the PR title is
  `feat!: ...` and the PR body carries a `BREAKING CHANGE:` footer with the
  release-notes list below. Verify the computed version before merging; a
  `4.0.0` that comes out as `3.9.0` cannot be taken back once tagged.

---

## Members — must ship in v4

Each of these forces an operator to do something at upgrade time. That is the
membership test.

| Ticket | What forces the migration | What the operator does |
|---|---|---|
| **[013](013-storage-format-v2.md)** storage format v2, including the RSA fingerprint fix moved in from 022 item 8 | Objects written by 3.x are not readable; `aes-iv` and `hmac` leave the metadata, `kek-fingerprint` values change for `aes` and `rsa`; `encryption.integrity_verification` and `optimizations.streaming_threshold` are removed; `streaming_segment_size` must be a multiple of 64 KiB or the proxy does not start; foreign objects answer `InvalidObjectState` 403; client-driven multipart needs aligned part sizes | Re-upload every object through the new proxy; drop the two keys; check `streaming_segment_size` |
| **[015](015-configuration-hygiene.md)** configuration hygiene | Seven keys removed (`s3_backend.use_tls`, six under `s3_security`); **the proxy refuses to start** on a plain-`http://` backend under an encrypting provider and on a scheme-less `target_endpoint`; pre-signed URL ceiling drops from 7 days to 3600 s by default; `max_clock_skew_seconds` (300 s in every shipped config) is honoured on the header-auth path, which today uses a 900 s constant. E-3, the default of `integrity_verification`, is moot once 013 deletes the key | Switch the backend endpoint to `https://` or the provider to `none`; drop the keys from config and Helm values; set `max_presign_expiry_seconds` if URLs above one hour are in use; check clock sync on clients between 300 s and 900 s off |
| **[012](012-performance-audit-round2.md)** items 4.3, 6.1, 6.5 — the surviving config-facing remnants | 4.3 sets `GOMEMLIMIT`/`GOGC`/`GOMAXPROCS` in compose and the chart and raises steady-state RSS by design (~110 → 300–400 MiB per the ticket) against a chart that ships a 512 Mi limit; 6.1 removes `use_tls` (done by 015 D-6, listed here so it is not done twice); 6.5 changes the shipped defaults of `streaming_segment_size` and `multipart_upload_concurrency` from the sweep | Re-size pod limits; re-read the defaults. **Conditional membership:** only what is done inside the collection window ships; 6.5 depends on numbers that [021](021-relative-performance-thresholds.md) re-picks after v2 |
| **[022](022-s3-surface-fidelity.md)** item 5 — key material in the example configs | Replacing the literal KEK and the RSA private keys with `${ENV}` references makes `config/*-example.yaml` fail to load unless the variables are exported, and the demo stack stops working from a clean clone | Export the variables or generate fixtures. **Conditional:** the ticket says not to implement before the owner decides between its three options |

---

## Candidates — should ride v4

Each changes an answer an S3 client gets today. None forces a migration, but a
client that matched on the old answer breaks, so by the letter each is a major.
Bundling them puts every behaviour change into one set of release notes instead
of scattering "acceptable behaviour change, note in changelog" across the 4.x
minors.

| Ticket | What a client sees change | Dependency on 013 |
|---|---|---|
| **[014](014-upload-checksum-verification.md)** upload checksum verification | `x-amz-checksum-*` is verified unconditionally: a mismatch answers `400 BadDigest`, a trailer named in `X-Amz-Trailer` that never arrives is a failure; `CreateBucket` with a malformed non-empty body answers `MalformedXML`; digest failures on the PUT routes move from 500 to 400 with a proper error document | None; sequenced after 013 to avoid rewriting handler tests twice |
| **[018](018-listobjectsv2-document.md)** `ListObjectsV2` document | `<Size>` becomes the plaintext size, so `aws s3 sync` and rclone re-transfer once; the document root becomes `ListBucketResult` with the S3 namespace; invalid `max-keys` answers 400 and values above 1000 are clamped; `HeadBucket` is a real `HeadBucket`, so a backend policy granting only `s3:ListBucket` starts failing the existence check | The size half needs v2's pure size function; the rest is independent |
| **[019](019-handler-unit-coverage.md)** item 12 only | `If-Match` / `If-None-Match` are forwarded on PUT, Complete and HEAD; `If-None-Match: *` on an existing key answers 412 instead of silently overwriting | Blocked on 013 like the rest of 019; item 12 is the only production change in it |
| **[022](022-s3-surface-fidelity.md)** items 1 (S-8) and 4 | Storage headers PUT drops today are refused or forwarded per header — refusing breaks a Velero BSL that sets `serverSideEncryption` or `tagging`, forwarding writes tags in plaintext onto the ciphertext object; `<Location>` in `CompleteMultipartUploadResult` is rebuilt, configured or dropped | None; both need an owner decision first |
| **[012](012-performance-audit-round2.md)** item 1.2 / N-8 | The blanket 30 s `ReadTimeout`/`WriteTimeout` go; transfers above 30 s stop being killed (a fix), and an in-flight transfer now outlives the 30 s shutdown grace and is hard-closed on exit (a change) | None |
| **[016](016-helm-chart-fixes.md)** Helm chart | `checksum/config` rolls the pods once on the first upgrade and on every config change after; the chart fails to render on an unparseable `config` or on a `Certificate` no ingress consumes | None. A candidate because 015 already makes every operator edit their values file |

---

## Not in v4

- **[017](017-filename-encryption.md)** — opt-in behind a flag that defaults to
  off; enabling it is a bucket-wide rename, not a re-encryption. Scheduled after
  013 and after 018 by its own text. Own release.
- **[020](020-dev-license-expiry.md)** — touches no format, handler or config
  schema, and its deadline (2026-10-05) is earlier than this bundle can be.
  Lands on `main`, must not wait for v4.
- **[021](021-relative-performance-thresholds.md)** — test harness only; lands
  on `main` before 013 per its own plan, and re-picks its numbers as the
  closing step of v2. The one interface it touches, the summary strings the
  badge scrapes, is a report string, not a proxy surface.

---

## Decisions needed before `feat/major-v4` merges

| Decision | Ticket | Why it gates the merge |
|---|---|---|
| Storage headers, per header: refuse or forward | 022 item 1 (S-8) | Both branches break something; the release notes have to name which |
| `<Location>`: forwarded headers, a config key, or drop the element | 022 item 4 | Option 2 adds a config key, option 3 removes a response field |
| Example configs: env-var references, keep, or RSA-only | 022 item 5 | Decides whether 022 item 5 is a member at all |
| Ship `GOMEMLIMIT` / `GOGC` in the chart, or not | 012 item 4.3 | Raises the memory floor of every deployment; the Helm limits move with it |
| Keep 016 in the bundle or release it on `main` | 016 | The chart can go either way; the answer decides where its PR targets |

`use_tls` (012 item 6.1) is decided by 015 D-6: delete. Nothing to decide.

---

## Order of work on the branch

1. **013** first — it deletes the code that 014, 018 and 019 would otherwise
   be written against, and it is the largest change. Its own work breakdown
   and performance gate apply unchanged.
2. **015** — after 013 so the example configs and values files are edited once
   for both. 015's own text allows it to go first if 013 slips.
3. **018**, then **014**, then **019 item 12** — the client-visible corrections,
   in dependency order (018's size half needs 013's size function; 014 and 019
   reuse 013's handler layout).
4. **022** — once the three decisions above exist. Item 5 is config only and
   can go earlier if decided earlier.
5. **012 remnants** — 4.3 last, because the RSS bound in 013's memory test has
   to be re-run under the new `GOMEMLIMIT`, and the test, not a manual number,
   is what the ticket demands.
6. **016** at any point, if it stays in the bundle.

---

## Release notes for 4.0.0 — skeleton

The final PR body carries this under a `BREAKING CHANGE:` footer. Each line is
owned by the ticket in brackets and is filled in when that ticket closes.

**Stored data**

- Objects written by 3.x are not readable by 4.x. Re-upload them through the
  new proxy; there is no in-place migration. [013]
- `s3ep-aes-iv` and `s3ep-hmac` are no longer written; `s3ep-dek-algorithm` is
  `s3ep-gcm-seg-v2`; `s3ep-kek-fingerprint` values change for `aes` and `rsa`
  providers. [013]

**Configuration — removed keys**

- `encryption.integrity_verification`, `optimizations.streaming_threshold`
  [013]; `s3_backend.use_tls`, `s3_security.enable_rate_limiting`,
  `.max_requests_per_minute`, `.max_failed_attempts`, `.unblock_ip_seconds`,
  `.strict_signature_validation`, `.enable_security_logging` [015].

**Configuration — the proxy refuses to start when**

- `optimizations.streaming_segment_size` is not a multiple of 65536 [013];
- `s3_backend.target_endpoint` has no scheme, or is `http://` while the active
  provider encrypts [015].

**Behaviour**

- `InvalidObjectState` 403 for objects the proxy did not write [013];
  `InvalidPart` at Complete for client-driven multipart with unequal or
  unaligned parts; 9999 usable parts [013].
- Pre-signed URLs above `max_presign_expiry_seconds` (default 3600 s) are
  refused; `max_clock_skew_seconds` applies to header authentication [015].
- Candidates, if bundled: `BadDigest` / `MalformedXML` [014]; plaintext sizes
  and the `ListBucketResult` document, `max-keys` validation, real
  `HeadBucket` [018]; 412 on conditional PUT [019]; storage headers and
  `<Location>` [022]; timeouts [012].

**Helm**

- Values files lose `use_tls` and the `s3_security` block [015]; if 012 4.3
  ships, pods carry `GOMEMLIMIT`/`GOGC` and need the limits the chart ships.

**Migration steps**, numbered, written once the members are closed: stop
writers, upgrade, re-upload, verify by SHA-256 over a sample, resume.

---

## Success criteria

- [ ] Every member ticket is closed on `feat/major-v4`; every candidate is
      either closed there or explicitly moved to "Not in v4" with a line
      saying why.
- [ ] The five decisions above are recorded in their tickets.
- [ ] On the branch head: `make test-unit`, `make test-integration`,
      `make test-integration-tls`, `make e2e-up && make test-e2e-velero` green.
- [ ] **Upgrade rehearsal**, once, documented here: a 3.8.x demo stack with
      objects in MinIO, upgraded in place to the branch build; GET on an old
      object answers `InvalidObjectState` 403 (proof that the notes say what
      happens), re-upload through the new proxy, GET matches by SHA-256.
- [ ] `grep -rn` over the tree for every removed key returns only
      `CHANGELOG.md` and `docs/tickets/`.
- [ ] The final PR title is `feat!: ...`, the body carries the
      `BREAKING CHANGE:` footer with the list above, and the computed next
      version is verified as `4.0.0` before the merge button is pressed.
- [ ] The four stale ticket spots below are corrected before their tickets
      are worked, so nobody implements a change the tree already has.

---

## Stale spots found by the sweep (2026-09-06)

Tickets that describe the tree as it was before the pre-merge round; each is
already shipped and the ticket text has to say so:

- [016](016-helm-chart-fixes.md) item 2b — the default `aes_key` in
  `values.yaml` is already `${S3EP_AES_KEY}` (F-25 / N-10).
- [018](018-listobjectsv2-document.md) item 6 — `ListBuckets` errors already go
  through `response.ErrorWriter` (F-23); the `http.Error` it cites is gone.
- [014](014-upload-checksum-verification.md) item 4 — `html.UnescapeString` in
  `CompleteMultipartUpload` is already deleted (F-13).
- [012](012-performance-audit-round2.md) item 2.2 still lists "remove
  `clean_http_transfer_chunked`", but the key is read at
  [parser.go:56](../../internal/proxy/request/parser.go#L56) and set to `false`
  in `test/e2e/velero/values-proxy.yaml`. Either the checkbox is wrong or the
  removal is one more config break that belongs in the list above — to be
  settled when 012 is next touched.
