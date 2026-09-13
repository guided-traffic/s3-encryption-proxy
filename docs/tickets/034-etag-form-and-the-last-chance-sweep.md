# 034 — The last-chance sweep: what only a major can change, and one read without a bound

Raised 2026-09-13 out of the question *what else has to be in 5.0.0 so that the
next major is years away, not months*. For the open tickets the answer is
**nothing**: [017](017-filename-encryption.md) is opt-in and changes no stored
byte and no associated data (ADR 0023 D1); [026](026-sse-c-passthrough.md)
lifts a `501`; [025](025-tink-kms-hcvault.md) adds a provider type and keys
beside the existing ones, and its one chart item — the cloud-KMS values — is
already gone from `values.yaml`; 027, 029 and 033 are an evaluation, a
loosening and a tool. Each was verified against the tree, not read off its
status block.

What the sweep found instead sits outside every ticket: one defect that has to
land in 5.0.0, one client-visible change that only a major can carry and whose
decision waits for evidence that has to be built first, and six decisions that
can only be taken in a major, because the rule that binds them is the project's
own — a change to an answer a client gets
carries the breaking marker (ADR 0018 D5), and a key or value that used to be
accepted and is refused from now on is a startup break (ADR 0013 D11, ADR 0017
D7 and D8). Whatever is not decided here waits for 6.0.0, which is unscheduled.

**Owner decisions, 2026-09-13.** Item 2 is in 5.0.0. Item 1 is **not decided**:
the owner accepts `-0` as the marker *if* the entity tag changes, and decides
whether it does only on the evidence of two end-to-end suites — one for rclone,
one for s3cmd — that do not exist yet and are built first. Ad-hoc probes, the
ones recorded below included, are how the finding was made; they are not what a
release stands on (ADR 0006 D5 and D7, ADR 0019 D1). Items 3 to 8 are recorded
with a recommendation and what each answer costs; they are decided in
discussion, not by this file.

---

## 1. The entity tag is an MD5 of the ciphertext in the shape of a content digest — **not decided; two end-to-end suites first**

### What happens

The proxy answers the backend's ETag verbatim. For an object written by a
single-request `PUT` — everything up to `optimizations.streaming_segment_size`,
12 MB by default — that is the backend's MD5 of the **stored** bytes: 32
lower-case hex digits in quotes, exactly the shape S3 gives the content digest
of an unencrypted single-part object. Every S3 client that verifies its uploads
compares that value with the MD5 of the file it sent, and the two never agree.

Read-proven, every site that answers an object-level ETag:

| Site | Verb |
|---|---|
| [operations.go:480](../../internal/proxy/handlers/object/operations.go#L480) | `PUT`, single request |
| [operations.go:1221](../../internal/proxy/handlers/object/operations.go#L1221) | `PUT` through the internal producer — already `<hex>-N`, see below |
| [operations.go:136](../../internal/proxy/handlers/object/operations.go#L136), [:205](../../internal/proxy/handlers/object/operations.go#L205), [:280](../../internal/proxy/handlers/object/operations.go#L280) | whole-object `GET`: both halves of the tail-first read, and the exit pass-through |
| [range.go:468](../../internal/proxy/handlers/object/range.go#L468) | ranged `GET` |
| [operations.go:610](../../internal/proxy/handlers/object/operations.go#L610) | `HEAD` |
| [complete.go:293](../../internal/proxy/handlers/multipart/complete.go#L293), [:304](../../internal/proxy/handlers/multipart/complete.go#L304) | `CompleteMultipartUpload`, header and document — already `<hex>-N` |
| [listing.go:129](../../internal/proxy/handlers/bucket/listing.go#L129), [:203](../../internal/proxy/handlers/bucket/listing.go#L203) | `<ETag>` in both listing versions |

**How the finding was made, and what that is worth.** Two ad-hoc probes on
2026-09-13 against the running demo stack, rclone v1.75.1 from its official
image. They are recorded because they are what turned a documented deviation
into a defect; they are **not** the evidence a release decision stands on — a
claim about a client rests on a suite that exercises it (ADR 0006 D5 and D7,
ADR 0019 D1), and that is what the section *Before anything is decided* below
builds.

A 1 MiB file, single-part, `rclone copy` with defaults:

```
DEBUG : etag-probe.bin: md5 = f43d49c42752b5de87469b481551a25d (Local file system at /data)
DEBUG : etag-probe.bin: md5 = 2c52a8e3b689c5ea7f55444e2000b35a (S3 bucket rclone-etag-probe)
ERROR : etag-probe.bin: corrupted on transfer: md5 hashes differ src(Local file system at /data) "f43d49c4…" vs dst(S3 bucket rclone-etag-probe) "2c52a8e3…"
INFO  : etag-probe.bin: Removing failed copy
```

rclone deletes the object it just uploaded and the transfer fails. Its
documentation says why, and that nothing on the proxy's side can tell it
otherwise: *"For small objects which weren't uploaded as multipart uploads
rclone uses the `ETag:` header as an MD5 checksum"*, and *"rclone will check that
the checksums of transferred files match, and give an error 'corrupted on
transfer' if they don't."* The escapes are all on rclone's side: the global
`--ignore-checksum`, which also switches off the check against real corruption,
and an internal `etagIsNotMD5` flag that its source sets only from rclone's
**own** SSE-KMS or SSE-C configuration, a provider quirk table, or a directory
bucket. Its binary carries `^[0-9a-f]{32}$` as the test for an MD5-shaped ETag.
A client that does not know it is being encrypted cannot know its ETag is not a
digest.

A 12 MiB file in 5 MiB chunks, rclone's defaults for `provider = Minio`:

```
ERROR : mp-probe.bin: Failed to copy: multipart upload corrupted: Etag differ: expecting dabe06b13f77fd6b0b43c03030e1c26a-3 but got 58d6a6131ee4337c8877716b2af05a6d-3
```

S3's multipart ETag is, by observed convention, `md5(md5(part_1) ‖ … ‖ md5(part_N))-N`
over the parts as uploaded; rclone computes it over its plaintext parts and
compares it with what `CompleteMultipartUpload` answered, which the backend
computed over the sealed parts. The part count agrees; the digest cannot. Unlike
the single-part case the object stays in the bucket and rclone's read side is
right: it stores its own MD5 as `X-Amz-Meta-Md5chksum`, the proxy preserves user
metadata, and `rclone hashsum md5`, `rclone check` and `rclone lsjson --hash`
all report the plaintext MD5 for the object. And rclone has a switch for exactly
this, because not every S3 implementation follows the formula: with the
per-remote setting `use_multipart_etag = false`, or with `provider = Other`,
whose default is off, the same upload succeeds and `rclone check` passes. The
single-part failure has no such switch short of `--ignore-checksum`.

s3cmd was not run at all. What is written about it below is reported
behaviour, and it is the reason the second suite exists.

### Where it stands against the recorded decisions

- **ADR 0010 D12** keeps `<ETag>` as the entity tag of the stored bytes and says
  in the same breath that *"making it describe the plaintext is a storage-format
  question, not a listing question, and is not decided here."* This is that
  decision, and it is still open.
- **ADR 0012**, residual risks, left the ETag as it is because *"no examined
  client verifies it."* rclone verifies it, and rclone is a named in-scope client
  ([README.md:1457](../../README.md#L1457), ADR 0006 D1); *"no client in scope
  does X"* is not an argument there (ADR 0006 D3). The residual is refuted, not
  open.
- **ADR 0006 D5 and D7**: a suite proves one client; support is claimed only as
  far as it is exercised, and the claim names its proof. Today the README names
  rclone and no suite exercises it. A decision about the ETag taken on two
  probes would be a claim resting on nothing the tree can re-run.
- **ADR 0008**: every response describes the proxy. An entity tag in the one
  shape S3 reserves for a content digest, carrying a digest of bytes the client
  never sees, describes the backend.
- **ADR 0018 D5**: the answer changes for every client, so the change carries the
  breaking marker and ships in a major — this one, or the next. **That is the
  consequence of deferring the decision to the suites: they are on the critical
  path of 5.0.0 if the change is to be in it, and if they are not built and the
  decision not taken before the cut, the change waits for 6.0.0, which is
  unscheduled.**
- **ADR 0025 D8** is the precedent for the exit provider: a listing reports the
  stored size there because it cannot tell a plain object from an encrypted one.
  The ETag would follow the same rule for the same reason.

### Before anything is decided: two end-to-end suites

Owner decision of 2026-09-13: nothing about the entity tag is decided on the
probes above. Two end-to-end suites are built first, one per client, and the
decision is taken on what they show. They follow the Velero suite's conventions,
which are ADR 0019's:

| Convention | Velero suite | The two new suites |
|---|---|---|
| Location, build tag | `test/e2e/velero/`, `//go:build e2e` | `test/e2e/rclone/`, `test/e2e/s3cmd/`, `//go:build e2e`, one package per client |
| The client | real `velero` and `kubectl` binaries, driven through `exec.CommandContext` ([exec.go:89-105](../../test/e2e/velero/exec.go#L89)), overridable by `VELERO_BIN` | the real `rclone` and `s3cmd` binaries, driven the same way, overridable by `RCLONE_BIN` and `S3CMD_BIN` |
| Pinned versions | `versions.env`, moved as one group (ADR 0019 D8) | `versions.env` per suite: the rclone release and the s3cmd release; installed by the suite's up-script, never `latest` |
| Environment | a kind cluster, MinIO, the chart, created and destroyed by `e2e-up.sh` / `e2e-down.sh`, identical on a workstation and in CI (D7) | no cluster: the demo stack (`./start-demo.sh`) — MinIO, the proxy on both endpoints, the documented `aes` configuration (D10) — plus whatever the client install needs, in a script that is the same on a workstation and in CI |
| Encryption at rest | read directly from the backend: ciphertext, `s3ep-*` metadata ([scenarios_atrest_test.go](../../test/e2e/velero/scenarios_atrest_test.go), [backend.go:96-171](../../test/e2e/velero/backend.go#L96)) (D6) | the same helpers, the same assertion on every object the client writes |
| Both endpoints | in-cluster TLS | both: rclone is on aws-sdk-go-v2 and, like the SDK, frames uploads with the unsigned trailer only over HTTPS, so only the TLS endpoint reaches the trailer decoder; s3cmd signs with the header form over both |
| Make targets, CI | `e2e-up`, `test-e2e-velero`, `e2e-velero`; job `e2e-velero`, a release gate (D9) | `test-e2e-rclone`, `test-e2e-s3cmd`, up/down targets as needed; one CI job each. **Whether they gate the release is decided when they are green** (recommendation: yes — they are the proof behind the README's claim to serve these clients, ADR 0006 D7); a suite red on a decision not yet taken is not put in the gate list to be red |
| Comparison | SHA-256 of what came back against what went in | the same, on every round trip (the work order of `CLAUDE.md`) |

**What the rclone suite exercises** — one remote per row where the row says so,
each case over both endpoints:

| Case | What it does | What it establishes |
|---|---|---|
| R1 | `copy` up, single-part (below `upload_cutoff`), remote with defaults | the single-part verdict and the exact client message |
| R2 | `copy` up, multipart (`--s3-upload-cutoff 5M --s3-chunk-size 5M`), three remotes: `provider = Minio` defaults, `provider = Other` defaults, `provider = Minio` with `use_multipart_etag = false` | the multipart verdict per provider default, and whether the setting is the answer |
| R3 | `copy` down, one single-part and one multipart object, SHA-256 against the source | the read side, and rclone's post-download check |
| R4 | `check` after each upload; `sync` up run twice, the second must transfer nothing; `sync --checksum` up | what rclone treats as changed, and on which hash |
| R5 | `lsl`, `hashsum md5`, `lsjson --hash --metadata` | which hash rclone reports for each object and where it got it (ETag, or `X-Amz-Meta-Md5chksum`) |
| R6 | `mkdir`, `delete`, `purge`, `rmdir` | the bucket and object lifecycle a user drives |
| R7 | the at-rest assertion on every object R1–R4 wrote; `X-Amz-Meta-Md5chksum` preserved on the multipart ones | ADR 0019 D6, and that the read side's hash survives the proxy |

**What the s3cmd suite exercises:**

| Case | What it does | What it establishes |
|---|---|---|
| S1 | `put`, single-part, defaults | whether s3cmd compares the ETag with its MD5 after a put, and what it does on a mismatch (reported: warns and retries) |
| S2 | `put`, multipart (`--multipart-chunk-size-mb=5`), defaults | whether s3cmd compares each `UploadPart` ETag with the part's MD5 (reported, unverified) — the one behaviour no object-level marker answers |
| S3 | `get`, one single-part and one multipart object, SHA-256 against the source | the read side |
| S4 | `sync` up twice, default and `--no-check-md5`; `sync` down | what s3cmd treats as changed, and whether an ETag that is not its MD5 re-uploads everything on every run |
| S5 | `ls`, `info` | what s3cmd reports as MD5 and where it got it (ETag, or `x-amz-meta-s3cmd-attrs`) |
| S6 | `del`, `rb` | the lifecycle |
| S7 | the at-rest assertion on every object; `x-amz-meta-s3cmd-attrs` preserved | ADR 0019 D6 |

**What the suites have to answer before the decision**, recorded in this ticket
as a table per client, per case, per endpoint, with the client's exact message:

1. Which cases are red against the tree as it is, and why, in the client's words.
2. Which of those cases turn green under the candidate change below, applied on a
   branch, with no client setting at all.
3. Which cases stay red under the candidate change and are answered by a
   documented client setting — and whether that setting switches off a check the
   proxy performs itself (`Content-MD5` per part, ADR 0012), or a check nothing
   else performs.
4. Whether any client parses the number behind the dash and refuses `0`.
5. Whether per-part ETags matter to either client (S2). If they do, the
   candidate below does not answer it, and the rejected alternative — the S3
   convention computed over the plaintext, stored on the object — is back on the
   table with its costs.

### What the two suites answer — run 2026-09-13, rclone v1.75.1, s3cmd 2.4.0

Both suites exist and are green: `test/e2e/rclone/` (R1-R7) and `test/e2e/s3cmd/`
(S1-S7), one package each, build tag `e2e`, every case over both endpoints,
driven as the real pinned binaries against the demo stack. A case whose expected
outcome is *refuses* records the defect it pins and the client's own sentence;
green therefore means "the tree behaves exactly as described below", and the
diff that flips a row to *accepts* is what the decision will look like. The
tables below are generated by the runs (`test-results/e2e-<client>-verdicts.md`).

**Both endpoints agree, in every case, for both clients.** The HTTP/TLS split
that matters for the SDK's trailer framing makes no difference to this question:
s3cmd signs the header form with the real payload SHA-256 over both, and rclone's
verdict is identical over both. Only the cases that need one endpoint (R1b, R6,
S2b, S6) are recorded once.

#### 1. Which cases are red against the tree as it is

| Case | Client | What it does | The client's words |
|---|---|---|---|
| R1 | rclone | `copy` a 1 MiB file up, provider defaults, no flags | `corrupted on transfer: md5 hashes differ` — and `Removing failed copy`: the object is deleted |
| R1b | rclone | upload identical bytes three times | three different entity tags for one unchanged file |
| R2a | rclone | `copy` 12 MiB in 5 MiB parts, `provider = Minio` | `multipart upload corrupted: Etag differ: expecting <a>-3 but got <b>-3` |
| R3b | rclone | `copy` a single-part object **down** | `corrupted on transfer: md5 hashes differ`, and the downloaded file is deleted |
| R4b | rclone | `check` a single-part object against its source | `md5 differ`, `1 differences found` |
| R4d | rclone | `sync --checksum` an unchanged single-part object | re-uploads it, then `corrupted on transfer` |
| R5b | rclone | `hashsum md5` of a single-part object | reports the entity tag as the object's md5 |
| S1 | s3cmd | `put` a 1 MiB file, defaults | `MD5 Sums don't match!` … `failed too many times`, exit 2 — **and the object is stored** |
| S2 | s3cmd | `put` 12 MiB in 5 MiB parts | refused on **part 1**, `abortmp` instructions printed, upload left open |
| S4 | s3cmd | `sync` the same unchanged file up twice | re-uploads on every run, refused every time |
| S5 | s3cmd | `info` vs `ls --list-md5` on one object | two different digests for the same object |
| S6a | s3cmd | `del --recursive` over a prefix | `501 (NotImplemented): ObjectSubResource` |
| S6b | s3cmd | `multipart` — list open uploads | `405 (MethodNotAllowed)` |

Green, and worth having pinned: R2b and R2c (rclone's `provider = Other` default
and `use_multipart_etag = false` both work), R3a, R4a, R4c, R5a, R6, S2b, S3,
S4b, S7 and R7 — every object both clients wrote is ciphertext at rest under the
four `s3ep-` keys, and each client's own annotation (`X-Amz-Meta-Md5chksum`,
`x-amz-meta-s3cmd-attrs`) survives the round trip.

#### Four findings the probes did not have

1. **The read leg is broken too, not only the write leg (R3b).** The section
   above says *"rclone's read side is right"*. That holds for a multipart
   object. For a single-request object rclone verifies the **download** against
   the same entity tag, calls an intact transfer corrupted and deletes the file
   it had just written. With a remote configured the documented way, such an
   object cannot be fetched back at all — only `--ignore-checksum` gets it out.
   This is the most serious consequence on the list and it changes the shape of
   the problem: it is not "uploads fail", it is "objects written by a
   single-request PUT are unreachable to this client in both directions".
2. **The entity tag is not stable for unchanged bytes (R1b).** The data key is
   fresh per object (ADR 0002), so three uploads of one file produce three
   different tags. A value in the shape of a content digest that changes when
   the content does not is worse than an opaque one: it is wrong in the one way
   the shape promises it cannot be.
3. **The two clients differ on what a refusal costs (S1 vs R1).** rclone deletes
   the object it will not vouch for; s3cmd leaves it stored, whole and
   decryptable, and exits 2. A caller that trusts s3cmd's exit code believes
   nothing was written when in fact everything was.
4. **Two routing defects that have nothing to do with the entity tag (S6a,
   S6b).** s3cmd addresses a bucket with a trailing slash, so it sends
   `POST /bucket/?delete` and `GET /bucket/?uploads`. The proxy routes
   DeleteObjects and ListMultipartUploads only on the path **without** the
   slash, and its trailing-slash bucket route carries no POST, so the request
   falls through to the object handler with an empty key. Consequence:
   `s3cmd del --recursive` cannot delete anything, `s3cmd multipart` cannot list
   the uploads S2 leaves behind, and therefore a user cannot remove their own
   bucket without backend credentials. Found only because a real client was
   driven; no SDK sends the trailing slash. **This is a separate defect and
   wants its own decision** — it is a routing fix, not a format change, and it
   is not gated on the entity-tag question.

#### 4. Does any client parse the number behind the dash and refuse `0`?

- **s3cmd: no, verified in its source.** Every one of its digest comparisons —
  the PUT response tag, each `UploadPart` response tag, the GET verification,
  the `sync` comparison and `ls --list-md5` — is gated on the same test,
  `'-' not in md5_from_s3`. It is a substring test; the number is never parsed.
- **rclone: the object-level test is `^[0-9a-f]{32}$`**, so anything with a
  suffix is treated as "no md5 available" rather than as a digest. Its separate
  multipart-formula check compares the whole string and is only reached for an
  upload it made in parts.
- **Neither has been exercised with the literal `-0` yet**, because that needs
  the candidate applied. That is the one remaining measurement, and both suites
  are now the instrument for it: applying the marker on a branch and re-running
  them turns questions 2 and 3 into a diff of expected outcomes.

#### 5. Do per-part entity tags matter? **Yes — and it changes the candidate's scope**

S2 settles it. s3cmd checks the tag of **every `UploadPart` response** against
that part's MD5, using the same code path as its single-object PUT. Under an
encrypting provider a full part's tag is the backend's MD5 of the **sealed**
part, so the upload is refused on **part 1** and never reaches
`CompleteMultipartUpload`. **No object-level rule can answer this**, because no
object-level answer is ever sent.

But the same `'-' not in tag` test that makes the marker work at object level
makes it work at part level, and **S2b measures that mechanism against the tree
as it is, with no change to the product**: a 20 MiB file in one client request
goes through the proxy's internal multipart producer, which answers `<hex>-N` —
and s3cmd accepts it, exit 0, `ls --list-md5` then reports the plaintext MD5 out
of its own attrs header, and `sync` settles. The same client, the same proxy,
the same encryption, refused at 1 MiB and accepted at 20 MiB, on nothing but
whether the answer carried a hyphen.

So:

- the marker is **sufficient** for s3cmd at object level — measured, not argued;
- the candidate's sentence *"Part-level ETags — `UploadPart` responses and
  `ListParts` — are not the object's and are not touched"* **leaves s3cmd's
  multipart upload refused**. If s3cmd is to work in parts, the rule has to
  cover a part's answer as well;
- there is a wrinkle worth knowing before that is decided: the proxy's answer
  for a short last part held in memory is **already** a synthetic hyphenated
  value, so part-level tags under this proxy are already of two shapes, and only
  the full-part one is bare 32-hex.

The rejected alternative (the S3 formula over the plaintext) is **not** brought
back by this: it would answer the object, and the object is not where s3cmd
fails.

### The candidate change

Accepted by the owner on 2026-09-13 as the marker **if** the entity tag changes;
whether it does is question 2 above.

**Rule.** Under an encrypting provider, an object-level ETag whose value is 32
hex digits — the shape of a content MD5 — is answered with the suffix `-0`
inside the quotes: `"2c52a8e3…b35a"` becomes `"2c52a8e3…b35a-0"`. Any other
shape, `<hex>-N` from a multipart completion included, passes unchanged. The
reverse map strips `-0` from every entity tag in `If-Match` and `If-None-Match`
before the precondition is forwarded — the header may carry a list, and `*` — so
a client that sends back what it was given revalidates exactly as before. Under
the exit provider nothing changes: the ETag is the backend's on every verb,
documented beside the size rule of ADR 0025 D8. Part-level ETags — `UploadPart`
responses and `ListParts` — are not the object's and are not touched. A foreign
object in a listing under an encrypting provider gets the marker too; it is
refused on every read anyway (ADR 0003).

**Why `-0`.** It stays inside the grammar every S3 client already parses,
`<hex>-<number>`, and S3 never produces it: a completed multipart upload has at
least one part, so `-1` is native — an object the producer or a client completes
from a single part carries it — and a marker a real object can wear is a marker
the reverse map cannot strip safely. A non-numeric suffix would be more honest
and would leave the grammar; what a client does with `"<hex>-s3ep"` is
unmeasured, what it does with `-0` is what it does with every multipart object —
question 4 above is the check on that sentence.

**What it does and does not do.** It removes the one shape a client mistakes for
a content digest. It does not honour the multipart formula: a multipart object's
ETag stays the backend's `<hex>-N`, and a client that computes the formula over
its own parts sees a mismatch, as rclone does with `use_multipart_etag` on; the
suites say whether a documented client setting is an acceptable answer there
(question 3). A client that wants to verify the plaintext has
`x-amz-checksum-crc32c` on a whole-object `GET` and on `HEAD`, the proxy's own
sealed digest (ADR 0003 D13, D14); a listing carries none (ADR 0010). Clients
that store the ETag opaquely — the AWS SDKs and CLI, kopia, Velero, Barman — see
a different string and nothing else.

**Rejected for now, and re-opened by question 5 if the suites demand it.**
*Answer the plaintext MD5, and the multipart formula over the plaintext parts.*
The proxy sees every plaintext byte and could compute both. Neither can be
answered in a listing: the backend's listing carries no metadata, so the value
would have to be stored on the object — a fifth metadata key against ADR 0009's
four — and read per entry, which is the round trip ADR 0010 refuses, or the
listing's ETag would differ from `HEAD`'s, a deviation S3 clients are not written
for. The upload leg would also pay an MD5 pass on every part whose client
declared no digest, for a value S3 itself calls opaque on multipart objects. It
is the one alternative that closes with this release (ADR 0018 D5). *Leave it
and document `--ignore-checksum`.* Costs every rclone user a flag that also
disables detection of real corruption, and the option to change the shape closes
with this release.

**Cost of the candidate.** One regular-expression match per response and per
precondition header. No per-byte cost.

### Work, in this order

- [x] **The rclone suite**: `test/e2e/rclone/`, cases R1–R7, both endpoints,
      pinned version, Make targets, CI job. The at-rest assertion lives in
      `test/e2e/harness/` and is shared by all three e2e suites, the Velero one
      included; each passes its own backend client and its own spelling of the
      stored contract. Verified by a full Velero run, 13 of 13 green in 580s.
- [x] **The s3cmd suite**: `test/e2e/s3cmd/`, cases S1–S7, the same.
- [x] **Run both against the tree as it is** and write the answers to questions
      1, 4 and 5 into this ticket — done above. Question 5 is answered *yes* and
      widens the candidate's scope to part-level entity tags.
- [ ] **Apply the candidate on a branch, run both again**, and write the answers
      to questions 2 and 3.
- [ ] **Decide**, in discussion: the rule, the marker, what the multipart formula
      is answered with, and what each client's README section says (ADR 0006
      D6: configuration and client-specific notes only). Then, and only then:
- [ ] **Amend ADR 0010 D12** with the rule, its reverse map and the exit
      exception; strike the ADR 0012 residual that says no examined client
      verifies the ETag and record the suites; note in ADR 0008's status that
      the ETag is the proxy's statement; add the two suites to ADR 0019's and
      ADR 0006's status blocks, and to `CLAUDE.md`'s test-layer list.
- [ ] **One pair of functions**, in `internal/proxy/response` or next to the
      conditional headers: the forward map for an answered ETag, the reverse map
      for a precondition value — list-aware, `*` untouched, weak tags untouched.
- [ ] **Route every emission site in the table through the forward map**, and
      `ReadConditionalHeaders`
      ([storage_headers.go:226](../../internal/proxy/handlers/object/storage_headers.go#L226))
      through the reverse map, so all four `ApplyTo*` inherit it. The proxy's own
      `If-Match` pins ([operations.go:85](../../internal/proxy/handlers/object/operations.go#L85),
      [range.go:404](../../internal/proxy/handlers/object/range.go#L404)) carry
      backend ETags and stay as they are.
- [ ] **Tests.** Unit: both maps over quoted and unquoted 32-hex, `-N`, `-0`, a
      list, `*`, empty. Integration, both transports: a single-request `PUT`
      answers an ETag that is not 32 hex digits, and `PUT`, `GET`, `HEAD` and
      both listings answer the same value; `If-Match` with that value is `200`
      and `If-None-Match` with it is `304`; `If-Match` with the backend's raw
      ETag, read from MinIO directly, is `412` — the marker is the contract, not
      a cosmetic; under the exit provider every ETag equals the backend's. The
      conformance precondition test
      ([refusal_test.go:159-186](../../test/integration/conformance/refusal_test.go#L159))
      keeps passing unchanged, which is the reverse map working. And the two
      suites, green.
- [ ] **Documentation.** `README.md`: the listing paragraph at
      [1184-1186](../../README.md#L1184) and the precondition paragraph at
      [1274-1277](../../README.md#L1274) say the ETag is the ciphertext's MD5;
      they say the decided shape instead, and the exit section states the
      exception. Per-client sections for rclone and s3cmd with their
      configuration and notes, each naming its proof (ADR 0006 D6, D7). Release
      notes: the *Behaviour — the entity tag* paragraph drafted in
      [023](023-major-v5.md), rewritten to the decision, and a `BREAKING CHANGE`
      footer on the commit.
- [ ] **Gate decision**: whether `e2e-rclone` and `e2e-s3cmd` join the release
      gate list once green.

---

## 2. Under the exit provider `UploadPart` reads the whole part into memory — **in 5.0.0**

### What happens

| Step | Where |
|---|---|
| Under `exit` the handler takes the pass-through branch before any length is looked at | [upload.go:111-117](../../internal/proxy/handlers/multipart/upload.go#L111) |
| `readWholePart` calls `Parser.ReadBody` | [upload.go:173](../../internal/proxy/handlers/multipart/upload.go#L173) |
| `ReadBody` is `readBody(r, true, 0)`, and *"a limit of zero or less reads the whole body"* | [parser.go:48-64](../../internal/proxy/request/parser.go#L48) |
| The bytes go to the backend from a `bytes.Reader` | [upload.go:433](../../internal/proxy/handlers/multipart/upload.go#L433) |

So one client part is held in memory in full, for as long as the backend takes
it, with no bound but the S3 part maximum of 5 GiB. The other two write paths
under `exit` already stream: the single-request `PUT` hands the request body to
the backend as a reader
([operations.go:400](../../internal/proxy/handlers/object/operations.go#L400),
[:438-443](../../internal/proxy/handlers/object/operations.go#L438)), and the
internal producer skips only the sealing step
([operations.go:897](../../internal/proxy/handlers/object/operations.go#L897)).
This is the one unbounded read left in the tree. The encrypting branch of the
same handler bounds what it holds at
`optimizations.multipart_short_part_buffer_size` before the bytes are in memory
([upload.go:143](../../internal/proxy/handlers/multipart/upload.go#L143)) and
forwards everything else while it arrives (ADR 0024 D1).

**Who can do it:** any client with an `s3_clients` credential, against a proxy
running the exit provider — which needs no licence (ADR 0025). **What it costs:**
resident memory equal to the sum of the parts in flight. One part larger than
the container's free memory ends the process; the limit the release's
measurements ran against is 512 MiB, and an S3 part may be ten times that. It is
also the reason a large client-driven upload under `exit` may simply not work,
which ADR 0013's residual-risk entry records as unmeasured.

### Where it stands against the recorded decisions

- **ADR 0025**: leaving is a supported mode, and the exit provider *"imposes no
  part layout: the backend's own rules about part sizes are the ones the client
  meets"* — the handler's own words. A mode that cannot take the part the backend
  takes is not that.
- **ADR 0024 D1**: an upload forwards while it receives. The pass-through part
  is the one client part that does not.
- **ADR 0011 D5** bounds what is *held* for sealing at Complete; a pass-through
  part is never held, so the bound was never applied to it — and nothing else
  was.
- **ADR 0012 D7** holds on a stream: the verifier withholds the final payload
  byte until the verdict is in, the backend refuses the short body, and the
  handler answers `BadDigest` from the verdict, the way the single-request `PUT`
  does at [operations.go:456-463](../../internal/proxy/handlers/object/operations.go#L456).

### The change

- **A part whose plaintext length the request declares** — `PlaintextContentLength`
  true, which is every SDK part — is forwarded as it arrives:
  `Parser.StreamingReader(r)` as the body, the declared length as
  `ContentLength`, the verdict asked after the backend call. No bound is needed:
  nothing is held, and a part beyond the backend's limits is the backend's
  refusal, mapped like any other.
- **A part whose length the request does not declare** — an aws-chunked body
  without `X-Amz-Decoded-Content-Length`, which no SDK sends — is read bounded
  by `optimizations.multipart_short_part_buffer_size` and refused beyond it with
  `EntityTooLarge`, naming the key, before the bytes are in memory.
  **Open sub-decision:** whether that transient read is charged to the global
  short-part budget (`SlowDown` when the budget is full) or only capped per
  request. Recommendation: charge it — ADR 0011 D5's promise is a process-wide
  bound on parts in memory, and this is one — at the cost of a session-less
  reserve and release on the manager. The smaller alternative caps per request
  and documents that N such parts in flight hold N times the cap.
- Not a breaking change: a request that failed for want of memory succeeds, and
  no answer changes for a part that worked. It ships in 5.0.0 because the exit
  provider does.

### Work

- [ ] The streamed pass-through branch, the bounded fallback, and the verdict
      after the backend call.
- [ ] Tests: a unit test that the pass-through branch never calls `ReadBody` —
      the mock backend sees a reader, not a buffer; an integration test under the
      exit provider uploading a part larger than
      `multipart_short_part_buffer_size` with a declared length, succeeding,
      compared by SHA-256; one with an undeclared length above the cap, refused
      `EntityTooLarge` before the body is consumed.
- [ ] Peak resident memory of the exit provider under one 256 MiB part, recorded
      with the local baseline instrument (ADR 0020).
- [ ] `docs/developer/multipart.md`, the exit row of its path table
      ([multipart.md:332](../../docs/developer/multipart.md#L332)); the README's
      exit section; ADR 0013's residual-risk line about the unmeasured large
      upload under exit.

---

## 3 to 8. Decisions that close with this release

Each of these is a tightening that the project's rules make a startup break or a
client-visible change. None is scheduled; each carries the recommendation and
the cost of both answers.

### 3. A provider's `config:` block accepts any key in silence

`validateAESKey` reads `aes_key` and nothing else
([config.go:817](../../internal/config/config.go#L817)); `NewAESProvider` the
same ([aes.go:72-89](../../pkg/encryption/keyencryption/aes.go#L72)); the exit
provider accepts a block it does not read
([exit.go:29-31](../../pkg/encryption/keyencryption/exit.go#L29)). ADR 0013 D11
leaves the block to the provider on purpose, *"because those parameters belong
to the provider and the provider validates them"* — and the provider does not.
ADR 0017's residual risks name it as the one place a removed or misspelt key is
still accepted; the chart round found `metadata_key_prefix` sitting inside a
provider block, silently dropped, which is the failure class.

Recommendation: **refuse now.** `aes` accepts exactly `aes_key`; `exit` accepts
an absent or empty block; anything else refuses the start naming the key, in the
words D11 already uses. Cost: two validators, a test each, one line in the
configuration table of `CLAUDE.md`. The factory's `kek` `[]byte` path
([factory.go:61](../../pkg/encryption/factory/factory.go#L61)) cannot be reached
from a file and answers a YAML `kek:` with *"kek must be []byte"*; it moves to the
tests that use it or goes.

### 4. Three environment variables and a fallback path list carry the licence

`LoadLicenseFromEnv` accepts `S3EP_LICENSE`, `S3EP_LICENSE_TOKEN` and
`S3_ENCRYPTION_PROXY_LICENSE`
([validator.go:304-317](../../internal/license/validator.go#L304)); ADR 0016 D6
names one, and its residual risks say an operator *"cannot tell which of them a
running proxy took its token from."* Every shipped path — the README, the chart,
`e2e-up.sh`, the workflows, the licence tool's own output — uses
`S3EP_LICENSE_TOKEN`. The well-known file list that applies when `license_file`
is not written is the same class, narrowed but kept by ADR 0013 D13.

Recommendation: **one name, `S3EP_LICENSE_TOKEN`, and no fallback list** — the
configured `license_file`, default `config/license.jwt`, is the one file. Cost: a
dozen lines, the README paragraph at [1585-1586](../../README.md#L1585), ADR
0016's residual. A deployment that set one of the two other names stops at
startup with the licence error, which names the variable to set.

### 5. `multipart_session_cleanup_interval: 0` switches the sweeper off

Recorded as a gap in ADR 0028's residual risks; the `validate:"min=60"` tag on
the field ([config.go:88](../../internal/config/config.go#L88)) is never
evaluated. Since the global short-part budget (ADR 0011 D5), a switched-off
sweeper makes every abandoned upload's hold on that budget permanent — the
starvation of [031](031-short-part-budget-starvation.md) without an attacker.

Recommendation: **minimum 1**, checked where the idle timeout is, naming the
key. Cost: three lines and a test; the dead `validate` tags on the struct go
with it.

### 6. `description` is parsed and, for a provider, never read

`providers[].description` is copied by the loader
([config.go:642-644](../../internal/config/config.go#L642)) and read nowhere;
`s3_clients[].description` is a log field in both authentication forms. ADR
0013 mentions neither. Under a literal reading of its D1 the provider one is a
key with no reader, and deleting it later refuses every file that carries it.

Recommendation: **keep both as annotation keys, and say so in ADR 0013** — one
sentence that a `description` is for the operator and is never a control. No
code.

### 7. `optimizations.streaming_segment_size` is not the segment size

The format's segment is a 64 KiB constant (ADR 0003 D2); this key is the part
size of the internal producer and the ceiling of a single-request `PUT` (ADR
0011 D7), and `CLAUDE.md` needs a "two jobs" sentence to keep them apart. A
rename is possible only now.

Recommendation: **leave it.** The name is quoted in six ADRs, which would each
need an amendment, and in the README, the chart values, the tests and the
baseline records; the confusion costs a sentence, the rename costs a day and a
diff nobody can review for behaviour. If the owner disagrees,
`multipart_part_size` is the honest name, and the rename lands with a startup
refusal of the old key (ADR 0013 D11) and a release-notes line.

### 8. The chart's `logging.*` values are read by no template

`logging.enabled`, `logging.format` and `logging.level`
([values.yaml:353-356](../../deploy/helm/s3-encryption-proxy/values.yaml#L353))
are matched by nothing under `templates/`; the chart README says so at
[424](../../deploy/helm/s3-encryption-proxy/README.md#L424). A values-schema
removal is bundled with the application major, as the chart round's breaking
items were.

Recommendation: **delete**, with the README row. Cost: minutes.

---

## Not in this ticket

- **[031](031-short-part-budget-starvation.md)** owns the short-part hold and
  its documentation; its recommendation A is the documentation debt of a 5.0.0
  change and belongs before the cut for that reason, not this one.
- The stale sentences on the short-part budget in [023](023-major-v5.md) were
  corrected in place on 2026-09-13.
- A listing's `KeyCount` is forwarded rather than counted; it becomes wrong only
  when the proxy drops entries, which no shipped path does.

## Done when

- [ ] The rclone and s3cmd suites exist, their answers to the five questions of
      item 1 are in this ticket, and the entity-tag decision is taken and
      recorded in ADR 0010.
- [ ] Item 2, and item 1 if decided, landed with their tests; `make test-unit`,
      `make test-integration`, `make test-integration-tls`,
      `make test-conformance`, `make test-e2e-velero`, `make test-e2e-rclone`
      and `make test-e2e-s3cmd` green on the branch head.
- [ ] Items 3 to 8 each carry a decision: an ADR amendment where a rule changes,
      or a "kept, and why" line here, before this file goes.
- [ ] [023](023-major-v5.md)'s rows for this ticket are closed and the release
      notes carry the entity-tag paragraph.
- [ ] `git grep 034` is empty outside this directory, and this file is deleted.
