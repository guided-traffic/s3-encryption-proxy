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
one for s3cmd. **Both suites now exist, have run, and their evidence is below**
(*What the two suites answer*, and *The option analysis of 2026-09-13*). What the
evidence changed about the question: the defect is not "uploads fail" but "an
object written by a single-request `PUT` is unreachable to rclone in both
directions", the candidate's scope has to widen to **part-level** entity tags or
s3cmd cannot upload below `optimizations.streaming_segment_size` at all, and one
claim — the per-object `HEAD` traffic the marker induces — is still unmeasured. Ad-hoc probes, the
ones recorded below included, are how the finding was made; they are not what a
release stands on (ADR 0006 D5 and D7, ADR 0019 D1). Items 3 to 8 are recorded
with a recommendation and what each answer costs; they are decided in
discussion, not by this file.

---

## 1. The entity tag is an MD5 of the ciphertext in the shape of a content digest — **suites built and run; the decision is open and now has evidence**

### Where this stands, 2026-09-13 — read this first

Both end-to-end suites exist, have run, and have been analysed. Nothing is
decided; what follows is the state to pick the decision up from.

**The defect, in one line.** 23 of 47 e2e rows are red. Two are routing (S6a,
S6b). The other 21 are the entity tag, and the worst of them is not an upload
failure: **an object written by a single-request `PUT` is unreachable to rclone in
both directions** (R3b), and **s3cmd can upload nothing below
`optimizations.streaming_segment_size`** and no explicit multipart upload at all
(S1, S2).

**What the analysis settled.**

- Eight candidates costed. Three are empirically dead — s3cmd's only escape is a
  hyphen in the string, and it substitutes `''` for a missing tag and fails the
  same comparison. One is measured out on performance (every object as a backend
  multipart upload: 3.2× on a 1 KiB write).
- The candidate written in this ticket is **half an answer**: it has to widen to
  part-level entity tags, or s3cmd stays where it is.
- The expensive alternative — a plaintext digest in the sealed trailer — is costed
  in its own section. It buys **two rows** that no marker can buy, ships the
  marker anyway, and carries a security regression on the precondition path.
  Verdict: not in 5.0.0.
- Three named conditions turn the recommended candidate from a fix into a live
  defect if they are missed. They are listed under *What the recommended candidate
  requires*.

**What is owed before a decision.** One measurement — the per-object `HEAD`
traffic the marker induces. It is the single load-bearing claim with no recorded
column, it is the only axis on which the marker can lose, and it is one afternoon.

**What only the owner can answer.** R2a: whether a documented rclone setting is
the target behaviour. That answer is also the gate answer — see the last work
items.

**Two defects found along the way**, neither gated on this decision and both
recorded at the end of the O4 section: a `PUT` above the ceiling silently drops
both entity-tag preconditions, and R2a's own case cannot catch a proxy that
forwards the backend's composite.

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

### The option analysis of 2026-09-13 — eight candidates against the suites' evidence

Run once both suites existed and had been run against the tree as it is. Eight
candidates were evaluated against the **clients' own sources** — rclone v1.75.1
`backend/s3/s3.go` and `fs/operations/`, and the pinned s3cmd 2.4.0 in
`test/e2e/s3cmd/venv/` — each one refuted from three independent lenses, and four
of the findings below were reproduced **live** against the running demo stack with
the pinned `rclone` binary. Everything marked *verified* was read in a source file
or produced by a command; everything else says so.

#### Two constraints nobody had written down, and they decide more than the marker

**A — the listing dictates the form of the answer.** A listing carries no
metadata, no trailer and no data key;
[listing.go:98](../../internal/proxy/handlers/bucket/listing.go#L98) is its only
backend call and `reportedSize` is arithmetic on the stored length. ADR 0010 D2
forbids the per-key round trip. **Therefore every listing entity tag must be a
pure function of the backend's entity tag**, and any candidate that answers
something else is necessarily a hybrid with a marker on the listing. Five of the
red rows are decided by the listing tag.

**B — invertibility, not honesty, is what the wire needs.** `If-Match` is
forwarded to the backend today
([storage_headers.go:244-278](../../internal/proxy/handlers/object/storage_headers.go#L244)),
and
[listobjects_conformance_test.go:841](../../test/integration/s3-methods/listobjects_conformance_test.go#L841)
asserts that the tag a listing reports satisfies an `If-Match`. A marker survives
that because it is invertible — strip, forward. Every SDK download manager pins
the first response's entity tag as `If-Match` for the rest of a multipart read
(aws-sdk-go-v2 `download.go:376`, boto3 `s3transfer/download.py:515`, minio-go
`api-get-object.go:198`), so whatever is answered comes back and has to be
translatable into something the backend recognises. This is the strongest single
argument for the marker family and it appeared in no earlier note.

**B does not make a plaintext digest impossible — it prices it.** An earlier
reading of this constraint concluded that a value the backend never issued forces
non-atomic, proxy-side precondition evaluation. That is too strong: the proxy can
read the object's tail, compare proxy-side, and forward the **backend's** own
entity tag as `If-Match` so the backend still performs the atomic compare — free
on `HEAD` and on a whole-object `GET`, which already read the tail. What the
constraint really costs is set out under *O4 costed* below: a standing +1 backend
request on every ranged `GET`, a valued `If-None-Match` on a write that cannot be
expressed at all, and a fail-open wherever a backend ignores a conditional write.

#### What each candidate buys, out of the 23 red rows

Two of the 23 (S6a, S6b) are the trailing-slash routing gap and belong to no
candidate here.

| | Candidate | Rows green | Rows red | Verdict |
|---|---|---|---|---|
| O1 | Leave it, document the client flags | 0 | 23 | rejected |
| O2 | `-0` marker, object level only — the candidate as written above | 15 | 8 | half the answer |
| O3 | `-0` marker, object **and part** level | 17 | 6 | **recommended** |
| O4 | Answer the plaintext MD5 and the plaintext multipart composite | 20, and it loses R1b | 3 | **not in 5.0.0** — costed in its own section below |
| O5 | Write every object as a backend multipart upload | 15 | 8 | rejected, measured |
| O6 | An opaque tag outside the `<hex>-<number>` grammar | 0, and three green rows regress | 23 | rejected, measured |
| O7 | Omit the entity tag under an encrypting provider | 0, and six green rows regress | 23 | rejected, measured |
| O8 | A marker whose digits come from the trailer, so it is stable | — | — | rejected |

Two more rows go green under O2, O3 and O5 once the R5b harness bug below is
fixed, so O3 reads 19 of 23 with four left: R2a twice, and the two routing rows.
O1's zero is the whole point of it: nothing changes. Its only lever that moves an
e2e row is upstream — rclone's compiled-in `etag_is_not_md5` quirk, which carries
exactly one provider today (Fastly, rationale *mandatory encryption*). An entry
for this proxy would close all thirteen rclone rows including R2a at no cost to
this product; it closes none of s3cmd's ten, and it is an upstream release cycle,
not a decision this project can take alone.

#### The three candidates that look cheap and are empirically dead

- **O6.** s3cmd 2.4.0 has exactly **one** escape from its digest comparison: a
  hyphen anywhere in the string. Verified at every comparison site — `S3.py:2067`,
  `:2294`, `:2316`, `FileLists.py:486`, `:590`, `bin/s3cmd:242` — with no length
  test and no hex test anywhere in its source. A prefix, a base64 value and a
  longer hex string carry no hyphen, so they fix **none** of S1/S2/S4/S5 and turn
  the three green S2b/S2c/S2d rows red.
- **O7.** A missing entity tag is substituted with `''` and fails the same
  comparison; the source comment at `S3.py:2021` reads *"Force re-upload here"*.
  In a listing the omitted element kills s3cmd with a Python traceback
  (`FileLists.py:478` indexes `object['ETag']` directly). It is also the only
  candidate that would close R2a, because rclone's multipart gate is
  `head.ETag != nil && *head.ETag != ""` — a presence test. That win is
  unreachable: it costs s3cmd entirely.
- **O5.** Measured, not estimated: **2.691 ms/op against 0.848 ms/op** for a
  1 KiB write, reproduced at three concurrency levels — a factor of 3.2 on the
  most frequently used verb, to change the shape of a string that a 23 ns
  predicate changes. It has one real advantage worth recording: the value stays a
  genuine backend entity tag, so nothing is invented, no reverse map exists
  anywhere, and a listing cannot desynchronise from `HEAD`.

#### Two facts that widen the candidate beyond what is written above

1. **The part-level arm is not optional.** s3cmd decides a multipart upload part
   by part and never sees an object-level answer, so `-0` at object level alone
   leaves S2 red — which means s3cmd can upload **nothing** below
   `optimizations.streaming_segment_size` (single-request `PUT`, refused) and no
   explicit multipart upload (refused on part 1). It works only in the window at
   or above the ceiling, where the internal producer answers `<hex>-N`. That
   window is what S2b measures.
2. **The proxy already ships a hyphenated non-digest entity tag on a
   client-visible encrypting path.** The held short part answers
   `fmt.Sprintf("%08x-%d", …)`
   ([segmented_session.go:519](../../internal/orchestration/segmented_session.go#L519)).
   Live against the demo stack, rclone accepted `ETag: "9ae471bc-2097152"` for
   part 3 of a three-part upload without comment. The mechanism the candidate
   relies on is already in production use inside this product.

#### What the recommended candidate requires, or it is a live defect

Each of these was found by adversarial review of the plan, not by running it:

- **The reverse map in `complete.go` ships in the same commit, inside the
  encrypting branch** — not where `parts` is built at
  [complete.go:176](../../internal/proxy/handlers/multipart/complete.go#L176),
  because the exit arm forwards that same map to the backend as the part identity.
  Without it every client-driven multipart upload under an encrypting provider
  answers `400 InvalidPart` from
  [segmented_session.go:717](../../internal/orchestration/segmented_session.go#L717);
  with it in the wrong place, every exit multipart upload breaks instead.
- **The reverse rule is shape-driven, never a trailing-`-0` trim.** A held part of
  length zero carries the literal `"00000000-0"` — `%08x` of `Value=0` and a
  `Length` of 0. A trim rule corrupts it and fails `VerifyClientParts` on a path
  no test covers. The rule is *strip `-0` only when the remaining head is exactly
  32 hex digits*, which is also what leaves `%08x-%d` alone.
- **The unit layer is blind and would pass a broken implementation.** Thirteen
  test files under `internal/` touch an entity tag and between them they contain
  exactly **one** 32-hex literal; the fixtures are names — `"stored-etag"` ×14,
  `"mpu-etag"` ×11, `"part-etag-1"` ×10, `"ciphertext-etag"` ×6 — so the forward
  map never fires in a unit test. At least one real 32-hex fixture per emission
  site **and per internal pin** —
  [operations.go:85](../../internal/proxy/handlers/object/operations.go#L85),
  [range.go:404](../../internal/proxy/handlers/object/range.go#L404) — or nothing
  catches a marker wrongly applied to the tail-first pin, which would answer 412
  to every whole-object `GET` above one segment.
- **R5b needs a suite-harness fix and is not a product defect.**
  [scenarios_read_test.go:186](../../test/e2e/rclone/scenarios_read_test.go#L186)
  takes `strings.Fields(stdout)[0]`; `rclone hashsum md5` prints `%*s  %s` with
  width 32, so an empty hash makes `fields[0]` the **filename**. The assertion
  stays exactly as written and only the parsing is corrected, so ADR 0031 is not
  touched.

#### What no candidate answers

**R2a is closed by no proxy-side value of any shape.** rclone builds `wantETag`
from the MD5s of its own plaintext chunks (`s3.go:4762`) and compares the whole
string against the entity tag of the **post-upload HEAD** (`s3.go:5173`); the
guard is a presence test, not a shape test, and the parts the proxy stores are
ciphertext. Reproduced live: `expecting 0e2d7c9cd4e676c2cfc5ddb8f868fc9b-3 but got
19b9c07ba009803db0e52448470d1ba4-3`. Four things reach it: `use_multipart_etag =
false` (already green as R2c), rclone's compiled-in `etag_is_not_md5` quirk, an
absent HEAD entity tag, or a stored plaintext composite.

**What `use_multipart_etag = false` switches off is a check this product performs
twice over.** Verified live: rclone sends `Content-Md5` on **every** `UploadPart`,
and ADR 0012 verifies each one against the decoded plaintext before a byte reaches
the backend ([upload.go:175-200](../../internal/proxy/handlers/multipart/upload.go#L175)).
The composite's other job — these parts, in this order, N of them — is what the
segment associated data and the sealed trailer already enforce strictly (ADR 0003).
**R2a is a reporting gap, not an integrity gap**, and that is the fact the decision
about it should rest on.

#### The security consequence of every marker candidate — this needs an owner decision

The mechanism by which every row turns green is that **the client stops checking**.
It is asymmetric between the two clients, and the second half is a real loss:

- **rclone: nominal.** Its upload stays verified end to end — by the proxy, against
  the plaintext, using the `Content-MD5` rclone itself sends (verified live on a
  single-request `PUT` and on every part). Its download stays verified by the
  segment tags and the sealed trailer, which are stronger than MD5.
- **s3cmd: a real loss.** Verified in the pinned source: `generate_content_md5` is
  called only for bucket sub-resource bodies and the `DeleteObjects` body, never
  from `object_put` or `send_file`, and `MultiPart.py:211` says
  `# TODO implement Content-MD5`. The proxy takes `X-Amz-Content-Sha256` as the
  signed *claim* in the canonical request
  ([s3auth_robust.go:318-336](../../internal/proxy/middleware/s3auth_robust.go#L318))
  and never re-derives it from the body. So after the marker, S1 and S2 go from
  *refused because the only end-to-end digest disagreed* to *exit 0, with no
  end-to-end digest anywhere*. Over the plain-HTTP listener that is a genuine loss
  of detection; over TLS the record MAC covers the wire, which is not this
  product's doing.
- **The mechanism of the S4 and S5 fix relies on unauthenticated client
  metadata.** Both turn green because s3cmd falls back to
  `x-amz-meta-s3cmd-attrs`, a client-written plaintext MD5 stored in the clear
  beside the ciphertext. Under ADR 0001 the backend is the adversary and that
  value is attacker-writable. It is not new — rclone already writes
  `X-Amz-Meta-Md5chksum` the same way, which is why R3a and R5a are green today —
  but the marker **extends** the reliance on it, and that belongs in the ADR
  rather than in a test file.

Two complements are proposed against that loss, each decided on its own:

- **Verify `x-amz-content-sha256` against the decoded body** when it is a real hex
  digest, not `UNSIGNED-PAYLOAD` and not a `STREAMING-*` form. The machinery
  exists — ADR 0012's verifier already withholds the final payload byte until the
  verdict is in. It gives s3cmd a **stronger** end-to-end check than it had before
  the marker, and costs a SHA-256 pass only where a client declares a real payload
  hash (s3cmd does; aws-sdk-go-v2 over HTTPS does not).
- **Serve `x-amz-checksum-crc32c` on the verbs that lack it** — `PUT`,
  `UploadPart`, `CompleteMultipartUpload`, a ranged read. The values are already
  computed (`EncryptReader.Checksum()`, the session part table). It moves **zero**
  e2e rows, because neither named client reads it, and it is worth doing anyway:
  it is the only integrity channel the proxy can vouch for itself, and ADR 0008
  D13's own uniformity bullet asks for it.

#### Where the recommended candidate stands against ADR 0008

ADR 0008 D13 says a header that describes the **stored object** belongs to the
proxy and is restated from what the client actually receives, never forwarded.
`-0` does not do that: it decorates a forwarded backend value. **The marker is a
compatibility correction, not an honesty correction** — the proxy stops making a
false claim without yet describing itself. The amendment to ADR 0010 D12 has to
say that in those words, or it claims more than the change delivers. ADR 0008 D12
("a value the proxy does not have is omitted, never rendered as a zero value") is
the clause a reviewer will raise, and the answer is that `-0` is not a zero value
standing in for a missing one — it is a shape that removes a false promise while
staying invertible. That answer has to be written down, not assumed.

#### The `-0` premise, checked

S3 cannot produce `<hex>-0`: a completed multipart upload has at least one part,
and MinIO's own strict parser rejects part number 0. The premise that matters is
narrower — *can anything on the inbound path legitimately carry `-0`* — and the
answer is **yes, inside this repository**: the zero-length held part above. Two
mitigations, both cheap: the shape-driven rule, and a conformance assertion
(ADR 0027's minio, localstack and wasabi) that no backend in the set ever answers
`-0`. This is also the axis on which `-0` beats the `-1` that gaul/s3proxy uses: a
genuine one-part multipart upload ends in `-1` on every backend, so `-1` is not
invertible.

#### The one unmeasured claim, and the measurement that settles it

Every correctness claim above is double-sourced and four were reproduced live.
**One** load-bearing claim has zero recorded columns and was asserted in opposite
directions by two reviewers:

> the per-object `HEAD` traffic the marker induces is acceptable.

The mechanism by which R4b, R4d, R5b, S4 and S5 turn green **is** that both
clients stop trusting the listing and start asking per object. Each such ask costs
this proxy a backend ranged `GET` (`bytes=-40`), a key unwrap and a trailer open
([operations.go:525](../../internal/proxy/handlers/object/operations.go#L525) →
[tail.go:65](../../internal/proxy/handlers/object/tail.go#L65)), and the data-key
cache holds 1024 entries
([providers.go:23](../../internal/orchestration/providers.go#L23)), so a sweep over
a larger bucket is a full miss stream that also evicts the entries serving real
reads. `O(N/1000)` listing calls become `O(N)` authenticated object reads on the
sweep verbs. `test/perf/` has no listing or `HEAD`-rate instrument, so the workload
is unmeasured rather than unaffected, and under ADR 0020 neither claim may be
quoted.

The measurement, one afternoon: the candidate on a branch, a bucket of
1000 × 4 KiB objects, and the **backend request count** plus wall clock for
`rclone check`, `rclone sync --checksum` and `s3cmd sync` before and after — the
request count is the number that settles it, readable from MinIO or from the
proxy's own `:9090`. The same run gives questions 2 and 3 of this ticket for free,
because `make e2e-rclone` and `make e2e-s3cmd` are 5 s and 8 s on a warm stack.

### O4 costed: a plaintext digest sealed in the trailer

Costed on 2026-09-13 because it is the one candidate that closes R2a, and because
a storage-format decision has a deadline this one does not obviously have. Every
number below is either measured on this machine or counted in the tree; the two
adversarial reviews that follow the estimate are folded in.

#### The deadline is real, and it covers less than it looks like

**`s3ep-gcm-seg-v2` has never been in a release.** Verified: `git tag -l 'v5*'`
is empty, `git describe` on this branch reads `v4.0.3-170-g2e52a30`, and
`git ls-tree v4.0.3 -- pkg/encryption/dataencryption/` lists only `aes_ctr.go`
and `aes_gcm.go` — the codec exists in **zero tags**. `release.config.mjs` cuts
only from `main`, and `main` does not carry the codec either. The published
`:latest` image is v4.0.3 and writes the format this release deletes.

So a field added to the trailer **now** is not a v2→v3 break: it is the shape v2
ships with. No second format id, no dual reader, no migration, no release note.
The only objects in the format anywhere are on disposable stacks, and a 40-byte
trailer read under a 58-byte constant fails closed at
[segmented_gcm.go:174](../../pkg/encryption/dataencryption/segmented_gcm.go#L174)
— `403`, loud and correct.

Added **after** the tag, ADR 0017 D10 forbids it landing in a minor at all, so it
becomes a 6.0.0 with a second forced re-upload of every object. That is the
asymmetry, and it is what makes this worth costing now rather than later.

**But only the 18 bytes are time-limited.** The MD5 pass, the answer sites, the
precondition work and the listing split are major-only under ADR 0018 D5 either
way — they cost the same in 6.0.0 as in 5.0.0. And a trailer field that is
reserved but never filled is speculative code (CLAUDE.md rule 2); a field that is
filled but never answered pays the full per-byte cost for a value nothing reads,
which is exactly what
[segmented_gcm_io.go:28-33](../../pkg/encryption/dataencryption/segmented_gcm_io.go#L28)
already rejected once for the running CRC32C. There is no cheap half-step. The
question is binary: decide now that the entity tag will one day be the plaintext
digest and build it now, or decide it will not and ship the marker.

#### The size is trivial; the payload is not

A sibling agent flipped `TrailerSize` in-tree, compiled the whole tree, ran
`go test ./... -short` against a captured baseline and reverted. Result:

| | |
|---|---|
| Non-test lines for the size alone | **3, in one file** — everything else derives from the constant and recompiled untouched |
| Test lines with a hardcoded literal | **18, in five files**, and they map exactly onto the 18 new failing nodes |
| Documentation lines stating 40 / 65604 / the overhead formula | ~18 across seven non-ticket files |
| Migration, dual reader, second format id | **zero** |

**The trailer is 40 → 58, not 40 → 56.** One 16-byte field cannot be both
`md5(plaintext)` and S3's composite `md5(concat(md5(part_i)))-N`: the composite
needs `N` to render at all. The body becomes
`uint64 length ‖ uint32 crc32c ‖ [16]byte digest ‖ uint16 partCount`, where
`partCount == 0` means a bare digest and `> 0` the composite over that many
client parts. Derived: the tail-first first window 65604 → **65622**, HEAD's
suffix `bytes=-40` → **`bytes=-58`**, and ADR 0003 D12a's two named unreachable
lengths 68/65605 → **86/65623** — the last of which owes a third exhaustive
well-formedness sweep, because [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)
records one per trailer size.

**`Checksum` must not absorb the digest.** `Checksum.Append` folds two CRC32Cs
with `crc32Combine`, without the plaintext. **MD5 has no such construction.** The
digest needs its own type threaded separately through the seal and open paths, and
that parameter churn is most of the orchestration diff. It is also why
`md5(whole plaintext)` is *structurally impossible* on the client-driven multipart
path: parts arrive in any order, concurrently, and may be re-uploaded, so no
hasher ever sees the object's plaintext in order. Only the composite is available
there — which is fine, because the composite is exactly what rclone compares.

#### What it costs per byte — measured, and not fixable

On this machine (Apple M5 Pro, arm64; the instrument agrees with the project's own
recorded `cryptofloor` column within 3.4 %, which is what makes the comparison
legitimate):

| | |
|---|---|
| MD5 standalone | 890 MiB/s — **1.12 ms/MiB** |
| CRC32C, the hash the trailer already carries | 11 409 MiB/s — **12.8× faster** |
| SHA-256, for contrast | **3.65× faster than MD5** — arm64 has SHA-2 and CRC32C in silicon and no CPU has an MD5 instruction |
| Seal + running CRC32C, what ships today | 4741 MiB/s |
| Seal + CRC32C + MD5 | **752 MiB/s — 6.2×** |
| Per-core line rate the proxy can seal | 39.8 → **6.3 Gbit/s** |
| Aggregate sealing at 16 concurrent streams | 40.2 → **9.9 GB/s** |

Three mitigations were measured and all three fail: sharing the memory traversal
with the seal loop buys **0.4 %** (MD5 is compute-bound, not memory-bound); a
second goroutine at 1 MiB handoff recovers 16 % and costs a whole extra core per
stream; at 64 KiB handoff the wakeups eat most of it. Go's `crypto/md5` is already
hand-written assembly on both architectures, so 890 MiB/s **is** the fast path.

**What that means end to end is genuinely unresolved, and honestly so.** In-process
crypto is 3.5–5.1 % of a PUT's wall clock today, and the whole proxy adds only
+0.11 ms/MiB over a direct client while the seal alone costs 0.214 ms/MiB of CPU —
today's encryption is already more than absorbed by pipeline overlap. Applied to
the recorded rows, a fully serial MD5 costs −15.3 % at 5 MiB to −21.0 % at 128 MiB
TLS. The adversarial review is right that this claim cannot be made: ADR 0020 says
*"nothing below roughly 15 % end to end may be claimed at all"*, three of those
four rows sit at that floor, **and both columns are missing** — ADR 0020's own
2026-09-12 note says the 2026-09-11 after column *"is already the run to replace,
not the state of the tip"*. Worse, the effect that would decide it — aggregate
sealing capacity falling 4–6× under concurrency — has **no instrument**:
`test/perf/throughput_test.go` runs no parallel streams and every recorded
measurement is single-stream against a co-located backend. Building that
instrument is an uncosted work item.

What can be said without an instrument: a single-request PUT seals **inside** the
`Read` the backend's HTTP writer pulls, so the serial end of the bracket is the
shape that path actually has; and one core on a 10 GbE link crosses from
network-bound to CPU-bound.

#### The expensive candidate ships the cheap one as well

A listing has no trailer, so under constraint A the listing tag stays a marker
while `HEAD`/`GET` carry the digest. **Both designs get built**, and one object is
named by two different 32-hex-shaped strings depending on the verb. Consequences,
each verified:

- [listobjects_conformance_test.go:781-845](../../test/integration/s3-methods/listobjects_conformance_test.go#L781)
  asserts `LIST == HEAD == GET` for four object shapes *and* that the listing's tag
  satisfies an `If-Match`. Under the split it is **unsatisfiable** — it has to be
  overturned by an ADR, not edited by a developer. Under the marker it passes
  unchanged.
- A precondition carrying either of the two forms is **indistinguishable by shape**,
  so the evaluator has to accept both on every verb.
- A new client-visible inconsistency appears where the marker has none: `s3cmd
  ls --list-md5` HEADs on a hyphen and then reads **only** `s3cmd-attrs`, never the
  HEAD entity tag. For an object s3cmd did not write, `info` reports the trailer
  digest and `ls --list-md5` reports the marker — which is the S5 defect displaced
  onto foreign objects.

#### The ranged `GET` is forced, and it is the standing cost

ADR 0008 D13 names a per-path entity-tag asymmetry as a defect of the response
surface, and its own residual exempts a ranged read only for
`x-amz-checksum-crc32c`, on the argument that a partial read cannot make a
statement about the whole object at rest. **An entity tag is not such a
statement** — it identifies the whole object and is what `If-Match` and every SDK
download manager key on. So neither "keep the backend tag on a 206" nor "omit the
tag on a 206" is available, and what is left is **+1 backend request on every
ranged `GET`, conditional or not, permanently**. A 1 GiB download at the SDK's
8 MiB default goes from 128 to 256 backend requests.

And even where the trailer bytes are already in hand it cannot be answered without
restructuring: `provisionalWindow`
([range.go:334-345](../../internal/proxy/handlers/object/range.go#L334)) over-asks
by exactly `TrailerSize`, but `rangeReader.finish()` opens the trailer only after
the body is consumed, by which time the status and headers are out.

#### The preconditions: the translate design works, and it moves a race rather than closing it

Reading the tail, comparing proxy-side and then forwarding the **backend's** entity
tag as `If-Match` costs **zero** extra requests on `HEAD` and on a whole-object
`GET` — both already read the tail and the `GET` already pins its second leg with
the backend tag ([operations.go:85](../../internal/proxy/handlers/object/operations.go#L85)).
The earlier conclusion that a plaintext digest forces a TOCTOU is too strong. What
it does force, each verified:

- The proxy becomes the precondition evaluator on five verbs. Atomicity then rests
  entirely on the backend honouring `If-Match` on a write — and this repo's own
  [conditional_requests_test.go:380-388](../../test/integration/s3-methods/conditional_requests_test.go#L380)
  already tolerates a backend that ignores it. Where it is ignored the write
  proceeds while the proxy has claimed to evaluate the precondition: **fail-open**,
  and now the proxy's failure rather than the client's.
- **A valued `If-None-Match` on a write is unspecified under translate.** "Write
  unless the current plaintext digest is D" cannot be expressed by forwarding the
  backend tag: `If-None-Match: E` inverts the condition and refuses the very write
  the client wanted, `If-Match: E` is strictly stronger and yields spurious 412s
  under any concurrent writer, and on a nonexistent object there is no `E` at all.
- A replacement by a **different object with identical plaintext** answers 412
  where native S3 allows the write, because the backend tag moves with the fresh
  per-object data key. A deliberate conformance deviation, covered by no test.

#### The security regression, and it is exclusive to this design

**Today's entity tag is the backend's MD5 of the ciphertext under a random
per-object data key: a client cannot predict it, choose it or collide it.** The
trailer digest makes the tag `md5(the client's own plaintext)` — fully chosen —
and the translate design then makes the **proxy** evaluate `412`/`304` and the
lost-update guard against that value. That puts a collision-broken hash on the
input side of a precondition verdict. It is no worse than native S3, and it is
strictly worse than what this product does today and than the marker, which keeps
the unpredictable value. Under CLAUDE.md rule 9 this is the finding that has to be
answered before the design is chosen, not after.

Two smaller entries, for completeness:

- **The confirmation oracle is not new.** The proxy already answers
  `x-amz-checksum-crc32c` — a checksum over the whole plaintext — on a whole-object
  `GET` and on `HEAD` (ADR 0003 D14). MD5 is the same leak at higher resolution,
  and against the low-entropy candidate sets that matter a 32-bit CRC32C already
  confirms a guess. The incremental leak is small; the claim that the entity tag
  "says nothing about the plaintext today" is false.
- **`gosec` cost.** `crypto/md5` would land inside `pkg/encryption/dataencryption`
  — the crypto package itself — and `make gosec` flags G501 and G401. The two
  existing suppressions are justified with *"not a security primitive"*, which is
  precisely what the value stops being once it drives a precondition verdict. A new
  suppression justified in the opposite direction, inside the codec, is a review
  artefact in a product with a published threat model.

#### What it buys: two rows

| | Marker (O3) | Trailer digest |
|---|---|---|
| Red rows turned green | 17, or 19 with the R5b harness fix | 20 |
| Rows it wins that the other cannot | — | **R2a, twice** |
| Rows it loses that the other wins | — | **R1b** — the digest is *stable* for unchanged bytes, which is the better property, but the case asserts instability as its premise and non-digest shape as its target, so it fails before a verdict is recorded and has to be rewritten |
| Rows of its total actually won by the listing **marker** half | — | 8 of the 20 |

**The exclusive product delta is two rows**, against ~1400–2000 changed lines, a
format change, a new precondition evaluator, an overturned conformance assertion,
a per-byte regression the project cannot currently measure, and a security
regression on the precondition path. And R2a has a **zero-product-cost**
alternative: an upstream rclone provider entry carrying `etag_is_not_md5`, which
one provider already carries (Fastly, rationale *mandatory encryption*).

#### Size estimate, and why it is soft

15 non-test Go files plus one new, ~23 test files, ~30 new tests, one new ADR and
**six** amended (0003, 0006, 0008, 0010 D12, 0012, 0020), ~1400–2000 lines.
Calibrated against this branch: the tail-first read was 18 files / +918 / −371;
the segment chain end to end was 16 files / +1114 / −1300. Four to seven commits
over two to four focused days, plus a full gate cycle and a performance baseline —
and add roughly two days if the precondition evaluator needs its own component.
**The estimate is soft at both ends**, because the two largest items — the ranged
`GET` and the evaluator — are the ones the adversarial reviews reopened.

#### Verdict on O4

**Not in 5.0.0.** The deadline argument is real but covers only 18 bytes, and
there is no honest half-step that banks them: a reserved field is speculative and
a filled-but-unanswered field pays the full per-byte cost for a value nothing
reads. If the plaintext digest is ever wanted it is a 6.0.0 with a format break —
which [ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md) already
permits and already prescribes a procedure for (D1 no migration owed, D2 the
precondition re-confirmed with the owner per release, D5 announced, D6 rehearsed).
That is a known, rehearsed cost, not a catastrophe, and paying it buys the
question a real answer instead of a deadline-shaped one.

#### Found along the way, independent of this decision

1. **A `PUT` above `optimizations.streaming_segment_size` silently drops both
   entity-tag preconditions.** `ConditionalHeaders.ApplyToCompleteMultipartUpload`
   has exactly one caller,
   [complete.go:272](../../internal/proxy/handlers/multipart/complete.go#L272);
   the internal producer builds its own `CompleteMultipartUploadInput`
   ([operations.go:1203-1209](../../internal/proxy/handlers/object/operations.go#L1203))
   and sets neither. So `If-None-Match: *` — create-if-absent — is lost for every
   object above the ceiling, and a client that relies on it overwrites silently.
   Verified by reading both call sites. Nothing to do with the entity tag's shape.
2. **R2a cannot catch a proxy that forwards the backend's composite.** Its 12 MiB
   in 5 MiB chunks gives parts of 5, 5 and 2 MiB; the short tail means the trailer
   rides the last client part, so the backend's part count happens to equal the
   client's. A size that is an exact multiple of the chunk size — 10 or 15 MiB —
   puts the trailer in its own part and makes them differ by one. Neither suite has
   such a case, and it matters for any design that answers a composite.

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
- [x] **The option analysis**: eight candidates against the clients' own sources,
      three adversarial lenses each, four findings reproduced live — written up
      above. It answers question 5 in the wider form, refutes three candidates
      empirically, and leaves exactly one claim unmeasured.
- [ ] **Measure the induced per-object `HEAD` traffic** — the one unmeasured
      claim, and the only axis on which the marker can lose. The candidate on a
      branch, 1000 × 4 KiB objects, backend request count and wall clock for
      `rclone check`, `rclone sync --checksum` and `s3cmd sync`, before and after
      (ADR 0020 wants two recorded columns). The same run answers questions 2 and
      3, because both suites are 5 s and 8 s on a warm stack.
- [ ] **Decide**, in discussion, five things and not one: the rule and the
      marker; **whether the part-level arm is in scope** (without it s3cmd cannot
      upload below `optimizations.streaming_segment_size` at all); what R2a is
      answered with, given that the client setting switches off a check ADR 0012
      already performs per part; whether the loss of s3cmd's only end-to-end
      digest is accepted or answered by verifying `x-amz-content-sha256`; and
      what each client's README section says (ADR 0006 D6). Then, and only then:
- [ ] **Amend ADR 0010 D12** with four rules, not one: the forward rule at object
      level, the forward rule at **part** level, the reverse map at both
      positions (the two precondition headers *and* the `CompleteMultipartUpload`
      part list), and the exit exception, stated the way ADR 0025 D8 states the
      size rule. Record as named residuals: R2a, the exit provider's own objects,
      and a foreign object in a listing, which gets the marker although its
      backend tag is a true content digest. Strike the ADR 0012 residual that says
      no examined client verifies the ETag and name the suites; note in ADR 0008's
      status that the marker is a **compatibility** correction, not the honesty
      correction D13 asks for; add the two suites to ADR 0019's and ADR 0006's
      status blocks and to `CLAUDE.md`'s test-layer list.
- [ ] **Three functions**, in `internal/proxy/response`: the forward map, the
      reverse map for a precondition header (list-aware, `*` and weak tags
      untouched, **quote-aware** — every client that replays a tag hands it back
      quoted, minio-go re-quotes explicitly), and the reverse map for one part
      value. All three **shape-driven**: strip `-0` only when the remaining head
      is exactly 32 hex digits, or the zero-length held part's `"00000000-0"` is
      corrupted.
- [ ] **Route every emission site through the forward map** — value-wrapping, not
      statement-wrapping: [operations.go:480](../../internal/proxy/handlers/object/operations.go#L480)
      and [:1221](../../internal/proxy/handlers/object/operations.go#L1221) are
      single unconditional `w.Header().Set` calls, and wrapping the *statement* in
      a provider gate drops the header entirely under exit. The three response
      funnels are shared by both provider arms and are not told which arm called
      them, so the gate belongs at the call sites. The proxy's own `If-Match` pins
      ([operations.go:85](../../internal/proxy/handlers/object/operations.go#L85),
      [range.go:404](../../internal/proxy/handlers/object/range.go#L404)) carry
      backend ETags and stay as they are.
- [ ] **The two reverse maps, in the same commit as the forward map.**
      `ReadConditionalHeaders`
      ([storage_headers.go:226](../../internal/proxy/handlers/object/storage_headers.go#L226)),
      so all four `ApplyTo*` inherit it; and the part list in
      [complete.go](../../internal/proxy/handlers/multipart/complete.go) **inside
      the encrypting branch**, before `VerifyClientParts` — not where `parts` is
      built, because the exit arm forwards that same map to the backend as the
      part identity. Without it every client-driven multipart upload under an
      encrypting provider answers `400 InvalidPart`.
- [ ] **Tests.** Unit: both maps over quoted and unquoted 32-hex, `-N`, `-0`, a
      list, `*`, empty, and `"00000000-0"`. **And first: give the unit layer eyes**
      — thirteen files under `internal/` touch an entity tag and contain exactly
      one 32-hex literal between them, so the forward map fires nowhere today. At
      least one real 32-hex fixture per emission site and per internal pin, or a
      marker wrongly applied to the tail-first pin goes undetected and answers 412
      to every whole-object `GET` above one segment. Integration, both transports:
      a single-request `PUT` answers an ETag that is not 32 hex digits, and `PUT`,
      `GET`, `HEAD` and both listings answer the same value; `If-Match` with that
      value is `200` and `If-None-Match` with it is `304`; under the exit provider
      every ETag equals the backend's. **A ranged `GET` carrying a marked
      `If-Match`** — no test covers it today and no suite exercises an SDK
      download manager, which pins the first response's tag for every later chunk,
      so the failure mode is a 412 on the *second* chunk. The conformance
      precondition test
      ([refusal_test.go:159-186](../../test/integration/conformance/refusal_test.go#L159))
      keeps passing unchanged, which is the reverse map working. And the two
      suites, green — plus the R5b harness fix below, without which R5b stays red
      for a reason that is not the product's.
- [ ] **Open sub-decision raised by the reverse map.** The bullet above that said
      *"`If-Match` with the backend's raw ETag, read from MinIO directly, is
      `412` — the marker is the contract, not a cosmetic"* does not survive a
      shape-driven map: an unmarked raw 32-hex is a no-op for the map, reaches the
      backend and **matches**, so it is `200`. Either the marked value is the only
      accepted contract — which needs the map to reject an unmarked one, and
      therefore state under which provider — or both are accepted and the ADR says
      so. It cannot be left implicit.
- [ ] **Fix the R5b harness**, not the assertion:
      [scenarios_read_test.go:186](../../test/e2e/rclone/scenarios_read_test.go#L186)
      takes `strings.Fields(stdout)[0]`, and `rclone hashsum md5` prints `%*s  %s`
      with width 32, so an empty hash yields the filename. Parse the fixed-width
      column. ADR 0031 is untouched: the assertion stays exactly as written.
- [ ] **Run what compiling does not prove**: `make test-integration` and
      `make test-integration-tls` (thirteen sites echo an `UploadPart` ETag into
      `CompleteMultipartUpload`, and two drive aws-sdk-go-v2's own uploader),
      `make test-conformance` against minio and localstack, and the Velero gate —
      kopia never reads an entity tag, but `go vet` does not execute an assertion
      and this is a release gate.
- [ ] **Documentation.** `README.md`: the listing paragraph at
      [1184-1186](../../README.md#L1184) and the precondition paragraph at
      [1274-1277](../../README.md#L1274) say the ETag is the ciphertext's MD5;
      they say the decided shape instead, and the exit section states the
      exception. Per-client sections for rclone and s3cmd with their
      configuration and notes, each naming its proof (ADR 0006 D6, D7) — and for
      rclone, what `use_multipart_etag = false` actually switches off. Release
      notes: the *Behaviour — the entity tag* paragraph drafted in
      [023](023-major-v5.md), rewritten to the decision, and a `BREAKING CHANGE`
      footer on the commit.
- [ ] **Gate decision**: whether `e2e-rclone` and `e2e-s3cmd` join the release
      gate list once green. It depends on R2a: a suite that keeps one red row by
      decision cannot be a gate, so the R2a answer and the gate answer are one
      decision, not two. **The O4 costing below sharpens this rather than
      loosening it.** R2a was the only row O4 bought that no marker can; with O4
      out of 5.0.0, R2a stops being a design question and becomes a product
      statement with exactly two answers: either a documented client setting is
      the target behaviour — and the case is rewritten to configure the remote
      that way, green, gate possible — or the proxy is supposed to satisfy
      rclone's composite unaided, in which case R2a is red until 6.0.0 and
      `e2e-rclone` cannot gate the release it was built to gate.
- [ ] **Two defects found while costing O4, neither gated on this decision.**
      (1) A `PUT` above `optimizations.streaming_segment_size` drops both
      entity-tag preconditions — the internal producer builds its own
      `CompleteMultipartUploadInput`
      ([operations.go:1203-1209](../../internal/proxy/handlers/object/operations.go#L1203))
      and never calls `ApplyToCompleteMultipartUpload`, so `If-None-Match: *`
      silently stops protecting anything above the ceiling. (2) R2a's 12 MiB in
      5 MiB chunks has a short tail, so the backend's part count equals the
      client's by accident; the suite cannot catch a proxy that forwards the
      backend's composite. A 10 or 15 MiB case would.
- [ ] **Two complements, each decided on its own and neither gated on the
      marker.** (1) Verify `x-amz-content-sha256` against the decoded body when it
      is a real hex digest — it gives s3cmd a stronger end-to-end check than the
      one the marker silences, and ADR 0012's verifier already has the shape for
      it. (2) Serve `x-amz-checksum-crc32c` on `PUT`, `UploadPart`,
      `CompleteMultipartUpload` and a ranged read; the values are already
      computed, it moves no e2e row, and it is what ADR 0008 D13's uniformity
      bullet asks for.

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
