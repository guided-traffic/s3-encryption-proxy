# The test suite audited against what the product promises

Work list from the audit of 2026-09-12. Fifteen subsystems of the 5.0.0 bundle
were read test-first: not "is there a test", but "would this test fail if the
behaviour it is named for were reverted". Seventy-one findings were raised, each
re-checked by an independent second reader against the code; **62 survived, 9 were
refuted**. Eight of the survivors were put to a mutation probe — production code
edited in a throwaway worktree, the test re-run — and **four are proven to pass
with the guard they exist for deleted**.

This file adds no decisions. Where a row needs one, it names the ADR that already
made it; where the tree and an ADR disagree, that is written down as the finding.

## State

**Every row in this file is now worked.** Rows 1 to 5 landed with the ticket; the
rest landed on 2026-09-12 in the wave described below. What is left before the
file can be deleted is running the suites that need a backend — the integration,
TLS, conformance and Velero runs — because several rows change paths they
exercise.

### What the second wave changed, by kind

**Five defects in the product, not in its tests:**

| Defect | Fix |
|---|---|
| The two end-relative ranged reads took a HEAD and then a GET with nothing pinning them to one object | The GET carries `If-Match` on the HEAD's entity tag, as the whole-object read has since ADR 0003 D14. A client's own `If-Match` is never replaced. The exit provider's two HEADs for one suffix range became one |
| A large PUT cut short by the shutdown budget orphaned a backend multipart upload nothing could see | The internal producer registers its upload; `AbandonAllSessions` sweeps it with the client-driven ones and the idle clock never touches it |
| A licence that lapsed at runtime called `os.Exit(1)` from the monitoring goroutine, past the whole ADR 0029 tail | An injectable expiry handler; `main` runs the same drain, sweep and listener close a SIGTERM runs, and exits 1 at the end |
| ADR 0011 D5's global short-part budget did not exist, and the body was buffered in full **before** the cap was consulted | The budget is the process's; a part that does not fit beside the others is `SlowDown`, one larger than the whole budget is `EntityTooLarge` **before it is read**. Found beside it: a held part replaced by a storable one was left in the session, so Complete stored the old bytes under the new part's checksum |
| `DeleteResult` went out without the S3 namespace, against ADR 0008 D3; a 416 from the backend lost its `Content-Range`; a pass-through range answered `206` for a response that carried none | All three answer what S3 answers |

**Decisions the rows forced, recorded where they belong:** ADR 0011 D5 (built,
with the two answers spelled out), ADR 0019 D4 (the three offenders are gone),
ADR 0020 D11 (built — the throughput gate and its switch are deleted) and D14
(the memory bound is an assertion now), ADR 0027 D4 (the enforcement claim
corrected to what the suite does), ADR 0003 D6 (the scope of "before it releases
the last segment" corrected to what a streaming reader can give).

**Everything else was a test that could not fail**, and each is now pinned with a
mutation probe behind it. The four untagged `bucket_*_test.go` files — 129 cases
importing no package of this project, one of them asserting a canned-ACL
validation the proxy does not perform — were deleted.

| # | Row | State |
|---|---|---|
| 1 | The exit provider serves an unopenable object of ours as `200` + ciphertext | **Done.** Predicate split, three gates refuse, five sub-tests that fail without the fix |
| 2 | The shipped `default.yaml` is never validated in CI | **Done.** The licence comes from the environment or the file, and a CI run without either fails instead of skipping |
| 3 | Nothing has ever run under `-race` | **Done.** Two targets, one release-gating job. The unit suite is clean under the detector today |
| 4 | Nothing pins the stored byte layout | **Done.** Captured vectors; the AAD-reversal and trailer-swap mutation now fails four tests |
| 5 | A readiness loop that never succeeds still passes | **Done.** All three loops fail on exhaustion, matching the fourth which already did |

**Found while doing them, and fixed:** `make lint` was **red at the branch head**,
before any of this — one `revive` unused-parameter in an orchestration test.
Reproduced in a pristine worktree of `HEAD` to be sure it was not ours. The status
block of [023](023-major-v5.md) claims `make lint` (0 issues) for that head, and
that claim was false. It is 0 issues now.

**Gates after the whole wave:** `go build`, `go vet` (including the `integration`,
`conformance`, `e2e` and `perf` tags), `gofmt`, `make test-unit`,
`make test-unit-race` (0 races), `make lint` (0 issues), `helm unittest`
(34 passed). The integration, TLS, conformance and Velero suites have **not** been
re-run — they need a backend, and this wave touches paths every one of them
exercises, so they are owed before the merge.

## How the findings were produced

Every row carries the evidence it was confirmed with, because a test-suite finding
is worthless without it: a claim that something is untested is a claim about the
absence of code, and absence is what people get wrong. Three forms appear below:

- **grep-proven** — the search that came back empty is quoted.
- **read-proven** — the production line and the test line are quoted side by side.
- **mutation-proven** — production code was edited, the test re-run, and it still
  passed. These are marked **(mutation-proven)** and are not open to argument.

Four probes could not run offline because their targets sit behind the
`integration` or `conformance` build tag and need a live backend. They are marked
**(not probed)** and their rows rest on reading alone.

---

## 1. The exit provider serves an unopenable object of ours as `200` plus ciphertext

**This is a behaviour defect, not a coverage hole.** A test asserting the right
answer fails against the tree as it stands, so the code moves first.

`IsSegmentedObject` requires both the format id **and** a base64-decodable
`s3ep-encrypted-dek`. When an object carries `s3ep-gcm-seg-v2` but its wrapped key
is missing or unparseable, the predicate is false. Under an encrypting provider
false routes to `OpenSegmented` → `ErrForeignObject` → `403 InvalidObjectState`.
Under the exit provider, false **is the pass-through arm**, on all three read
paths:

- whole-object `GET` — `writeGetObjectResponse(w, output, "")`: HTTP 200 with the
  AES-GCM segment chain as the body and the stored length as `Content-Length`
- `HEAD` — skips `PlaintextSize` and reports the stored length as if it were the
  plaintext length
- ranged `GET` — takes the pass-through arm and serves a window of ciphertext as
  `206`

ADR 0025 forecloses this twice. Alternatives: *"An object that is ours and cannot
be opened is still refused: that is a missing key, not a foreign object."*
Consequences: *"The read path still refuses an object whose key material does not
authenticate."* ADR 0009 makes the `s3ep-` prefix the proxy's exclusive namespace
in both directions, so an object carrying the format id cannot be a foreign write.

The AES side of exactly this case **is** covered (`no_wrapped_key` → 403). None of
the exit-handler call sites constructs the shape: they cover no metadata at all, a
v4.0.3 aes-ctr object, a correctly sealed object, and a forged fingerprint whose
wrapped key is valid — that last one passes the predicate and is refused
correctly, which is why the suite looks complete.

- [x] Split the predicate: `ClaimsSegmentedFormat(metadata)` next to
      `IsSegmentedObject`, true when the algorithm is the format id whatever the
      state of the wrapped key
- [x] At each of the three exit gates, refuse with `ErrKeyMaterialUnreadable` —
      the `403 InvalidObjectState` the AES side already gives — when the object
      claims the format and cannot be opened. Nothing changes under an encrypting
      provider; there the two predicates already agree
- [x] One test per read path, each asserting `403 InvalidObjectState` and that no
      stored byte reaches the body, table-driven over a deleted and an unparseable
      `s3ep-encrypted-dek`
- [x] `docs/developer/storage-format.md` classes an object "carrying no wrapped
      key" as foreign. Under ADR 0025 foreign is precisely the class exit serves
      verbatim, so that sentence is what makes the defect look deliberate

## 2. The shipped `default.yaml` is never validated in CI

The assertion for this danger is already written, and it never runs:

```go
assert.Equal(t, "aes", cfg.Encryption.Providers[0].Type,
    "an exit provider here would start without a key and store plaintext")
```

`TestCfgDefaultConfigLoads` skips four lines earlier when `config/license.jwt` is
absent — it is gitignored, and the `unit-tests` job injects no licence secret.
It is the only test in the tree that puts `config/default.yaml` through `Load()`.

**(mutation-proven)** `config/default.yaml` switched to `type: "exit"` — the
active provider of the shipped image configuration becomes the one that stores
plaintext — and `go test ./internal/config/... -short` stays green.

- [x] Inject `S3EP_LICENSE_TOKEN` into the `unit-tests` job, the way the
      integration and conformance jobs already do
- [x] Re-run the mutation afterwards: with the licence present the test must fail

## 3. Nothing has ever run under `-race`

`grep -rn '\-race' Makefile .github/workflows/ scripts/` is empty. The proxy's
concurrency surface is the internal producer's worker pool and free list, the
multipart session map, the DEK LRU and the shutdown drain counters — every one of
them reached by `multipart_upload_concurrency`, whose default is 4.

The detector is dynamic: it reports only races on paths a run actually executes,
and it never reports a false one. So the flag is half the work and tests that
genuinely run things in parallel are the other half. The flag comes first because
it costs one target.

- [x] A `test-unit-race` target, and the same for the integration tag
- [x] A CI job running it. Separate from `unit-tests` because the detector costs
      roughly 2-20× runtime and 5-10× memory
- [x] Whatever it finds becomes rows here

## 4. Nothing pins the stored byte layout

Every codec test seals with this tree's writer and opens with this tree's reader,
so writer and reader can agree on a **different** layout and stay green. There is
no captured ciphertext anywhere in the repo: no testdata directory, no committed
golden file, no hex or base64 ciphertext literal in any test. Integration and e2e
cannot substitute — one binary writes and reads, and their `s3ep-gcm-seg-v2`
assertions cover only the metadata string, which a field reorder leaves untouched.

**(mutation-proven)** The AAD field order reversed **and** the trailer's
length/CRC positions swapped: `go test -short ./...` completely green. What *is*
caught is only the size arithmetic, by two literals in the codec test, so a
`SegmentSize`, `SegmentOverhead` or `TrailerSize` change fails — the field order
inside those sizes does not.

The intent to pin this already exists and was abandoned: `export_test.go` exports
`AADForTest` and **no test calls it**.

Two ways this ships without anyone touching the codec:

- the object key handed to `NewCodec` is the AAD's one variable field. Any change
  to how the handler normalises the key — URL-decoding, trimming, prefixing —
  silently rewrites the AAD for new writes. ADR 0023 is Accepted-but-unimplemented
  and puts exactly this in play: filename encryption is *"a rename pass, never a
  re-encryption"*, which holds only if the AAD keeps binding the client-visible key
- a cleanup of the trailer packer that switches to a struct reorders the fields
  for free

Consequence when it lands: every object written by the previous build answers
`403 InvalidObjectState`, and ADR 0017 D3 guarantees there is no way back — no
converter, no dual-format reader, no extraction procedure. ADR 0017 D10 forbids
that in a minor, and the suite cannot tell a minor from a format break.

- [x] A vector file of constants captured once from the current build and never
      regenerated: one sealed segment at index 0, one at a non-zero index (asserted
      to fail at index 0, which pins the 8-byte big-endian index and its position),
      one captured trailer with length and CRC asserted **separately** so a swap
      fails even when the two round-trip, and one whole small object read through
      the assembled reader
- [x] Assert `AADForTest` against captured AAD bytes — the cheapest pin of the
      field order, and it needs no ciphertext at all
- [x] A fresh test-only DEK literal, not one of the KEK fixtures already in the
      tree, so it can never be copied out of a test into a configuration (ADR 0021)
- [x] A header comment saying these constants describe the stored format, are not
      regenerated, and a failure here means the format changed (ADR 0003, ADR 0017 D10)

Out of scope for the vector and worth its own row: nothing pins *which* string is
passed as the object key. A vector pins the AAD's shape, not its content.

## 5. A readiness loop that never succeeds still passes

The three wait steps in the release workflow are `for i in {1..30}; do curl -f …;
done` with **no `exit 1` after the loop**, so the step exits 0 even if nothing
ever answered. The suite's own gate then turns that into silence:
`EnsureMinIOAndProxyAvailable` calls `t.Skipf` when MinIO or the proxy is
unreachable. An integration run in which every test skipped is indistinguishable
from a green one, and `make` reports success either way.

- [x] Fail each readiness step when its loop is exhausted
- [x] A floor in the suite: when a CI marker is set, an unavailable backend is a
      failure, not a skip

---

## Code the audit found, beyond row 1

- [x] **ADR 0011 D5 is not built.** D5: *"Across all sessions, buffered short-part
      bytes are capped by `optimizations.multipart_short_part_buffer_size`"*. The
      code bounds what **one** session may hold; no aggregate accounting exists, so
      N concurrent client-driven uploads can each park the full budget. The three
      tests naming the limit are all single-session. Decide whether D5 or the code
      is right, then close the gap on that side
- [x] **A large PUT cut short by the shutdown budget orphans a backend multipart
      upload the ADR 0029 sweep cannot see.** The internal producer creates a real
      backend upload and never registers it as a session —
      `RegisterSegmentedSession` has exactly one call site, the client-driven path
      — and the sweep walks only that map. `grep` for the producer entry point in
      the shutdown and orchestration tests is empty
- [x] **A licence that lapses at runtime calls `os.Exit(1)`** from the monitoring
      goroutine, straight past the whole ADR 0029 shutdown tail: no readiness 503,
      no drain, no `AbandonAllSessions`, no listener close. Every multipart session
      the process holds is abandoned without an abort, every transfer in flight is
      cut mid-byte. The only test asserts the exit code. Needs an injectable
      shutdown hook before it can be tested at all
- [x] **The two end-relative ranged reads take a HEAD and then a GET with nothing
      pinning them to one object.** The whole-object path has the `If-Match` pin
      and a test for it; the suffix and open-ended ranged paths discard the HEAD's
      ETag, so an overwrite between the two requests splices two objects
- [x] **The prefix body of a tail-first GET is closed by a `defer` whose guard no
      test can reach**: every mock wraps `io.NopCloser`, so the leak guard is
      untestable by construction. The production comment names the consequence —
      the body leaks and its connection is never pooled

## Tests proven to assert nothing

- [x] **The range tail test's negative case dies in `openSegment`**, so the
      trailer-vs-window length guard it is named for is pinned by nothing. **(mutation-proven:
      guard deleted, test still passes.)** The bare `assert.Error` is satisfied by
      `ErrCorrupt` arriving from the wrong place
- [x] **`TestChkTrailerBlockIsBounded` cannot fail**: its 50,000 junk lines are
      filtered before they can pressure the bound. **(mutation-proven: the
      `lines < maxTrailerLines && read < maxTrailerBytes` condition replaced by
      `true`, test and package still green.)** Both bounds are uncovered
- [x] **`perf-compare` judges absolute medians** instead of re-forming the
      proxy/direct ratio, under a 3 % noise floor its own README puts at ~10 %.
      **(mutation-proven: the reference leg slowed 10 % in the after-run artifact →
      "0 slower".)** Stronger still and needing no mutation: two committed
      baselines of the *identical* commit on the same machine already differ by
      more than the threshold
- [x] **`TestServerTLSConfiguration` skips both subtests on every run.** It reads
      `httpServer.Addr`, which is the configuration literal `localhost:0`, never
      the resolved listener address — so the skip condition is always true. The
      proxy's own TLS listener has no unit test that executes an assertion. Fix:
      take the port from the listener
- [x] **`"no plaintext byte is written before the refusal"` is the tautology
      `0 == 0`**
- [x] **The chart's `checksum/config` assertion compares against a stale literal**,
      so it is dead. The bug it was written for is caught by the Velero e2e, which
      is why nobody noticed
- [x] **`TestV8b`'s descriptor scan can match nothing and still pass** (ADR 0019 D12)
- [x] **The conformance refusal cost guard is vacuous**: the cost file sorts before
      the refusal file, so it lists a prefix nothing has written to yet. All three
      cost guards audit the *previous* run **(not probed)**
- [x] **`TestOptimizationsConfig` never compares the error message it declares**
- [x] **`TestRtPxMetadataPrefixResolution` pins a getter whose only consumer
      discards it**, and its empty-prefix case contradicts ADR 0009 D2
- [x] **The namespace assertion in the `BuildSegmentedMetadata` collision test
      cannot fail**, and its comment claims a guard the function does not have
- [x] **Seven subtests in the integration auth suite end in `t.Logf`**, two of them
      named after security boundaries
- [x] **The dead throughput gate** ADR 0020 D11 forbids: disarmed on every path
      that runs it. Deleting it loses no coverage
- [x] **`TestMultipartUploadCorruption` asserts nothing about size or hash**; its
      coverage is already given by the 1 GB comprehensive test

## Invariants nothing pins

- [x] **ADR 0002 D1 — "a data key is never reused across objects".** Hoist the
      `rand.Read(dek)` to a process-wide constant and every test still passes:
      stored bodies still differ (fresh segment nonces), envelopes still differ
      (fresh wrap nonces). No test unwraps two objects' stored envelopes and
      compares the keys
- [x] **ADR 0004 D7 — the wrap derivation labels `s3ep-kek-wrap-v1` and
      `s3ep-dek-wrap-v1`** have no known-answer vector, only a same-process round
      trip. Change either and every previously stored object's DEK becomes
      unopenable with the suite green. Neither string appears in any test file
- [x] **ADR 0028 D1 — expiry measured from the last part received.** The idle-clock
      test writes `lastTouched` by hand, so it proves only that the sweep compares
      against that field. **(mutation-proven: the four `touchLocked()` calls emptied,
      the whole unit suite green.)** No suite can catch it at runtime either: no
      configuration in the tree sets a non-default idle timeout, so every run sits
      at 3600 s
- [x] **The aligned last part of a client-driven upload.** All three orders in the
      part-size inference test end in the same unaligned 100-byte tail, the case
      that works. A last part that is segment-aligned and ≥ 5 MiB counts as a
      possible middle part: 10/10/6 MiB in order 3,1,2 fails `Complete` with
      `ErrPartTableInvalid` after every byte was transferred; in order 1,2,3 it
      succeeds. **(verified by running both orders.)** The guard that turns the bad
      inference into a refusal rather than a corrupt object is reached by no test —
      delete it and the suite stays green while a completed upload stores 27 MB that
      reads back as an authentication failure
- [x] **`multipart_upload_concurrency` has no behavioural test**: pin the producer
      to one worker and every package stays green
- [x] **ADR 0003 D5 — the bucket is absent from the associated data** — is asserted
      by no test
- [x] **A completed upload freeing its session** is unasserted; only the abort path
      is pinned
- [x] **A real `AbortMultipartUpload` driven from the sweep** is never observed at
      any layer; the abandoner closure is unexercised
- [x] **The four listener budgets reaching the data-plane server** are unasserted,
      and the download-side integration guard cannot detect a `WriteTimeout`
      regression — its payload is too small to hold the server in `Write`
- [x] **The shutdown deadline's anchor**: no test pins it to the shutdown start,
      and the anchor is written twice by hand
- [x] **ADR 0025 D10 and ADR 0013 D5 — the two startup warnings** (an active exit
      provider stores new objects unencrypted; a plain-HTTP backend carries
      credentials and keys in clear) live only in `main.go` and are asserted nowhere
- [x] **ADR 0013 D8 — `pprof_enabled` stands on its own.** The rule is one `if`
      outside the monitoring block, in untested wiring; re-nesting it restores the
      defect the comment there records
- [x] **A configured `max_presign_expiry_seconds`** is never driven through
      authentication; both ceiling cases use the unset fallback. The trailing edge
      of the pre-signed grace window is unpinned in both directions
- [x] **Route-to-auth binding is pinned for 6 of 31 routes.** A route on the health
      router, or a new root-router route the catch-alls do not shadow, serves
      unsigned with no test failing
- [x] **A GET/HEAD of a zero-byte backend object** is never tested; the
      416 → `ErrForeignObject` mapping is unexercised
- [x] **Neither `ErrCorrupt` guard in the tail fetch is reached**, and the case
      named for the length guard exits three lines earlier
- [x] **Every ranged-read fault injection hits the first segment of the window**; a
      fault in a later segment is untested
- [x] **An unimplemented algorithm named in `X-Amz-Trailer`** is never tested; only
      the request-header form is
- [x] **The 5 MB floor on `multipart_short_part_buffer_size`** has no test
- [x] **`config/multi-example.yaml` is the one shipped config nothing loads**, so
      decode is its entire coverage
- [x] **`cmd/keygen` has no test file.** It produces the KEK an operator pastes
      into the configuration, so two contracts are unpinned: that its output is
      accepted by `validateAESKey`, and that its banner layout stays the one the
      documented `sed -n 2p` depends on. Its printed instructions also name an
      environment variable nothing in the tree reads

## Tests that test something other than their name

- [x] **The four untagged `bucket_{acl,cors,location,logging}_test.go` files are
      129 test cases that import no package of this project.** `grep -n
      "s3-encryption-proxy"` on all four returns nothing. They assert the test
      file's own helpers and SDK constants against themselves. They run under
      `make test-unit` and are documented as "offline XML and validation tests".
      Delete them, or rewrite them against the bucket handlers
- [x] **The 39-cell sub-resource matrix runs against a hand-copied router** with no
      middleware, and its comment claims a drift check it cannot perform — nothing
      in the file reads the real route table. Neither ADR 0007 guard derives its
      parameter set from the router, so a newly added sub-resource route is
      exercised by neither
- [x] **The batch-delete shape test pins the missing S3 namespace on
      `<DeleteResult>` as expected behaviour**, against ADR 0008 D3 and the file's
      own oracle contract **(not probed)**
- [x] **`TestSegmentedTrailerAnswersHead` never opens the trailer** it is named for,
      and its comment describes the pre-D14 HEAD
- [x] **"A refused upload must leave no object behind" is asserted as any error**,
      so a 403 from a committed truncated object reads as success
- [x] **The owner-guard source walk checks the field is present**, not that it
      carries the client's value
- [x] **The S3 namespace is asserted on 5 of 12 bucket sub-resource documents**
- [x] **No LIST entry's ETag is read by any end-to-end test**, so no run proves
      LIST, GET and HEAD name the same entity tag against a real backend
- [x] **The unsatisfiable-range table holds a byte-identical duplicate** whose
      comment describes a backend-416 path the test never reaches
- [x] **The exit-provider ranged sub-test pins a 206 that contradicts the project's
      own recorded decision**, using a scenario no real backend produces, while the
      reachable scenario is untested
- [x] **Three comments in the out-of-order multipart test still describe the deleted
      AES-CTR ordering pipeline**, contradicting the subtests below them
- [x] **The sealed-CRC detector test discards the released plaintext.** At an exact
      segment multiple the reader has already released every byte before the trailer
      is read, so ADR 0003 D6 — *"checks the trailer's length and checksum against
      the bytes it produced before it releases the last segment"* — does not hold at
      that size, and the test picks precisely that size. Measured: 131072 of 131072
      bytes released before the error. Decide whether D6 is the promise or the
      implementation is; today the ADR, the code and the prose invariant in the
      tamper test disagree with each other
- [x] **A stale comment on the GET path** claims closing the reader is what makes a
      failure visible; the codec reader's `Close()` returns nil unconditionally and
      the error path skips it anyway

## Green by skipping

- [x] **`t.Skip(err)` as error handling**: eight occurrences in the memory
      measurement alone, plus the only real `/metrics` scrape and the only CORS
      document round trip. The CORS one goes through the proxy, so an error there
      is as likely the proxy's as the backend's — and the comment above it records
      exactly that defect once happening
- [x] **MAIN GOAL 3 has no gate.** The memory test says so itself: *"It records
      only: the bound is not asserted here."* The container limit is logged, never
      asserted, and `test/perf` runs in no CI job. Nothing fails if peak RSS starts
      scaling with object size
- [x] **The throughput size set never reaches the multipart producer**, though its
      comment says it does
- [x] **20 hex dumps of plaintext payloads** sit on the success path of the
      360-degree suites, against WORK ORDER 1. The comparison itself correctly uses
      SHA-256
- [x] **The conformance seed-completeness check runs last** and covers 7 of 17
      seeded objects, so the precondition it exists to enforce lands after the
      cascade it was written to pre-empt
- [x] **Nothing couples the conformance run script's segment size to the corpus
      size**, so the multipart split can stop happening silently
- [x] **The conformance budget's ceiling refusal is untested and its zero-limit
      branch unreachable**; ADR 0027 D4 claims an enforcement its own residual-risk
      section retracts

---

## What was refuted, so nobody re-opens it

Nine findings did not survive the second reader, and they are worth recording
because each names a place that looks thin and is not: read-side metadata lookups
**are** pinned case-insensitively; "four keys and no more" **is** checked as set
equality on stored metadata, not as a denylist; the metadata-leak fix **is** pinned
on the ranged exit arm as well as the whole-object GET; a part refused for a bad
digest **is** checked against the backend; the 5 MiB half of the hold rule **is**
covered; a ranged read starting inside part 2 or later **is** exercised; the
truncated-body-with-declared-checksum branch **is** tested; the at-rest gzip
assertion is **not** satisfied by the format's nonce alone; and the e2e preflight
does assert more than the chart's own render.

The tamper suite is the model the four vacuous tests above should be rewritten
against: it asserts exact released-byte counts rather than "an error arrived".

## Deliberately not in this ticket

- **Coverage percentage.** Nothing here is about a number going up.
- **Style, naming, `t.Parallel`, table-driven-ness.** None of it changes whether a
  test can fail.
- **The four probes that could not run offline.** They are marked and rest on
  reading; running them needs the docker environment and is worth doing when the
  rows are worked, not before.

## Done when

- [x] Rows 1 to 5 are on the branch and each is re-verified by re-running the
      mutation that proved it
- [x] Every remaining row is either done, or moved to a ticket of its own with a
      reason
- [x] The ADR contradictions this audit surfaced are settled in the ADR or in the
      code, not left as a disagreement: ADR 0011 D5, ADR 0025 (the exit refusal),
      ADR 0003 D6, ADR 0027 D4
- [ ] The suites that need a backend are green: `make test-integration`,
      `make test-integration-tls`, `./scripts/conformance-run.sh minio` and
      `make e2e-velero`
- [ ] `git grep 030` is empty outside this directory, and this file is deleted
