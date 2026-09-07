# ADR 0020: Performance is measured before and after, never asserted

## Status

Accepted. Date: 2026-09-07.

**Partly implemented.** Implemented today: the performance suite measures both legs of every
size — the proxy path and a direct-to-backend path — in the same run and computes a ratio from
them; one response-copy comparison has been run under these rules, with its decision rule fixed
before the run and the losing path deleted rather than left switchable. Decided and specified,
not implemented: the ratio is still not enforced (the assertions are disarmed by an environment
switch on every step that runs them), no thresholds have been recorded, the measurement
environment is not cleaned between runs, the memory bound is not a test, the runtime memory
limit is not set in the shipped compose environment or chart, the ranged-read benchmark does not
exist, and the deferred key-unwrap measurement has no instrument. The enforcement work is
independent of the release train; the runtime memory limit and the memory test ride 5.0.0 with
the storage format change.

## Context

Performance is a stated product goal, ranked directly behind encryption at rest. That makes it
exactly the kind of goal that gets argued rather than measured, and the project has now twice
found a confident performance claim that was wrong about its own tree.

**A buffer optimisation whose premise did not hold.** A pooled 128 KiB response-copy buffer was
reported as being silently switched on and off by an unrelated monitoring flag, because the
standard library's copy helper prefers a destination's own read-from method over any supplied
buffer, and only the monitoring wrapper hid that method. The reasoning was correct and the
premise was false: a second, unconditional wrapper on every S3 route hid the same method in both
modes, so the pooled buffer was always the copy path. There was no performance defect. What was
real, and twice as broad as reported, was a capability loss — both wrappers dropped the
passthroughs that let a handler flush or hijack a response, on every route in both modes — and
it had been attributed to a flag that turns out not to matter. When the comparison was finally
run, the benchmark had to be written first: nothing in the tree could resolve a response-buffer
change at all.

**A crypto floor that was a third transport.** An earlier round closed with "42 % crypto floor"
in the proxy's CPU profile. Attributing the profile showed that roughly ten of those points sat
under the TLS records of the proxy-to-backend hop, not under object encryption; the real
data-crypto floor was about 32 %. The same round's 1 GB benchmark turned out to exercise the
client-driven multipart handler rather than the internal upload path it was believed to measure,
which is where its unexplained allocation residual had been hiding the whole time.

Both are one failure: a number quoted without an instrument that could tell the competing
explanations apart.

**Absolute thresholds measure the runner.** The suite already computed a proxy-versus-backend
efficiency percentage and then threw the assertion away, because absolute throughput numbers on
a shared self-hosted runner go red on load rather than on regressions — a 100 MB case failed at
17.6 % inside the full suite and passed when run alone. The single threshold left in force was
15 % in continuous integration: the proxy would have had to be more than six times slower than
the storage behind it before anything went red, and even that was disarmed by an environment
switch. One measurement was polluted as well — the encrypted comparison bucket was never
cleaned, so every repeat run measured a baseline against a fuller backend.

This mattered more than ordinary test hygiene because of what is about to land: the storage
format change (ADR 0003) rewrites the entire crypto path, and its own success criterion is "does
not regress on upload, on download or on small objects". Without a gate, that criterion is a
human reading two log files.

Two further forces shaped the rules below. A redundant key unwrap on every whole-object read
costs 392 ns with a local AES key encryption key and about 0.94 ms with a 2048-bit RSA one,
which roughly halves that provider's read ceiling — but it sits on a path the format change
rewrites, and with a KMS-backed key encryption key (ADR 0005) it becomes a second network round
trip rather than a microbenchmark. And the proxy container runs with Go runtime defaults inside
a 512 Mi limit, garbage collecting roughly every 100 MiB allocated.

## Decision

**D1.** A change made for performance carries a benchmark before and after: fresh stack, at
least three runs, median reported, against a baseline measured on the same machine on the
pre-change commit. A number quoted from an earlier round or from different hardware is not a
baseline.

**D2.** Where two candidate paths exist, both are measured and the loser is deleted. A
performance choice is never left configurable, and never left reachable by accident of
middleware composition or of an optional feature being enabled — a choice that depends on the
deployment is a choice nobody made.

**D3.** The decision rule of a comparison — the margin that decides it and the tie-breaker — is
written down before the run, and the instrument's bias is stated with the result.

**D4.** If a benchmark regresses, work stops and the regression is reported. It is never shipped
with an explanation attached.

**D5.** A performance defect on a path that a scheduled format change rewrites is not patched in
isolation. The deferral records the obligation to measure the same thing after the rewrite, the
baseline number to beat, and the instrument that will do it — and the instrument is built if it
does not exist. A deferral without that record is not a deferral.

**D6.** The continuous-integration performance gate is a ratio between the proxy leg and a
direct-to-backend leg measured in the same run of `make test-integration-performance`, which stays
an isolated step so the rest of the suite is not the load it measures. The gate is never an
absolute throughput number.

**D7.** Per size and per repetition, both legs are measured with the leg order alternating
between repetitions, and the assertion is on the median of the per-repetition ratios. At least
three repetitions, so that a load spike inside one leg produces one bad ratio that the median
discards.

**D8.** Thresholds are recorded, not invented: at least three separate runs on the actual runner
with the assertions still disarmed, then derived mechanically as 20 % headroom below the worst
observed ratio. The recorded table carries the absolute throughput of both legs and enough
identification of the runner and the stack to reproduce the run.

**D9.** A ratio worse than roughly a third of the direct path is a finding and is reported as
one, rather than encoded as a threshold.

**D10.** Thresholds are re-recorded whenever a change is expected to move throughput, not only
after the change that prompted them. An improvement raises the threshold with it; keeping
yesterday's number after a known gain stops the gate catching tomorrow's loss.

**D11.** No switch disarms the performance assertions. The only legitimate skip is the suite's
own availability check when the backend or the proxy is unreachable (ADR 0019). A convenience
mode that shortens a local run may exist, provided the gated run still covers every size.

**D12.** A new benchmark is born with a direct-to-backend leg and a row in the threshold table,
or it is not a gate. A test that measures one leg is a profiling harness and is named as one.

**D13.** The measurement run cleans up after itself — every bucket it writes to, paged to the
end. Cleanup is not optional and not behind a switch: a baseline measured against a backend that
is fuller on every repetition is not a baseline.

**D14.** Memory is held by a test that fails on a hard bound, not by a manual measurement. The
test samples `process_resident_memory_bytes` from the proxy's own metrics endpoint and asserts
peak-minus-idle against a bound expressed in the configured `optimizations.streaming_segment_size`
and `optimizations.multipart_upload_concurrency`. Logging the number instead of failing on it is
not sufficient.

**D15.** The Go runtime memory limit is set explicitly rather than left to the default:
`GOMEMLIMIT` as a visible value in the shipped chart and compose environment, defaulting to 80 %
of the container memory limit (`400MiB` for the shipped 512 Mi), documented next to that limit.
`GOGC` keeps its default and is never disabled while any client-controlled full-body allocation
exists. The value ships only if the memory test stays green under it and the benchmark shows a
gain; no gain, and it is dropped before the release.

**D16.** Absolute throughput of both legs is logged and published alongside the ratio, and the
published number is described for what it measures — a proxy path against a direct path, with
one plaintext hop and one TLS hop on the proxy side against one TLS hop on the direct side. It
is not "the cost of encryption" and is not labelled as such.

## Consequences

* Every performance change costs a measurement round. A one-line change that is obviously faster
  still needs an instrument, and sometimes the instrument has to be written before the change
  can be judged. Drive-by optimisation is out.
* The gated run gets more expensive: three repetitions across ten sizes move roughly 20 GiB
  through loopback, minutes of wall clock on a shared runner. It is paid for by deleting a
  duplicate measurement and by generating the report and the badge from the gated run's own
  output instead of re-running the suite — which also removes the possibility of a published
  number disagreeing with the gate.
* With 20 % headroom, a 10 % regression passes. Accepted deliberately: a gate tight enough to
  catch 10 % on this runner would be red half the time for reasons unrelated to the code.
* Thresholds are a standing maintenance obligation. Every deliberate throughput change costs
  three recording runs and an edit, and a threshold nobody re-records silently stops meaning
  anything.
* Deferring a known defect creates paperwork whose value depends entirely on somebody reading it
  later. The obligation to measure after the rewrite is written into the rewrite's own success
  criteria for that reason, not left in a note.
* Setting the runtime memory limit raises steady-state resident memory by design. Operators who
  change the container memory limit must move the runtime value with it, and benchmark baselines
  taken before the change do not carry over.
* Until the thresholds are recorded there is no gate, and the largest change to the crypto path
  in the project's history is developed against human judgement. Enforcement cannot precede the
  recording runs; that ordering is accepted, which is why the recording is scheduled ahead of
  the format change rather than after it.

## Alternatives Considered

**Absolute throughput thresholds in continuous integration.** Rejected. On a shared self-hosted
runner the number the assertion compares against is a property of the machine at that minute.
This is not a prediction: it is why the thresholds were disarmed in the first place and stayed
disarmed.

**Serialising the performance package and keeping absolute thresholds.** Kept as far as it goes
— running the performance measurement alone removes the load the rest of the suite creates — but
rejected as the gate. It does nothing about a second job, a dependency-update run or another
developer's cluster on the same machine.

**An absolute time series stored across runs, with trend alerting.** Rejected for now. It is
infrastructure to own, and it answers a different question than the gate does: it would catch
the uniform slowdown the ratio is blind to, at the price of a second thing to keep honest. The
absolutes are logged so this stays available later.

**Waiting for the storage format change and picking thresholds once.** Rejected. Threshold
picking is the cheap half — three recording runs are three ordinary runs — while not enforcing
until afterwards means the biggest rewrite of the crypto path is merged with no gate at all. The
pre-change table is also precisely the "before" column that rewrite needs, measured by the same
harness on the same machine.

**Leaving both copy paths reachable and choosing per deployment.** Rejected. That is the defect
itself, generalised: a measured choice that depends on an unrelated flag. Making the winning
path unconditional by construction, and asserting in a test that the losing one stays
unreachable, is what keeps the choice a choice.

**Patching the redundant key unwrap immediately.** Rejected. The path is being rewritten, the
work would be discarded, and the shortcut is not free — the cached key is cache-owned, and a
naive fix that zeroizes it corrupts every later cache hit into a silent decryption failure. The
obligation to measure it after the rewrite is recorded instead, with the baseline number.

**Tuning garbage collection aggressively alongside the memory limit, or disabling it.**
Rejected while any full-body allocation under client control exists. Near-limit operation with
collection off is an out-of-memory kill, not a speed-up.

**Pinning the process's CPU count explicitly in the container.** Moot rather than rejected: on
Linux the Go runtime has derived it from the cgroup CPU limit since Go 1.25, and the shipped
image builds with a newer toolchain than that.

## Residual risks

* **Accepted: the ratio is blind to a uniform slowdown.** If the backend regresses, or the
  runner is re-provisioned on slower disks, both legs move together and the gate stays green.
  The absolutes are logged for the human who eventually notices. No alerting is proposed.
* **Accepted: regressions smaller than the headroom pass unseen.**
* **Accepted: only the measured shapes are covered.** A fixed set of object sizes, one upload
  style per size, whole-object reads, one concurrency, one client transport. Ranged reads are
  not gated until that benchmark exists with a direct-backend leg; small-object request rate is
  not covered at all today.
* **Not verified: that runner noise is common-mode across both legs.** The premise the whole
  ratio design rests on is reasoned, not measured. The recording runs are the measurement, and
  if the per-repetition ratios inside one run scatter as widely as the absolutes do between
  runs, the premise is wrong and the design needs more repetitions or a gate restricted to the
  large sizes. This must be checked explicitly when the first table is filled.
* **Not verified: that three runs are three samples.** If the runner happens to be equally idle
  for all three, the "worst observed" is not a worst case and the first busy run after
  enforcement is red. The answer is to re-record and write the re-recording into the table, not
  to lower the number by feel.
* **Open: whether the smallest sizes can be gated at all.** A sub-megabyte round trip takes
  milliseconds and scheduler jitter is a large fraction of it. The standing recommendation is
  to gate them at a deliberately loose threshold and say so in the table; leaving them
  report-only until a small-object benchmark exists is the other option, and neither is
  confirmed. Quietly picking a threshold that nothing can fail is excluded either way.
* **Open: whether the gated run covers both listener transports.** Today it measures the
  plain-HTTP listener only, so a regression confined to the trailer-framed chunked upload path
  — the default for modern SDKs over HTTPS — would not be caught. Doubling the gated run is the
  obvious answer and the obvious cost. It changes what the threshold table must contain, so it
  belongs before the table is filled.
* **Open: the published summary describes the ratio as encryption overhead**, which D16 says it
  is not. Renaming it is recommended and touches strings that the reporting and badge steps
  parse, so it is a deliberate interface change of its own.
* **Open: one response body copy is still unpooled.** The ranged-read response does not use the
  pooled buffer, and that is the path every ranged read takes. Found while measuring something
  else, deliberately not changed in that measurement, still awaiting a decision.
* **Not verified: that the runtime memory limit delivers the predicted CPU gain.** It is a
  3–5 % expectation from a profile, and it ships conditional on the memory test and the
  benchmark confirming it.
* **Not measurable over a real network yet.** While a whole-transfer wall clock is still in
  force (ADR 0015), a single large download below roughly 35 MB/s fails outright instead of
  reporting a poor number, so only loopback measurements can be trusted until that release
  lands.

## References

* ADR 0003 — Objects are stored as an authenticated segment chain
* ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
* ADR 0006 — The proxy serves any S3 client
* ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
* ADR 0017 — Stored data compatibility is not owed; a major release may break the format
* ADR 0018 — A major release is declared by a label, never discovered at merge
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0022 — Tickets are work lists that get deleted; decisions live in ADRs
* [README.md](../../README.md) — the performance optimisation settings and the test targets
