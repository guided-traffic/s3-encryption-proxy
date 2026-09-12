# ADR 0020: Performance is measured before and after, never asserted

## Status

Accepted. Date: 2026-09-07.

**Amended 2026-09-09**, before a single threshold was ever recorded: **the gate leaves
continuous integration.** Comparing one commit against another is a local act on one machine, and
a shared runner cannot perform it — the repetitions it would need make an already long pipeline
longer, and every further test the project adds makes that worse. Continuous integration keeps a
single, unrepeated performance measurement and publishes what it measured; it never fails on a
performance number. The judgement about whether a change is faster or slower is made locally, by
running the same instruments on both commits on the same machine. D6, D7, D8, D10, D11, D12 and D17
change accordingly, D14 is explicitly carved out of D11, and D18 to D22 add the local baseline suite, what it records about the machine
it ran on, and the shape of its output.

**Partly implemented.** Implemented today: the performance suite measures both legs of every
size — the proxy path and a direct-to-backend path — in the same run and computes a ratio from
them; one response-copy comparison has been run under these rules, with its decision rule fixed
before the run and the losing path deleted rather than left switchable. The local baseline suite
of D18 exists, carries its own build tag, is referenced by no workflow, and produces the record
of D19 and D20. **D11 was built on 2026-09-12**: the minimum-efficiency assertion in the
integration performance comparison is gone, and so is the environment switch that disarmed it —
which every pipeline step that ran the test set, so the gate was armed only where nobody ran it.
The comparison measures and reports; nothing about throughput can turn a build red. The same day
the local comparison tool stopped judging **absolute medians** and started judging the
**proxy/direct ratio** with the reference leg's own move printed beside it: medians move with the
machine, and two runs of the same commit used to come back with 63 of 234 measurements marked
slower. **D14 became a test on 2026-09-12**: the memory instrument asserts what the load
costs — peak minus idle — against a bound derived from the two keys that size the producer's
buffers, and against the object size, so a proxy that started holding objects instead of streaming
them fails there rather than showing a larger number in a report. It fails in the **local** suite
only: D18 keeps that suite out of every workflow on purpose, so nothing in continuous integration
runs it, and that gap is real rather than implied. The memory instrument
itself was blocked until 2026-09-11: /metrics had stopped exporting
`process_resident_memory_bytes` when it moved off the default registry, so D14's figure could not
be read at all.

**Corrected 2026-09-12, two items this block used to carry.** The measurement environment *is*
cleaned, though not to the letter of D13: both comparison buckets are emptied at the start of
every run, so the proxy leg is no longer measured against a backend that grew by the whole matrix
on the previous run — but the emptying reads one listing page and logs a failure instead of
failing, so it is not the "paged to the end" D13 asks for. It covers what one run writes and
would not cover a bucket that had accumulated past a page. Nothing cleans the two comparison
buckets *after* a run at all: the one cleanup switch that exists purges the run's own scratch
bucket, not those two, and with it unset that scratch bucket is left behind on every run. The
pre-run emptying is the whole of what keeps a run off the previous one's data.

The second item is the runtime memory limit, and it is no longer outstanding: **it does not ship,
decided 2026-09-12, with D15 followed as written and unamended.** D15 makes the value conditional
on the benchmark showing a gain; the measurement shows the load never approaches the container
limit, so there is no mechanism for a gain, and no gain means it is dropped before the release —
which is what D15 says. Nothing in the tree sets `GOMEMLIMIT`, nothing is owed, and this block
used to say the limit rides 5.0.0 with the storage format change. The memory bound of D14 rode
nothing either: it remains unbuilt.

**The obligation this decision exists to enforce is met, 2026-09-11.** The after column is the
last of the three complete runs taken that day, the second of two labelled `post-v2-wave5`, every
instrument at `ok`, on the machine that took the `pre-v2` column, with its findings written the
same day. Claims about 5.0.0 are bounded by it: the upload deficit is gone (46-72 % of a direct
write before, 78-125 % after), the single-request write path is 0-8 % slower, downloads and the
crypto floor are unchanged, and peak resident memory fell from 130 MB to 109 MB against an
unchanged 512 MB container limit. Nothing below roughly 15 % end to end may be claimed at all:
three full runs within one hour, two of them on identical code, moved by that much.

**Three things qualify that column, stated 2026-09-12.** Its record marks the working tree as
not clean, which D19 records precisely so a reader can weigh it; so does the `pre-v2` column it
is compared against, so the two are at least alike in that. The revision it names is no longer in
this branch's history — the branch was rewritten afterwards — so the run is identified by its
timestamp and nothing else: its label is shared with an earlier run of the same day, and that
label plus the date does not pick one of the two. That is thinner identification than D8 assumes
when it makes a recorded run the unit of comparison. And performance work has landed on the write
and read paths since it was taken, with no run recorded after it; under D10 the after column is
therefore already the run to replace, not the state of the tip.

**The run found a defect, which is what D4 is for.** A ranged read fetched a provisional window
and consumed only the real one, so the backend body was closed with bytes unread and Go's
transport dropped the connection instead of pooling it. A 1 MiB ranged read ran at 155 MiB/s
against a backend doing 220, where pre-v2 it was 207 against 217. It is the path kopia reads on,
it had been in the release since the segment chain landed, and no gate would have caught it —
every functional suite passed throughout. It is fixed and the column above is the fixed code.

One thing the instrument cannot do, and the report has to say so: the format change, the producer
restructuring and the removal of the self-copy landed in **one commit**, so a before/after across
them measures the release and attributes nothing to any one of them. Separating them would mean
putting a switch into the product for the sake of a measurement, which D2 forbids in the general
case and which is not worth it here.

**Corrected 2026-09-12.** This paragraph used to say the full instrument set had only ever been
recorded once, before any 5.0.0 change, and that every later run was a two-instrument subset.
That was true when it was written and is not now: three runs of 2026-09-11 carry every instrument
at `ok`, the after column among them. D17's obligation — the complete set on the pre-change
commit, recorded before the rewrite lands — was met by the `pre-v2` column, which carries every
instrument except the upload-path one it predates; that one has its own pre-change run.

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
cost 392 ns with a local AES key encryption key and about 0.94 ms with a 2048-bit RSA one when it was first
measured, and 146 ns against 0.63 ms when the baseline suite recorded it on 2026-09-09,
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

**D6** (amended 2026-09-09). A performance number is always a **ratio** between the proxy leg
and a direct-to-backend leg measured in the same run, never an absolute throughput. Continuous
integration measures that ratio once and **publishes** it; it is a reported number, not a gate.
The measurement stays an isolated step so the rest of the suite is not the load it measures.

**D7** (amended 2026-09-09). Repetition belongs to the **local** suite, not to continuous
integration. Locally, both legs are measured per size and per repetition with the leg order
alternating between repetitions, and every reported figure is the median of the per-repetition
values, so that a load spike inside one leg produces one bad sample the median discards. At least
three repetitions; the suite defaults to more, because an unattended local run can afford them.
Continuous integration measures each point once: a test series there costs pipeline minutes that
buy nothing, since the number it produces is not judged against a threshold.

**D8** (amended 2026-09-09). Numbers are recorded, not invented, and a recorded run is the unit
of comparison — there is no threshold table any more, because nothing asserts against one. A run
is recorded by the local suite on one machine and carries the absolute throughput of both legs,
the ratio derived from them, the spread across repetitions, and enough identification of the
machine and the stack to reproduce it (D19). A change is judged by two such runs on the same
machine, one per commit, not by a number carried over from earlier hardware.

**D9.** A ratio worse than roughly a third of the direct path is a finding and is reported as
one, rather than encoded as a threshold.

**D10** (amended 2026-09-09). What used to be a threshold to re-record is now a **recorded run
to replace**. A baseline is re-taken whenever a change is expected to move throughput, not only
after the change that prompted it, and the newer run becomes the one the next change is judged
against. Keeping an old run after a known gain hides tomorrow's loss inside yesterday's slack —
the reason the old rule existed survives the removal of the thresholds it was written for.

**D11** (amended 2026-09-09). **No performance measurement fails a build.** Continuous
integration reports throughput and never turns red on it; the local suite records and never
asserts. This removes the switch the old rule forbade rather than legitimising it: there is no
assertion left to disarm, so there is nothing a switch could hide. The one thing that still stops
a run is the suite's own availability check when the backend or the proxy is unreachable
(ADR 0019), and a run that measured no stack says so in its own record rather than passing
quietly (D20).

This is about **throughput**. A throughput number is a property of the machine that produced it,
so asserting on one teaches people to ignore red. A **resource bound** is not: how much memory a
process holds under a defined load is a property of the code, it does not drift with runner load,
and exceeding it is a defect rather than a slow day. D14's memory test is therefore the one
performance-adjacent assertion that is allowed to fail a build, and it is the only one.

**D12** (amended 2026-09-09). A new benchmark of a request path is born **with a
direct-to-backend leg**, measured in the same run, or it is a profiling harness and is named
as one. A single-leg number cannot separate a slower proxy from a slower machine. The
instruments that measure no request path — a microbenchmark of a primitive, an in-process
crypto path — have no second leg to take and are exempt; they are compared against their own
earlier recording instead.

**D13.** The measurement run cleans up after itself — every bucket it writes to, paged to the
end. Cleanup is not optional and not behind a switch: a baseline measured against a backend that
is fuller on every repetition is not a baseline.

**D14** (bound extended 2026-09-09; carved out of D11 the same day). Memory is held by a test that fails on a
hard bound, not by a manual measurement. The
test samples `process_resident_memory_bytes` from the proxy's own metrics endpoint and asserts
peak-minus-idle against a bound expressed in the configured `optimizations.streaming_segment_size`,
`optimizations.multipart_upload_concurrency` and, since 2026-09-09,
`optimizations.multipart_short_part_buffer_size` (ADR 0011). Logging the number instead of failing
on it is not sufficient.

**D15.** The Go runtime memory limit is set explicitly rather than left to the default:
`GOMEMLIMIT` as a visible value in the shipped chart and compose environment, defaulting to roughly 80 %
of the container memory limit (`400MiB` for the shipped 512 Mi, which is 78 %), documented next to that limit.
`GOGC` keeps its default and is never disabled while any client-controlled full-body allocation
exists. The value ships only if the memory test stays green under it and the benchmark shows a
gain; no gain, and it is dropped before the release.

**D16.** Absolute throughput of both legs is logged and published alongside the ratio, and the
published number is described for what it measures — a proxy path against a direct path, with
one plaintext hop and one TLS hop on the proxy side against one TLS hop on the direct side. It
is not "the cost of encryption" and is not labelled as such.

**D17** (added 2026-09-09, amended the same day). A rewrite of a measured path is preceded by
the **complete instrument set** it will be judged with, run **locally** on the pre-change commit
and recorded before the rewrite lands: the throughput ratio on both listener transports, the
ranged-read benchmark with its direct-to-backend leg, the small-object request-rate benchmark,
the key-unwrap microbenchmark, the proxy's resident-memory numbers and the CPU profiles. A
benchmark born after the change has no "before" and cannot judge it. Two of these instruments —
the key unwrap and the in-process crypto floor — depend on no stack and no stored object, and are
therefore the only "before" that survives a storage format change unchanged; they are recorded
even when no stack is available. The published summary is renamed to what it measures, in a
commit of its own.

**D18** (added 2026-09-09). The instrument set of D17 lives in a **local baseline suite**: one
place, run on demand, carrying its own build tag so that no continuous-integration workflow can
pick it up by accident. It is repeatable — the same command on two commits produces two records
that differ only in what the code did — and it is the suite a rewrite is judged with. Adding an
instrument means adding it here; continuous integration does not grow with it.

**D19** (added 2026-09-09). A run records **the machine it ran on**, because a number without one
cannot be compared with anything: processor model, physical and logical core counts, memory size,
operating system and kernel, the language toolchain version, the container runtime, the power
source, and the load average before and after the run. It records the commit, whether the working
tree was clean, the repetition count, and the stack it measured — or, when there was none, why.

**D20** (added 2026-09-09). A run writes **one machine-readable record and one human-readable
summary**, side by side, under a schema version that is raised whenever the shape changes. Every
measurement has the same shape whatever produced it — instrument, transport, operation, subject,
size, unit, the raw samples, and the spread derived from them — so two runs diff mechanically
instead of being read. A ratio is derived when the summary is rendered and is never stored as a
primary number: the two legs it came from stay visible, and a missing leg shows as missing rather
than as a plausible ratio. An instrument that produced nothing records why, so a partial run can
never be mistaken for a complete one.

**D21** (added 2026-09-09). A measurement whose spread across repetitions is wide is **marked as
carrying no comparison value**, and the mark is part of the output rather than a footnote. This is
a reporting mark and not a gate: it tells a reader which rows of two runs may honestly be
compared, which is the whole product of a baseline.

**D22** (added 2026-09-09). Nothing about performance is allowed to make the pipeline longer than
the value it returns there. Continuous integration measures once, publishes, and moves on. When
the two are in conflict — a more trustworthy number against a slower pipeline — the number is
taken locally and the pipeline stays short.

## Consequences

* Every performance change costs a measurement round. A one-line change that is obviously faster
  still needs an instrument, and sometimes the instrument has to be written before the change
  can be judged. Drive-by optimisation is out.
* **Nothing mechanical now stops a regression from being merged.** With no assertion on a throughput number anywhere, the
  obligation of D1 and D4 — measure before, measure after, stop on a regression — rests entirely on
  the person making the change running the local suite on both commits. This is the price of the
  amendment and it is accepted knowingly: a gate on a shared runner that goes red on load teaches
  people to ignore red, which is worse than no gate. The obligation is written into the success
  criteria of the changes that need it rather than left to goodwill.
* A baseline is only worth what the machine that produced it is worth. Two runs on different
  machines, or on the same laptop on mains and on battery, are not comparable, which is why D19
  records both. A recorded run whose machine no longer exists is history, not a baseline.
* The expensive run moves off the shared runner and onto a workstation: repetitions across nine
  sizes on both transports move tens of gibibytes through loopback and take minutes to tens of
  minutes. That cost is now paid by whoever is making the change, at the moment they need the
  answer, instead of by every pull request.
* A number published by continuous integration carries no verdict. A reader who wants to know
  whether a pull request made the proxy slower has to run the local suite; the published figure
  answers "what did this stack do today", not "is this change a regression".
* Recorded runs accumulate. They are small text records and they are kept, because the value of a
  baseline is entirely in there being an older one to compare against; the profiles they reference
  are large, reproducible, and are not kept.
* Deferring a known defect creates paperwork whose value depends entirely on somebody reading it
  later. The obligation to measure after the rewrite is written into the rewrite's own success
  criteria for that reason, not left in a note.
* Setting the runtime memory limit raises steady-state resident memory by design. Operators who
  change the container memory limit must move the runtime value with it, and benchmark baselines
  taken before the change do not carry over.
* The largest change to the crypto path in the project's history is developed against human
  judgement reading two recorded runs. That is accepted, which is why the recording is scheduled
  ahead of the format change rather than after it.

## Alternatives Considered

**Keeping the gate on the shared runner (rejected 2026-09-09).** The ratio design was
built to survive runner noise, and it might have. What killed it was the arithmetic around
it: a trustworthy ratio needs repetitions, repetitions across nine sizes on two transports
move tens of gibibytes and take minutes, and the pipeline is already long and still
growing. A gate that makes every pull request slower, and that goes red on load often
enough to be ignored, buys less than it costs. Measuring once and publishing keeps the
number; the verdict moves to where the comparison is actually valid.

**Keeping the gate but running it only on a release branch, or nightly.** Rejected as the
worst of both: still a shared runner, still no repetitions worth the name, and now the
signal arrives after the change it should have caught was merged.

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
  machine is slower than it was, both legs move together and the ratio does not notice. The
  absolutes are recorded for the human who eventually does. No alerting is proposed.
* **Accepted, and now the central risk: a regression is caught only if somebody runs the
  local suite.** Nothing mechanical stops one from being merged. This is the price of the
  2026-09-09 amendment, taken knowingly.
* **Accepted: only the measured shapes are covered.** A fixed set of object sizes, one upload
  style per size, and the concurrencies the small-object instrument names. A shape the
  instrument list does not cover is not measured, and a claim about it after a rewrite is an
  argument rather than a number.
* **Not verified, and the first recorded run argues against the simple version of it: that
  spread is a function of object size alone.** The expectation was tight numbers on large
  objects and noise on small ones. The run half-confirms it. Small objects are noisy as
  expected, on reads as well as writes, and there the rate is not the number to read: they
  measure request latency, and their ratio is what carries meaning. Reads settle from a
  quarter of a mebibyte upward and stay settled to the largest size. Writes do not: the widest
  spread among the throughput rows is the largest upload, at a quarter of its own value, while
  the largest downloads sit near four percent. The widest spread in the run overall is not a
  throughput row at all — it is what the load costs the proxy in resident memory, at three
  fifths of its own value, which is the figure a memory bound would have to be picked from. Why the largest writes stay noisy is unexplained —
  the multipart pipeline's part concurrency is the obvious suspect and has not been examined.
  This is why a wide-spread row is marked as carrying no comparison value (D21) rather than
  quietly averaged.
* **Superseded 2026-09-09: everything about threshold picking.** There is no threshold table,
  so there is nothing to pick loosely, tightly or at all. The local run covers both listener
  transports because the trailer-framed upload path is the default for modern SDKs over HTTPS
  and was otherwise unmeasured.
* **Still owed: the published summary is renamed**, in a commit of its own. It survives the
  amendment because a number that names itself wrongly is wrong whether or not it gates.
* **Settled: the unpooled ranged-read copy is fixed** by the pooled-copy change that landed on
  `main`; its measurement is part of the baseline of D17.
* **The baseline is only as complete as the instrument list above.** A shape the list does not
  name — a concurrency, a client transport, a read mix — is not measured, and a claim about it
  after the rewrite is an argument, not a number.
* **Confirmed 2026-09-10, and it is what the rules exist for: a well-argued cause was wrong.** The
  upload deficit against a direct backend was attributed to the post-completion copy on the
  strength of an arithmetic model that fitted the measured ratios at three sizes. Timing the copy
  directly showed it running an order of magnitude faster than the model required — it is about a
  twentieth of the gap, not the whole of it — and a third proxy on the streaming path turned out
  to be *faster* than the backend it writes to. The cause is the store-and-forward shape of the
  multipart pipeline. A model that fits three points is not a measurement, and the instrument that
  settled it took under an hour to write because the harness already existed.
* **Settled 2026-09-12: the runtime memory limit does not ship, and D15 needed no amendment.**
  The 3–5 % expectation assumed the collector runs often because the process allocates its way
  there. Measured 2026-09-09 on the demo stack under a large-object load, the proxy settled at
  about 98 MiB resident, peaked at 124 MiB, and started from 22 MiB cold against a 512 MiB
  container limit; the 2026-09-11 after column lowered the peak again. A runtime limit at roughly
  80 % of the container limit is never approached by that load, so there is no mechanism for the
  gain to appear, and D15 already makes the value conditional on a measured gain. No gain, so it
  is dropped before the release, which is D15 followed as written. What is accepted with it: the
  proxy ships on runtime defaults and has no out-of-memory guard of its own, and a workload that
  does approach the limit has still not been measured.
* **Closed 2026-09-12: measurement over a real network.** The whole-transfer wall clock is gone
  — `read_timeout` and `write_timeout` default to no deadline (ADR 0015) — so a slow large
  download reports a poor number instead of failing outright. Every recorded run is still a
  loopback run, so nothing is *known* about a real network; what is gone is the reason it could
  not be measured.

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
