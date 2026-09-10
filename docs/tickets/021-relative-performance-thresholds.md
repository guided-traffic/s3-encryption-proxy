# Ticket 021: The local performance baseline, and the CI leftovers of the old gate

## Status (2026-09-09)

**Rewritten.** This ticket used to build a threshold gate on the continuous-integration
runner. That gate is gone: measuring one commit against another is a local act on one
machine, continuous integration measures once and publishes, and no performance number
fails a build. The decision and its cost are in
[ADR 0020](../adr/0020-performance-is-measured-before-and-after.md), amended 2026-09-09
(D6, D7, D8, D10, D11, D12 and D17 changed; D18 to D22 added). Everything this ticket used to say
about recording runs on the runner, deriving 20 % headroom and enabling assertions is
**cancelled**, not deferred.

What is left is two things: the local suite, which is **built and has produced its
pre-v2 baseline**, and a list of leftovers in continuous integration that only made
sense while a gate was coming.

## Done (2026-09-09)

The local baseline suite exists and has run.

- Build tag `perf`, referenced by no workflow, so continuous integration cannot pick it
  up and does not grow with it (ADR 0020 D18).
- `make perf-baseline`, `make perf-baseline-quick`, `make perf-baseline-offline`.
  `S3EP_PERF_REPS`, `S3EP_PERF_LABEL`, `S3EP_PERF_MAX_SIZE`, `S3EP_PERF_OUTDIR` and
  `S3EP_PERF_PROFILE_SECONDS` steer a run.
- Seven instruments, the complete set ADR 0020 D17 requires before the storage format
  change: whole-object throughput on both transports, ranged reads, small-object request
  rate, key unwrap, the in-process crypto floor, proxy resident memory, and CPU and heap
  profiles. The unwrap and the crypto floor need no stack and are the only "before" that
  survives the rewrite unchanged.
- One record per run: `run.json` (schema 1) and `REPORT.md` beside it, under
  `perf-baseline/<UTC timestamp>-<commit>/`. Every measurement has the same shape, so two
  runs diff mechanically; ratios are derived when the summary is rendered, never stored
  (ADR 0020 D20).
- The machine is recorded with the numbers: processor, core counts, memory, operating
  system and kernel, toolchain, container runtime, power source, load average before and
  after, the commit and whether the tree was clean (ADR 0020 D19).
- A row whose spread across repetitions is wide is marked as carrying no comparison
  value (ADR 0020 D21).
- Every bucket the suite writes to is emptied before and after, paged to the end
  (ADR 0020 D13).

The **pre-v2 baseline is recorded** under `perf-baseline/`. It is the "before" column
that [013](013-storage-format-v2.md) is judged against, and re-running the same command
on the post-change commit is the "after".

## Open — leftovers of the cancelled gate

All on `main`, all in continuous integration, none of them a gate. They exist because a
gate was coming; with no gate they are dead weight or active harm.

- [ ] **1. Delete the disarming switch and the dead threshold branch.** With no
      assertion left there is nothing to disarm. `SKIP_PERFORMANCE_CHECKS` in
      `.github/workflows/release.yml` (four places), in `performance.sh`, and both it and
      `SKIP_PERFORMANCE_TESTS` in `test/integration/performance-test/performance_test.go`,
      together with the `minEfficiency` branch and its continuous-integration relaxation.
      The step keeps measuring and keeps publishing; it stops pretending it could fail.
- [ ] **2. Delete the duplicate measurement run.** `performance.sh` runs the comparison a
      second time to generate the report and the badge. Generate both from the measured
      run's own output instead: it is half the wall clock and it removes the possibility
      of a published number disagreeing with the one that was measured.
- [ ] **3. Delete the module-cache wipe from `performance.sh`.** It wipes a shared
      runner's Go module cache for every other job on that machine.
- [ ] **4. Clean the comparison bucket in the continuous-integration test too.** The
      encrypted comparison bucket is never cleared and the listing is not paged, so every
      repeat run measures against a fuller backend (ADR 0020 D13). The local suite already
      does this; the CI test does not.
- [ ] **5. Rename the published summary to what it measures.** `Encryption Overhead` is
      not the cost of encryption — it is a proxy path against a direct path, with one
      plaintext hop and one TLS hop on the proxy side against one TLS hop on the direct
      side (ADR 0020 D16). Its own commit, because the string is a parsed interface: the
      workflow greps it, `performance.sh` matches it twice, and a positional `grep -A 3`
      reads the block under it.
- [ ] **6. Keep the step from growing.** The continuous-integration measurement stays one
      run per size. Repetition, more sizes and new instruments belong in the local suite
      (ADR 0020 D22).

## Done when

- [ ] `grep -rn "SKIP_PERFORMANCE" --exclude-dir=graphify-out` returns nothing outside
      this ticket. The knowledge-graph artefacts under `graphify-out/` carry the string
      inside copied ticket text and clear on the next graph rebuild.
- [ ] The performance job runs the measurement once, publishes from that run's own
      output, and no longer wipes the module cache.
- [ ] The published summary names what it measures, and both parsers follow the rename in
      the same commit.
- [ ] The continuous-integration performance step is no slower than it is today.
