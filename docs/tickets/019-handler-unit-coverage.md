# Ticket 019: Test-suite hygiene

## Status (2026-09-10)

**The coverage work this ticket was opened for is done**, and not through this
ticket: the handler tests were written during the pre-merge fix round and then
migrated to the segment chain with the format change. Measured on HEAD with
`go test -short -cover ./internal/proxy/...`:

| Package | Coverage |
|---|---|
| `internal/proxy` | 100 % |
| `handlers/object` | 95.7 % |
| `handlers/bucket` | 100 % |
| `handlers/multipart` | 97.7 % |
| `handlers/root` | 100 % |
| `handlers/health` | 100 % |
| `middleware` | 99.4 % |
| `request` | 99.4 % |
| `response` | 97.1 % |
| `utils` | 94.2 % |

Every floor the original ticket set is met, and the analysis it carried — 682
lines of per-function figures from 2026-09-06 — described a tree that has been
rewritten twice since. It is gone rather than updated; the numbers above are the
only ones that are true.

What is left is not coverage. It is the suite's own quality, and it is worth
doing because [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md)
calls these suites the product.

---

## Work list

- [ ] **One shared backend mock.** Four copies of `MockS3Backend` exist —
      `handlers/object`, `handlers/bucket`, `handlers/root` and
      `handlers/multipart` — and **none** carries
      `var _ interfaces.S3BackendInterface = (*MockS3Backend)(nil)`. A method
      added to the 58-method interface therefore breaks four files, or worse,
      breaks none of them and lets a mock drift out of shape without the
      compiler noticing. One mock in its own internal package, with the
      assertion.

- [ ] **`UploadPart` reads the body before it validates.**
      [upload.go](../../internal/proxy/handlers/multipart/upload.go) calls
      `ReadBody` and only then checks for an empty `uploadId` or `partNumber`.
      A request with neither has its whole body read into memory first. Move the
      parameter checks ahead of the read.

- [ ] **Four skips that assert nothing** (ADR 0019 D2, D4). Two more were
      removed on 2026-09-10 — an integration subtest whose body was a bare skip,
      and a placeholder file that only skipped — and these are what is left:
      - `internal/config/config_test.go:12`, `:231`, `:278` — three tests skipped
        for `tink`, a provider type configuration validation refuses at startup.
        They can never run. Either delete them or turn them into the assertion
        that the type *is* refused.
      - `test/integration/authentication/auth_test.go:437` — skips whenever the
        metrics endpoint cannot be reached, which green-lights a broken listener
        instead of failing on it. The monitoring listener is part of the proxy;
        D4's carve-out is for an unreachable backend, not for a component under
        test.
      - `test/integration/encryption_validation_helper.go:359` — an assertion
        helper that skips instead of failing when handed empty input. That is
        the "assertions that never read anything" case ADR 0019 exists to end.

- [ ] **The test tree is not linted at all.** `make lint` and the pipeline both
      run over `./...` without build tags, so every `integration`- and
      `e2e`-tagged file is invisible to them. `golangci-lint run
      --build-tags=integration ./test/...` reports 38 findings today: 5 gosec,
      8 staticcheck, 13 revive, 5 unused, 4 errcheck, 2 ineffassign, 1 misspell.
      Decide whether the test tree joins the gate; if it does, the `revive`
      argument-order findings want fixing across all files at once rather than
      file by file, because the suite's helpers share a `(t, ctx, ...)`
      convention.

- [ ] **`manager.NewUploader` is deprecated** in the AWS SDK, superseded by
      `feature/s3/transfermanager`. Three call sites in
      `test/integration/360-degree-variants/comprehensive_multipart_test.go`.
      Found by the lint run above; it will not go away on its own.

- [ ] **Stale in-source markers** (ADR 0019 D16). Roughly 23 tests under
      `internal/orchestration/` still carry "the segmented-GCM format (ADR 0003)
      replaces this; update together". That format landed and those tests did
      not move with it, because the code they pin is the previous format's and
      is reachable from no handler. They go with that code — see the deletion
      items in [013](013-storage-format-v2.md).

## Success criteria

- [ ] `golangci-lint run --build-tags=integration ./test/...` is either green or
      its remaining findings are a written, deliberate exclusion list.
- [ ] No test in the tree skips for a reason other than an unreachable backend
      or proxy.
- [ ] Adding a method to `S3BackendInterface` breaks compilation in exactly one
      place.
