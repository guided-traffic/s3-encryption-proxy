# ADR 0019: Integration and end-to-end tests are the product; they are never skipped

## Status

**Accepted.** Date: 2026-09-07.

Built today: the integration suite runs against a real MinIO backend over both the plain-HTTP
and the TLS proxy endpoint (`make test-integration`, `make test-integration-tls`); the
end-to-end suite runs thirteen Velero backup and restore scenarios in a disposable kind
cluster (`make test-e2e-velero`), with the encryption-at-rest assertions read straight from
the backend; both suites are brought up by the same scripts on a workstation and on a CI
runner (`make e2e-up`, `make e2e-down`); the end-to-end job blocks the release job; the
end-to-end bring-up refuses to run without a license token supplied out of band; test doubles
have been moved out of the production build and the resulting coverage jump was reported as a
denominator correction rather than as new testing; tests that pin behaviour the next storage
format replaces carry an in-source marker saying so.

Decided and specified, not built: the performance comparison in continuous integration still
asserts a minimum ratio, and the pipeline still sets the switch that disarms it. Both go with
D11 of ADR 0020: removing the assertion is what removes the switch.

**Corrected 2026-09-12.** Two items that stood in that paragraph as unbuilt are built. The
end-to-end environment no longer runs the client's own published default repository password:
the bring-up generates one, and the preflight fails the whole suite if the repository was
created under the published default. And every version pinned in the environment's own
version file now has an automated update path, the four storage-driver sidecars that had none
included; those move as the single reviewed group D8 requires. Two pins sit outside that file and
outside that group: the object-store image, which is watched but is pinned to its last community
release and no further one is expected, so the path exists and will produce nothing; and the
workload image every scenario's pods run, pinned in the suite's own source, which nothing watches
at all. D8 asks for every pin the environment consumes, so it is not met yet.

**Corrected 2026-09-10.** Two items above were wrong. Handler-level unit coverage is no longer
deferred: it was written and has since been migrated to the segment chain, which also makes the
Consequences bullet about a regression surfacing only in a ten-minute suite false. And the
end-to-end health check *does* now fetch the client's own backup and restore logs; what it does
not do is run them through the forbidden-pattern scan it applies to the container logs, which is
the narrower gap that remains.

**Closed 2026-09-12 against D12.** That narrower gap is gone. The client's own backup and
restore logs are scanned with the same forbidden patterns as the container logs, nothing is
allowlisted, and an empty or unreadable log is reported as a failed fetch rather than passing as
a clean scan.

**Closed 2026-09-12 against D4.** All three places the re-enumeration of that day found are
gone: the authentication subtest that skipped whenever the metrics endpoint could not be reached
now fails on it, and both performance environment switches are deleted along with the throughput
assertion one of them disarmed (ADR 0020 D11 — there is no assertion left for a switch to hide).
Seven subtests in the same authentication suite that ended in `t.Logf` were given the assertions
their names claim, two of them security boundaries: an unsigned request, a signature that does
not verify and a request 20 minutes out of the skew window are each refused, and named.

The unit-suite item in this block was closed with the same wave: the test that loads the
configuration the image ships with takes its licence from the environment, and a run without one
fails instead of skipping.

**Closed 2026-09-12:** three of the six items that stood here went with the code they were in —
the integration subtest whose body was a bare skip with no condition, the unit-test file that was
a single always-skipping placeholder, and the three configuration tests skipped for a provider
type that is refused at startup.

Everything else that skips is legitimate under D4 or asserts nothing: the availability checks in
the integration helpers and in the three benchmark entry points that reuse them; two short-mode
guards, which only take effect under the unit target; one subtest that skips when the backend
refuses a CORS configuration; one that skips unless the endpoint is HTTPS, because the framing it
needs is what the TLS run supplies (D5); and the conformance suite's two opt-in entry points, a
corpus-seeding run and a sweep of dangling uploads, neither of which is a test of the product.

**Closed 2026-09-10 against D16:** the in-source markers saying a test pins behaviour the next
storage format replaces went with the code they pinned, in the round that deleted the previous
format. No marker in the tree points at a change that has already happened.

## Context

Unit tests in this repository prove plumbing. They assert on a captured request struct or on a
response recorder against a mocked backend. What they structurally cannot show is the only
thing this product exists to do: that what was written to the backend actually decrypts, that
a real S3 SDK accepts the response the proxy composed, and that a backup tool can restore what
it backed up through the proxy.

Three concrete failures made that gap expensive rather than theoretical.

*A framing path nobody ran.* The AWS SDK emits `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload
framing only over HTTPS. For as long as the integration suite ran against the plain-HTTP
endpoint only, the trailer-framed upload path was never exercised, and a defect that stored the
chunk framing as object payload lived in it. Measured on the branch that closed it: a full run
against the TLS endpoint hits the buffered chunked path 718 times, a run against the plain-HTTP
endpoint zero times. One transport is not a cheaper sample of the other; it is a different code
path.

*A restore that never worked.* Ranged GET was refused for every object. Every unit
test passed. The failure was that no restore driven by the uploader Velero uses could complete
— found only when a real client was run end to end against a real cluster.

*Assertions that never read anything.* An end-to-end check that scans fetched output for error
patterns passes in silence when the fetch failed or the source was empty. Several specified
checks had never been built, and the suite ran past two data-loss defects — a bucket deleted by
an ordinary CLI call, and an upload committed short after a client hang-up — because nothing
was reading for them.

Against those, coverage percentages proved actively misleading. A quarter of every uncovered
statement in the repository was test-double code counted as production code; moving it out
raised one package from 13.1 % to 81.0 % without a single line being tested, and lowered
another, whose doubles had been holding its average up, to the honest number for its handler
code.

The cost side is real and was weighed. Keeping both transports roughly doubles one CI job; the
end-to-end environment builds an image, creates a cluster, installs a CSI driver, a storage
backend, the proxy chart and the backup client, and budgets forty-five minutes of runner time
for bring-up, run and teardown; the suite itself measured 592 s on 2026-09-06. That is the
price of the only evidence that counts.

## Decision

**D1** The integration suite and the end-to-end suite are part of the product, not developer
convenience. The integration suite runs against a real backend; the end-to-end suite runs one
real S3 client through backup and restore in a disposable cluster.

**D2** Neither suite is disabled, skipped, weakened or deleted to make a change pass. A test
may be folded into another test that keeps every assertion it carried, and that fold needs the
repository owner's explicit approval, stated as such.

**D3** Work is not finished until both suites are green. The report on a change names which
suites ran and against which stack.

**D4** No environment switch, flag or configuration value disarms an assertion. The only
legitimate skip is a suite skipping itself when the backend or the proxy it needs is
unreachable. Build tags select which suite runs; they never soften one.

**D5** The integration suite runs over both the plain-HTTP and the TLS proxy endpoint, and both
runs must be green, because the client SDK frames uploads differently over TLS and only that
run reaches the trailing-checksum path. If the wall-clock cost becomes a problem, the runs are
split into parallel jobs; one is never dropped.

**D6** Encryption at rest is asserted by reading the stored object directly from the backend,
never by round-tripping it through the proxy. A proxy that decrypts its own output proves
nothing about what was stored (see ADR 0001).

**D7** The end-to-end environment is created and destroyed by the same scripts on a workstation
and in continuous integration. CI carries no bespoke bring-up path, so a workstation and a
runner cannot drift apart. Re-testing a code change reloads a freshly built image into the
existing cluster; the cluster is not recreated for each attempt.

**D8** The pinned upstream versions of the end-to-end environment move as one group, in one
change, reviewed by a person. Automatic merging stays off for that group against a repository
default of automatic merges, and is reconsidered only once the group has been green across
several update cycles: a backup client and the chart that installs it are versioned separately,
and upgrading one without the other produces an environment that is not the supported one. Every pin the environment consumes has an automated
update path; a pin nothing watches is an unmanaged network dependency of every run.

**D9** The end-to-end suite gates the release. A release is not cut while it is red. Taking it
off the gate is a deliberate, temporary, recorded act, never a way past a failure (release
mechanics: ADR 0018).

**D10** The end-to-end environment runs the configuration the documentation tells operators to
use, not the client's insecure defaults. A suite that exercises a configuration nobody is told
to run is evidence about the wrong system.

**D11** Every test is shown to fail without the change it covers — per change, not once at the
end. A test that passes against both the fixed and the broken product is not a test. A test
that pins behaviour that is already correct states that it is a drift guard and is proven by
breaking the behaviour locally and watching it fail.

**D12** An assertion over fetched output — logs, listings, generated documents — is proven at
least once to have read something, by making it fail deliberately against known input. An empty
or never-fetched source passes a scan in silence.

**D13** Unit coverage is a floor, not a goal. The criterion is the named list of tests; the
percentage is secondary. Any movement in the number that comes from changing the denominator —
test doubles leaving the production build, dead code deleted — is labelled as a denominator
correction and not reported as new testing.

**D14** A unit test never substitutes for an integration test. The moment "the handler is unit
tested" is used as the argument for dropping an integration case, the unit suite has done harm.

**D15** Test doubles live in test files, are asserted against the interface they stand in for so
a change to that interface breaks the build, and exist once rather than once per package.

**D16** A test that pins behaviour a decided change will replace carries an in-source marker
naming that change, so the churn is localised and greppable and the change and its tests move
together. Tests are not written against code a decided change deletes; that work is sequenced
after the change — today that is the storage format change of ADR 0003.

## Consequences

- Every release depends on a cluster coming up. An upstream tag that moves, a registry outage
  or a pulled image blocks the release train, and by D9 there is no way around it but a fix.
- Two transports roughly double one CI job, and the end-to-end job needs a forty-five minute
  budget on a runner that is shared with everything else.
- A contributor without Docker, a kind cluster and a license token cannot reach the "done" bar
  in D3 on their own machine. That is accepted: the alternative is a bar that means nothing.
- **Superseded 2026-09-10.** This bullet said that because handler-level unit coverage is
  deferred until the storage format change lands, a regression in header handling or request
  routing surfaces in a ten-minute suite whose failure mode is "a backup did not complete", not
  in a one-second assertion naming the header. That coverage was written and migrated to the
  segment chain, so the cost is not paid.
- Coverage numbers move for reasons that are not testing, and every jump therefore has to be
  explained in the change that causes it. That is extra reporting work on every coverage change,
  and it is the only thing that keeps the number worth quoting.
- Moving the environment pins as one manually reviewed group means slower uptake of upstream
  releases and more review work than the repository's default of automatic merges.
- D11 and D12 make every test more expensive to write than "it passes now". Proving a test fails
  requires deliberately breaking something and putting it back.
- Nobody likes this part: a suite that may never be skipped will sooner or later be red for a
  reason that is not the change under review, and the rule still holds. The escape hatch is
  fixing the environment, not the gate.

## Alternatives Considered

**Unit tests with a mocked backend as the primary evidence.** Fast, no Docker, no cluster.
Rejected: a mock cannot show that stored bytes decrypt, that an HMAC or an AEAD tag verifies,
or that a real SDK accepts the response. It proves the proxy called the function it was written
to call.

**Keep a switch that disarms the assertions when a gate goes red.** Rejected on the same
grounds the product rejects dead configuration keys: a control that exists only in
configuration is worse than none, because it gets relied on. The switch is set the first time
the gate is inconvenient and never unset — which is exactly what happened to the performance
thresholds (see ADR 0020).

**Run the integration suite over one transport.** Halves a CI job. Rejected: the two transports
carry different upload framing, and the framing only the TLS run reaches is the default for
modern SDKs and the one a stored-framing defect hid in. Parallel jobs are the answer to the
runtime, not a dropped run.

**Take the end-to-end job off the release gate**, or make it advisory, because it is long and
depends on the network. Rejected: a release cannot ship past a broken restore path. The
condition for revisiting it is the job proving flaky, which it has not — thirteen of thirteen
twice, once from a freshly created cluster.

**A CI-specific bring-up tuned for the runner.** Rejected: the workstation and the runner drift,
and the resulting "green in CI, red on my machine" is unfixable by the person who has to fix it.
One script, both places.

**Write handler unit tests now to raise the number.** Rejected: they would pin behaviour the
storage format change deletes, would be rewritten line for line, and — worse — would make that
change look like a regression, because the tests would encode today's behaviour as the contract.

**Chase a repository coverage percentage as the goal.** Rejected: the number is gameable in at
least four ways that test nothing, and it was demonstrably wrong before the denominator was
corrected.

**Auto-merge the end-to-end environment version bumps.** Rejected while the gate blocks
releases: an auto-merged bump clears the gate with nobody having read it, and the client and its
chart must move together.

## Residual risks

- **One client, end to end.** The end-to-end suite exercises Velero and the uploader it uses.
  Other named supported clients — CloudNativePG Barman among them — have no end-to-end suite,
  and the proxy's scope is any S3 client (ADR 0006).
  Accepted; the integration suite is the broader net and it drives one SDK.
- **Narrowed 2026-09-12: whether the published performance run must also cover the TLS
  endpoint.** The local baseline suite measures both transports, so the question is no longer
  whether the number exists — it is whether the run continuous integration publishes has to
  carry it. That run measures the plain-HTTP listener only, so a regression confined to the
  trailer-framed upload path would not move the published figure. There is no threshold table to
  fill any more (ADR 0020), which removes the reason this was being held; it stays undecided.
- **Closed 2026-09-12: what an end-to-end log scan is allowed to excuse.** Nothing. The client's
  own backup and restore logs are scanned with the same patterns as the container logs and there
  is no allowlist, which is the stated preference — fix a hit rather than excuse it. The risk
  that returns with the first recoverable error-level line the client emits is that somebody
  adds the first entry; there is nowhere for one to hide, because there is no list.
- **Open: whether one duplicate one-leg performance test is folded or kept.** It measures a
  duration it never asserts on and its round trip is a subset of another test. Folding it needs
  explicit approval under D2; keeping it costs about a minute of runtime and a name that must
  stop claiming a comparison it does not make.
- **Not verified: that the two forbidden log patterns added for goroutine dumps are silent on a
  healthy run.** They are in force, and they are now applied to the client's own logs as well as
  to the container logs. No recorded green run has been checked against them; a pattern that
  fires on healthy output has to be narrowed, not dropped.
- **Not verified: that the automated update path actually produces change requests** for the
  environment pins. Every pin in the environment's version file now has one configured, the four
  storage-driver sidecars that had none included, and they are grouped and held off automatic
  merging as D8 requires. Two pins are outside that: the object-store image, watched from outside
  the group and therefore on the repository's default of automatic merging, and the workload image
  the scenarios' pods run, watched by nothing. The updater runs on a schedule, so whether a change
  request actually appears is only observable later; it is an open loop, not a green one.
- **Narrowed 2026-09-12: which S3 clients use conditional writes against this proxy** is still
  unverified, but the failure mode that made it urgent is gone. `If-Match` and `If-None-Match`
  are carried on the write paths and covered by an integration case, so a conditional write is no
  longer answered by a silent overwrite.
- **A thirteen-of-thirteen record twice is not a long track record.** The judgement that the
  end-to-end job is stable enough to block releases rests on that, and on nothing more.
- **The measurement premise behind unit coverage floors is not the same as correctness.** Every
  floor in this repository can be met by tests that assert only that a mock was called. Reviewers
  read the named test list first and the number second; nothing enforces that.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0006 — The proxy serves any S3 client
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration refuses to start
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0018 — A major release is declared by a label, never discovered at merge
- ADR 0020 — Performance is measured before and after, never asserted
- ADR 0021 — Key material and licenses are generated, never committed
- [README.md](../../README.md) — user-facing reference, including the client configuration the end-to-end environment must run
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model and the residual-risk checklist the suites are evidence against
- [CLAUDE.md](../../CLAUDE.md) — project conventions, the testing strategy and the build and test targets
