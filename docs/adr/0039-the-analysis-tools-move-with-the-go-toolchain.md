# ADR 0039: The analysis tools move with the Go toolchain

## Status

**Accepted.** Date: 2026-10-10.

Implemented with this decision, in the same change that moves Go to 1.27.2: golangci-lint,
gosec and govulncheck are pinned in a Go module of their own; the three static gates build them
from that pin with the toolchain that compiles the code; `golang.org/x/tools` is required there at
v0.51.0, above the v0.49.0 that gosec v2.29.0 asks for; and the dependency bot puts every update
of that module into the "Go toolchain" group together with the Go version, keeping
`golang.org/x/tools` current although it is an indirect requirement.

Verified when this was written: under Go 1.27.2 all three gates pass locally with these pins,
where the previous pins failed two of them with the error quoted below. Not verified by a live
run of the bot: see *Residual risks*.

## Context

Go 1.27.2 was tagged on 2026-10-08 with fixes for nine vulnerabilities in the standard library —
in `net/http`, its HTTP/2 implementation, `mime/multipart` and `crypto/tls`. From then on the
Vulnerability Check failed every pull request still built with Go 1.27.1, which was every pull
request except the one that moved Go. Three dependency pull requests — the AWS SDK, the
Prometheus client and smithy-go — were red on that gate and on nothing else.

The pull request that moved Go to 1.27.2 was red as well, on Code Linting and on the GoSec
Security Scan. Go 1.27.2 writes the export data a compiled package leaves for its importers in
version 5 of that format; 1.27.1 wrote one the analysis tools could read. golangci-lint v2.13.1
and gosec v2.29.0 read it through `golang.org/x/tools` v0.49.0, which reads up to version 4:

    cannot decode "internal/goarch", export data version 5 is greater than maximum supported version 4

golangci-lint reported it as a type-check error on the first import. gosec reported "package has
type errors" for 23 packages, skipped its SSA analysis for each of them, printed `Issues : 0`, and
exited non-zero.

Nothing about this was sudden. `golang.org/x/tools` v0.50.0, which reads version 5, was released
on 2026-09-08, a month before Go 1.27.2. govulncheck v1.8.0 shipped with it the same day and
golangci-lint v2.14.0 on 2026-09-24. But the tool versions were written by hand into the build
script — and golangci-lint's a second time into the pipeline definition, where the two had to be
kept equal — and the dependency bot read neither. The build script said so in a comment: not
managed by the bot, bump by hand together with the Go version. Nobody did, so the Go bump met
tools a month behind it. gosec was worse off: no gosec release read version 5 at all. Its
development line had moved to `golang.org/x/tools` v0.50.0 and then v0.51.0, and it took up
Go 1.27.2 the day after the Go release, but the newest release still carried v0.49.0.

That was a deadlock. Every pull request waited for the Go bump to clear the vulnerability gate,
the Go bump waited for the tools, and the tools were not something the bot moved. Four pull
requests were held, and none of them could merge without a person.

It was the second time. On 2026-09-07 gosec v2.22.8, and a govulncheck built with Go 1.26, failed
on Go 1.27 for the same family of reason. The fix then — build the pinned tool with the toolchain
that compiles the code, instead of taking whatever binary is on the path — was right, and it is
kept. It left the pin outside the bot.

## Decision

**D1.** The analysis tools that gate a pull request — golangci-lint, gosec and govulncheck — are
pinned in one Go module of their own, beside the product's module and separate from it. Their
dependencies never take part in version selection for the shipped binary, and the product's
build, tests and gates never see that module.

**D2.** Each gate runs its tool from that pin, built by the toolchain that compiles the code being
judged. No gate takes a tool binary from the path, and the pipeline definition carries no pin of
its own: a workstation and continuous integration run the same coordinate.

**D3.** `golang.org/x/tools`, through which the tools read the compiler's export data, is required
in that module at its newest release, above what the tools themselves ask for, and the dependency
bot keeps it there. A Go release that changes the export data format is readable on the day it
lands whenever `golang.org/x/tools` can read it, without waiting for each tool to cut a release
of its own.

**D4.** The tools never move apart from the Go version. The dependency bot puts the Go version of
the build image, the go directive of the product's module and every update of the tools' module
into one group, "Go toolchain", and opens one pull request for it. Two pull requests would wait
for each other whenever a Go release fixes a vulnerability: the Go bump for the tools, the tools
for the vulnerability gate.

**D5.** When a Go release needs a tool release that does not exist yet, the "Go toolchain" pull
request stays red until it does. No gate is skipped, loosened, excused or pointed at an older
toolchain to get a Go version in; the red check is the record of what is missing.

## Consequences

- An update of a tool arrives as "Update Go toolchain" even when Go itself did not move, and it is
  released as a patch like every dependency update (ADR 0018). A title that does not say which
  tool moved is the price of never splitting the two; the pull request body lists them.
- `golang.org/x/tools` ahead of the version a tool was released with is a combination that tool's
  maintainers did not test. A later `golang.org/x/tools` can remove something a tool uses; the
  group pull request then fails to build that tool and stays red (D5) until the tool catches up
  or the requirement is held back by hand. The failure is loud, never silent.
- The tools' module carries a go directive of its own. It is not a pin: it is the floor the module
  system derives from what the tools require, and it never selects the toolchain that builds them.
- The tools' dependency tree — several hundred modules, most of them golangci-lint's — becomes
  visible to the repository's dependency graph, so a vulnerability alert can name a module that
  never reaches the product. Such an alert concerns the gate tooling, not the shipped binary.

## Alternatives Considered

**Keep running each tool at a published version and teach the bot the hand-written pins with
pattern rules.** It would have moved golangci-lint and govulncheck a month early. It would not have
moved gosec, which had no release that read version 5: a tool run at a published version is built
with that release's own `golang.org/x/tools`, and nothing outside the release can raise it.
Rejected because it ties the gates to the slowest tool's release cadence.

**Put the tools into the product's own module.** One file fewer, and the bot needs no rule.
Rejected: the tools' dependency tree would take part in version selection for the shipped binary.
A lint tool could raise a cryptographic or networking dependency of the proxy, and a proxy
dependency bump could break a tool.

**Run gosec as one linter inside golangci-lint and drop the standalone scan.** golangci-lint
v2.14.0 builds gosec v2.29.0 against `golang.org/x/tools` v0.50.0, so it read version 5. Rejected:
it changes what the security gate is — its configuration, its exclusions, its check on the
required list — to work around a version problem, and it still waits for golangci-lint's release.

**Pin gosec to an unreleased commit of its development line.** It would have worked for 1.27.2.
Rejected as the rule: the next export format change repeats the wait, and a commit pin is a
hand-kept coordinate of exactly the kind that caused this.

**Give the tools a group of their own, apart from the Go version.** Each pull request would then
describe one thing. Rejected for the deadlock D4 names; it held four pull requests on 2026-10-09.

## Residual risks

- **A Go release with new syntax needs a tool release.** `golang.org/x/tools` alone does not teach
  a linter a language feature. Until that tool ships, the "Go toolchain" pull request is red, and
  if the same Go release fixes a standard-library vulnerability, every other pull request is red
  on the vulnerability gate meanwhile. Accepted: the alternative is merging past a gate.
- **A published Go vulnerability stops every pull request, not only the one that moves Go.** That
  is the gate working — the shipped image carries that standard library — and it is the reason D4
  exists, not a defect of it.
- **Not verified by a live run of the bot.** That the bot puts the image, the go directive, the
  tool modules and `golang.org/x/tools` into one "Go toolchain" pull request, and leaves the tools'
  go directive alone, was shown by a local dry run of the same bot major against a copy of the
  repository with older pins. The next Go or tool release is the first live proof.

## References

- ADR 0018 — releases are computed from the commits that reach `main`; a dependency update,
  tool updates included, is released as a patch
- ADR 0019 — the suites are never skipped, weakened or disarmed; D5 holds the static gates to the
  same rule
- [DEVELOPER.md](../../DEVELOPER.md) — how the tools are pinned and run, and how to move one by hand
