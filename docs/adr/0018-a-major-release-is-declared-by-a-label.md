# ADR 0018: A major release is declared by a label, never discovered at merge

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: releases are cut automatically from the `main` branch, the version is
derived from the Conventional Commits headers and footers of the commits that reach it, the
changelog and the GitHub release are generated per commit, and the release step runs only after
the full check set — malware scan, static security scan, vulnerability check, lint, unit tests,
integration tests over both the plain-HTTP and the TLS endpoint, the combined coverage report and
the Velero end-to-end suite — is green.

Also implemented: the guard of D3 and D4. A check runs on every pull request into
`main` and fails when a breaking marker is present without the `release:major` label. It reads
three sources, because a merge commit and a squash merge hand the release analyser different text:
the commits the pull request adds, the pull-request title, and the pull-request body. Its marker
patterns are deliberately wider than the analyser's own — case insensitive, and not requiring the
space the parser wants after the colon — because over-reporting costs a label that was not needed
and under-reporting costs a major release, and only one of those can be taken back. It was verified
by replaying the 2026-09-07 accident: over the forty-three commits of the pull request that
produced 4.0.0, the check reports the two breaking commits and nothing else.

**Amended 2026-09-09:** D6 becomes a machine check — a dry run of the release tool on every pull
request into `main` prints the computed next version and is compared with the label — and D11
settles the previous line: nothing before the major receives another release. The dry run is
implemented with this amendment: a pull-request workflow runs the release tool in dry-run mode
on the pull request branch and fails when the computed bump and the label disagree.

**Amended 2026-09-11: D3's guard and D6's dry run are one job, not two workflows.** They had grown
into two pull-request checks that read as duplicates of each other, and a contributor cannot be
expected to know which is which. They are now `Semantic-Release (dry run)`, one workflow with one
job, in which the marker inspection is a step rather than a check of its own.

**Neither check was dropped in the merge, because neither subsumes the other.** The dry run reads
the commits and would not notice a marker that exists only in the pull-request title or body —
which is the text a squash merge puts on `main`. The marker inspection reads all three sources
and computes no version, so it would not notice a release configuration that no longer loads.
Both verdicts still run on every pull request, and the marker step runs even when the dry run has
already failed, because it is the step that says which marker caused it.

One behaviour is deliberately preserved rather than simplified away: the dry run is
same-repository only — a fork's token is read-only, so the release tool fails at its own push
check before analysing anything — while **the marker inspection runs for forks too**. Putting the
fork condition on the job rather than on the steps would have left a fork pull request with no
guard at all. It takes **two checkout steps**, and the first attempt at this merge got it wrong:
the head branch can be checked out by name only for a same-repository pull request, because that
name is resolved in this repository and a fork's branch does not exist here. The fork path takes
the merge ref instead, which is what the deleted breaking-change workflow used for every pull
request. Pointing the checkout at the fork's repository would have fetched fork-controlled code
onto a self-hosted runner, which is a worse trade than skipping the dry run.

**The two steps judge different halves of the disagreement, and only one half fails.** A computed
major *without* the label is the 2026-09-07 accident and the commits alone are enough to refuse
it, so the dry run fails. The label *without* a computed major is not an accident waiting to
happen — the worst it produces is a needless label — and the dry run cannot judge it, because it
reads only the commits while the marker may live in the title or body a squash merge puts on
`main`. It warns there and leaves the verdict to the marker inspection, which reads all three
sources. Before the merge this cost nothing, because the dry run was not a required check; with
one gate it would have turned a correctly declared squash-merge major red.

**What the merge costs, stated rather than discovered later.** The gate now depends on the npm
registry and on semantic-release running at all: an outage reds a check that used to be
network-free, and there is no way around that while both questions share one job. And `edited`
now re-runs the whole npm path on every title or body change, cancelling the in-flight run,
because one workflow means one concurrency group.

## Context

The release process is fully automatic and commit-driven. A push to `main` triggers the test
matrix; if every gate passes, the automation reads the Conventional Commits headers of the new
commits, computes the next version, writes the changelog, tags, and publishes the release with
the built binaries and the coverage artifacts attached. `feat!`, `fix!` and any `BREAKING CHANGE:`
footer produce a major; `feat` a minor; `fix`, `perf`, `refactor` and `revert` a patch;
documentation, style, chore, test, build and CI commits produce no release at all.

On 2026-09-07 that mechanism produced version 4.0.0, which nobody had planned. A pull request
that raised test coverage was merged into `main` with a merge commit rather than a squash. A merge
commit hands the automation every commit of the branch individually, and two of them were marked
breaking: one made `encryption.metadata_key_prefix` a validated value that refuses an empty or
non-lowercase setting at startup, the other moved the profiling endpoints off
`monitoring.bind_address` onto the separate loopback listener named by
`monitoring.pprof_bind_address`. Both markers were correct — each change breaks a configuration
that worked before. The accident was not the labelling; it was that a branch nobody intended to
release a major from reached `main` with its individual commits intact.

The cost was real. The 4.x line was the number reserved for a planned bundle of breaking changes —
a new storage format, a configuration cleanup, a set of client-visible corrections — none of which
had been written yet. A published tag cannot be withdrawn, so the number is spent: the bundle
moves to 5.0.0, and 4.0.x keeps taking patches until it ships.

The obvious fix — allow only squash merges, so one pull request becomes one commit and one
changelog entry — was weighed and rejected on evidence from the same week. The release cut from a
squash-merged pull request carries a single changelog line consisting of a truncated pull-request
title. The release cut from the merge commit carries sixteen lines, one per change, each naming
what it did. Per-commit release notes and per-commit release analysis are the same mechanism: the
automation reads exactly the commits it turns into notes. Removing the exposure removes the notes.

So the guard has to sit on the pull request, not on the merge method.

## Decision

**D1.** `main` is the only release branch. Every push to it that passes the gates is a candidate
release, and the version is computed from the Conventional Commits headers and footers of the
commits it introduces. No version number is ever set by hand.

**D2.** Merge commits into `main` stay allowed. A pull request may be merged so that its commits
reach `main` individually, because that is what produces a changelog entry per change instead of a
list of pull-request titles.

**D3.** A check runs on every pull request into `main` and fails when any commit in the pull
request carries a breaking marker — a `!` in the Conventional Commits header, or a line beginning
`BREAKING CHANGE:` in the body — unless the pull request carries the label `release:major`.

**D4.** The `release:major` label is how a major release is declared. It is the record of intent:
applying it is the deliberate act, and no other signal declares a major.

**D5.** A commit carries the breaking marker whenever the change breaks stored data, an existing
configuration or a client-visible answer — including on a branch that is not releasing. Markers
are never softened to route around the guard; the label is what controls the release, the marker
is what describes the change.

**D6** (amended 2026-09-09; merged with D3's guard into one job 2026-09-11). On every pull request into `main`, a dry run of the release tool
computes the next version from the pull request's commits and prints it on the check — pull
requests only, never on a push, and it writes no tag, no changelog and no release. A pull request
labelled `release:major` fails that check unless the computed bump is a major, and a computed
major without the label fails it too. The final merge of a major is made against that printed
number, not against a reading of the commits. What the release step finally reads is the merge
or squash message on `main`; the guard of D3 keeps it in agreement with the commits the dry run
analysed. A tag that comes out wrong cannot be taken back.

**D7.** Breaking changes are collected on one long-lived branch and released as a single major.
Each unit of work is its own pull request into that branch, squash-merged with a Conventional
Commits title, so the branch history is one commit per unit and a single unit can be reverted
alone. Breaking markers are used freely there; nothing releases from that branch. The branch is
rebased onto `main` whenever `main` moves, and the end-to-end suite is the gate on every rebase.

**D8.** While a bundle is in flight, `main` keeps shipping: dependency bumps, fixes and additive
features release as patches and minors on the current major line.

**D9.** The release step runs only from `main` and only after every gate is green, the Velero
end-to-end suite included. A release does not ship past a broken end-to-end run; when the suite
breaks, the suite gets fixed. Dropping it from the gate list is a deliberate, temporary, recorded
measure, never a way to get a release out.

**D10.** The notes of a major release state what breaks and what the operator has to do about it,
in the release itself rather than in an external document. They are assembled from the breaking
footers of the commits the release contains, which is why those footers are written for an
operator to read.

**D11** (added 2026-09-09). The release line before a major receives no further releases of any
kind once the major is out — no security patches, no fixes, no backports. 4.0.x and everything
before it are end-of-life at the 5.0.0 release; there is one supported line, the newest. No
deployment is known on the old lines, and the old format is one the product no longer describes
as fit for an untrusted backend (ADR 0003), so keeping it alive would be work spent on a state
the product has left.

## Consequences

Every pull request into `main` pays one more check, and a genuinely breaking change needs a label
applied before it can merge. That is a manual act and a repository-specific convention: a
first-time contributor will hit the failing check without knowing why, so the check's failure
message has to explain the label.

`main` does not have a one-commit-per-pull-request history. Reverting a whole pull request means
reverting a merge, which is more awkward than reverting a squash. That is the price of the
granular changelog, paid knowingly.

Because every commit that reaches `main` becomes a public release note, every commit message is
product documentation and has to be written as one. Sloppy commit subjects are now a user-facing
defect.

Nothing outside the pull request records why a major was declared. The label says that it was
deliberate; it does not say what the reasoning was. The reasoning belongs in an ADR.

The release cannot ship while any gate is red, and one of the gates is a multi-minute end-to-end
run that builds a cluster, installs the proxy and a backup client, and exercises the whole stack.
A flaky run, or an upstream image that stops resolving, blocks shipping entirely. That cost was
accepted when the gate was introduced and is accepted again here.

Version 4.0.0 exists and contains none of the changes the 4.x number was reserved for. Anyone
reading the version history will find a major release whose breaking-changes section lists two
configuration corrections and nothing of the bundle the number was held for. The bundle is 5.0.0, and objects written by 4.0.x are as unreadable under the
next storage format as objects written by 3.x.

## Alternatives Considered

**Discipline only — write the rule down and expect it to be followed.** Rejected: a control that
exists only in a document is one merge-button click away from repeating the accident, and this
project does not accept controls that exist only in prose.

**Squash-only merging: disable merge commits and derive the release from the pull-request title.**
Rejected on measured evidence. It is the tidiest option and it works — a single title, a single
analysed message, no inner footer can leak — but it collapses the changelog to one truncated line
per pull request, as the release cut that way the same week demonstrates. The changelog is how an
operator finds out what changed; it is worth more than the tidiness.

**Squash-only with the pull-request body as the squash message.** Rejected with the option above,
for the same reason: it still yields one commit and one note per pull request.

**Keep merge commits but forbid breaking markers on feature branches, deferring them to a final
release commit.** Rejected: it makes commit messages lie about what the commits do, moves the
breaking-change inventory out of the commits and into someone's memory, and produces exactly the
release notes the merge-commit policy exists to avoid.

**Make the end-to-end suite advisory, or gate only pull requests and leave `main` ungated.**
Rejected when the gate was introduced and not reopened: the end-to-end suite is the only place the
full client stack is exercised against the proxy, and a release that has not passed it is a
release nobody has tested end to end.

## Residual risks

- **A pull request can edit the guard that judges it.** A pull-request check runs the workflow as
  it exists in the merge of the pull request into the base branch, so a branch that modifies the
  guard is judged by its own version of it. The guard therefore raises the cost of an accidental
  major; it does not survive a deliberate one. Review of changes to the check, and a branch
  protection rule that requires it, are what close that — neither is configured in the repository
  settings by this decision.
- **A repository administrator can merge past a failing check.** The guard raises the cost of an
  accidental major; it does not make one impossible.
- **Still unverified, but no longer load-bearing: whether a breaking footer inside a branch commit
  can reach the analyser through a squash body.** It was never tested against the parser this
  repository actually runs. The guard makes the answer stop mattering by inspecting the commits,
  the title and the body together, so every text a squash or a merge can turn into the analysed
  message is judged the same way.
- **The label name is a bare convention.** `release:major` has no meaning to any tool other than
  the guard that reads it. Renaming or misspelling it silently disarms the guard.
- **Flakiness of the end-to-end gate is a shipping risk, not a testing risk.** It has been
  deterministic so far — thirteen of thirteen scenarios, twice, once from a freshly created
  cluster — and the agreement is to revisit after ten CI runs if that changes. The revisit would
  make the suite deterministic again, not weaken the gate.
- **Settled 2026-09-09: the dry run of D6 is the automated check.** What remains: it analyses the
  pull request's commits, while the release step reads the squash or merge message on `main`;
  the guard of D3 is what keeps the two from disagreeing, and a pull request merged past a red
  check by an administrator can still produce a version the dry run did not print.
- **The dry-run job holds a token that can push.** The release tool verifies push access with a
  dry-run push before it analyses a single commit, even in dry-run mode, so the check runs with
  write access to the repository contents on same-repository pull requests; a fork's read-only
  token skips it. Nothing in the run pushes. The exposure is a dependency executed before review
  with that token. Accepted: the release step runs the same packages with a broader token one
  step later, install scripts are disabled, and registry signatures are checked.
- **Settled 2026-09-09: the release configuration is one file, and it recognises the `!`
  shorthand.** The dry run's own test found that the release tool loaded the `release` block of
  the package manifest, which shadowed the dedicated configuration file; under the loaded
  configuration only a `BREAKING CHANGE` footer produced a major, the release attached no
  binaries, and the coverage badge on `main` was written by the release job and never
  committed. The manifest block is gone, the dedicated file is a script that reads the
  release-notes template from disk, the preset it names is installed and pinned to the
  generation the release tool is built on, and the release job builds the binaries it attaches.
  Verified against a mirror: `feat!:` and a `BREAKING CHANGE` footer both compute a major, a
  `fix:` computes a patch, and the notes render. What stays open: the first real release under
  the new configuration is the proof that the asset upload and the badge commit work end to
  end, and it has not run yet.
- **Settled 2026-09-09: 4.0.x and earlier are end-of-life at 5.0.0 (D11).** No patches of any
  kind. The release notes of 5.0.0 say so.

## References

- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start (removing a key is a breaking change and therefore a major)
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0022 — Tickets are work lists that get deleted; decisions live in ADRs
- [CHANGELOG.md](../../CHANGELOG.md) — the generated release history, including the 4.0.0 entry
  this decision came out of
- [README.md](../../README.md) — user-facing reference
