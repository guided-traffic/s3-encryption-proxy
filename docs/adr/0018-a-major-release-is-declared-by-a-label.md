# ADR 0018: A major release is declared by a label, never discovered at merge

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: releases are cut automatically from the `main` branch, the version is
derived from the Conventional Commits headers and footers of the commits that reach it, the
changelog and the GitHub release are generated per commit, and the release step runs only after
the full check set — malware scan, static security scan, vulnerability check, lint, unit tests,
integration tests over both the plain-HTTP and the TLS endpoint, the combined coverage report and
the Velero end-to-end suite — is green.

Decided and specified, not implemented: the pull-request guard and the `release:major` label of
D3 and D4. Nothing enforces them yet; until the guard exists, the only thing standing between an
honestly marked breaking commit on a feature branch and an unplanned major release is the person
pressing the merge button. The guard lands on `main` before the next breaking-change bundle
branches off, or alongside it.

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

**D6.** Before a pull request labelled `release:major` is merged, the computed next version is
verified against the intended one. A tag that comes out wrong cannot be taken back.

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

- **The guard is specified, not built.** Until it exists, D3 and D4 are conventions with nothing
  enforcing them, and the 2026-09-07 accident can repeat on any branch carrying an honest breaking
  marker.
- **A repository administrator can merge past a failing check.** The guard raises the cost of an
  accidental major; it does not make one impossible.
- **Unverified: whether a breaking footer inside a branch commit can reach the analyser through a
  squash body.** The repository assembles squash messages from the branch's commit messages by
  default, and the Conventional Commits footer syntax suggests an inner footer would survive into
  the squashed message and be read as breaking. This was reasoned from the specification, not
  tested against the parser this repository actually runs. If it holds, squash merging is not the
  safe path it looks like, which is a further argument for the guard sitting on the commits.
- **The label name is a bare convention.** `release:major` has no meaning to any tool other than
  the guard that reads it. Renaming or misspelling it silently disarms the guard.
- **Flakiness of the end-to-end gate is a shipping risk, not a testing risk.** It has been
  deterministic so far — thirteen of thirteen scenarios, twice, once from a freshly created
  cluster — and the agreement is to revisit after ten CI runs if that changes. The revisit would
  make the suite deterministic again, not weaken the gate.
- **Open: nothing verifies the intended version before the tag is written.** D6 is a human check.
  An automated dry run that prints the computed next version on the pull request was not specified
  and would close the remaining half of the problem.
- **Open: what happens to the 4.0.x line once 5.0.0 ships** — whether it keeps receiving security
  patches, and for how long — is not decided.

## References

- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start (removing a key is a breaking change and therefore a major)
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0022 — Tickets are work lists that get deleted; decisions live in ADRs
- [CHANGELOG.md](../../CHANGELOG.md) — the generated release history, including the 4.0.0 entry
  this decision came out of
- [README.md](../../README.md) — user-facing reference
