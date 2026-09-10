# ADR 0022: Tickets are work lists that get deleted; decisions live in ADRs

## Status

Accepted. Date: 2026-09-07.

**Partly implemented.** Implemented today: this directory exists, its format and ground rules are
written down, the contributor instructions carry the rule, and the decisions taken between
2026-09-06 and 2026-09-07 are being lifted out of the backlog into ADRs as part of the same
round. Not implemented today: the backlog still exists in its old shape — every open ticket still
carries decision text next to its work list.

**Corrected 2026-09-10**, twice. A ticket **has** been deleted under this rule — the
development-license one, on 2026-09-09. And ticket *numbers* are gone from the user-facing
documents: the only one left anywhere outside the ticket directory is the released changelog
entry, which can never be corrected.

**What is still open is D6, the work-tracking labels.** They survive in source comments and
test names, and in six released changelog entries that are as uncorrectable as the ticket
number. **Corrected 2026-09-11:** this block used to name a shipped example configuration as
the worst of the set. No label is in one — nor in any chart values file, compose file or
script. Nothing the product hands to a user carries one; what is left is internal.

## Context

The backlog was carrying four different kinds of content in one place: the outstanding work, the
decision behind it, the verification notes that produced it, and the closed history of everything
already fixed. Nothing separated them. At the point this decision was taken the ticket directory
held roughly twelve thousand lines of prose across eighteen files, the largest single file over
twelve hundred lines, plus captured profiling artefacts from a finished performance round.

The decision record lived inside files that are supposed to be deleted. One index page defined
over a hundred work-tracking labels in five parallel series — decisions taken, threat-model
findings, sweep findings, parked defects, landed fixes — and that page was the only place several
settled rules were written down at all.

Four concrete failures followed:

* **The product documentation sent readers into a work list.** The security architecture pointed
  at ticket files in roughly two dozen places and the user-facing README in eight, in each case to
  explain a current limitation or a planned change. A reader looking for what the product does
  landed in a document written as a plan, where the plan is usually longer and louder than the
  rule.
* **A ticket could never be deleted.** Twenty-nine of the repository's source files — six of them
  production code, the rest tests — carried a ticket number or a label in a comment, and commit
  subjects carried label identifiers. Deleting a finished ticket would have broken all of it, so
  finished tickets stayed. The oldest completed one had been done for four months and was still
  sitting there.
* **The identifiers drifted, and the references did not.** One decision in the series was reversed
  by a later decision in the same series, and the only record of the reversal was a note in the
  file marked for deletion; every citation of the first identifier now states a rule that no
  longer holds. A ticket was renumbered when the release it named changed from the fourth major to
  the fifth. Work identifiers are not stable, so they are the wrong thing for anything durable to
  cite.
* **A reader could not tell a decision from a proposal.** Both were written in the same voice, in
  the same file, often one paragraph apart. And because a decision was only written up when the
  work landed, decisions with a whole release of implementation ahead of them existed as a
  conversation and a table row, and nowhere else.

The trigger was seeing ticket numbers in commit messages and in the user-facing documentation on
2026-09-07. Both were called a mistake, and the shape of the fix followed from what had gone
wrong: the durable record and the work list are two different documents with two different
lifetimes, and only one of them may be referenced.

## Decision

**D1.** Every durable design decision is recorded as an ADR in this directory, one file per
decision family, named `NNNN-kebab-case-title.md` and numbered in the order the ADRs are written.
The ADR states what was decided, why, what was rejected and what it costs.

**D2.** The ADR is written in the session the decision is taken, not when the implementation
lands. A decision is a decision before it is code.

**D3.** A ticket is a work list and nothing else: what is outstanding, and enough context to pick
it up. It is not the decision record, not the threat model, not the release note, not an archive
of verification runs.

**D4.** A ticket is closed by **deleting the file**. Before deleting it, everything durable moves
out: the decision into an ADR, the operator-facing consequence into the user-facing README or the
security architecture document, the contributor-facing one into the developer guide. Finish,
document, delete.

**D5.** Nothing outside the ticket directory references a ticket. Not the README, not the security
architecture, not the contributor instructions, not a source comment, not a commit message, not a
pull request, not a release note. A ticket may reference an ADR; an ADR never references a ticket.

**D6.** Work-tracking labels are internal to the ticket directory and die with it. Nothing outside
cites one. A durable statement names the rule, or the ADR that holds it.

**D7.** A comment, commit or pull request that has to point at a pending change points at its ADR
by number and title — "the segmented storage format, ADR 0003" — never at a work item.

**D8.** An ADR carries no references into the code: no file paths, no line numbers, no function,
type or package names, no links into the tree. A reader acts on it without opening the repository,
and it does not go stale when a file is renamed. The product's own vocabulary is not a code
reference and is named exactly: configuration keys, `s3ep-` metadata keys, S3 error codes, header
and algorithm names, release versions, and the commands the project ships.

**D9.** When a decision changes, the ADR is amended in place in the same change: the `Decision`
section states the new rule, the `Status` section records the amendment with its date, and the
superseded rule is marked as superseded rather than deleted. A reader never finds an old rule
stated as current. A reversal amends the ADR; it does not become a new row in a work list.

**D10.** Before a ticket file is deleted, the repository is searched for its number and for the
labels it defined, and every remaining reference is cleared or rewritten to point at the ADR.

**D11.** The `Status` section of every ADR says plainly what is implemented and what is only
decided. The `Decision` section is written in the present tense either way, because it is the rule
the product follows from the moment the decision is taken.

## Consequences

* Closing a change costs more at the end than it used to: write or amend the ADR, update the
  user-facing documents, search for stale references, then delete the ticket. That is the point.
  The record that survives is the one a later reader needs, and the backlog stays small enough to
  stay focused.
* There are now two places to look and a discipline to keep them apart. A rule found in a ticket
  is a defect in the process, not a shortcut.
* Deleting a file feels like throwing away history. Version control keeps it, but nobody will go
  looking. Whatever is worth reading later has to be moved out deliberately, at the moment of
  deletion, by the person who still knows what mattered.
* The existing backlog does not migrate itself. Over a hundred labels and thousands of lines have
  to be either lifted into an ADR or consciously accepted as lost, one ticket at a time, before
  any of those files can be removed.
* Source comments that pointed at pending work have to be rewritten to point at an ADR, or at
  nothing. Some of them exist only to explain why a test pins behaviour that a future release
  removes, and that explanation now has to survive without a work identifier.
* Commit messages already written cannot be repaired, and the released changelog entry naming a
  ticket stays wrong permanently. History is not rewritten for tidiness.
* ADR numbers are one shared sequence claimed by hand. Two decisions written in parallel can pick
  the same number, and nothing catches it.
* Recording a decision at the moment it is taken means ADRs describe behaviour that does not exist
  yet, sometimes for a full release cycle. A reader who skips `Status` is misled by an accurate
  document.

## Alternatives Considered

**Keep decisions in the tickets and stop deleting them.** The status quo, and the failure. The
backlog grows without bound, a plan and a rule stay indistinguishable, and every finished ticket
survives as a reference target for work that ended months ago.

**Keep the tickets as they are, but forbid only the outward references.** Rejected. It fixes the
linkage and not the mixing: the decision would still live in a document written as a plan, a
reader inside the directory still cannot tell a rule from a proposal, and the question of when a
ticket may be deleted is left unanswered — which is the question that made the directory grow.

**Archive closed tickets in a subdirectory instead of deleting them.** Rejected. An archive is a
place where everything is kept and nothing is read. It preserves exactly the ambiguity that hurt —
a stale plan sitting one directory away from a live rule — and it re-creates the referencing
problem at the new location.

**Record decisions only in the user-facing documents.** Rejected. Those state what the product
does now. They have no room for the alternatives, the rejected option and the accepted cost, which
is the material a later change needs in order to argue with a decision instead of rediscovering
it. A limitation section is not a decision record.

**Track decisions in an external issue tracker.** Rejected. The record must live in the tree,
be reviewed in the same pull request as the change it justifies, and be readable offline from a
clone. A decision behind a service login is not part of the product.

**Write the ADR when the work lands rather than when the decision is taken.** Rejected. That is
what was being done. It leaves long-running decisions unwritten for a whole release, and by the
time the work lands the reasoning — especially the rejected options — has already been forgotten.

**Allow source comments to cite a ticket for pending work.** Rejected. Those are precisely the
references that outlive the ticket, and they are the ones that made deletion impossible.

## Residual risks

* **Open: where closed history goes.** The label index holds settled material no ADR claims — the
  defects already repaired, the findings that were investigated and refuted, and the reasons
  several pieces of code look the way they do. It is worth keeping and it is not a decision. No
  home has been chosen, and today it exists only in a file marked for deletion.
* **Open: where measurement artefacts live.** A finished performance round left captured profiles
  checked in beside its ticket. Measuring before and after is required elsewhere in this ADR set;
  where the evidence lives once the work list that produced it is gone was not decided.
* **Open: enforcement is manual.** The reference ban and the pre-deletion search are a habit, not
  a check. Whether a continuous-integration guard rejects a ticket reference in a commit message
  or in a tracked file was not decided, and until one exists the rule holds only as long as it is
  remembered.
* **Not verified: that every decision in the backlog is claimed by an ADR.** The set of ADRs for
  this round was defined in one sitting from the tickets as they stood. No cross-check has been
  run, and a decision that no ADR covers is lost the moment its ticket is deleted.
* **Not verified: that the ADRs of this round agree with each other.** They were written in
  parallel from the same sources. Overlaps between siblings, and any contradiction between them,
  have not been reviewed.
* **Open: how much of the documentation debt is repaid before the first deletion.** The
  user-facing README and the security architecture still carry the ticket references this decision
  forbids. Nothing sets a date by which they are cleared, and the first ticket deletion will force
  the issue for that ticket only.
* **Accepted: the history keeps pointing at tickets.** Existing commit messages and the published
  changelog name work items that will not exist. They are read as archaeology, not as guidance.
* **Accepted: numbering collisions.** ADR numbers are assigned by hand with no uniqueness check.

## References

* ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
* ADR 0017 — Stored data compatibility is not owed; a major release may break the format
* ADR 0018 — A major release is declared by a label, never discovered at merge
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0020 — Performance is measured before and after, never asserted
* This directory's [README.md](README.md) — the ADR format, the ground rules and the index
* [README.md](../../README.md) — user-facing reference; the destination for the operator-facing
  half of a closing ticket
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model and hardening
  checklist; the destination for the security-facing half
* [CLAUDE.md](../../CLAUDE.md) — project conventions, including this lifecycle as a working rule
