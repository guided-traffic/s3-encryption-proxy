# ADR 0022: Tickets are work lists that get archived; decisions live in ADRs

## Status

Accepted. Date: 2026-09-07.

**Amended 2026-09-13: a closed ticket is archived, not deleted.** D4 and D10 now move the
file into an archive subdirectory of the ticket directory instead of removing it, and the
alternative this ADR rejected on 2026-09-07 — *Archive closed tickets in a subdirectory* — is
superseded below. What did **not** change is the work that closing costs: everything durable
still moves out before the file is archived, and a file that arrives in the archive with a
rule in it that no ADR holds is the same defect it always was. Two things carried the
reversal. The referencing objection does not apply to an archive inside the ticket directory,
because D5 forbids a reference from outside it either way, and the archive is inside it. And
version control keeping the history is true and useless: nobody reads a deleted file, so the
closed history the residual risk below has never found a home for had nowhere to go at all.

**Partly implemented.** Implemented today: this directory exists, its format and ground rules are
written down, the contributor instructions carry the rule, and the decisions taken between
2026-09-06 and 2026-09-07 are being lifted out of the backlog into ADRs as part of the same
round. Not implemented today: the backlog still exists in its old shape — every open ticket still
carries decision text next to its work list.

**Corrected 2026-09-10**, twice. A ticket **has** been deleted under this rule — the
development-license one, on 2026-09-09. And ticket *numbers* are gone from the user-facing
documents: the only one left anywhere outside the ticket directory is the released changelog
entry, which can never be corrected.

**Corrected 2026-09-12**, twice again. Three tickets have now been deleted under this rule, not
one: the development-license one on 2026-09-09, and the S3-surface and upload-checksum ones on
2026-09-11. And "every open ticket carries decision text" is too wide for what is there today —
the tickets written since this decision are work lists that cite ADRs, while the large ones
inherited from before it still hold decisions that no ADR claims. The directory has grown on
balance: three deleted, five written, four of them on 2026-09-12 alone — a performance round, a
defect found while correcting the developer pages, a test-suite audit and a budget defect the
audit turned up — which is the lifecycle working rather than failing. The 2026-09-10 correction
above is also wider than the tree: ticket references outside the directory are not down to the
changelog entry alone, see Residual risks.

**What is still open is D6, the work-tracking labels.** They survive in source comments, and in six
released changelog entries that are as uncorrectable as the ticket number. **Corrected
2026-09-11:** this block used to name a shipped example configuration as the worst of the set. No
label of the ticket series is in one — nor in any chart values file, compose file or script.
**Narrowed 2026-09-12:** eleven files still carry a work-tracking label and every one of them is
a test file. No production source does, so the specific harm the Context describes — a label in
shipped code holding a finished ticket open — is gone for the labels themselves; what remains is
that deleting a ticket still leaves comments citing an identifier nothing defines.
**Corrected again 2026-09-12:** one work identifier does survive outside the series, and nothing
in the tree defines it any more: it sits in a shipped example configuration, in the
continuous-integration pipeline definition and in five test files. Until it is rewritten into the
rule it stands for, something the product hands to a user does carry a work item.

## Context

The backlog was carrying four different kinds of content in one place: the outstanding work, the
decision behind it, the verification notes that produced it, and the closed history of everything
already fixed. Nothing separated them. At the point this decision was taken the ticket directory
held roughly twelve thousand lines of prose across eighteen files, the largest single file over
twelve hundred lines, plus captured profiling artefacts from a finished performance round.

The decision record lived inside files that are supposed to be deleted, and in the index page
beside them. That page defined over a hundred work-tracking labels in five parallel series —
decisions taken, threat-model findings, sweep findings, parked defects, landed fixes — and it was
the only place several settled rules were written down at all.

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

**D4.** A ticket is closed by **moving the file into the `archive` subdirectory of the ticket
directory**. Before moving it, everything durable moves out: the decision into an ADR, the
operator-facing consequence into the user-facing README or the security architecture document,
the contributor-facing one into the developer guide. Finish, document, archive. **The
extraction is the close**; the move is what is left of it afterwards. An archived file is
history and is never a source of a current rule: a reader who finds a rule there has found a
defect in the process, exactly as a reader who finds one in a live ticket has.

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

**D10.** Before a ticket file is archived, the repository is searched for its number and for the
labels it defined, and every remaining reference is cleared or rewritten to point at the ADR.
The archive changes nothing about this: a reference to an archived ticket is a reference to a
work list that ended, and D5 forbids it wherever it stands.

**D11.** The `Status` section of every ADR says plainly what is implemented and what is only
decided. The `Decision` section is written in the present tense either way, because it is the rule
the product follows from the moment the decision is taken.

## Consequences

* Closing a change costs more at the end than it used to: write or amend the ADR, update the
  user-facing documents, search for stale references, then archive the ticket. That is the point.
  The record that survives is the one a later reader needs, and the backlog stays small enough to
  stay focused.
* There are now two places to look and a discipline to keep them apart. A rule found in a ticket
  is a defect in the process, not a shortcut.
* The archive keeps what version control kept in name only, and that is its whole benefit: a
  finished work list stays readable without a commit hash. It buys nothing for the durable
  record, because whatever is worth citing later still has to be moved out deliberately, at
  the moment of archiving, by the person who still knows what mattered.
* An archive grows without bound and is read by almost nobody — the objection this ADR first
  accepted, now carried rather than avoided. It is kept survivable by two things and no more:
  the extraction duty of D4, which is what stops a live rule living there, and keeping the
  archive out of the knowledge-graph corpus, so a stale plan cannot be surfaced as an answer
  about the product.
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

**Archive closed tickets in a subdirectory instead of deleting them.** ~~Rejected. An archive is a
place where everything is kept and nothing is read. It preserves exactly the ambiguity that hurt —
a stale plan sitting one directory away from a live rule — and it re-creates the referencing
problem at the new location.~~ **Superseded 2026-09-13: this is what D4 now does.** The
referencing half of the objection was wrong — the archive sits inside the ticket directory, and
D5 already forbids a reference from outside it, so there is no new location to cite. The
ambiguity half was right and is accepted as a cost, held down by the extraction duty D4 keeps
and by leaving the archive out of the knowledge-graph corpus.

**Delete the file and rely on version control for the history.** Superseded 2026-09-13, and it
is what this ADR did between 2026-09-07 and that date. The history survives and is not read:
recovering a finished work list means knowing it existed, finding the commit that removed it
and reading it out of a diff. That is enough for an audit and not enough for the question the
material actually gets asked — why does this look the way it does — which is the question the
residual risk below has never had a home for.

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

* **Narrowed 2026-09-13: where closed history goes.** The archive is now the home for one half of
  it — the finished work list itself, with its verification notes and the reasons a piece of code
  looks the way it does, readable without a commit hash. It is not a home for the other half: the
  label index still defines over a hundred identifiers no ADR claims, it lives on the ticket
  directory's own index page, and that page is not archived with any ticket, so nothing forces the
  question. Outside the security findings, which the security architecture document restates as
  its hardening checklist, nothing else holds the material.
* **Accepted 2026-09-13: an archived plan can be read as a current rule.** This is the objection
  the 2026-09-07 decision avoided by deleting, and it is now carried. Three things hold it down
  and none of them is a check: D4's extraction duty, which is what keeps a live rule out of the
  archive in the first place; the archive staying out of the knowledge-graph corpus, so a stale
  plan is never surfaced as an answer about the product; and D5, unchanged, which keeps every
  reference to any ticket inside the ticket directory. A reader who opens an archived file
  directly has no marker in the file itself telling them its age.
* **Answered for new work, 2026-09-12: where measurement artefacts live.** ADR 0020 settled it
  for anything measured since — a run writes its record and its summary side by side, outside the
  ticket directory, and those records are kept while the profiles they reference are not. What is
  unresolved is the inheritance: the captured profiles of the finished performance round still sit
  in five directories beside their ticket, and deleting that ticket means deciding whether they
  move or go.
* **Open: enforcement is manual, and verified so on 2026-09-12.** No continuous-integration job
  looks for a ticket reference in a tracked file or in a commit message. The reference ban and the
  pre-deletion search are a habit, not a check, and the rule holds only as long as it is
  remembered.
* **Not verified: that every decision in the backlog is claimed by an ADR.** The set of ADRs for
  this round was defined in one sitting from the tickets as they stood. No cross-check has been
  run, and a decision that no ADR covers is lost the moment its ticket is archived.
* **Not verified: that the ADRs of this round agree with each other.** They were written in
  parallel from the same sources. Overlaps between siblings, and any contradiction between them,
  have not been reviewed.
* **Narrowed 2026-09-12: the documentation debt.** Neither the user-facing README nor the
  security architecture carries a ticket reference any more, and no hand-written document outside
  the ticket directory names a ticket number except the released changelog entry, which is
  history and cannot be corrected. What is left is smaller and not nothing: two comments — one in
  an integration test, one in the end-to-end deployment values — still say "the ticket" without
  naming one, and the committed knowledge graph names ticket files by path because it indexes the
  directory as part of its corpus.
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
* [docs/operations/](../operations/) — the destination for the operator-facing half of a closing ticket
* [README.md](../../README.md) — the product's front page and the configuration key reference
* [docs/security/](../security/) — the destination for the security-facing half of a ticket
* [CLAUDE.md](../../CLAUDE.md) — project conventions, including this lifecycle as a working rule
