# How a security page in this directory is written

This directory is the security architecture of the product: what it defends,
how, and — with the same weight — what it does not. One page covers one
perspective. There is deliberately no single page that covers all of them,
because a document nobody finishes is a document nobody checks.

This page describes the **form**. It names no individual page on purpose: the
set changes, and an index here would be a second place to keep current. The
file names are the index.

## What belongs here, and what does not

| Statement | Home |
|---|---|
| What the product defends against, how, and what it leaves open | here |
| Why a decision was taken, what was rejected | an [ADR](../adr/) |
| How a subsystem works for somebody changing it | [docs/developer/](../developer/) |
| What an operator has to configure, run or watch | [docs/operations/](../operations/) |
| Work still outstanding | a [ticket](../tickets/) |
| How to report a vulnerability | [SECURITY.md](../../SECURITY.md) at the root |

A page here is written for somebody who has to judge whether the product is
safe enough for their data — an operator, an auditor, a contributor changing
something security-relevant. It names files and functions where that makes the
claim checkable, the way a developer page does, and it therefore goes stale
when the tree moves: **whoever changes the behaviour updates the page in the
same change.**

## The shape of a page

1. **A title that names the perspective**, not the mechanism. The reader is
   choosing a page from a directory listing.
2. **One paragraph under it** saying what the page covers, and pointing at the
   neighbouring perspective a reader may actually have wanted.
3. **The body**, in `##` sections. No numbered sections — see *Citing* below.
4. **A closing `## What this does not cover`.** Every page ends with one. A page
   that cannot name its own limits has not been thought through, and a reader
   who finds no limits section assumes there are none.

Open gaps live in that closing section of the page whose mechanism has the gap,
never in a list of their own. A gap beside the thing it affects is read by
somebody evaluating that thing; a central list is read by nobody.

## Ground rules

- **Every claim is verified against the code before it is written.** Read the
  type, the function, the test. Where something could not be verified, the page
  says so in the sentence that makes the claim — "not verified, and this is the
  gap" is a complete statement. An assumption must never travel as a fact.
- **Where the code and this directory disagree, the code wins**, and the
  disagreement is named rather than quietly corrected.
- **A gap is documented, not hidden.** Name which mechanism, which adversary,
  whether it is live today, and what an operator can do in the meantime. A
  vague warning is worse than none, because it cannot be acted on.
- **No tickets.** No checkbox lists, no owners, no dates for work that has not
  happened, no "planned for". A page here states what *is*. Outstanding work is
  a ticket and lives elsewhere; a decision is an ADR and lives elsewhere.
- **History only where it carries a rule.** A defect that was closed is worth
  three sentences if, and only if, it explains why a current rule reads the way
  it does — it is written as prose inside the mechanism's own section, in the
  past tense, never as an entry in a changelog. Everything else about it is in
  the git history.
- **A fixed identifier for an open gap.** An open gap carries an `H-<n>` in its
  heading, and the number never changes or gets reused, because reports and
  conversations name it. A gap that closes loses its number along with its
  entry: what survives is the rule it left behind.
- **Security notes only where a real security relation exists.** No boilerplate
  paragraph on a page that has no such relation.
- **English, always** — as everywhere in this repository.

## Citing

Cite a page by its file name and its heading, never by a section number. The
previous single document was cited by number from ADRs, from operator pages and
from code comments, and every renumbering silently pointed a reader at the
wrong rule. Headings are stable because they are what the page is about; a
number is stable only until something is inserted above it.

## Adding a perspective

Add a page; never add a section to a page about something else. If a new
subject fits an existing page's title, it belongs there — if it needs the title
widened, it is a new page. Same rule, same reason, as one client per page under
[docs/operations/](../operations/): a reader looking for the subject should
find it by the file name, and a page whose name stops predicting its content
stops being findable.

A page that has grown past one sitting holds two perspectives. Split it.
