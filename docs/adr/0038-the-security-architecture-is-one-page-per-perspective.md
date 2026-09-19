# ADR 0038: The security architecture is one page per perspective

## Status

Accepted. Date: 2026-09-19. **Supersedes D5 of ADR 0035**, which kept the security design
as one undecomposed document at the repository root.

**Implemented in the change that wrote this record.** The single security document and the
page of closed hardening items are deleted; `docs/security/` carries one page per
perspective plus a page describing the form; vulnerability reporting is `SECURITY.md` at
the repository root. What is *not* done is the knowledge graph, which is rebuilt by a
separate, user-approved run and still names the deleted layout.

## Context

The security design had grown to twelve hundred lines under nine numbered sections, two of
which were over three hundred lines on their own. It had the shape ADR 0035 diagnosed in
the README and treated everywhere else: one page holding every subject, where a reader who
wants one answer meets all of them.

ADR 0035 D5 kept it whole on purpose, and gave a reason worth taking seriously — that
twenty-four ADRs cite it, several by section number, so splitting it means editing those
citations, and a mis-edited citation points a reader at a rule that is not where it says it
is. **That reason was measured before this change and did not hold.** Of the live
references outside the knowledge graph and the ticket directory, six named a section or an
anchor: two code comments, one ADR, one operator page, and two links to the
vulnerability-reporting section. Every other citation was a "see also" link with no anchor,
which needs a new target and no thought. The alternative priced the cost of anchors; there
were six.

Two further things did not work, and neither is about length.

**Splitting history from current rule produced a backlog.** The closed hardening items were
moved to a page of their own, where they became eleven entries with closure dates, checkbox
lists and identifiers — a work list living in the security documentation, cited by an index
rather than read by anybody. What was valuable in them was never the entry; it was the
sentence explaining why a current rule reads the way it does, and that sentence belongs
beside the rule.

**A policy was living inside a design.** The last section was how to report a
vulnerability — a GitHub convention with its own well-known filename, which has nothing to
do with a threat model and is looked for somewhere else entirely.

## Decision

**D1 — The security architecture is a directory, one page per perspective.** A perspective
is a question a reader arrives with — what the adversary can do, where the keys live, what
a stored object proves, what is checked on a request — not a mechanism in the code. A new
subject is a new page; it is never a section added to a page about something else.

**D2 — Every page ends with what it does not cover, and a gap lives beside its mechanism.**
An open gap is stated in the closing section of the page whose mechanism has the gap,
together with what an operator can do in the meantime. There is no central list of gaps.

**D3 — An open gap keeps a stable identifier; a closed one loses it.** An open gap carries
an `H-<n>` in its heading, and the number is never changed or reused, because reports name
it. When a gap closes, the entry goes with the number: what survives is the rule it left
behind, written as prose inside the mechanism's own section, in the past tense. **Nothing
under the security directory takes the shape of a ticket** — no checkbox list, no owner, no
closure log, no date for work that has not happened.

**D4 — The directory's own README states the form and names no page.** It says what a page
must contain, how a claim is verified, and how to add one. The file names are the index; a
second index would be a second thing to keep current.

**D5 — A security page is cited by file name and heading, never by a section number.**
Numbered sections are not used. A heading is stable because it is what the page is about; a
number is stable only until something is inserted above it.

**D6 — Vulnerability reporting is `SECURITY.md` at the repository root.** It is a policy,
not a design, and it belongs at the filename the platform and every reader look for.

**D7 — The five homes of ADR 0035 D7 are unchanged in number.** The security home is the
`docs/security/` directory rather than a single root file; every other home is as that
record left it.

## Consequences

- **There is no single page to hand somebody who asks for the security architecture.** They
  get a directory. That is the point — the previous single page was handed over and not
  read — but it is a real loss for anybody who wanted one artefact, and a reader who does
  not open the README learns the shape from the file names alone.
- **Every inbound reference had to name a page.** Two dozen ADR references, four root
  documents, three index pages, two operator pages, two code comments, one test comment,
  the chart README, and the citations in nine live and nine archived tickets. A reference
  that names a directory rather than a page survives the next split; one that names a page
  and a heading does not, and that is the trade D5 takes on purpose.
- **A closed gap's record is now prose, not an entry.** It cannot be counted, listed or
  reported on, and finding "what was H-6" needs the git history rather than a page. What it
  gains is being read by the person who is reading the rule it explains.
- **Allocating the next gap number means searching the directory**, because the numbers no
  longer live in one list.
- **Nothing enforces D2, D3 or D4** beyond review, like every documentation rule this
  project has.
- **The knowledge graph is behind**, as it was after ADR 0035, and now names two layouts
  that no longer exist.

### Where each section went

Text written before 2026-09-19 — a commit message, a pull request, a copy of the
old document — cites the deleted single document by section number. This is what
each section became.

| Cited as | Now |
|---|---|
| §1 threat model, §2 roles and boundaries, §6.6 transport | `threat-model.md` |
| §3.1–3.3 keys, providers, secret custody; §7.1–7.2 rotation | `key-management.md` |
| §3.4–3.6 metadata, format guarantees, what the backend learns | `stored-objects.md` |
| §6.1–6.4 authentication, clock skew, what is not verified (H-2) | `request-authentication.md` |
| §6.4a the client leg | `upload-integrity.md` |
| §6.5 handlers that refuse | `refusals.md` |
| §4 isolation, §5 privilege footprint | `tenancy-and-privilege.md` |
| §7.3–7.5 propagation, chart default, licence expiry (H-4) | `operational-security.md` |
| §8 residual risks | the closing section of the page whose mechanism has the gap |
| §9 reporting a vulnerability | `SECURITY.md` at the repository root |

The eight closed hardening items of §8 kept no entry of their own: each survives
as prose in the section of the mechanism it explains, and lost its `H-<n>` with
its entry (D3).

## Alternatives Considered

**Keep the single document (ADR 0035 D5).** Rejected, and this record exists because the
reason it gave was measurable and was measured: the citation cost it priced was six
anchors, not twenty-four documents.

**Keep a thin root document as a map of the directory.** Rejected. It is a second index to
maintain beside the directory README, and an index that is not read decays into a summary
that contradicts the pages it points at. The documentation map already lives in the
README, where a reader who does not know the layout actually starts.

**Collect the open gaps on one page.** Rejected for the reason the closed-item page
demonstrated: a list of items organised by item is a backlog, and it is read by nobody who
is evaluating a mechanism. Beside its mechanism, a gap is read by exactly the person who
needs it.

**Keep the history page and only remove the ticket shape.** Rejected. What made it a
backlog was not the checkboxes, it was being organised by item rather than by subject. A
closed defect is not a subject.

## Residual risks

- **The citation count was measured on 2026-09-19** by searching the tree with the
  knowledge graph and the ticket directory excluded. The tickets were then retargeted as
  well, archived ones included: a statement recording a past edit to the deleted document
  keeps its tense and says "the security design", while a statement about where material
  lives now names the page. Rewriting an archived work list is a deliberate exception to
  treating an archive as immutable, taken so that no reader of one follows a dead name.
- **The prose folded out of the closed-item page was condensed by hand in this change.**
  The facts were carried across from text that had been verified against the code; the new
  wording was not re-verified against the code, and the pages say where a claim is old.
- **Nothing checks that a page ends with its limits section**, which is the rule most likely
  to be forgotten by somebody adding a page in a hurry.
- **D6 moves an anchor other repositories may have linked.** Two in-repository links were
  updated; a link from outside this repository to the old reporting section is broken and
  cannot be detected here.

## References

* [ADR 0035](0035-the-readme-advertises-the-reference-lives-under-docs.md) — the record this
  one amends: the README advertises, the reference lives under `docs/`
* [ADR 0022](0022-tickets-are-work-lists-that-get-archived.md) — why a work list does not
  live in documentation that states current rules
* [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md),
  [ADR 0014](0014-authentication-is-sigv4-no-rate-limiting.md) — the two decisions whose
  closed findings became prose under the threat model's second rule
* [docs/security/](../security/) — the directory this record describes
* [SECURITY.md](../../SECURITY.md) — the reporting policy D6 moves to the root
