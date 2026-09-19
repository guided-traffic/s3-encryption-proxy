# ADR 0035: The README advertises the product; the reference lives under `docs/`

## Status

Accepted. Date: 2026-09-15. **Amended 2026-09-19: D5 is superseded by
[ADR 0038](0038-the-security-architecture-is-one-page-per-perspective.md)**, which
decomposes the security design into one page per perspective under `docs/security/` and
deletes both the root document and the page of closed hardening items. Every other rule of
this record stands.

**Implemented in the change that wrote this record.** The README went from 2075 lines to
about 550, `docs/operations/` was created with eight pages, and the eight closed items of
the hardening checklist moved to a page of their own under `docs/security/`. What is *not*
done is the knowledge graph under `graphify-out/`, which is rebuilt by a separate,
user-approved run and does not know about the new directories.

## Context

The README had grown for as long as the product had. By 2026-09-15 it was 2075 lines, and
the growth was not padding — every line of it was true and most of it was load-bearing
somewhere. That was the problem. The page carried, in one scroll:

- the pitch, the feature list and the fast start — the part a reader who does not yet use
  the product needs;
- the complete configuration key reference;
- seven hundred lines of S3 API behaviour, verb by verb, down to which sub-resource answers
  `501` and which answers `405`;
- the exported metric set, the probe semantics and the `/status` document;
- a hundred-line migration guide from releases that can no longer read their own data;
- deployment detail for three installation paths;
- and the per-client configuration notes for Velero, rclone and s3cmd, including the one
  rclone option this product asks for and the reason behind it.

The consequence is not that the page is long. It is that **the promotional half is
unreachable behind the reference half**. Somebody evaluating the product meets a table of
`x-amz-*` header behaviour before they have decided whether they want an encrypting proxy
at all, and somebody already running it scrolls past the pitch every time they need the
metric table. Neither audience is served by the page being one page.

The project already had three homes for durable material and a rule for choosing between
them: a decision goes in an ADR, a subsystem goes in `docs/developer/`, the threat model
goes in the security design at the root. Operator and client reference had no home of its own —
the rule sent it to the README — so everything that was neither a decision, nor a
subsystem, nor a threat landed there by default. The README was not chosen as the place for
this material; it was the only place left.

`SECURITY_ARCHITECTURE.md` had the same shape of problem at 1447 lines, but not the same
answer. Twenty-four of the thirty-four ADRs cite it, several by section number, and so do
`CONTRIBUTING.md` and the chart README. Moving a section out of it moves an anchor that
something else names. What is genuinely separable there is its history: eight of the eleven
hardening items are closed, and they account for roughly three hundred lines that describe
defects the product no longer has. (The "several by section number" was never counted. When
it was, in 2026-09, it was six — see ADR 0038.)

## Decision

**D1 — The README is the front page, and its job is to make somebody want the product and
able to start it.** It carries the pitch, the feature list, the naming conventions, the
documentation map, the fast start, the encryption providers, the supported clients, the
installation paths, the configuration, a monitoring summary, a security summary, the
development entry point and the licence. A reader who has never run the proxy must be able
to read it from top to bottom.

**D2 — Operator and client reference lives under `docs/operations/`, one page per subject.**
That is the fourth home, beside the ADRs, the developer pages and the security architecture.
A page there is written for somebody who runs the proxy or points a client at it, and —
unlike an ADR — it may name files, flags and functions, so it goes stale when the tree moves
and is updated in the same change.

**D3 — The complete configuration key reference stays in the README, and exactly there.**
Every key the proxy reads, with its default, has one home. A page under `docs/operations/`
explains a setting; it never restates the key list, because two lists drift and the drift is
invisible.

**D4 — Each supported client gets one page under `docs/operations/clients/`.** Adding a
client adds a page; it never adds a section to another client's page. This is the same rule
the end-to-end suites already follow — one tool, one suite, one job — for the same reason:
what is broken should be named by where it is, not found by reading.

**D5 — The security design stays at the repository root.** ~~`SECURITY_ARCHITECTURE.md` is
not decomposed. Its closed hardening items move to a history page under `docs/security/`,
which states no current rule; everything a reader might cite by section number stays where
it is.~~ **Superseded 2026-09-19 by
[ADR 0038](0038-the-security-architecture-is-one-page-per-perspective.md).** The security
design is a directory of one page per perspective, the history page is gone, and a security
page is cited by heading rather than by section number. The citation cost this rule was
protecting was measured before the split: six anchors, not twenty-four documents.

**D6 — The README links, it does not explain.** When a paragraph in the README starts
explaining a mechanism, the explanation belongs in the page the paragraph links to. The
README's own links point at documents, at the example configurations a user actually opens,
and at ADRs — not into the source tree.

**D7 — Five homes, and a durable statement goes to exactly one.** A decision goes to an ADR.
A subsystem's invariants go to `docs/developer/`. What an operator or a client needs goes to
`docs/operations/`. The threat model and the residual risks go to `docs/security/` (ADR 0038;
this record wrote `SECURITY_ARCHITECTURE.md` here). Outstanding work goes to a ticket. The README carries the product's front page and the
configuration key reference, and points at the rest.

## Consequences

- **The README is readable end to end again** — about 550 lines against 2075 — and the
  reference it used to hold is not lost, it is addressable: a reader who wants the sub-resource
  table opens one page instead of scrolling past it.
- **There is one more directory to keep current**, and a page under `docs/operations/` goes
  stale exactly the way a developer page does. Whoever changes the behaviour updates the page
  in the same change; there is no automated check for this and there was none before.
- **A cross-document link is now a hop.** Somebody reading about rclone's entity-tag option
  follows a link to learn what an entity tag is here, where it used to be an anchor in the same
  file. That is the price of the split and it is paid by the reader who is already deep in one
  subject, which is the right reader to charge.
- **The README's emoji headings need explicit HTML anchors** for the handful of targets other
  documents name, because an emoji heading's generated anchor is neither stable nor guessable.
  Four anchors carry that weight today.
- **`SECURITY_ARCHITECTURE.md` lost three hundred lines and no anchor.** Every section number
  an ADR cited was still in the file it was in — until ADR 0038 replaced the file with a
  directory and retargeted every citation.
- **The knowledge graph and the marketing site are behind.** `graphify-out/` was built before
  this change and its articles name a documentation layout that no longer exists; the site
  repository carries its own hand-maintained copies of some of this prose and is not touched
  by a change in this repository.

## Alternatives Considered

**Leave it in the README and accept the length.** Rejected. The cost was not theoretical: the
page had reached a size where its first audience — somebody deciding whether to use the product
— could not get through it, and its second audience scrolled past the pitch on every visit. A
page that serves nobody well is not saved by being correct.

**Fold the operator reference into `docs/developer/`.** Rejected, and it was the cheaper option:
no new directory, no new convention, no record like this one. But that directory defines itself
in its own first paragraph as the place for people *changing the code*, and its index is a
package map, a codec description and a test-layer overview. An operator who needs the metric
table should not have to decide whether they are a contributor first.

**One large `docs/reference.md`.** Rejected. It moves the problem one level down and produces the
same page with a different name, without the property that makes the split worth anything: that a
question has an address.

**Split `SECURITY_ARCHITECTURE.md` the same way.** Rejected here, **and taken in ADR 0038 on
2026-09-19.** The reason given at the time: twenty-four ADRs cite it, several by section number,
along with `CONTRIBUTING.md` and the chart README, so splitting means editing those citations,
and a mis-edited citation in an ADR is worse than a long page. What was not done was counting
"several": six references named an anchor, and the rest were see-also links. The estimate, not
the reasoning, is what kept the document whole for four days.

**Per-client sections on one `clients.md`.** Rejected for the reason D4 gives: a third client
would be a third section on a page that is already two subjects long, and the page's name would
stop predicting its content.

## Residual risks

- **Nothing enforces D2 or D6.** A future change can put an explanation back into the README, and
  the only thing that catches it is review. The same is true of every documentation rule this
  project has.
- **`docs/operations/` was populated by moving existing text.** The text was true when it was
  written and the move did not re-verify it against the code. Claims about request counts, error
  codes and client behaviour carry the verification date they had in the README, which is not
  stated per paragraph.
- **The link rewriting was checked mechanically**, by resolving every relative link and every
  fragment in the changed files. That proves a target exists; it does not prove the target is the
  right one.
- **Ticket files still name README sections that have moved.** Tickets are outside this rule and
  are archived when their work lands, so they were left alone.
- **`docs/security/` holds one file.** If nothing else ever belongs there it is a directory for a
  single page, which is a small cost accepted to keep history out of the design document.

## References

* [ADR 0022](0022-tickets-are-work-lists-that-get-archived.md) — the same shape of rule for tickets:
  durable material is extracted, the work list is not the home of a decision
* [ADR 0006](0006-the-proxy-serves-any-s3-client.md) — why each supported client is argued and
  proven separately, which D4 follows for their documentation
* [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) — why the configuration key
  reference has to have exactly one home
* [README.md](../../README.md) — the front page this decision defines
* [docs/operations/README.md](../operations/README.md) — the index of the new home
* [docs/security/](../security/) — the security design, decomposed by
  [ADR 0038](0038-the-security-architecture-is-one-page-per-perspective.md)
