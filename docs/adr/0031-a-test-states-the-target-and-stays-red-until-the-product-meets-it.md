# ADR 0031: A test states the target behaviour, and stays red until the product meets it

## Status

**Accepted.** Date: 2026-09-13.

Built today: the two client end-to-end suites were rewritten to this rule and are red; a sweep of
the whole test tree against it found twenty-seven further tests that asserted the answer the
product gives rather than the answer it owes, and those now state the target and are red too. The
unit round, the integration suites and two of the end-to-end suites therefore do not pass on the
unreleased 5.0.0 branch, and the release is blocked behind them, which is D8 working rather than
failing.

**Decided and not built: D7 and D9, for everything except the two client suites.** Those two name
the rule and the record in the failure itself and report what is still broken in their own output.
The twenty-seven tests the sweep rewrote do not: their citation sits in a source comment beside the
assertion, and the failure a reader sees is bare tool output. The integration suites produce no
summary of what is open. This matters more than bookkeeping — D7 and D9 are named below as the
whole mitigation for the largest risk this record accepts, so until they are built that risk is
accepted unmitigated.

What is **open** is the product work the red tests are waiting for — it is tracked as a work list,
not here, because a defect is not a decision.

This record generalises a rule that ADR 0019 states for the integration and end-to-end suites
alone. It binds every layer, the unit round included.

## Context

The two client end-to-end suites — one per supported S3 client, driven as the real client binary —
were built to answer an open question about the entity tag. Every case that the product failed was
written down as an **expected refusal**: the case recorded what the client does today, together
with the defect that expectation pinned, and passed when the product behaved that way.

The suites were green. The release gate was green. And the pipeline reported, in the only place
anyone looks, that the product was ready to be merged — while an object written by a single
request could, through a client configured the documented way, be **neither uploaded nor fetched
back**, and a client-driven upload in parts was refused part by part. Objects written by other
paths worked, which is exactly why the green was believable. The defects were real, they were
written down, and they were written down in a generated table that nobody opens when the check
beside it is green.

That is the failure this record exists to prevent, and it has a precise shape. A test is not a
notebook. It is the one artefact in the tree whose colour is read by people who are not reading
anything else — a pull request, a release gate, a contributor deciding whether their change broke
something. Encoding the current answer as the expectation does not record a defect; it **spends
the only signal the project has** to say the opposite of the truth.

Two further things came out of the sweep, and both shape the decision below.

The first is that the anti-pattern is not rare and does not look like itself. It appears as a
comment conceding a deviation next to an assertion that locks it in; as a skip whose reason is a
product gap rather than a missing environment; as an assertion written negatively so that it
cannot fail; as a test asserting a refusal the product intends to remove. Fifty-five candidates
were found across the tree.

The second is that **half of them were not defects at all.** A refusal an ADR records as the
product's intent — a server-side copy refused under encryption, a customer-provided key refused, a
checksum algorithm this proxy does not compute refused, an object with no proxy metadata refused —
is the product working, and a test that asserts it is stating the target. Twenty-eight candidates
were refused on exactly that ground. Without that distinction the rule below would have turned
every deliberate refusal in the product into a red test, and the rule would have been abandoned
within a week.

## Decision

**D1** A test states the behaviour the product is **supposed** to have. It never states the
behaviour the product has, where the two differ.

**D2** A test the product does not satisfy is **red**, and it stays red until the product is
fixed. A red suite is a correct suite.

**D3** Such a test is **committed red**, and may be written before the fix, beside a defect
report, or on its own. Landing the test is not gated on landing the fix. The reason is not that
there is nowhere else to record a defect — a work list records it — but that a running red test
keeps proving the defect is still that defect, and keeps the path under test exercised. A work
list proves nothing and rots.

**D4** The current answer is never the expectation, in any disguise. Not an expected-failure
marker, not a table of known defects, not a "today it answers X" comment beside the assertion that
makes it so, not an assertion weakened until it cannot fail.

**D5** A test is never skipped, disabled or deleted to make a suite green (ADR 0019 D4). A skip
states a missing *environment* — an unreachable backend, a transport the client does not use —
never a missing *behaviour*. Skipping and pinning are the same decision wearing different clothes.

**D6** **A behaviour an ADR records as the product's intent is the target.** A refusal, a
restriction or a deviation that a decision here puts in place is asserted as what the product
does, and such a test is green and correct.

A behaviour counts as decided only when a record states it as the rule **and leaves no part of the
question open**. A record that puts a deviation in place while deferring the question underneath it
has decided the smaller thing and not the larger one, and the larger one is open. A residual risk
is not a decision; it is the record saying it knows and has not chosen.

The entity tag is the worked example, and it is the case this rule is easiest to score wrong. One
record keeps it as the entity tag of the stored bytes, consistent across the listing and the head,
and documents that as a known deviation — decided. The same record says in the next sentence that
making it describe the plaintext is not decided there, and two further records carry it as an open
residual risk. The consistency is the target; the value is the open question. A test asserting that
the listing and the head agree is green; a test asserting that a client can verify what it uploaded
is red.

Before treating an assertion as a pinned defect the record that decides it must be looked for, and
quoted. This is the load-bearing half of the rule and the expensive one to get wrong in either
direction: read too widely it turns every deliberate refusal red, read too narrowly it legalises
every defect that anyone once wrote down.

**D7** A red test **names the rule it wants and the record that rule belongs to**, in its own
failure message. A reader of a failing pipeline is owed the target and its authority, not a diff
between two values.

**D8** A red test blocks what a red test blocks. Where a suite gates the release, the release
stays blocked until the product meets the target or the decision behind it changes. Deciding the
answer differently is a legitimate way out; making the test agree with the product is not.

Four moves weaken a gate and all four are covered. A suite is not removed from the release job's
prerequisites. **The list of checks a merge requires is part of the gate**, even though it is
configured outside the repository and changes to it leave no diff — a change to it is a recorded
decision like any other, and it is the least visible of the four. A pinned client or tool version
is never moved in order to change a verdict; a verdict that changes when a pin moves is reported,
because that is the finding. And a suite that asserts a target is placed where it gates, not in a
round that gates nothing.

**D9** A suite **reports what is still broken in the place its result is already read** — the run's own output, and the summary a continuous
integration check shows. Nobody should have to open an artefact, or read the test tree, to learn
which defects are open.

**D10** The list of what the red tests are waiting for is a work list, and is deleted when the
last one is green. It is not a decision and does not live here.

## Consequences

**The branch cannot be merged, and that is the point.** The unit round, the integration suites and
two end-to-end suites are red, so the release is blocked. Before this record the same defects
existed and the pipeline was green; the only thing that changed is that the pipeline now says so.
An owner who wants to ship anyway has one honest route — decide the behaviour differently and
record that decision — and one dishonest one, which D8 forecloses.

**Red becomes normal, and that is the cost.** A permanently red check is a check people stop
reading, and the project has now taken on that risk deliberately. D7 and D9 are the mitigation:
a failure that names its target and a summary that lists what is open are readable in a way that
"14 tests failed" is not. Whether that is enough is not verified, and it is the first thing to
re-measure if this rule starts being worked around.

**Every new deviation costs a decision.** Under D6 a test may only assert a refusal once a record
decides it. That makes the cheap move — shipping a limitation and pinning it in a test — unavailable,
and replaces it with writing the decision down. That is the intended price, and it is the same
price ADR 0008 charges for a response element and ADR 0013 for a configuration key.

**Half of an audit's findings are not findings.** D6 means any sweep for this anti-pattern has to
carry an adversarial second pass that tries to prove each candidate is decided behaviour. A sweep
without it produces a list that is half wrong, and acting on it would flip deliberate refusals
into red tests.

**A test's failure message is now a product of the decision, not an afterthought.** D7 makes the
message part of what is reviewed.

## Alternatives Considered

**Pin the current behaviour and record the defect elsewhere** — the practice this record replaces.
It fails on the signal: the pipeline is green while the product is broken, and the record lives
where it is read only by someone already looking for it. It is also self-erasing, because the
pinned expectation is what a later reader takes for the intent.

**An expected-failure marker**, so the suite is green while the case is known to fail. It keeps
the bookkeeping honest and still reports green, which is the half that caused the failure above.
It also decays: a marker nobody must remove is a marker nobody removes, and the case quietly stops
being about a defect and starts being about the marker.

**An enforced known-failure manifest**, which is the strongest form of the previous option and the
one a reader will propose. The test still states the target and still fails; the set of failing
tests is committed to a file; and the run fails when a test outside that set fails **or** when a
test inside it starts passing. It does not decay, because a fixed defect that stays listed breaks
the build. It keeps D1 and D4 intact, since the assertion is unchanged. And it does the one thing
permanent red cannot: it preserves the regression signal, because a new breakage is a test outside
the set.

It was rejected, and not because it is unsound — it is the better engineering. It loses on what it
costs to be wrong. The manifest is a second place where the current answer is written down, and it
is authoritative: adding a line to it is how a defect is admitted, so it is also how a defect is
admitted quietly. The record above began with exactly that shape — a written-down set of known
failures, honest when written, unread by the time it mattered — and the difference between that and
a manifest is enforcement, which stops it rotting but does not make anyone read it. Permanent red
is the cruder instrument and the one that cannot be satisfied by editing a list. **This is the
alternative most likely to replace this decision**, and the honest form of the rejection is: it is
refused for now because the project has just been burned by the softer form of it, and it should be
revisited once the red is small enough to be about regressions rather than about a backlog.

**Land the test with the fix**, which is what most reviewers propose first and which D3 refuses.
It is right whenever the fix is at hand. It fails for a defect nobody is fixing this month: the
choice then is a test that does not exist, or a work list entry that proves nothing and rots, and
the path under test goes unexercised either way.

**Skip the case until the fix lands.** Worse than the marker: the case stops running, so it also
stops proving that the defect is still the defect, and a second, unrelated breakage in the same
path is now invisible. ADR 0019 D4 already refused this for the integration and end-to-end suites;
D5 above extends it.

**Keep the suites green by asserting only what works.** This is pinning with the evidence removed.
The product would look correct and the gap would be nowhere in the tree.

**Let each layer choose.** Unit tests pin, end-to-end suites state the target. Rejected because
the failure has nothing to do with the layer: the sweep found the same anti-pattern in the unit
round, in the integration suites and in one of the client end-to-end suites, and a rule that holds in
one place and not another is a rule nobody can apply without asking.

**Take the red suites off the release gate so the branch can ship.** Rejected as the specific
thing D8 exists to forbid. It converts a statement about the product into a statement about the
pipeline's configuration, and the next reader cannot tell the difference.

## Residual risks

- **Red fatigue.** Accepted, and the largest risk here. A pipeline that is red for a long time
  trains people to ignore it, and D8 guarantees it stays red until real work lands. Not verified:
  whether D7 and D9 keep it readable long enough for that work to happen.
- **D6 is a judgement, and judgements drift.** "A record decides this" is clear at the extremes
  and not at the edges — a decision that names a behaviour in passing, a residual risk that reads
  like an acceptance. Two readers will disagree on some cases. The rule is to find the record and
  quote it; where there is nothing to quote, the behaviour is not decided.
- **A decision can be written to make a defect legal.** Nothing here prevents recording a
  deviation purely so that a red test may go green. The protection is that the decision is then
  visible, arguable and dated, which a pinned assertion never was — but it is a protection by
  exposure, not by construction.
- **Not verified: the sweep's completeness.** The tree was read by eight parallel readers against
  the definition above, and every candidate was checked adversarially. Both halves can miss: a
  reader can fail to recognise the anti-pattern in an unfamiliar shape, and the adversarial pass
  refuses a true finding whenever it can construct a plausible decision for it. The count is a
  floor, not a total.
- **A red target may be unsatisfiable, and nobody would know.** A test that has never passed has
  never been shown to be *correct*. Until someone attempts the fix, "the product is broken" and
  "the test asks for the wrong thing" look identical, and a pinned assertion at least passed once.
  This is the sharpest cost of D3 and it is accepted: the target is an argument, not a measurement,
  until the product meets it.
- **Regression blindness**, which is not red fatigue and is worse. With several rounds red and
  nothing comparing today's failing set against yesterday's, a breakage introduced tomorrow does
  not change any colour. Red fatigue is about attention; this is the mechanism no longer producing
  the signal at all, however attentive the reader. It is the strongest argument for the enforced
  manifest above, and it is accepted here without a mitigation.
- **No emergency release path.** The release job requires every gate, so a security fix in a
  dependency of an encryption product cannot ship while an unrelated target is red. The way out
  this record offers — decide the behaviour differently and record it — is not available in an hour
  under a disclosure deadline. **This is not decided**, and it should be decided before it is
  needed rather than during: either a security release may cut past red gates under a named,
  written procedure that says who may do it and what backfills afterwards, or it may not and the
  project accepts an unbounded delay on security fixes. Both are defensible; finding out which one
  was meant during an incident is not.
- **Not verified: what this costs a contributor.** The rule asks for a decision record before a
  limitation may be asserted. Whether that slows ordinary work enough to matter has not been
  measured.

## References

- ADR 0019 — the integration and end-to-end suites are the product and are never skipped; this
  record generalises its rule to every layer and supplies the target-versus-current distinction
  it did not state.
- ADR 0006 — support is claimed only as far as it is exercised, and a claim names its proof; a
  suite that asserts the current answer proves the claim against itself.
- ADR 0027 — a difference between two backends is the conformance suite's finding rather than a
  defect of this proxy, and is therefore asserted rather than treated as a pinned defect under D6.
- ADR 0008 — a response carries only what the proxy can vouch for; the same discipline applied to
  a response element that D6 applies to an assertion.
- ADR 0010 — the entity tag of a stored object is left open there, which is why the client suites
  are red rather than wrong.
- [CLAUDE.md](../../CLAUDE.md) — the working form of this rule for anyone changing the tree.
