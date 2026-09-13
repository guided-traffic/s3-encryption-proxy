# Archived tickets

Finished work lists. **Nothing in this directory is a current rule**, and nothing
here is maintained: a file arrives when its work has landed and is never updated
afterwards, so every path, line number and status it names describes the tree of
the day it was archived.

What a file here is good for is the question a decision record does not answer —
why does this look the way it does: what was tried, what was measured, what was
refused on the way. What it is never good for is what the product does today.
That is:

| Question | Where |
|---|---|
| What the product does and why, what was rejected | [docs/adr/](../../adr/) |
| How a subsystem works, an invariant, a hard-won detail | [docs/developer/](../../developer/) |
| What an operator or a client needs | [README.md](../../../README.md) |
| The threat model and residual risks | [SECURITY_ARCHITECTURE.md](../../../SECURITY_ARCHITECTURE.md) |
| Work still outstanding | a live ticket in [docs/tickets/](../) |

**A ticket is archived only after everything durable in it has been moved out**
(ADR 0022 D4). If you find a rule here that no ADR holds, that is a process
defect from the day it was archived — lift it into an ADR rather than citing this
file.

The reference ban is unchanged: nothing outside `docs/tickets/` may reference a
ticket, archived or live (ADR 0022 D5). This directory is also kept out of the
knowledge-graph corpus, so a finished plan is never surfaced as an answer about
the product.
