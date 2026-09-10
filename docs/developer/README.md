# Developer documentation

Overviews for people changing this code. The detail is in the code; what lives
here is the shape of things — how the pieces fit, which invariants hold, and why
a design that looks odd is the way it is.

**What belongs here:** anything a future developer needs before touching a
subsystem, that the code cannot state on its own. A package map. The invariants
a format or a protocol rests on. The reason a boundary sits where it does. The
hard-won knowledge from a defect that was expensive to find.

**What does not:** decisions (those are [ADRs](../adr/), and an ADR carries no
references into the code so that it stays true when the tree moves), work lists
(those are [tickets](../tickets/), and they are deleted when the work lands),
user-facing reference (that is [README.md](../../README.md)), and the security
design (that is [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md)).

Unlike an ADR, a document here **may and should** point at files and functions.
That is the point of it. It also means it goes stale when the tree moves, so
whoever moves the tree updates the page in the same change.

| Page | Read it when |
|---|---|
| [package-map.md](package-map.md) | You are new, or you are looking for where something lives |
| [storage-format.md](storage-format.md) | You touch the codec — one stored format, `s3ep-gcm-seg-v2` — or anything that computes a size or an offset |
| [request-paths.md](request-paths.md) | You touch a handler: what happens on a PUT, a GET, a ranged GET, a HEAD |
| [multipart.md](multipart.md) | You touch multipart upload, the part table, or the trailer |
| [errors.md](errors.md) | You are choosing a status code or an S3 error code |
| [testing.md](testing.md) | You are adding a test, or a suite is failing and you need to know what it is for |
| [performance.md](performance.md) | You are changing a hot path, or you need a before/after number |

## What has no page here

Four subsystems are not covered by a page above. That is a gap, not a hidden
document; where their material actually is today:

| Subsystem | Where it is |
|---|---|
| SigV4 authentication, header and pre-signed | The validation story in [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md), including what is *not* verified |
| Configuration keys and their validation | [README.md](../../README.md) for the keys, [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) for the rule that a key exists only if code reads it |
| The license gate | [ADR 0016](../adr/0016-the-license-is-a-startup-gate.md) |
| Monitoring and the exported metric set | `internal/monitoring/metrics.go`; the endpoint and its configuration keys are in [README.md](../../README.md) |
