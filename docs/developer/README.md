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
(those are [tickets](../tickets/), and they are archived when the work lands),
what an operator or a client needs (that is [docs/operations/](../operations/),
with the configuration key reference itself in [README.md](../../README.md)), and
the security design (that is
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md)).
[ADR 0035](../adr/0035-the-readme-advertises-the-reference-lives-under-docs.md)
is the rule that separates those homes.

Unlike an ADR, a document here **may and should** point at files and functions.
That is the point of it. It also means it goes stale when the tree moves, so
whoever moves the tree updates the page in the same change.

| Page | Read it when |
|---|---|
| [package-map.md](package-map.md) | You are new, or you are looking for where something lives |
| [storage-format.md](storage-format.md) | You touch the codec — one stored format, `s3ep-gcm-seg-v2` — or anything that computes a size or an offset |
| [request-paths.md](request-paths.md) | You touch a handler: what happens on a PUT, a GET, a ranged GET, a HEAD |
| [multipart.md](multipart.md) | You touch multipart upload, the part table, or the trailer |
| [configuration.md](configuration.md) | You are adding or changing a configuration key, or you need to know where a value comes from |
| [errors.md](errors.md) | You are choosing a status code or an S3 error code |
| [testing.md](testing.md) | You are adding a test, or a suite is failing and you need to know what it is for |
| [performance.md](performance.md) | You are changing a hot path, or you need a before/after number |

## What has no page here

The contributor-facing material that is not per-subsystem — repository layout,
the build and test matrix, continuous integration, the extension checklists, the
conventions — is [DEVELOPER.md](../../DEVELOPER.md).

Five subsystems are not covered by a page above. That is a gap, not a hidden
document; this is where their material actually is today:

| Subsystem | Where it is |
|---|---|
| SigV4 authentication, header and pre-signed | The validation story in [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md), including what is *not* verified; what a client is told when it fails is [docs/operations/s3-api.md](../operations/s3-api.md) |
| The per-key validation rules and the bounds checked at startup | `internal/config/config.go` — `validate` and the `validate*` functions it calls, plus the two checks `Load` runs before the unmarshal (`multipart_session_max_age` refused by name, `multipart_session_idle_timeout` minimum 1). [README.md](../../README.md) carries every key and its default, [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) the rule that a key exists only if code reads it, [docs/operations/configuration.md](../operations/configuration.md) the operator's guide to the ones that need explaining, and [configuration.md](configuration.md) where a value comes from |
| The license gate | [ADR 0016](../adr/0016-the-license-is-a-startup-gate.md) for the decision, [README.md](../../README.md) for the operator view of the gate and the exit-provider exemption, [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) 7.5 for what an expiry does to a running process |
| Monitoring, the exported metric set and the `/status` document | [docs/operations/monitoring.md](../operations/monitoring.md) — the endpoints, their configuration keys, and the thirteen `s3ep_*` series with their labels, with the Go runtime and process collectors served alongside them; the collectors themselves are `internal/monitoring/metrics.go`, the document `internal/monitoring/status.go`, and what every backend round trip is observed with `internal/monitoring/backend.go` |
| What a probe may and may not report | [ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md) for the rule, [request-paths.md](request-paths.md) for where the two routes sit, [docs/operations/monitoring.md](../operations/monitoring.md) for the operator view |
