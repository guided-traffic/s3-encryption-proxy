# Shutdown Order and Probes

> 20 nodes · cohesion 0.12

## Key Concepts

- **The Four-Step Shutdown Order** (5 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **The Seven Middlewares and Their Order** (5 connections) — `docs/developer/request-paths.md`
- **/readyz: Readiness Is a Lifecycle Signal the Drain Makes False** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Shutdown Ends What the Process Is Still Holding** (4 connections) — `docs/developer/multipart.md`
- **/livez: Liveness Is a Constant Success** (3 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **internal/proxy — The HTTP Surface** (3 connections) — `docs/developer/package-map.md`
- **The Probe Subrouter Sits Ahead of the Middleware Chain** (3 connections) — `docs/developer/request-paths.md`
- **Manager.Shutdown** (3 connections) — `docs/developer/multipart.md`
- **drainGuardMiddleware** (3 connections) — `docs/developer/multipart.md`
- **Drain Guard: 503 ServiceUnavailable With Retry-After While the Listener Stays Up** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **A Multipart Session Is Process-Local and Unfinishable Once the Process Exits** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Every Upload the Process Still Holds Is Ended at the Backend** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **A Second Replica Answers NoSuchUpload for an Upload the First Holds** (2 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **The Chart Refuses to Render a Second Replica** (2 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **internal/proxy/router.go — route table** (2 connections) — `docs/developer/request-paths.md`
- **Server.Shutdown** (2 connections) — `docs/developer/request-paths.md`
- **No Probe Depends on Anything Outside the Process** (1 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Readiness Is Never a Load Signal** (1 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **AbandonAllSessions** (1 connections) — `docs/developer/multipart.md`
- **interfaces.S3Backend** (1 connections) — `docs/developer/package-map.md`

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (5 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)

## Source Files

- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/developer/multipart.md`
- `docs/developer/package-map.md`
- `docs/developer/request-paths.md`

## Audit Trail

- EXTRACTED: 27 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*