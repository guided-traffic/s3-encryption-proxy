# Shutdown Order and Probes

> 10 nodes · cohesion 0.22

## Key Concepts

- **Shutdown Ends What the Process Is Still Holding** (4 connections) — `docs/developer/multipart.md`
- **The Four-Step Shutdown Order** (3 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Drain Guard: 503 ServiceUnavailable With Retry-After While the Listener Stays Up** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **A Multipart Session Is Process-Local and Unfinishable Once the Process Exits** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Every Upload the Process Still Holds Is Ended at the Backend** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **A Second Replica Answers NoSuchUpload for an Upload the First Holds** (2 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **Manager.Shutdown** (2 connections) — `docs/developer/multipart.md`
- **drainGuardMiddleware** (2 connections) — `docs/developer/multipart.md`
- **The Chart Refuses to Render a Second Replica** (1 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **AbandonAllSessions** (1 connections) — `docs/developer/multipart.md`

## Relationships

- [Entity Tag Marker](Entity_Tag_Marker.md) (1 shared connections)

## Source Files

- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/developer/multipart.md`

## Audit Trail

- EXTRACTED: 9 (82%)
- INFERRED: 2 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*