# Entity Tag Marker

> 14 nodes · cohesion 0.14

## Key Concepts

- **Multipart Uploads** (11 connections) — `docs/developer/multipart.md`
- **Parts Are Segment-Aligned** (4 connections) — `docs/developer/storage-format.md`
- **The -0 Entity Tag Marker** (2 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **The Marker Is Invertible and the Inverse Is Driven by Shape** (2 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **Under the Exit Provider There Is No Session at All** (2 connections) — `docs/developer/multipart.md`
- **The Part Table Is the Authority, Not the Client's Completion Document** (2 connections) — `docs/developer/multipart.md`
- **The Trailer's Part Number Is Reserved** (2 connections) — `docs/developer/multipart.md`
- **The Marker Is Answered at Object Level and at Part Level** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **ListParts Is Answered From the Session Part Table** (1 connections) — `docs/developer/multipart.md`
- **The Part Size Is Inferred and Must Survive Arrival Order** (1 connections) — `docs/developer/multipart.md`
- **ErrPartNumberReserved** (1 connections) — `docs/developer/multipart.md`
- **uploadPassThroughPart** (1 connections) — `docs/developer/multipart.md`
- **FinishPart** (1 connections) — `docs/developer/storage-format.md`
- **NewPartWriter** (1 connections) — `docs/developer/storage-format.md`

## Relationships

- [Client-Driven Multipart Paths](Client-Driven_Multipart_Paths.md) (2 shared connections)
- [Abandoned Upload Sweeper](Abandoned_Upload_Sweeper.md) (1 shared connections)
- [Short-Part Budget and Memory](Short-Part_Budget_and_Memory.md) (1 shared connections)
- [Shutdown Order and Probes](Shutdown_Order_and_Probes.md) (1 shared connections)
- [Storage Format Invariants](Storage_Format_Invariants.md) (1 shared connections)

## Source Files

- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/developer/multipart.md`
- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 19 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*