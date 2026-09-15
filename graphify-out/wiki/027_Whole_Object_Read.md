# 027 Whole Object Read

> 8 nodes · cohesion 0.25

## Key Concepts

- **What a read costs (tail-first whole-object GET)** (4 connections) — `docs/operations/s3-api.md`
- **The first read of a whole-object GET (evaluation)** (4 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **Option C — issue the second request on the first answer's headers** (3 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **x-amz-checksum-crc32c answered on write, GET and HEAD** (2 connections) — `docs/operations/integrity.md`
- **Window options A, B, D and E** (2 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **The second backend round trip costs small reads** (2 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **test/perf baseline records, never asserts throughput** (1 connections) — `docs/developer/testing.md`
- **serveWholeObject** (1 connections) — `docs/tickets/027-whole-object-read-first-window.md`

## Relationships

- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (1 shared connections)
- [Integrity](Integrity.md) (1 shared connections)
- [Hardening History](Hardening_History.md) (1 shared connections)

## Source Files

- `docs/developer/testing.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/tickets/027-whole-object-read-first-window.md`

## Audit Trail

- EXTRACTED: 10 (83%)
- INFERRED: 2 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*