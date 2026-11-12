# Adr: 0039 The Analysis Tools Move With The Go Toolchain

> 31 nodes · cohesion 0.07

## Key Concepts

- **Separate Go module pinning the analysis tools** (6 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Client-driven multipart upload** (6 connections) — `docs/developer/multipart.md`
- **exit provider type (D1/D2)** (5 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Committed red test blocks the release gate** (5 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Entity tag as opaque change token** (5 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **-0 entity tag marker** (5 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **Test asserts target behaviour, never current behaviour** (3 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Renovate 'Go toolchain' group** (3 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Session part table is the authority for Complete** (3 connections) — `docs/developer/multipart.md`
- **encryption.filename_encryption mode: off / drain / mixed / strict (D1)** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-every-segment-with-a-searchable-leaf-head.md`
- **Behaviour an ADR decides is the target** (2 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Shape-driven inverse of the -0 marker** (2 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **Go 1.27.2 export data version 5 incompatibility** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **golang.org/x/tools required at newest release** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Go toolchain PR stays red until the tool release exists** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Exit provider multipart pass-through (no session)** (2 connections) — `docs/developer/multipart.md`
- **Process-wide short-part budget (multipart_short_part_buffer_size)** (2 connections) — `docs/developer/multipart.md`
- **Streamed vs held part shapes** (2 connections) — `docs/developer/multipart.md`
- **.SegmentedSession()** (2 connections) — `internal/orchestration/segmented_session.go`
- **Enforced known-failure manifest (rejected alternative)** (1 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **No emergency release path past red gates** (1 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Red test names its rule and record; suite reports what is still broken** (1 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Sealed plaintext MD5 digest refused** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **rclone client** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **s3cmd client** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- *... and 6 more nodes in this community*

## Relationships

- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (2 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (2 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)

## Source Files

- `docs/adr/0023-filename-encryption-encrypts-every-segment-with-a-searchable-leaf-head.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- `docs/developer/multipart.md`
- `internal/orchestration/segmented_session.go`

## Audit Trail

- EXTRACTED: 39 (95%)
- INFERRED: 2 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*