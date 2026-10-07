# Integrity Failure Reporting

> 7 nodes · cohesion 0.29

## Key Concepts

- **A Fault Found After WriteHeader Aborts the Body** (3 connections) — `docs/developer/errors.md`
- **The Sealed 40-Byte Trailer** (3 connections) — `docs/developer/storage-format.md`
- **The Object Checksum Is a CRC32C Because Parts Fold It** (2 connections) — `docs/developer/storage-format.md`
- **Segment Chain Layout** (2 connections) — `docs/developer/storage-format.md`
- **Handler.reportStreamFault** (2 connections) — `docs/developer/errors.md`
- **s3ep_object_integrity_failures_total, Phased Before-Response and Mid-Stream** (1 connections) — `docs/developer/errors.md`
- **Checksum.Append** (1 connections) — `docs/developer/storage-format.md`

## Relationships

- [Error Conventions](Error_Conventions.md) (1 shared connections)
- [Storage Format Invariants](Storage_Format_Invariants.md) (1 shared connections)

## Source Files

- `docs/developer/errors.md`
- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 7 (88%)
- INFERRED: 1 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*