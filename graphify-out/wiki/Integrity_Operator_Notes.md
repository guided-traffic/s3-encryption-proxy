# Integrity Operator Notes

> 12 nodes · cohesion 0.18

## Key Concepts

- **403 InvalidObjectState for objects this proxy did not write** (10 connections) — `docs/operations/integrity.md`
- **Under exit the decision is taken per object** (4 connections) — `docs/operations/integrity.md`
- **Ranged reads (Range: bytes=...)** (4 connections) — `docs/operations/s3-api.md`
- **Assert what is stored, compare by SHA-256** (3 connections) — `docs/developer/testing.md`
- **s3ep-dek-algorithm** (3 connections) — `docs/operations/integrity.md`
- **stored = plaintext + ceil(plaintext/65536)*28 + 40** (3 connections) — `docs/operations/integrity.md`
- **HEAD, GET and listings report the plaintext size** (3 connections) — `docs/operations/s3-api.md`
- **Operations: Upgrading** (3 connections) — `README.md`
- **Objects written by an earlier release cannot be read** (2 connections) — `docs/operations/upgrading.md`
- **kopia reads pack blobs with ranges** (1 connections) — `docs/operations/clients/velero.md`
- **metadata_key_prefix is the proxy's exclusive namespace** (1 connections) — `docs/operations/integrity.md`
- **The refusals are 4xx deliberately** (1 connections) — `docs/operations/integrity.md`

## Relationships

- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (4 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (2 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (2 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (1 shared connections)
- [Segment Tamper](Segment_Tamper.md) (1 shared connections)
- [Integration Test Layers](Integration_Test_Layers.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (1 shared connections)
- [Configuration](Configuration.md) (1 shared connections)

## Source Files

- `README.md`
- `docs/developer/testing.md`
- `docs/operations/clients/velero.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`

## Audit Trail

- EXTRACTED: 22 (85%)
- INFERRED: 4 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*