# Client Library and Storage Format

> 62 nodes · cohesion 0.05

## Key Concepts

- **Developer: Storage format** (23 connections) — `docs/developer/storage-format.md`
- **ADR 0041: The project ships a client library for its stored format** (17 connections) — `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- **Stored objects: what is written, what it guarantees, what leaks** (16 connections) — `docs/security/stored-objects.md`
- **Operations: The client library (pkg/s3enc)** (15 connections) — `docs/operations/client-library.md`
- **Velero** (10 connections) — `docs/operations/clients/velero.md`
- **How a security page is written** (10 connections) — `docs/security/README.md`
- **validateOptimizations()** (10 connections) — `internal/config/config.go`
- **Security: Operational security** (9 connections) — `docs/security/operational-security.md`
- **The AAD key is the decoded client key, uncleaned** (7 connections) — `docs/developer/storage-format.md`
- **What the reader guarantees: verify before release, abort the body mid-stream** (7 connections) — `docs/developer/storage-format.md`
- **pkg/s3enc client library** (7 connections) — `docs/operations/client-library.md`
- **SegmentSize, SegmentOverhead and TrailerSize are frozen for the format id** (6 connections) — `docs/developer/storage-format.md`
- **Parts Are Segment-Aligned** (6 connections) — `docs/developer/storage-format.md`
- **Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length** (6 connections) — `docs/developer/storage-format.md`
- **On an error path, assert how many plaintext bytes were released** (6 connections) — `docs/developer/testing.md`
- **Invariant 1: Each Seal Is Bound to Its Position and Its Object** (5 connections) — `docs/developer/storage-format.md`
- **The Four Metadata Keys That Mark an Object as Ours** (5 connections) — `docs/developer/storage-format.md`
- **optimizations.multipart_part_size** (5 connections) — `docs/operations/configuration.md`
- **H-<n> stable gap identifiers** (5 connections) — `docs/security/README.md`
- **The four metadata keys and what backend alteration causes** (5 connections) — `docs/security/stored-objects.md`
- **Enabling filename encryption is a rename, never a re-encryption** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **HEAD as a 40-byte trailer read** (4 connections) — `docs/developer/request-paths.md`
- **Foreign Object Versus Missing Key Material** (4 connections) — `docs/developer/storage-format.md`
- **The Ranged-Read Window and Its Amplification Bound** (4 connections) — `docs/developer/storage-format.md`
- **The Sealed 40-Byte Trailer** (4 connections) — `docs/developer/storage-format.md`
- *... and 37 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (15 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (12 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (11 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (9 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (9 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (8 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (6 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (5 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (4 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (3 shared connections)

## Source Files

- `CHANGELOG.md`
- `README.md`
- `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`
- `docs/developer/testing.md`
- `docs/operations/client-library.md`
- `docs/operations/clients/velero.md`
- `docs/operations/configuration.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/security/README.md`
- `docs/security/key-management.md`
- `docs/security/operational-security.md`
- `docs/security/stored-objects.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/026-sse-c-passthrough.md`
- `internal/config/config.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`

## Audit Trail

- EXTRACTED: 171 (85%)
- INFERRED: 31 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*