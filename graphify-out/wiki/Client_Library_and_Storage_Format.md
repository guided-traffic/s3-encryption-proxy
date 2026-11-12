# Client Library and Storage Format

> 68 nodes · cohesion 0.04

## Key Concepts

- **Developer: Storage format** (23 connections) — `docs/developer/storage-format.md`
- **Stored objects: what is written, what it guarantees, what leaks** (17 connections) — `docs/security/stored-objects.md`
- **Key management: hierarchy, providers, custody, rotation** (16 connections) — `docs/security/key-management.md`
- **ADR 0041: The project ships a client library for its stored format** (15 connections) — `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- **Operations: The client library (pkg/s3enc)** (14 connections) — `docs/operations/client-library.md`
- **Threat model and trust boundaries** (13 connections) — `docs/security/threat-model.md`
- **validateOptimizations()** (10 connections) — `internal/config/config.go`
- **Velero** (8 connections) — `docs/operations/clients/velero.md`
- **Security: Operational security** (8 connections) — `docs/security/operational-security.md`
- **What the reader guarantees: verify before release, abort the body mid-stream** (7 connections) — `docs/developer/storage-format.md`
- **pkg/s3enc client library** (7 connections) — `docs/operations/client-library.md`
- **SegmentSize, SegmentOverhead and TrailerSize are frozen for the format id** (6 connections) — `docs/developer/storage-format.md`
- **Parts Are Segment-Aligned** (6 connections) — `docs/developer/storage-format.md`
- **Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length** (6 connections) — `docs/developer/storage-format.md`
- **On an error path, assert how many plaintext bytes were released** (6 connections) — `docs/developer/testing.md`
- **Where each secret lives** (6 connections) — `docs/security/key-management.md`
- **How a security page is written** (6 connections) — `docs/security/README.md`
- **Invariant 1: Each Seal Is Bound to Its Position and Its Object** (5 connections) — `docs/developer/storage-format.md`
- **The AAD key is the decoded client key, uncleaned** (5 connections) — `docs/developer/storage-format.md`
- **The Four Metadata Keys That Mark an Object as Ours** (5 connections) — `docs/developer/storage-format.md`
- **optimizations.multipart_part_size** (5 connections) — `docs/operations/configuration.md`
- **Derived KEK fingerprint (HKDF label s3ep-kek-fingerprint)** (5 connections) — `docs/security/key-management.md`
- **H-<n> stable gap identifiers** (5 connections) — `docs/security/README.md`
- **The four metadata keys and what backend alteration causes** (5 connections) — `docs/security/stored-objects.md`
- **HEAD as a 40-byte trailer read** (4 connections) — `docs/developer/request-paths.md`
- *... and 43 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (17 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (13 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (12 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (12 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (9 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (8 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (6 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (6 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (5 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (3 shared connections)

## Source Files

- `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`
- `docs/developer/testing.md`
- `docs/operations/client-library.md`
- `docs/operations/clients/velero.md`
- `docs/operations/configuration.md`
- `docs/operations/s3-api.md`
- `docs/security/README.md`
- `docs/security/key-management.md`
- `docs/security/operational-security.md`
- `docs/security/stored-objects.md`
- `docs/security/tenancy-and-privilege.md`
- `docs/security/threat-model.md`
- `internal/config/config.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`

## Audit Trail

- EXTRACTED: 191 (88%)
- INFERRED: 27 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*