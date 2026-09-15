# Configuration Loading and Upload Sweeper

> 49 nodes · cohesion 0.04

## Key Concepts

- **Error Conventions** (20 connections) — `docs/developer/errors.md`
- **The Storage Format (s3ep-gcm-seg-v2)** (12 connections) — `docs/developer/storage-format.md`
- **Configuration: Where a Value Comes From** (9 connections) — `docs/developer/configuration.md`
- **Developer Documentation Index** (9 connections) — `docs/developer/README.md`
- **The Session Sweeper Measures Inactivity, Not Age** (8 connections) — `docs/developer/multipart.md`
- **Defaults Written Into Viper Before the File Is Read** (6 connections) — `docs/developer/configuration.md`
- **Strict Decoding: An Unknown Key Refuses the Start** (5 connections) — `docs/developer/configuration.md`
- **The Four Metadata Keys That Mark an Object as Ours** (5 connections) — `docs/developer/storage-format.md`
- **Parts Are Segment-Aligned** (5 connections) — `docs/developer/storage-format.md`
- **The Sealed 40-Byte Trailer** (4 connections) — `docs/developer/storage-format.md`
- **Expiry Is Measured From the Last Part, Never From Creation** (3 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **The Sweeper Aborts at the Backend Before It Forgets** (3 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **${VAR} References Inside a Named List of Fields** (3 connections) — `docs/developer/configuration.md`
- **A Fault Found After WriteHeader Aborts the Body** (3 connections) — `docs/developer/errors.md`
- **Invariant 1: Each Seal Is Bound to Its Position and Its Object** (3 connections) — `docs/developer/storage-format.md`
- **An Incomplete Multipart Upload Is Treated as a Leak** (2 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **optimizations.multipart_session_idle_timeout** (2 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **It Refuses Rather Than Documents** (2 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **An ADR Carries No References Into the Code** (2 connections) — `docs/adr/README.md`
- **AutomaticEnv Removed in 5.0.0** (2 connections) — `docs/developer/configuration.md`
- **A Renamed Key Is Refused by Name, Not by a Generic Unknown-Key Error** (2 connections) — `docs/developer/configuration.md`
- **403 InvalidObjectState: The Three Integrity Refusals** (2 connections) — `docs/developer/errors.md`
- **A Developer Page May and Should Name Files and Functions** (2 connections) — `docs/developer/README.md`
- **The Object Checksum Is a CRC32C Because Parts Fold It** (2 connections) — `docs/developer/storage-format.md`
- **Segment Chain Layout** (2 connections) — `docs/developer/storage-format.md`
- *... and 24 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (8 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (6 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (5 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (3 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (3 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (3 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (2 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (2 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (2 shared connections)
- [Config Defaults and Provider Loading](Config_Defaults_and_Provider_Loading.md) (1 shared connections)
- [Config Env Var Expansion](Config_Env_Var_Expansion.md) (1 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (1 shared connections)

## Source Files

- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/adr/README.md`
- `docs/developer/README.md`
- `docs/developer/configuration.md`
- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 90 (96%)
- INFERRED: 4 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*