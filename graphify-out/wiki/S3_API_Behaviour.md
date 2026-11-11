# S3 API Behaviour

> 59 nodes · cohesion 0.05

## Key Concepts

- **ADR 0007: Forward it or refuse it** (48 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Developer: Request paths** (32 connections) — `docs/developer/request-paths.md`
- **Operations: S3 API behaviour** (19 connections) — `docs/operations/s3-api.md`
- **PlaintextSize()** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Upload checksum verifier reader** (11 connections) — `docs/developer/request-paths.md`
- **Listings report plaintext size** (7 connections) — `docs/developer/request-paths.md`
- **x-amz-expected-bucket-owner set in every s3 Input literal** (7 connections) — `docs/developer/request-paths.md`
- **What is verified on every S3 request** (6 connections) — `docs/security/request-authentication.md`
- **405 MethodNotAllowed vs 501 NotImplemented dispatch** (5 connections) — `docs/developer/request-paths.md`
- **Client part sizes must cover whole 64 KiB segments** (5 connections) — `docs/operations/s3-api.md`
- **Sub-resources: 501 NotImplemented or 405 MethodNotAllowed** (5 connections) — `docs/operations/s3-api.md`
- **fillPart()** (5 connections) — `internal/proxy/handlers/object/operations.go`
- **TestEveryBackendCallCarriesTheOwnerGuard()** (5 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **CRC-64/NVME slicing-by-8 table** (4 connections) — `docs/developer/request-paths.md`
- **response-* query parameter overrides** (4 connections) — `docs/developer/request-paths.md`
- **Short-body guard (declared length check, only io.EOF ends a part)** (4 connections) — `docs/developer/request-paths.md`
- **x-amz-expected-bucket-owner forwarded on every verb** (4 connections) — `docs/operations/s3-api.md`
- **Storage headers on upload: forward it or refuse it** (4 connections) — `docs/operations/s3-api.md`
- **TestSegOversizeRefused()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeGuardRejectsUnreachableLengths()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **.reportedSize()** (3 connections) — `internal/proxy/handlers/bucket/listing.go`
- **Error behind non-error status answered 500 (304 carve-out)** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **CompleteMultipartUpload reads body unverified** (3 connections) — `docs/developer/request-paths.md`
- **When the defect is an omission, test the source** (3 connections) — `docs/developer/testing.md`
- **HEAD, GET and listings report the plaintext size** (3 connections) — `docs/operations/s3-api.md`
- *... and 34 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (28 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (16 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (8 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (6 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (6 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (5 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (4 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (4 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (4 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (4 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/s3-api.md`
- `docs/security/refusals.md`
- `docs/security/request-authentication.md`
- `docs/security/upload-integrity.md`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/request/bucketowner_guard_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`
- `pkg/s3enc/read.go`

## Audit Trail

- EXTRACTED: 174 (89%)
- INFERRED: 20 (10%)
- AMBIGUOUS: 1 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*