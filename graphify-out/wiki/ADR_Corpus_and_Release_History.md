# ADR Corpus and Release History

> 60 nodes · cohesion 0.05

## Key Concepts

- **ADR 0019: Integration and e2e tests are the product** (43 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0006: The proxy serves any S3 client** (33 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **ADR 0010: Sizes and listings describe the plaintext** (31 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0027: Conformance is asserted against a backend that is not MinIO, seeded once and bounded by a byte budget** (25 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **ADR 0036: A response follows S3, deviates only so a client stays usable, and changing one is never a breaking change** (20 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **ADR 0031: A test states the target and stays red until the product meets it** (13 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **PlaintextSize()** (12 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Listings report plaintext size** (7 connections) — `docs/developer/request-paths.md`
- **Encryption at rest asserted by reading the backend directly (D6)** (6 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Conformance suite (any backend)** (5 connections) — `docs/developer/testing.md`
- **TestSegSizeFunctionsRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeGuardRejectsUnreachableLengths()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **.reportedSize()** (3 connections) — `internal/proxy/handlers/bucket/listing.go`
- **A test asserts the target behaviour, never today's** (3 connections) — `CLAUDE.md`
- **Any S3 client is in scope** (3 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Suites are never disabled, skipped, weakened or deleted (D2/D4)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Corpus seeded once, then read-only (D4)** (3 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Changing a response is a fix, never a breaking change** (3 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **Entity tag is a change token (-0 suffix)** (3 connections) — `docs/operations/integrity.md`
- **HEAD, GET and listings report the plaintext size** (3 connections) — `docs/operations/s3-api.md`
- **Decision 18: answer table (503 SlowDown transient, 404 NoSuchUpload, 403 InvalidObjectState, 200 on retried Complete)** (3 connections) — `docs/tickets/036-high-availability.md`
- **PlaintextSize()** (3 connections) — `pkg/s3enc/read.go`
- **Adding an end-to-end client suite checklist** (2 connections) — `DEVELOPER.md`
- **CloudNativePG Barman** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **An e2e suite proves one client end to end** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- *... and 35 more nodes in this community*

## Relationships

- [S3 API Behaviour](S3_API_Behaviour.md) (20 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (19 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (15 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (12 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (8 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (7 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (7 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (5 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (5 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (4 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (4 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (3 shared connections)

## Source Files

- `CLAUDE.md`
- `DEVELOPER.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `internal/proxy/handlers/bucket/listing.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`
- `pkg/s3enc/read.go`

## Audit Trail

- EXTRACTED: 203 (96%)
- INFERRED: 9 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*