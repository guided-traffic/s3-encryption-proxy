# ADR Corpus and Release History

> 98 nodes · cohesion 0.04

## Key Concepts

- **CLAUDE.md AI coding instructions** (48 connections) — `CLAUDE.md`
- **ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt** (48 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **ADR 0019: Integration and e2e tests are the product** (42 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded** (40 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0020: Performance is measured before and after** (39 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0006: The proxy serves any S3 client** (34 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **ADR 0010: Sizes and listings describe the plaintext** (34 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0025: Leaving is a supported mode** (34 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **ADR 0008: Every response describes the proxy** (32 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **CHANGELOG release history** (26 connections) — `CHANGELOG.md`
- **ADR 0024: An upload forwards while it receives** (23 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **ADR 0032: The entity tag is a change token** (23 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR index and format rules** (21 connections) — `docs/adr/README.md`
- **ADR 0015: A transfer is bounded by the client and by shutdown, not by a server wall clock** (20 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **ADR 0029: The shutdown budget finishes work and sweeps what cannot be finished** (20 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Errors (developer page)** (20 connections) — `docs/developer/errors.md`
- **ADR 0036: A response follows S3, deviates only so a client stays usable, and changing one is never a breaking change** (17 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **ADR 0027: Conformance against a backend that is not MinIO** (16 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **ADR 0028: An abandoned upload is ended, not forgotten** (16 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **ADR 0031: A test states the target and stays red until the product meets it** (15 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Multipart uploads (developer page)** (15 connections) — `docs/developer/multipart.md`
- **Multipart session sweep and shutdown abort** (9 connections) — `docs/security/key-management.md`
- **Integration and e2e suites are never skipped, disabled or weakened** (6 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **A test asserts the target behaviour, never today's** (4 connections) — `CLAUDE.md`
- **terminationGracePeriodSeconds = preStopSleepSeconds + shutdown_timeout + 5** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- *... and 73 more nodes in this community*

## Relationships

- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (58 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (47 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (45 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (28 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (26 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (19 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (15 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (12 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (12 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (12 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (11 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (9 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `DEVELOPER.md`
- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`

## Audit Trail

- EXTRACTED: 507 (97%)
- INFERRED: 16 (3%)
- AMBIGUOUS: 2 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*