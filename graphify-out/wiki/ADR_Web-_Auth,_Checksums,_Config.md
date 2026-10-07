# ADR Web: Auth, Checksums, Config

> 83 nodes · cohesion 0.04

## Key Concepts

- **ADR 0013** (59 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0034** (36 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0014: authentication is sigv4 no rate limiting** (31 connections) — `README.md`
- **ADR 0016** (29 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0021** (22 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0030** (18 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0037** (15 connections) — `docs/tickets/042-a-certificate-failure-is-not-retried.md`
- **Subsystems without a developer page** (6 connections) — `docs/developer/README.md`
- **Unauthenticated monitoring listener discloses the active provider** (6 connections) — `docs/security/request-authentication.md`
- **Ticket 043: the backend is checked before the first client request** (6 connections) — `docs/tickets/043-the-backend-is-checked-before-the-first-client-request.md`
- **A Configuration Key Exists Only If Code Reads It (D1)** (5 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **s3ep_encryption_provider_info** (5 connections) — `docs/operations/monitoring.md`
- **s3ep_object_integrity_failures_total** (5 connections) — `docs/operations/monitoring.md`
- **GET /status document** (5 connections) — `docs/operations/monitoring.md`
- **Ticket 042: a certificate failure is not retried** (5 connections) — `docs/tickets/042-a-certificate-failure-is-not-retried.md`
- **Thirteen s3ep_* Prometheus series** (4 connections) — `docs/operations/monitoring.md`
- **Request authentication: what is checked before a handler runs** (4 connections) — `docs/security/request-authentication.md`
- **Unauthenticated probe exemption (/livez, /readyz)** (4 connections) — `docs/security/request-authentication.md`
- **Three security rules** (4 connections) — `docs/security/threat-model.md`
- **Trust boundary between proxy and backend** (4 connections) — `docs/security/threat-model.md`
- **Finding F: readiness says nothing about backend usability** (4 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Licence routes: chart-managed Secret or S3EP_LICENSE_TOKEN env** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Unworkable Configuration Refuses to Start (D7)** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **No working key material tracked in the repository** (3 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **S3EP_AES_KEY environment reference** (3 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- *... and 58 more nodes in this community*

## Relationships

- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (21 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (17 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (15 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (14 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (14 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (11 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (10 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (9 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (6 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (5 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (4 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (2 shared connections)

## Source Files

- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/README.md`
- `docs/developer/configuration.md`
- `docs/operations/integrity.md`
- `docs/operations/monitoring.md`
- `docs/security/operational-security.md`
- `docs/security/request-authentication.md`
- `docs/security/threat-model.md`
- `docs/security/upload-integrity.md`

## Audit Trail

- EXTRACTED: 244 (90%)
- INFERRED: 26 (10%)
- AMBIGUOUS: 2 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*