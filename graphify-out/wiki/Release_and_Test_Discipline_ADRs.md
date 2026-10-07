# Release and Test Discipline ADRs

> 51 nodes · cohesion 0.06

## Key Concepts

- **ADR 0019: Integration and e2e tests are the product** (42 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0017** (32 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0006: the proxy serves any s3 client** (30 connections) — `README.md`
- **ADR 0018** (29 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0036** (19 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0031: A test states the target** (6 connections) — `docs/tickets/README.md`
- **ADR 0027: conformance is asserted against a backend that is not minio** (5 connections) — `CLAUDE.md`
- **Conventional Commits drive the release; breaking change requires release:major label** (4 connections) — `CONTRIBUTING.md`
- **semantic-release dry-run workflow (major release label guard)** (4 connections) — `DEVELOPER.md`
- **Semantic-release generated changelog with quality metrics** (3 connections) — `CHANGELOG.md`
- **A test asserts the TARGET behaviour and stays red until fixed** (3 connections) — `CLAUDE.md`
- **Any S3 client is in scope** (3 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Unknown Configuration Key Refuses the Start (D11)** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Object Not in Current Format Is Refused, Never Guessed (D4)** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **No performance measurement fails a build** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Changing a response is a fix, never a breaking change** (3 connections) — `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- **conformance-paid.yml (Wasabi, weekly, billed)** (2 connections) — `DEVELOPER.md`
- **Trust claims describe what running code verifies** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **CloudNativePG Barman** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **An e2e suite proves one client end to end** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Support claimed only as far as exercised** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Velero (with kopia)** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **No Compatibility Owed for Data at Rest (D1/D2)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Operator-Facing Breaks Ship in One Major (D10)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Removed Configuration Key Has No Alias (D7/D8)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- *... and 26 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (21 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (17 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (14 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (14 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (9 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (6 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (6 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (5 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (4 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (4 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (3 shared connections)
- [CI Pipeline and Renovate Jobs](CI_Pipeline_and_Renovate_Jobs.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 165 (94%)
- INFERRED: 11 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*