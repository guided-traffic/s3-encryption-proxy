# Multipart Part Layout Decisions

> 55 nodes · cohesion 0.05

## Key Concepts

- **ADR 0001: The backend is hostile** (42 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0011** (40 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Ticket 037: multiple backends** (37 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0020: Performance is measured before and after** (31 connections) — `docs/tickets/037-multiple-backends.md`
- **Tickets index and label index** (24 connections) — `docs/tickets/README.md`
- **Ticket 036: high availability** (15 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Ticket 039: backend under a private CA, certificate failure is named** (9 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **ca_file per s3_backends entry (sole trust roots for that backend)** (8 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **Ticket 026: SSE-C on every verb, or not at all** (5 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Ticket 033: out-of-band recovery path for a damaged object** (5 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **SSE-C key forwarded on every verb or on none** (4 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Proposed high_availability config block (store, sentinel_addresses, key_prefix, peer)** (4 connections) — `docs/tickets/036-high-availability.md`
- **Row field rule: backend-visible or sealed under the object's data key** (4 connections) — `docs/tickets/036-high-availability.md`
- **s3ep_object_integrity_failures_total{reason,phase}** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **Read fallback to another backend on integrity refusal** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **Resident-memory bound test** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **sseCustomerHeaders helper applied to Put/Get/Head/CreateMultipart/UploadPart inputs** (3 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Shared session table in external Valkey with Sentinel** (3 connections) — `docs/tickets/036-high-availability.md`
- **Per-backend metric label is an operator-chosen name, never endpoint** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Only a before_response refusal can fall back** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Fan-out: seal once tee to N vs seal N times** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Short Part Held in Memory and Sealed at Complete (D5)** (2 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Verdict Lands Before Anything Is Committed (D7)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **GOMEMLIMIT set explicitly (~80% of container limit)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Stored objects: what is written, what it guarantees, what leaks** (2 connections) — `docs/security/stored-objects.md`
- *... and 30 more nodes in this community*

## Relationships

- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (24 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (21 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (17 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (15 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (15 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (14 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (11 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (7 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (6 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (5 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (3 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (1 shared connections)

## Source Files

- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/security/stored-objects.md`
- `docs/security/upload-integrity.md`
- `docs/tickets/026-sse-c-passthrough.md`
- `docs/tickets/033-out-of-band-recovery-path.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `docs/tickets/040-managed-buckets.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 214 (96%)
- INFERRED: 9 (4%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*