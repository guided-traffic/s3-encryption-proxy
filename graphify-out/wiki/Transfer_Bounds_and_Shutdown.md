# Transfer Bounds and Shutdown

> 39 nodes · cohesion 0.06

## Key Concepts

- **ADR 0015: a transfer is bounded by the client and by shutdown** (18 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **ADR 0029** (13 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **router.go** (10 connections) — `internal/proxy/router.go`
- **Multipart session sweep and shutdown abort** (7 connections) — `docs/security/key-management.md`
- **ADR 0028: an abandoned upload is ended not forgotten** (6 connections) — `CLAUDE.md`
- **Security: Threat model** (5 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Pin as holder address plus random instance identity (no lease)** (5 connections) — `docs/tickets/036-high-availability.md`
- **S3 route middleware chain (drain guard first, SigV4 second)** (4 connections) — `docs/developer/request-paths.md`
- **Tenancy and privilege: the blast radius** (4 connections) — `docs/security/tenancy-and-privilege.md`
- **Forward verdict table (identity mismatch / refused -> dead; timeout -> 503 SlowDown)** (4 connections) — `docs/tickets/036-high-availability.md`
- **/readyz readiness as lifecycle signal** (3 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Key management: hierarchy, providers, custody, rotation** (3 connections) — `docs/security/key-management.md`
- **HA answer table (503 SlowDown transient, 404 NoSuchUpload permanent, 200 on retried Complete)** (3 connections) — `docs/tickets/036-high-availability.md`
- **Row completion state machine open -> completing -> completed(ETag) | dead (CAS)** (3 connections) — `docs/tickets/036-high-availability.md`
- **Held short last part stays in receiving process memory** (3 connections) — `docs/tickets/036-high-availability.md`
- **Member register: active alias takes effect when every live member can read it** (3 connections) — `docs/tickets/036-high-availability.md`
- **Session miss classified against backend via ListParts (404 vs 403 InvalidObjectState)** (3 connections) — `docs/tickets/036-high-availability.md`
- **Shutdown lets go: aborts only producer uploads and unfinished pinned uploads** (3 connections) — `docs/tickets/036-high-availability.md`
- **Idle is the store's clock; every instance sweeps by compare-and-set** (3 connections) — `docs/tickets/036-high-availability.md`
- **Release 5.0.2: multipart idle clock moves while a part arrives** (2 connections) — `CHANGELOG.md`
- **Explicit timeout on every KMS call** (2 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **Multipart Completion Is Final (D8)** (2 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **No Wall-Clock Budget on Request/Response Bodies (D1)** (2 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **shutdown_timeout Is the Single Shutdown Budget (D4)** (2 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **Roles table (operator, client, proxy, backend, legs)** (2 connections) — `docs/security/threat-model.md`
- *... and 14 more nodes in this community*

## Relationships

- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (10 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (6 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (5 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (4 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (4 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (4 shared connections)
- [Backend](Backend.md) (2 shared connections)
- [Router](Router.md) (2 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)
- [Main](Main.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/developer/request-paths.md`
- `docs/security/key-management.md`
- `docs/security/tenancy-and-privilege.md`
- `docs/security/threat-model.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `internal/proxy/router.go`

## Audit Trail

- EXTRACTED: 83 (94%)
- INFERRED: 5 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*