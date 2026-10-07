# Service TLS and Operator Certificates

> 29 nodes · cohesion 0.12

## Key Concepts

- **Ticket 038: s3-encryption-operator** (46 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0033** (9 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0026** (8 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **TLS at the Service (serviceTLS, four computed DNS names)** (5 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Finding E: rolling a pod aborts the uploads it holds** (5 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **D-C: one licence token copied into each provisioned namespace** (5 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **D-B: fully typed CRD schema over proxy configuration keys** (5 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **D-A: ValidatingAdmissionPolicy bounding operator Secret writes** (5 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **One cluster-scoped operator Deployment** (4 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Accepted risk: cluster-wide Secret read bounded by nothing** (4 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Strict loader refuses unknown configuration keys (dc.ErrorUnused)** (4 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Render refuses TLS configurations that are not TLS** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **cert-manager adopted into the kind e2e setup** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Configuration read only at start (no SIGHUP, no watch)** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Finding AM: one licence token guarantees fleet-wide simultaneous expiry** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Finding D: licence lapse ends the process and the pod crash-loops** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Finding M: operator-written Deployment can land a privileged pod** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Process-local client-driven multipart session** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Operator credential model (backend carried, client minted, licence copied, KEK open)** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Finding C: one key pair serves as backend and client credential** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Listener TLS certificate loaded once (no GetCertificate)** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Namespaced Custom Resources** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **No cross-namespace references in a Custom Resource** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Open question 21: which Secrets the operator caches** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **s3-encryption-operator (separate program, own Helm chart)** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- *... and 4 more nodes in this community*

## Relationships

- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (14 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (7 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (5 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (4 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (3 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (3 shared connections)
- [Documentation Homes and Ticket Lifecycle](Documentation_Homes_and_Ticket_Lifecycle.md) (2 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (1 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (1 shared connections)

## Source Files

- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/040-managed-buckets.md`

## Audit Trail

- EXTRACTED: 89 (95%)
- INFERRED: 5 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*