# Planned Work: SSE-C and HA

> 46 nodes · cohesion 0.05

## Key Concepts

- **Ticket 037: Several backends kept in sync with integrity fallback** (33 connections) — `docs/tickets/037-multiple-backends.md`
- **Ticket 036: High Availability** (11 connections) — `docs/tickets/036-high-availability.md`
- **Ticket 038: s3-encryption-operator** (11 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Ticket 040: Managed Buckets** (8 connections) — `docs/tickets/040-managed-buckets.md`
- **Tickets Index (docs/tickets/README)** (7 connections) — `docs/tickets/README.md`
- **Ticket 039: Backend Certificate Verification Failure is Named** (6 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **Startup Readability Verdict per Managed Bucket** (5 connections) — `docs/tickets/040-managed-buckets.md`
- **SSE-C key forwarded on every verb or on none** (4 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Read fallback to another backend on integrity refusal** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **Finding Label Index (N-, S-, P-, F- series)** (4 connections) — `docs/tickets/README.md`
- **sseCustomerHeaders helper applied to Put/Get/Head/CreateMultipart/UploadPart inputs** (3 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Shared Session Table in Valkey with Sentinel** (3 connections) — `docs/tickets/036-high-availability.md`
- **Per-backend metric label is an operator-chosen name, never endpoint** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Only a before_response refusal can fall back** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **s3ep_object_integrity_failures_total{reason,phase}** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **s3_backends list shape shipped in 5.0.0, one entry read** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Customer key never logged, stored, cached or kept in session state** (2 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Pinned Part Size** (2 connections) — `docs/tickets/036-high-availability.md`
- **Row Field Rule: Backend-Visible or Sealed Under Data Key (Decision 14)** (2 connections) — `docs/tickets/036-high-availability.md`
- **Session Store Interface of Operations (RaisePartSizeAndComputeOffset, RecordPartIfCurrent)** (2 connections) — `docs/tickets/036-high-availability.md`
- **Reference Scenario: Velero Backup Through Rolling Update** (2 connections) — `docs/tickets/036-high-availability.md`
- **Entity tags, conditionals and VersionId are backend-local** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **Replicate operation: bring an added backend to parity** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **Fallback after a one-backend delete resurrects deleted data** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **Listing divergence across backends** (2 connections) — `docs/tickets/037-multiple-backends.md`
- *... and 21 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (12 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (9 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (7 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (6 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (3 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (2 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (2 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Monitoring: Backend (2)](Monitoring-_Backend_2.md) (1 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (1 shared connections)

## Source Files

- `docs/tickets/026-sse-c-passthrough.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `docs/tickets/040-managed-buckets.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 99 (98%)
- INFERRED: 2 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*