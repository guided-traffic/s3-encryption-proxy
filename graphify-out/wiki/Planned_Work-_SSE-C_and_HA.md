# Planned Work: SSE-C and HA

> 42 nodes · cohesion 0.06

## Key Concepts

- **Ticket 037: Several backends kept in sync with integrity fallback** (34 connections) — `docs/tickets/037-multiple-backends.md`
- **Ticket index (open and archived tickets)** (8 connections) — `docs/tickets/README.md`
- **Ticket 026: SSE-C on every verb, or not at all** (7 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **F11 extensible pass engine (enumerate/plan/transfer/verify/report)** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Ticket 017: Filename encryption** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Filename encryption staged plan (Stage 0-8)** (5 connections) — `docs/tickets/017-filename-encryption.md`
- **SSE-C key forwarded on every verb or on none** (4 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **Read fallback to another backend on integrity refusal** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **Tickets README (index and label index)** (4 connections) — `docs/tickets/README.md`
- **F5 hand-rolled RFC 5297 AES-SIV with 512-bit key** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **names tools: wrap, map, unmap, audit, migrate** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **sseCustomerHeaders helper applied to Put/Get/Head/CreateMultipart/UploadPart inputs** (3 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **A part is an independent slice of the segment chain** (3 connections) — `docs/tickets/036-high-availability.md`
- **Decision 14: row field rule - backend-visible or sealed under the data key; tampering is denial** (3 connections) — `docs/tickets/036-high-availability.md`
- **Per-backend metric label is an operator-chosen name, never endpoint** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Only a before_response refusal can fall back** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **s3ep_object_integrity_failures_total{reason,phase}** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **s3_backends list shape shipped in 5.0.0, one entry read** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Fan-out: seal once tee to N vs seal N times** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **internal/naming (planned package: segment codec, mode, cache)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **400 KeyTooLongError** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Listing performance instrument (BEFORE column, requests per page)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Name key wrap AAD label s3ep-name-wrap-v1** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Pass operation: replicate (ticket 037)** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Enabling name encryption is a rename, never a re-encryption** (2 connections) — `docs/tickets/017-filename-encryption.md`
- *... and 17 more nodes in this community*

## Relationships

- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (9 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (8 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (5 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (5 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (4 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (3 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (3 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (3 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (2 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/026-sse-c-passthrough.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 91 (94%)
- INFERRED: 6 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*