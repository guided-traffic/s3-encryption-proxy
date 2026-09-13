# Filename Encryption Ticket

> 13 nodes · cohesion 0.23

## Key Concepts

- **Ticket 018 ListObjectsV2 Document** (9 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Ticket 017: Filename encryption, directory segments only** (8 connections) — `docs/tickets/017-filename-encryption.md`
- **AES-SIV-CMAC per directory segment with a chained AAD** (6 connections) — `docs/tickets/017-filename-encryption.md`
- **Object keys leak namespace, backup and restore names in cleartext** (3 connections) — `docs/tickets/017-filename-encryption.md`
- **reportedSize: Plaintext Size By Arithmetic** (3 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **The boundary decorator between the proxy and the backend SDK client** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **The leaf name stays clear so prefix listings survive** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **A mapping index in the bucket is rejected** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **K_name: a 64-byte name key wrapped by the active KEK** (2 connections) — `docs/tickets/017-filename-encryption.md`
- **Outstanding Listing Benchmark** (2 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Deliberate Mixed-Bucket Under-Report** (2 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **P-4 ListObjectsV2 Defects** (2 connections) — `docs/tickets/README.md`
- **Listing Findings Found And Not Fixed** (1 connections) — `docs/tickets/018-listobjectsv2-document.md`

## Relationships

- [Storage Format Ticket](Storage_Format_Ticket.md) (2 shared connections)
- [Open Ticket Backlog](Open_Ticket_Backlog.md) (2 shared connections)
- [Velero E2E Environment](Velero_E2E_Environment.md) (1 shared connections)
- [Upload Deficit Investigation](Upload_Deficit_Investigation.md) (1 shared connections)
- [Coverage and Surface Tickets](Coverage_and_Surface_Tickets.md) (1 shared connections)
- [Upload Checksum Ticket](Upload_Checksum_Ticket.md) (1 shared connections)

## Source Files

- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/018-listobjectsv2-document.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 25 (96%)
- INFERRED: 1 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*