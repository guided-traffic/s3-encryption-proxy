# S3 Surface Fidelity Ticket

> 19 nodes · cohesion 0.14

## Key Concepts

- **Ticket 022: S3 surface fidelity** (16 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Ticket 018: ListObjectsV2 — a real S3 document and plaintext sizes** (11 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Ticket 026: SSE-C on every verb, or not at all** (8 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **The silent 200: accept a request, do something else, answer success** (5 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Listing sizes computed by the proxy, never read from the backend** (4 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Tier 3.3: HEAD and List report the ciphertext size** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **A real ListBucketResult document instead of the marshalled SDK struct** (3 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **S-8: PUT drops the storage headers and answers 200** (3 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Either every verb carries the customer key, or none does** (3 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **The rsa provider type is removed in 5.0.0** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **No per-key HeadObject in a listing, under any circumstances** (2 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Item 8: the RSA fingerprint keeps one byte of the public exponent** (2 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **SSE-C buys compatibility, not security, under this threat model** (2 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **start-after, fetch-owner and encoding-type are silently dropped** (1 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **handleHeadBucket is a listing in disguise** (1 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **No integration coverage for the copy operations or versioned buckets** (1 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **<Location> is built from client-controlled request data** (1 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Two implementations of one S3 error document** (1 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **The customer key is never logged, stored, cached or put in session state** (1 connections) — `docs/tickets/026-sse-c-passthrough.md`

## Relationships

- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (5 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (5 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (3 shared connections)
- [Helm Chart Fix Ticket](Helm_Chart_Fix_Ticket.md) (3 shared connections)
- [Upload Checksum Verification](Upload_Checksum_Verification.md) (2 shared connections)
- [Configuration Hygiene Ticket](Configuration_Hygiene_Ticket.md) (2 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (1 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/018-listobjectsv2-document.md`
- `docs/tickets/022-s3-surface-fidelity.md`
- `docs/tickets/026-sse-c-passthrough.md`

## Audit Trail

- EXTRACTED: 43 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*