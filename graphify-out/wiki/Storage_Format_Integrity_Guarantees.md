# Storage Format Integrity Guarantees

> 67 nodes · cohesion 0.04

## Key Concepts

- **ADR 0003** (58 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0012: client checksums are verified never forwarded** (34 connections) — `CLAUDE.md`
- **ADR 0010: Sizes and listings describe the plaintext** (31 connections) — `docs/tickets/037-multiple-backends.md`
- **Storage format s3ep-gcm-seg-v2** (14 connections) — `docs/operations/integrity.md`
- **ADR 0032: The entity tag is a change token** (12 connections) — `docs/tickets/037-multiple-backends.md`
- **Declared client checksums are verified and dropped** (10 connections) — `docs/operations/integrity.md`
- **Out-of-band recovery tool for a damaged object** (8 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **Tail-first whole-object GET (bytes=-65604, then If-Match prefix)** (7 connections) — `docs/developer/request-paths.md`
- **Client-leg checksum verification** (7 connections) — `docs/security/upload-integrity.md`
- **The load-bearing decryption inputs stay minimal** (5 connections) — `docs/tickets/033-out-of-band-recovery-path.md`
- **tail.go** (5 connections) — `internal/proxy/handlers/object/tail.go`
- **ADR 0024: an upload forwards while it receives** (4 connections) — `CLAUDE.md`
- **Entity tag -0 marker gates** (4 connections) — `docs/developer/request-paths.md`
- **Ranged GET window planning** (4 connections) — `docs/developer/request-paths.md`
- **Entity tag is a change token (-0 suffix)** (4 connections) — `docs/operations/integrity.md`
- **KEK/DEK envelope key hierarchy** (4 connections) — `docs/security/key-management.md`
- **Where a failed proof surfaces (before vs after the response)** (4 connections) — `docs/security/stored-objects.md`
- **What the segment chain guarantees** (4 connections) — `docs/security/stored-objects.md`
- **Internal multipart producer (concurrency+1 buffers, receive overlaps send)** (3 connections) — `DEVELOPER.md`
- **Sealed trailer with plaintext length and CRC32C** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Tail-first whole-object read and x-amz-checksum-crc32c** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **x-amz-checksum-crc32c answered on writes** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **HEAD as a 40-byte trailer read** (3 connections) — `docs/developer/request-paths.md`
- **Associated data binds segment index and object key** (3 connections) — `docs/operations/integrity.md`
- **s3ep-kek-fingerprint** (3 connections) — `docs/operations/integrity.md`
- *... and 42 more nodes in this community*

## Relationships

- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (24 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (14 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (14 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (14 shared connections)
- [Changelog and Project Front Page](Changelog_and_Project_Front_Page.md) (11 shared connections)
- [Forward-or-Refuse Response Rules](Forward-or-Refuse_Response_Rules.md) (8 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (6 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (4 shared connections)
- [Filename Encryption Pass Engine](Filename_Encryption_Pass_Engine.md) (3 shared connections)
- [Streaming Aws Decoder](Streaming_Aws_Decoder.md) (3 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (3 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (2 shared connections)

## Source Files

- `CLAUDE.md`
- `DEVELOPER.md`
- `README.md`
- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/developer/request-paths.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/security/key-management.md`
- `docs/security/stored-objects.md`
- `docs/security/upload-integrity.md`
- `docs/tickets/033-out-of-band-recovery-path.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `internal/proxy/handlers/object/tail.go`

## Audit Trail

- EXTRACTED: 183 (86%)
- INFERRED: 31 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*