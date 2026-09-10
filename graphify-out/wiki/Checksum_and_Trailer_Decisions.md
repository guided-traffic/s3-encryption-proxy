# Checksum and Trailer Decisions

> 5 nodes · cohesion 0.40

## Key Concepts

- **A CRC32C over the Plaintext, Sealed in the Trailer (D13)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **The Tail-First Read and the Served Checksum (D14, not built)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **The Proxy Serves Its Own Sealed CRC32C on a Whole-Object Read (D10, D10a)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **A Failed Whole-Object Read Reaches the Client as a Short Body** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **No Plaintext Checksum in Object Metadata: It Is a Confirmation Oracle (D9)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (3 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (2 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*