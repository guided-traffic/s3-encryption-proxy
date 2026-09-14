# Hostile Backend Decisions

> 8 nodes · cohesion 0.25

## Key Concepts

- **A Listing Size Is Computed by Arithmetic, With No Per-Key Request (D2, D3)** (5 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **Every Response Is Composed by the Proxy (D1)** (4 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **The Backend Is an Adversary (D1, D2)** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **A Ranged Read Fetches Only the Segments It Covers (D9)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Verification at Read Granularity (D3)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Plaintext Length Is a Pure Function of the Stored Length (D12, D12a)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Every Key Inside the Namespace Is Removed from Every Response (D7)** (2 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **A Listing Response Is a Real S3 Document, Built Explicitly (D4)** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (5 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (2 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (2 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`

## Audit Trail

- EXTRACTED: 15 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*