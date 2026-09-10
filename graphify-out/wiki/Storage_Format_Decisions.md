# Storage Format Decisions

> 5 nodes · cohesion 0.40

## Key Concepts

- **AES-256-GCM Segment Chain plus Trailer (D1)** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Uniform, Segment-Aligned Parts Checked Against the Part Table (D2, D3)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Integrity Is Not Separable from Decryption (D4)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **One 256-Bit Data Key per Object (D1)** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **The Verdict Lands Before Anything Is Committed (D7)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (2 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (2 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (1 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`

## Audit Trail

- EXTRACTED: 8 (89%)
- INFERRED: 1 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*