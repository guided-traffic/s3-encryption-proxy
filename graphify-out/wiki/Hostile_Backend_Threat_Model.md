# Hostile Backend Threat Model

> 11 nodes · cohesion 0.22

## Key Concepts

- **Authenticated Segment Chain (s3ep-gcm-seg-v2)** (15 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Hostile Backend Threat Model** (8 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **One 256-bit Data Key per Object** (4 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **One Local Key Provider (type aes)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Every Served Byte Is Proxy-Verified at Read Granularity** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **A Listing Issues No Per-Object Request, Ever** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **Uniform Segment-Aligned Parts Checked at Complete** (2 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Integrity Is Not Separable From Decryption** (1 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Bounded Ranged Read Over Segments** (1 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **HashiCorp Vault Transit as the First KMS Backend** (1 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **Encryption at Rest Is Asserted by Reading the Backend Directly** (1 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`

## Relationships

- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (4 shared connections)
- [One Data Key Per Object](One_Data_Key_Per_Object.md) (3 shared connections)
- [ADR Authoring Rules](ADR_Authoring_Rules.md) (2 shared connections)
- [SigV4 Without Rate Limiting](SigV4_Without_Rate_Limiting.md) (2 shared connections)
- [Major Release Label Policy](Major_Release_Label_Policy.md) (2 shared connections)
- [One Local Key Provider](One_Local_Key_Provider.md) (2 shared connections)
- [Authenticated Segment Trailer](Authenticated_Segment_Trailer.md) (1 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`

## Audit Trail

- EXTRACTED: 25 (89%)
- INFERRED: 3 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*