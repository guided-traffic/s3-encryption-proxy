# Authenticated Segment Trailer

> 5 nodes · cohesion 0.40

## Key Concepts

- **Authenticated Trailer (Length and Sealed CRC32C)** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Bounded Short-Part Buffer for the Trailer** (2 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Tail-First Whole-Object Read with If-Match** (1 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **The Proxy Serves Its Own Sealed CRC32C on Whole-Object Reads** (1 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Memory Is Held by a Test on a Hard Bound** (1 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`

## Relationships

- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (1 shared connections)

## Source Files

- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`

## Audit Trail

- EXTRACTED: 5 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*