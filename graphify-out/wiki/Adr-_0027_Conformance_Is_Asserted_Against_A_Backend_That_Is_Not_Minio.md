# Adr: 0027 Conformance Is Asserted Against A Backend That Is Not Minio

> 7 nodes · cohesion 0.29

## Key Concepts

- **Backend-agnostic conformance suite** (6 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Byte budget enforced in code** (2 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **x-amz-expected-bucket-owner not enforced by any reachable backend** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **LocalStack (free conformance backend)** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Incomplete multipart upload treated as a leak** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Corpus seeded once, then only read** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **Wasabi (paid conformance backend)** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)

## Source Files

- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`

## Audit Trail

- EXTRACTED: 7 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*