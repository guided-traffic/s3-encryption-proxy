# Integrity

> 9 nodes · cohesion 0.22

## Key Concepts

- **Declared client checksums are verified and dropped** (6 connections) — `docs/operations/integrity.md`
- **s3cmd sends no Content-MD5 for an object body** (2 connections) — `docs/operations/clients/s3cmd.md`
- **DeleteObjects requires a digest (400 InvalidRequest)** (2 connections) — `docs/operations/integrity.md`
- **s3_security.verify_payload_hash** (2 connections) — `docs/operations/integrity.md`
- **400 BadDigest** (1 connections) — `docs/operations/integrity.md`
- **Checksum throughput per algorithm** (1 connections) — `docs/operations/integrity.md`
- **A client checksum is never forwarded and never stored** (1 connections) — `docs/operations/integrity.md`
- **400 InvalidDigest** (1 connections) — `docs/operations/integrity.md`
- **501 NotImplemented for the xxhash checksum family** (1 connections) — `docs/operations/integrity.md`

## Relationships

- [Client E2E Verdicts](Client_E2E_Verdicts.md) (1 shared connections)

## Source Files

- `docs/operations/clients/s3cmd.md`
- `docs/operations/integrity.md`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*