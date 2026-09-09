# Integrity Modes and Flows

> 19 nodes · cohesion 0.15

## Key Concepts

- **H-5 integrity_verification does not refuse a tampered aes-ctr object** (6 connections) — `SECURITY_ARCHITECTURE.md`
- **H-6 An object without encryption metadata is served as plaintext** (6 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0003: objects are an authenticated segment chain** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **Integrity verification modes (off, lax, strict, hybrid)** (4 connections) — `CLAUDE.md`
- **What aes-gcm and aes-ctr actually guarantee** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **H-1 Ranged aes-ctr reads are not verified by the proxy** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **Auto-multipart and the metadata self-copy** (3 connections) — `CLAUDE.md`
- **GET request flow** (3 connections) — `CLAUDE.md`
- **orchestration.Manager facade** (3 connections) — `CLAUDE.md`
- **Integrity verification: detection, not refusal** (3 connections) — `README.md`
- **H-4 Velero kopia repositories default to a published password** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **PUT request flow** (2 connections) — `CLAUDE.md`
- **Ranged reads of encrypted objects** (2 connections) — `README.md`
- **Velero kopia repository password warning** (2 connections) — `README.md`
- **The self-copy window** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **Decisions live in ADRs; tickets are deleted** (1 connections) — `CLAUDE.md`
- **Objects without s3ep-* metadata are served as-is** (1 connections) — `README.md`
- **Versioned buckets and the extra self-copy version** (1 connections) — `README.md`
- **H-3 Rollback and object substitution are not prevented** (1 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Envelope Encryption Architecture](Envelope_Encryption_Architecture.md) (4 shared connections)
- [Velero E2E CI Job](Velero_E2E_CI_Job.md) (1 shared connections)
- [TLS Integration CI Job](TLS_Integration_CI_Job.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`

## Audit Trail

- EXTRACTED: 22 (71%)
- INFERRED: 9 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*