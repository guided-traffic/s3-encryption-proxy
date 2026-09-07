# Orchestration Package Architecture

> 40 nodes · cohesion 0.09

## Key Concepts

- **Multipart Operations (multipart.go)** (10 connections) — `internal/orchestration/README.md`
- **Manager (manager.go) - Central Orchestration** (9 connections) — `internal/orchestration/README.md`
- **Streaming Operations (streaming.go)** (9 connections) — `internal/orchestration/README.md`
- **EncryptCTR (AES-CTR streaming)** (8 connections) — `internal/orchestration/README.md`
- **Internal Orchestration Package** (8 connections) — `internal/orchestration/README.md`
- **Provider Manager (providers.go)** (8 connections) — `internal/orchestration/README.md`
- **SinglePart Operations (singlepart.go)** (8 connections) — `internal/orchestration/README.md`
- **EncryptGCM (AES-GCM small objects)** (7 connections) — `internal/orchestration/README.md`
- **HMAC Manager** (7 connections) — `internal/orchestration/README.md`
- **Metadata Manager (metadata.go)** (7 connections) — `internal/orchestration/README.md`
- **Factory (KEK + DEK Combination)** (6 connections) — `internal/orchestration/README.md`
- **DecryptCTR** (4 connections) — `internal/orchestration/README.md`
- **DecryptGCM** (4 connections) — `internal/orchestration/README.md`
- **BuildMetadataForEncryption** (3 connections) — `internal/orchestration/README.md`
- **ManagerV2.Decrypt()** (3 connections) — `internal/orchestration/README.md`
- **ProcessPart** (3 connections) — `internal/orchestration/README.md`
- **CreateDecryptionReader** (2 connections) — `internal/orchestration/README.md`
- **CreateEncryptionReader** (2 connections) — `internal/orchestration/README.md`
- **DEK Provider (AES-CTR, AES-GCM)** (2 connections) — `internal/orchestration/README.md`
- **FilterClientMetadata** (2 connections) — `internal/orchestration/README.md`
- **FinalizeSession** (2 connections) — `internal/orchestration/README.md`
- **GetAlgorithm** (2 connections) — `internal/orchestration/README.md`
- **KEK Provider (AES, RSA, Tink, None)** (2 connections) — `internal/orchestration/README.md`
- **ManagerV2.Encrypt()** (2 connections) — `internal/orchestration/README.md`
- **Rationale: AES-GCM for small, AES-CTR for large** (2 connections) — `internal/orchestration/README.md`
- *... and 15 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `internal/orchestration/README.md`

## Audit Trail

- EXTRACTED: 128 (93%)
- INFERRED: 10 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*