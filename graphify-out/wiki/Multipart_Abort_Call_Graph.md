# Multipart Abort Call Graph

> 14 nodes · cohesion 0.20

## Key Concepts

- **internal/validation.HMACCalculator.Cleanup** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.AbortSession** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.CleanupExpiredSessions** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.CleanupSession** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACManager.ClearSensitiveData** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.AESCTRStatefulEncryptor.Cleanup** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.CleanupMultipartUpload** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.CompleteHandler.Handle** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.startBackgroundCleanup$1** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.AbortHandler.Handle** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.hmacValidatingReader.Close** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.AbortMultipartUpload** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.CleanupExpiredSessions** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.startBackgroundCleanup** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [Object PUT Call Graph](Object_PUT_Call_Graph.md) (1 shared connections)
- [CTR Stateful Encryptor Graph](CTR_Stateful_Encryptor_Graph.md) (1 shared connections)
- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 20 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*