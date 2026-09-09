# Manager Accessor Graph

> 8 nodes · cohesion 0.25

## Key Concepts

- **internal/orchestration.Manager.GetStats** (6 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetMetadataKeyPrefix** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetMultipartUploadState** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetSessionCount** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.UploadHandler.Handle** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/config.Config.GetStreamingThreshold** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.GetSession** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.GetSessionCount** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [Orchestration Config Access Graph](Orchestration_Config_Access_Graph.md) (2 shared connections)
- [GCM Decryption Call Graph](GCM_Decryption_Call_Graph.md) (1 shared connections)
- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 11 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*