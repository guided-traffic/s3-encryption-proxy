# GCM Decryption Call Graph

> 12 nodes · cohesion 0.21

## Key Concepts

- **internal/orchestration.Manager.EncryptCTR** (13 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetMetadataPrefix** (6 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.EncryptGCM** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.DecryptData** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetAlgorithm** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.CreateEnvelopeEncryptor** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.Factory.CreateEnvelopeEncryptor** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.DecryptDataWithMetadata** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/object.Handler.handleGetObjectMemoryDecryption** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACCalculator.AddFromStream** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.DecryptCTRStream** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.EncryptCTR$1** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (6 shared connections)
- [Multipart Create Call Graph](Multipart_Create_Call_Graph.md) (4 shared connections)
- [Object PUT Call Graph](Object_PUT_Call_Graph.md) (2 shared connections)
- [Manager Accessor Graph](Manager_Accessor_Graph.md) (1 shared connections)
- [Orchestration Config Access Graph](Orchestration_Config_Access_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 27 (96%)
- INFERRED: 1 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*