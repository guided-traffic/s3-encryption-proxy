# Multipart Create Call Graph

> 16 nodes · cohesion 0.16

## Key Concepts

- **internal/orchestration.MultipartOperations.FinalizeSession** (8 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.InitiateSession** (8 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.buildEncryptionMetadataSimple** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.Factory.GetKeyEncryptor** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.InitiateMultipartUpload** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetActiveFingerprint** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetActiveProviderAlgorithm** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetProviderByFingerprint** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.AESCTRStatefulEncryptor.GetIV** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACManager.FinalizeCalculator** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.BuildMetadataForEncryption** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.SetHMAC** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.NewAESCTRStatefulEncryptor** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.EncryptDEK** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.CreateHandler.Handle** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.createStreamingEncryptor** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (5 shared connections)
- [GCM Decryption Call Graph](GCM_Decryption_Call_Graph.md) (4 shared connections)
- [Object PUT Call Graph](Object_PUT_Call_Graph.md) (4 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 32 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*