# HMAC Decryption Call Graph

> 14 nodes · cohesion 0.26

## Key Concepts

- **internal/orchestration.Manager.DecryptGCMStream** (14 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACManager.IsEnabled** (10 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.DecryptMultipartWithHMACVerification** (10 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.createDecryptionReaderWithSizeInternal** (7 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACManager.CreateCalculator** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.DecryptDEK** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetEncryptedDEK** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetFingerprint** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetHMAC** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.createStreamingDecryptor** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MetadataManager.GetIV** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.NewAESCTRStatefulEncryptorWithIV** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.DecryptGCMStream$1** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetFactory** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [GCM Decryption Call Graph](GCM_Decryption_Call_Graph.md) (6 shared connections)
- [Multipart Create Call Graph](Multipart_Create_Call_Graph.md) (5 shared connections)
- [CTR Stateful Encryptor Graph](CTR_Stateful_Encryptor_Graph.md) (5 shared connections)
- [Manager Accessor Graph](Manager_Accessor_Graph.md) (1 shared connections)
- [Orchestration Config Access Graph](Orchestration_Config_Access_Graph.md) (1 shared connections)
- [Multipart Abort Call Graph](Multipart_Abort_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 41 (95%)
- INFERRED: 2 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*