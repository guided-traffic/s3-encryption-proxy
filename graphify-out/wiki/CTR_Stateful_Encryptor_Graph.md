# CTR Stateful Encryptor Graph

> 11 nodes · cohesion 0.25

## Key Concepts

- **internal/orchestration.MultipartOperations.createStreamingDecryptionReader$1** (7 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.hmacValidatingReader.Read** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACCalculator.Add** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.HMACManager.VerifyIntegrity** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.processPartDataInOrder** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.AESCTRStatefulEncryptor.DecryptPart** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/dataencryption.AESCTRStatefulEncryptor.EncryptPart** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.decryptionReader.Read** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.encryptionReader.Read** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.createStreamingDecryptionReader** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.createStreamingDecryptionReader$1$1** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (5 shared connections)
- [Multipart Abort Call Graph](Multipart_Abort_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 17 (85%)
- INFERRED: 3 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*