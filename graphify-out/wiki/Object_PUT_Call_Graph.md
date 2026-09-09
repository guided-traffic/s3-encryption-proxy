# Object PUT Call Graph

> 18 nodes · cohesion 0.15

## Key Concepts

- **internal/orchestration.ProviderManager.IsNoneProvider** (10 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.EncryptDataWithContentType** (5 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.CompleteMultipartUpload** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.StorePartETag** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.UploadPart** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.UploadHandler.handleStandardUploadPart** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.EncryptDataWithHTTPContentType** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.UploadPartStreaming** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.UploadPartStreamingBuffer** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.CreateEncryptionReader** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.EncryptData** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.ProcessPart** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/multipart.UploadHandler.handleStreamingUploadPart** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/object.Handler.putObjectDirect** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy/handlers/object.Handler.putObjectStreamingReader** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.CreateEncryptionReaderBuffered** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetStreamingSegmentSize** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.MultipartOperations.StorePartETag** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [Multipart Create Call Graph](Multipart_Create_Call_Graph.md) (4 shared connections)
- [GCM Decryption Call Graph](GCM_Decryption_Call_Graph.md) (2 shared connections)
- [Multipart Abort Call Graph](Multipart_Abort_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 30 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*