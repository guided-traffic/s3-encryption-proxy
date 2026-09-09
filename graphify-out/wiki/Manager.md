# Manager

> God node · 60 connections · `internal/orchestration/manager.go`

**Community:** [Multipart Handler Construction](Multipart_Handler_Construction.md)

## Connections by Relation

### contains
- manager.go `EXTRACTED`

### method
- .EncryptDataWithContentType() `EXTRACTED`
- .IsNoneProvider() `EXTRACTED`
- .UploadPart() `EXTRACTED`
- .EncryptData() `EXTRACTED`
- .EncryptDataWithHTTPContentType() `EXTRACTED`
- .UploadPartStreaming() `EXTRACTED`
- .CreateEncryptionReader() `EXTRACTED`
- .CreateEncryptionReaderBuffered() `EXTRACTED`
- .CreateDecryptionReaderBuffered() `EXTRACTED`
- .UploadPartStreamingBuffer() `EXTRACTED`
- .GetStats() `EXTRACTED`
- .CompleteMultipartUpload() `EXTRACTED`
- .CreateDecryptionReader() `EXTRACTED`
- .DecryptData() `EXTRACTED`
- .InitiateMultipartUpload() `EXTRACTED`
- .GetProviderAliases() `EXTRACTED`
- .GetActiveProviderAlias() `EXTRACTED`
- .CleanupExpiredSessions() `EXTRACTED`
- .startBackgroundCleanup() `EXTRACTED`
- .StorePartETag() `EXTRACTED`
- *…and 12 more `method` connection(s) not listed (lowest-degree first to go)*

### references
- context.Context `EXTRACTED`
- [Config](Config.md) `EXTRACTED`
- github.com/sirupsen/logrus.Entry `EXTRACTED`
- ProviderManager `EXTRACTED`
- NewManager() `EXTRACTED`
- MultipartOperations `EXTRACTED`
- MetadataManager `EXTRACTED`
- setupMultipartTestEnv() `EXTRACTED`
- Handler `EXTRACTED`
- HMACManager `EXTRACTED`
- Handler `EXTRACTED`
- NewCreateHandler() `EXTRACTED`
- Server `EXTRACTED`
- MpuEnv `EXTRACTED`
- NewHandler() `EXTRACTED`
- NewHandler() `EXTRACTED`
- NewCompleteHandler() `EXTRACTED`
- CompleteHandler `EXTRACTED`
- CreateHandler `EXTRACTED`
- UploadHandler `EXTRACTED`
- *…and 7 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*