# Manager Envelope Encryption

> 41 nodes · cohesion 0.09

## Key Concepts

- **io.Reader** (42 connections)
- **bufioReader()** (39 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **Manager** (12 connections) — `internal/orchestration/singlepart.go`
- **.EncryptDataWithContentType()** (8 connections) — `internal/orchestration/manager.go`
- **.IsNoneProvider()** (8 connections) — `internal/orchestration/manager.go`
- **StreamingEncryptionResult** (8 connections) — `internal/orchestration/manager.go`
- **.createDecryptionReaderWithSizeInternal()** (7 connections) — `internal/orchestration/singlepart.go`
- **.UploadPart()** (7 connections) — `internal/orchestration/manager.go`
- **EnvFakeDataEncryptor** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.createEncryptionReaderInternal()** (6 connections) — `internal/orchestration/singlepart.go`
- **.EncryptData()** (6 connections) — `internal/orchestration/manager.go`
- **.CreateDecryptionReaderBuffered()** (5 connections) — `internal/orchestration/manager.go`
- **.CreateEncryptionReader()** (5 connections) — `internal/orchestration/manager.go`
- **.CreateEncryptionReaderBuffered()** (5 connections) — `internal/orchestration/manager.go`
- **.createStreamingEncryptor()** (5 connections) — `internal/orchestration/singlepart.go`
- **.EncryptCTR()** (5 connections) — `internal/orchestration/singlepart.go`
- **.EncryptDataWithHTTPContentType()** (5 connections) — `internal/orchestration/manager.go`
- **.UploadPartStreaming()** (5 connections) — `internal/orchestration/manager.go`
- **.UploadPartStreamingBuffer()** (5 connections) — `internal/orchestration/manager.go`
- **.buildEncryptionMetadataSimple()** (4 connections) — `internal/orchestration/singlepart.go`
- **.CreateDecryptionReader()** (4 connections) — `internal/orchestration/manager.go`
- **.CreateStreamingDecryptionReaderWithSize()** (4 connections) — `internal/orchestration/singlepart.go`
- **.createStreamingDecryptor()** (4 connections) — `internal/orchestration/singlepart.go`
- **.DecryptCTRStream()** (4 connections) — `internal/orchestration/singlepart.go`
- **.DecryptDataWithMetadata()** (4 connections) — `internal/orchestration/singlepart.go`
- *... and 16 more nodes in this community*

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (24 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (15 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (8 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (8 shared connections)
- [AES-CTR Range Reader](AES-CTR_Range_Reader.md) (6 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (4 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (4 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (3 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (3 shared connections)
- [Response Copy Benchmark](Response_Copy_Benchmark.md) (2 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (2 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/singlepart.go`
- `internal/orchestration/streaming_io_coverage_test.go`
- `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- `pkg/encryption/envelope/envelope_coverage_test.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 179 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*