# Multipart Session State

> 26 nodes · cohesion 0.16

## Key Concepts

- **MultipartOperations** (32 connections) — `internal/orchestration/multipart.go`
- **MultipartSession** (24 connections) — `internal/orchestration/multipart.go`
- **EncryptionResult** (10 connections) — `internal/orchestration/types.go`
- **NewMultipartOperations()** (9 connections) — `internal/orchestration/multipart.go`
- **.createStreamingDecryptionReader()** (7 connections) — `internal/orchestration/multipart.go`
- **.ProcessPart()** (7 connections) — `internal/orchestration/multipart.go`
- **.processPartOrdered()** (7 connections) — `internal/orchestration/multipart.go`
- **.getSession()** (6 connections) — `internal/orchestration/multipart.go`
- **.DecryptMultipartWithHMACVerification()** (5 connections) — `internal/orchestration/multipart.go`
- **.InitiateSession()** (5 connections) — `internal/orchestration/multipart.go`
- **.processNoneProviderPartStream()** (5 connections) — `internal/orchestration/multipart.go`
- **.processPartDataInOrder()** (5 connections) — `internal/orchestration/multipart.go`
- **multipart.go** (4 connections) — `internal/orchestration/multipart.go`
- **PartBuffer** (4 connections) — `internal/orchestration/multipart.go`
- **.processBufferedPartsData()** (4 connections) — `internal/orchestration/multipart.go`
- **sync.RWMutex** (3 connections)
- **.createNoneProviderSession()** (3 connections) — `internal/orchestration/multipart.go`
- **.FinalizeSession()** (3 connections) — `internal/orchestration/multipart.go`
- **.GetSession()** (3 connections) — `internal/orchestration/multipart.go`
- **.GetMultipartUploadState()** (2 connections) — `internal/orchestration/manager.go`
- **.AbortSession()** (2 connections) — `internal/orchestration/multipart.go`
- **.CleanupExpiredSessions()** (2 connections) — `internal/orchestration/multipart.go`
- **.StorePartETag()** (2 connections) — `internal/orchestration/multipart.go`
- **orchestration/types.go** (1 connections) — `internal/orchestration/types.go`
- **.CleanupSession()** (1 connections) — `internal/orchestration/multipart.go`
- *... and 1 more nodes in this community*

## Relationships

- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (8 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (7 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (5 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (4 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (4 shared connections)
- [Provider Manager DEK Cache](Provider_Manager_DEK_Cache.md) (3 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (3 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (2 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (2 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/multipart.go`
- `internal/orchestration/types.go`

## Audit Trail

- EXTRACTED: 101 (96%)
- INFERRED: 4 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*