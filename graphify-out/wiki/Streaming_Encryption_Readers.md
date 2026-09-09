# Streaming Encryption Readers

> 21 nodes · cohesion 0.12

## Key Concepts

- **AESCTRStatefulEncryptor** (19 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **hmacGatedDecryptionReader** (9 connections) — `internal/orchestration/streaming_io.go`
- **hmacValidatingReader** (8 connections) — `internal/orchestration/streaming_io.go`
- **streaming_io.go** (6 connections) — `internal/orchestration/streaming_io.go`
- **decryptionReader** (6 connections) — `internal/orchestration/streaming_io.go`
- **encryptionReader** (6 connections) — `internal/orchestration/streaming_io.go`
- **.Read()** (5 connections) — `internal/orchestration/streaming_io.go`
- **readCloserWrapper** (4 connections) — `internal/orchestration/streaming_io.go`
- **.Read()** (2 connections) — `internal/orchestration/streaming_io.go`
- **.Read()** (2 connections) — `internal/orchestration/streaming_io.go`
- **.Close()** (2 connections) — `internal/orchestration/streaming_io.go`
- **.Read()** (2 connections) — `internal/orchestration/streaming_io.go`
- **.Close()** (2 connections) — `internal/orchestration/streaming_io.go`
- **.Algorithm()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.Cleanup()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.DecryptPart()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.EncryptPart()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.GetIV()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **io.Closer** (1 connections)
- **.Close()** (1 connections) — `internal/orchestration/streaming_io.go`
- **.Close()** (1 connections) — `internal/orchestration/streaming_io.go`

## Relationships

- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (8 shared connections)
- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (5 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (4 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (3 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (3 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (2 shared connections)
- [AES-CTR Range Reader](AES-CTR_Range_Reader.md) (2 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (2 shared connections)

## Source Files

- `internal/orchestration/streaming_io.go`
- `pkg/encryption/dataencryption/aes_ctr.go`

## Audit Trail

- EXTRACTED: 55 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*