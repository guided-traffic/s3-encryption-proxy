# AES-GCM Data Encryptor

> 14 nodes · cohesion 0.14

## Key Concepts

- **AESCTRDataEncryptor** (7 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **AESGCMDataEncryptor** (7 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **sync.Mutex** (6 connections)
- **.DecryptStream()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.EncryptStream()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.DecryptStream()** (3 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **.EncryptStream()** (3 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **.GenerateDEK()** (2 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.GenerateDEK()** (2 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **aes_gcm.go** (2 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **.Algorithm()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.GetLastIV()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.Algorithm()** (1 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **.GetLastIV()** (1 connections) — `pkg/encryption/dataencryption/aes_gcm.go`

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (6 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (4 shared connections)
- [AES-CTR Range Reader](AES-CTR_Range_Reader.md) (1 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Provider Manager DEK Cache](Provider_Manager_DEK_Cache.md) (1 shared connections)
- [AES-GCM Encryption Tests](AES-GCM_Encryption_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/aes_ctr.go`
- `pkg/encryption/dataencryption/aes_gcm.go`

## Audit Trail

- EXTRACTED: 29 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*