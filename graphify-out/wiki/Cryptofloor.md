# Cryptofloor

> 16 nodes · cohesion 0.17

## Key Concepts

- **TestCryptoFloor()** (9 connections) — `test/perf/cryptofloor_test.go`
- **AESProvider** (8 connections) — `pkg/encryption/keyencryption/aes.go`
- **cryptofloor Instrument (In-Process Crypto Floor)** (5 connections) — `test/perf/README.md`
- **crypto/cipher.AEAD** (4 connections)
- **.wrapAEAD()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **cryptofloor_test.go** (4 connections) — `test/perf/cryptofloor_test.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **openSegments()** (3 connections) — `test/perf/cryptofloor_test.go`
- **sealSegments()** (3 connections) — `test/perf/cryptofloor_test.go`
- **Noise Floor — Below 10 % Is the Machine** (2 connections) — `test/perf/README.md`
- **.Fingerprint()** (1 connections) — `pkg/encryption/keyencryption/aes.go`
- **.Name()** (1 connections) — `pkg/encryption/keyencryption/aes.go`
- **64 KiB Is Where the Instrument Stops Resolving** (1 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Downloads and the Crypto Floor Are Unchanged** (1 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Every Variant Must Allocate the Same** (1 connections) — `test/perf/README.md`

## Relationships

- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)
- [Harness](Harness.md) (2 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (1 shared connections)
- [AES KEK Vector Tests](AES_KEK_Vector_Tests.md) (1 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)
- [Report](Report.md) (1 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)
- [Readme](Readme.md) (1 shared connections)

## Source Files

- `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- `pkg/encryption/keyencryption/aes.go`
- `test/perf/README.md`
- `test/perf/cryptofloor_test.go`

## Audit Trail

- EXTRACTED: 29 (88%)
- INFERRED: 4 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*