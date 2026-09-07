# Envelope Crypto Providers

> 347 nodes · cohesion 0.02

## Key Concepts

- **.Fingerprint()** (38 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **aes_ctr_coverage_test.go** (30 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **.EncryptDataStream()** (29 connections) — `pkg/encryption/envelope/envelope.go`
- **DekrandomBytes()** (28 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **NewAESGCMDataEncryptor()** (27 connections) — `/Users/hfi/repos/s3-encryption-proxy/pkg/encryption/dataencryption/aes_gcm.go`
- **envelope_coverage_test.go** (25 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.DecryptDEK()** (24 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **NewAESCTRDataEncryptor()** (23 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.EncryptDEK()** (23 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **factory_coverage_test.go** (20 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **DekbufReader()** (19 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **.CreateEnvelopeEncryptor()** (19 connections) — `pkg/encryption/factory/factory.go`
- **EnvelopeEncryptor.EncryptDataStream (builds s3ep- metadata)** (18 connections) — `pkg/encryption/envelope/envelope.go`
- **.DecryptDataStream()** (18 connections) — `pkg/encryption/envelope/envelope.go`
- **.EncryptStream()** (17 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **rsa_coverage_test.go** (17 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAProviderFromPEMFormats()** (17 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **NewRSAProvider()** (17 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.DecryptStream()** (16 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.CreateKeyEncryptorFromConfig()** (16 connections) — `pkg/encryption/factory/factory.go`
- **aes_gcm_coverage_test.go** (14 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESCTRStatefulEncryptorRoundTrip()** (13 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **DekencryptGCM()** (13 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestEnvDecryptWithWrongKEK()** (13 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvEncryptDecryptRoundTrip()** (13 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- *... and 322 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/pkg/encryption/dataencryption/aes_gcm.go`
- `docs/architecture/callgraph_orchestration_layer.svg`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/010-tier2/proxy-allocs-objects-top15.txt`
- `docs/tickets/010-tier4.1/proxy-allocs-objects-top15.txt`
- `docs/tickets/024-coverage-round-findings.md`
- `internal/orchestration/multipart.go`
- `internal/validation/hmac_calculator.go`
- `internal/validation/hmac_manager.go`
- `pkg/encryption/ciphertext_size.go`
- `pkg/encryption/ciphertext_size_invariant_test.go`
- `pkg/encryption/dataencryption/aes_ctr.go`
- `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- `pkg/encryption/dataencryption/aes_ctr_test.go`
- `pkg/encryption/dataencryption/aes_gcm.go`
- `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- `pkg/encryption/dataencryption/aes_gcm_test.go`
- `pkg/encryption/dataencryption/test_utils.go`
- `pkg/encryption/envelope/envelope.go`

## Audit Trail

- EXTRACTED: 1305 (56%)
- INFERRED: 1011 (44%)
- AMBIGUOUS: 3 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*