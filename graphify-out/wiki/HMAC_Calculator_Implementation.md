# HMAC Calculator Implementation

> 18 nodes · cohesion 0.18

## Key Concepts

- **HMACManager** (23 connections) — `internal/validation/hmac_manager.go`
- **HMACCalculator** (20 connections) — `internal/validation/hmac_calculator.go`
- **.AddFromStream()** (4 connections) — `internal/validation/hmac_calculator.go`
- **.VerifyIntegrity()** (4 connections) — `internal/validation/hmac_manager.go`
- **.Write()** (3 connections) — `internal/validation/hmac_calculator.go`
- **.WriteFromStream()** (3 connections) — `internal/validation/hmac_calculator.go`
- **.CreateCalculator()** (3 connections) — `internal/validation/hmac_manager.go`
- **.FinalizeCalculator()** (3 connections) — `internal/validation/hmac_manager.go`
- **.GetIntegrityMode()** (3 connections) — `internal/validation/hmac_manager.go`
- **.Add()** (2 connections) — `internal/validation/hmac_calculator.go`
- **.GetCurrentHash()** (2 connections) — `internal/validation/hmac_calculator.go`
- **.Sum()** (2 connections) — `internal/validation/hmac_calculator.go`
- **.IsEnabled()** (2 connections) — `internal/validation/hmac_manager.go`
- **.ShouldCreateHMAC()** (2 connections) — `internal/validation/hmac_manager.go`
- **.ShouldVerifyHMAC()** (2 connections) — `internal/validation/hmac_manager.go`
- **.Cleanup()** (1 connections) — `internal/validation/hmac_calculator.go`
- **.Reset()** (1 connections) — `internal/validation/hmac_calculator.go`
- **.ClearSensitiveData()** (1 connections) — `internal/validation/hmac_manager.go`

## Relationships

- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (6 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (4 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (4 shared connections)
- [HMAC Calculator Tests](HMAC_Calculator_Tests.md) (3 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (3 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (2 shared connections)
- [HKDF Integrity Key Derivation](HKDF_Integrity_Key_Derivation.md) (1 shared connections)

## Source Files

- `internal/validation/hmac_calculator.go`
- `internal/validation/hmac_manager.go`

## Audit Trail

- EXTRACTED: 53 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*