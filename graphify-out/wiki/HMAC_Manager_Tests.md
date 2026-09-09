# HMAC Manager Tests

> 26 nodes · cohesion 0.16

## Key Concepts

- **NewHMACManager()** (21 connections) — `internal/validation/hmac_manager.go`
- **hmac_manager_test.go** (11 connections) — `internal/validation/hmac_manager_test.go`
- **generateRandomBytes()** (10 connections) — `internal/validation/hmac_manager_test.go`
- **hmac_manager_coverage_test.go** (9 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **NewHMACManagerWithoutConfig()** (7 connections) — `internal/validation/hmac_manager.go`
- **ValnewCfg()** (6 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestValHMACManagerRoundTripAndTampering()** (5 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestHMACManager_CreateCalculator_HKDF_Integration()** (5 connections) — `internal/validation/hmac_manager_test.go`
- **TestValDeriveIntegrityKeyMatchesManagerDerivation()** (4 connections) — `internal/validation/hkdf_coverage_test.go`
- **TestValHMACManagerModeFlags()** (4 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestValHMACManagerSetConfig()** (4 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestValHMACManagerVerifyIntegrityWeakModes()** (4 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestHMACManager_CreateCalculator()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_EndToEndWorkflow()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_FinalizeCalculator()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_LargeDataHandling()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_VerificationModes()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_VerifyIntegrity()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **TestHMACManager_VerifyIntegrity_ConstantTimeComparison()** (4 connections) — `internal/validation/hmac_manager_test.go`
- **hmac_manager.go** (3 connections) — `internal/validation/hmac_manager.go`
- **TestValHMACManagerClearSensitiveData()** (3 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestValHMACManagerFinalizeCalculatorClearsKey()** (3 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestValNewHMACManagerWithoutConfig()** (3 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **TestHMACManager_CreateCalculator_DeterministicKeys()** (3 connections) — `internal/validation/hmac_manager_test.go`
- **TestNewHMACManager()** (3 connections) — `internal/validation/hmac_manager_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (19 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (3 shared connections)
- [HMAC Calculator Tests](HMAC_Calculator_Tests.md) (2 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (2 shared connections)
- [HKDF Derivation Tests](HKDF_Derivation_Tests.md) (1 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (1 shared connections)
- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (1 shared connections)

## Source Files

- `internal/validation/hkdf_coverage_test.go`
- `internal/validation/hmac_manager.go`
- `internal/validation/hmac_manager_coverage_test.go`
- `internal/validation/hmac_manager_test.go`

## Audit Trail

- EXTRACTED: 65 (76%)
- INFERRED: 20 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*