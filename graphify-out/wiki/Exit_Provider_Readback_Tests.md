# Exit Provider Readback Tests

> 13 nodes · cohesion 0.41

## Key Concepts

- **TestExitProvider_ReadsBackAnEncryptedObject()** (13 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ReadsBackAMultipartObject()** (12 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ClientDrivenMultipart()** (10 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **exit_provider_readback_test.go** (8 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **assertStoredPlaintext()** (8 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **assertDataHashesEqual()** (8 connections) — `test/integration/encryption-modes/test_helpers.go`
- **assertStoredEncrypted()** (7 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **getViaClient()** (6 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **storedObject()** (6 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **randomPayload()** (5 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **assertDataHashesNotEqual()** (4 connections) — `test/integration/encryption-modes/test_helpers.go`
- **test_helpers.go** (3 connections) — `test/integration/encryption-modes/test_helpers.go`
- **calculateSHA256()** (3 connections) — `test/integration/encryption-modes/test_helpers.go`

## Relationships

- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (15 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (10 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (4 shared connections)

## Source Files

- `test/integration/encryption-modes/exit_provider_readback_test.go`
- `test/integration/encryption-modes/test_helpers.go`

## Audit Trail

- EXTRACTED: 41 (67%)
- INFERRED: 20 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*