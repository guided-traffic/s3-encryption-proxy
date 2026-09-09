# HMAC Calculator Tests

> 23 nodes · cohesion 0.13

## Key Concepts

- **NewHMACCalculator()** (18 connections) — `internal/validation/hmac_calculator.go`
- **hmac_calculator_test.go** (15 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_Add()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_AddFromStream()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_AddFromStream_WithNilReader()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_AddFromStream_WithReadError()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_Cleanup()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_ConsistentHashWithMultipleCalls()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_EndToEndWorkflow()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_GetCurrentHash()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_MemoryClearing()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **TestNewHMACCalculator()** (3 connections) — `internal/validation/hmac_calculator_test.go`
- **hmacCalculator_example_test.go** (3 connections) — `internal/validation/hmacCalculator_example_test.go`
- **hmac_calculator.go** (2 connections) — `internal/validation/hmac_calculator.go`
- **TestHMACCalculator_Add_WithNilCalculator()** (2 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_AddFromStream_WithNilCalculator()** (2 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_Cleanup_WithAlreadyNilFields()** (2 connections) — `internal/validation/hmac_calculator_test.go`
- **TestHMACCalculator_GetCurrentHash_WithNilCalculator()** (2 connections) — `internal/validation/hmac_calculator_test.go`
- **ExampleHMACCalculator()** (2 connections) — `internal/validation/hmacCalculator_example_test.go`
- **ExampleHMACCalculator_consistency()** (2 connections) — `internal/validation/hmacCalculator_example_test.go`
- **ExampleHMACCalculator_multipleWrites()** (2 connections) — `internal/validation/hmacCalculator_example_test.go`
- **errorReader** (2 connections) — `internal/validation/hmac_calculator_test.go`
- **.Read()** (1 connections) — `internal/validation/hmac_calculator_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (3 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (2 shared connections)

## Source Files

- `internal/validation/hmacCalculator_example_test.go`
- `internal/validation/hmac_calculator.go`
- `internal/validation/hmac_calculator_test.go`

## Audit Trail

- EXTRACTED: 36 (69%)
- INFERRED: 16 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*