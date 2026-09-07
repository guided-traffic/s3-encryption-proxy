# HMAC Integrity and Streaming IO

> 178 nodes · cohesion 0.04

## Key Concepts

- **.Add()** (86 connections) — `internal/validation/hmac_calculator.go`
- **.Write()** (44 connections) — `internal/validation/hmac_calculator.go`
- **streaming_io_coverage_test.go** (43 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **.CreateCalculator()** (37 connections) — `internal/validation/hmac_manager.go`
- **.Sum()** (28 connections) — `internal/validation/hmac_calculator.go`
- **OrcStrPayload()** (27 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **.CreateRangeDecryptionReader()** (22 connections) — `internal/orchestration/rangeread.go`
- **NewHMACCalculator()** (21 connections) — `internal/validation/hmac_calculator.go`
- **TestValHMACManagerRoundTripAndTampering()** (19 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **NewHMACManager()** (19 connections) — `internal/validation/hmac_manager.go`
- **.VerifyIntegrity()** (19 connections) — `internal/validation/hmac_manager.go`
- **OrcStrSHA256()** (18 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrCTR()** (17 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrReadAll()** (17 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **.FinalizeCalculator()** (16 connections) — `internal/validation/hmac_manager.go`
- **hmac_calculator_test.go** (15 connections) — `internal/validation/hmac_calculator_test.go`
- **OrcStrLogger()** (15 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **.GetCurrentHash()** (15 connections) — `internal/validation/hmac_calculator.go`
- **.Read()** (14 connections) — `internal/orchestration/streaming_io.go`
- **OrcStrDEK()** (14 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrHMACManager()** (14 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestValHMACManagerVerifyIntegrityWeakModes()** (13 connections) — `internal/validation/hmac_manager_coverage_test.go`
- **.Read()** (13 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderRoundTrip()** (13 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderWithholdsFinalChunkOnTamper()** (13 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- *... and 153 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3_signing_helper.go`
- `docs/architecture/callgraph_orchestration_layer.svg`
- `docs/tickets/024-coverage-round-findings.md`
- `internal/orchestration/multipart.go`
- `internal/orchestration/multipart_coverage_test.go`
- `internal/orchestration/rangeread.go`
- `internal/orchestration/rangeread_coverage_test.go`
- `internal/orchestration/singlepart_coverage_test.go`
- `internal/orchestration/streaming_io.go`
- `internal/orchestration/streaming_io_coverage_test.go`
- `internal/validation/hkdf.go`
- `internal/validation/hkdf_coverage_test.go`
- `internal/validation/hmacCalculator_example_test.go`
- `internal/validation/hmac_calculator.go`
- `internal/validation/hmac_calculator_test.go`
- `internal/validation/hmac_manager.go`
- `internal/validation/hmac_manager_coverage_test.go`
- `internal/validation/hmac_manager_test.go`
- `test/e2e/velero/hash.go`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`

## Audit Trail

- EXTRACTED: 794 (56%)
- INFERRED: 628 (44%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*