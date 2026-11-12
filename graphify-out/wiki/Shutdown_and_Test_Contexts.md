# Shutdown and Test Contexts

> 182 nodes · cohesion 0.02

## Key Concepts

- **testing.T** (1582 connections)
- **expandConfigEnvVars()** (15 connections) — `internal/config/envexpand.go`
- **testHandler()** (15 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **expandEnvVars()** (13 connections) — `internal/config/envexpand.go`
- **MwauthService()** (13 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **RtPxlistBuckets()** (12 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **backendOptions()** (10 connections) — `internal/proxy/backend_client_test.go`
- **MwsignDateHeaderRequest()** (10 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **runShutdownTail()** (9 connections) — `cmd/s3-encryption-proxy/main.go`
- **parseByteRange()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **NewS3AuthenticationService()** (9 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **KekNewAES()** (9 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **monExportedSeries()** (8 connections) — `internal/monitoring/dashboard_contract_test.go`
- **RtPxdoListBuckets()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **RtPxnewHandler()** (8 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **stack** (8 connections) — `test/integration/s3enc/helpers_test.go`
- **setupTestHandler()** (7 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **readAllSized()** (7 connections) — `internal/proxy/request/parser.go`
- **aesVecProvider()** (7 connections) — `pkg/encryption/keyencryption/aes_vector_test.go`
- **s3cmd/scenarios_upload_test.go** (7 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **testRobustS3Authentication()** (7 connections) — `test/integration/authentication/auth_test.go`
- **SimpleTestContext** (5 connections) — `test/integration/authentication/auth_test.go`
- **TestRtPxListBucketsClientDisconnect()** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **TestKekAESNewProviderFromConfigMap()** (5 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **NewExitProvider()** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- *... and 157 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (172 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (90 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (83 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (64 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (60 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (58 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (54 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (50 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (50 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (45 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (43 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (42 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`
- `internal/config/accessors_coverage_test.go`
- `internal/config/config_test.go`
- `internal/config/default_config_test.go`
- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`
- `internal/config/optimizations_test.go`
- `internal/config/validation_coverage_test.go`
- `internal/monitoring/dashboard_contract_test.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/handlers/bucket/cors_test.go`
- `internal/proxy/handlers/bucket/location_test.go`
- `internal/proxy/handlers/bucket/logging_test.go`
- `internal/proxy/handlers/bucket/policy_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`

## Audit Trail

- EXTRACTED: 1871 (96%)
- INFERRED: 75 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*