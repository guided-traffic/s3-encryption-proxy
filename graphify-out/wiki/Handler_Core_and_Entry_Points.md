# Handler Core and Entry Points

> 402 nodes · cohesion 0.06

## Key Concepts

- **go_pkg_testing** (191 connections)
- **go_pkg_net_http** (153 connections)
- **go_pkg_github_com_stretchr_testify_require** (148 connections)
- **router.go** (137 connections) — `internal/proxy/router.go`
- **go_pkg_github_com_stretchr_testify_assert** (135 connections)
- **go_pkg_strings** (123 connections)
- **go_pkg_github_com_aws_aws_sdk_go_v2_aws** (120 connections)
- **go_pkg_github_com_aws_aws_sdk_go_v2_service_s3** (120 connections)
- **checksum_test.go** (114 connections) — `internal/proxy/request/checksum_test.go`
- **object_test.go** (113 connections) — `internal/proxy/handlers/object/object_test.go`
- **go_pkg_fmt** (111 connections)
- **go_pkg_context** (110 connections)
- **go_pkg_time** (104 connections)
- **multipart_test.go** (102 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **config.go** (100 connections) — `internal/config/config.go`
- **go_pkg_github_com_sirupsen_logrus** (97 connections)
- **go_pkg_io** (97 connections)
- **operations_coverage_test.go** (96 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **complete.go** (94 connections) — `internal/proxy/handlers/multipart/complete.go`
- **go_pkg_bytes** (92 connections)
- **helpers.go** (86 connections) — `internal/proxy/handlers/object/helpers.go`
- **parser_test.go** (84 connections) — `internal/proxy/request/parser_test.go`
- **providers_coverage_test.go** (82 connections) — `internal/orchestration/providers_coverage_test.go`
- **errors_coverage_test.go** (79 connections) — `internal/proxy/response/errors_coverage_test.go`
- **go_pkg_errors** (75 connections)
- *... and 377 more nodes in this community*

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (172 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (130 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (97 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (91 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (86 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (79 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (69 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (68 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (62 shared connections)
- [Configuration Loading](Configuration_Loading.md) (58 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (57 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (54 shared connections)

## Source Files

- `cmd/keygen/main.go`
- `cmd/keygen/main_test.go`
- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`
- `docs/developer/storage-format.md`
- `docs/developer/testing.md`
- `docs/security/key-management.md`
- `docs/security/refusals.md`
- `docs/security/tenancy-and-privilege.md`
- `docs/security/threat-model.md`
- `docs/tickets/036-high-availability.md`
- `internal/config/accessors_coverage_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/default_config_test.go`
- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`
- `internal/config/optimizations_test.go`
- `internal/config/tls_test.go`

## Audit Trail

- EXTRACTED: 6986 (100%)
- INFERRED: 8 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*