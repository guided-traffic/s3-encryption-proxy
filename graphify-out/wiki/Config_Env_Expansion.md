# Config Env Expansion

> 65 nodes · cohesion 0.06

## Key Concepts

- **testing.T** (1273 connections)
- **envexpand_test.go** (18 connections) — `internal/config/envexpand_test.go`
- **expandConfigEnvVars()** (15 connections) — `internal/config/envexpand.go`
- **expandEnvVars()** (11 connections) — `internal/config/envexpand.go`
- **cors_test.go** (6 connections) — `internal/proxy/handlers/bucket/cors_test.go`
- **bucket_cors_test.go** (6 connections) — `test/integration/s3-methods/bucket_cors_test.go`
- **bucket_logging_test.go** (6 connections) — `test/integration/s3-methods/bucket_logging_test.go`
- **accessors_coverage_test.go** (5 connections) — `internal/config/accessors_coverage_test.go`
- **bucket_location_test.go** (5 connections) — `test/integration/s3-methods/bucket_location_test.go`
- **TestCfgIsValidProviderType()** (3 connections) — `internal/config/accessors_coverage_test.go`
- **TestCfgExpandConfigEnvVarsErrorPerField()** (3 connections) — `internal/config/envexpand_coverage_test.go`
- **TestCfgExpandConfigEnvVarsExpandsEveryField()** (3 connections) — `internal/config/envexpand_coverage_test.go`
- **TestExpandConfigEnvVars_MissingProviderVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_MissingVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_MultipleClientsWithMixedRefs()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_NonStringProviderConfigSkipped()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_PlainValuesUnchanged()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_ProviderConfig()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_RSAProviderConfig()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_S3Backend()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_S3Clients()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_BareDoublareNotExpanded()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_EmptyString()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_EmptyVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_MultilineValue()** (3 connections) — `internal/config/envexpand_test.go`
- *... and 40 more nodes in this community*

## Relationships

- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (81 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (57 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (56 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (55 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (51 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (45 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (39 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (38 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (38 shared connections)
- [Provider Manager](Provider_Manager.md) (31 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (27 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (25 shared connections)

## Source Files

- `internal/config/accessors_coverage_test.go`
- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`
- `internal/config/optimizations_test.go`
- `internal/proxy/handlers/bucket/cors_test.go`
- `test/integration/s3-methods/bucket_cors_test.go`
- `test/integration/s3-methods/bucket_location_test.go`
- `test/integration/s3-methods/bucket_logging_test.go`
- `test/integration/s3-methods/bucket_subresource_test.go`

## Audit Trail

- EXTRACTED: 1329 (98%)
- INFERRED: 24 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*