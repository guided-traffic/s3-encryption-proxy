# Configuration Loading and Validation

> 167 nodes · cohesion 0.03

## Key Concepts

- **Load()** (33 connections) — `internal/config/config.go`
- **config.go** (29 connections) — `internal/config/config.go`
- **setDefaults()** (26 connections) — `internal/config/config.go`
- **loading_coverage_test.go** (26 connections) — `internal/config/loading_coverage_test.go`
- **CfgResetViper()** (26 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (20 connections) — `internal/config/config.go`
- **envexpand_test.go** (18 connections) — `internal/config/envexpand_test.go`
- **expandConfigEnvVars()** (16 connections) — `internal/config/envexpand.go`
- **config_test.go** (16 connections) — `internal/config/config_test.go`
- **validation_coverage_test.go** (14 connections) — `internal/config/validation_coverage_test.go`
- **.Reset()** (13 connections) — `internal/validation/hmac_calculator.go`
- **expandEnvVars()** (12 connections) — `internal/config/envexpand.go`
- **CfgNoLicense()** (12 connections) — `internal/config/loading_coverage_test.go`
- **CfgWriteConfigFile()** (12 connections) — `internal/config/loading_coverage_test.go`
- **Config** (11 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (11 connections) — `internal/config/config.go`
- **validateEncryption()** (11 connections) — `internal/config/config.go`
- **.Validate()** (11 connections) — `pkg/encryption/keyencryption/tink.go`
- **CfgNoneProviderConfig()** (11 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgMetadataKeyPrefix()** (10 connections) — `internal/config/loading_coverage_test.go`
- **Tier 2 proxy CPU profile (top 20)** (10 connections) — `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- **loadProviderConfigs()** (9 connections) — `internal/config/config.go`
- **accessors_coverage_test.go** (9 connections) — `internal/config/accessors_coverage_test.go`
- **TestCfgValidateMonitoringPprofBindAddress()** (9 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgLoadAndStartLicenseWithoutLicense()** (8 connections) — `internal/config/loading_coverage_test.go`
- *... and 142 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption-modes/none_provider_test.go`
- `docs/architecture/callgraph_orchestration_layer.svg`
- `docs/tickets/010-tier2/proxy-cpu-top20.txt`
- `docs/tickets/010-tier4.1/cpu-top20.txt`
- `docs/tickets/010-tier4.1/proxy-cpu-top20.txt`
- `internal/config/accessors_coverage_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`
- `internal/config/integrity_verification_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`
- `internal/config/validation_coverage_test.go`
- `internal/monitoring/pprof.go`
- `internal/orchestration/streaming_io.go`
- `internal/validation/hmac_calculator.go`
- `pkg/encryption/dataencryption/aes_ctr.go`
- `pkg/encryption/keyencryption/tink.go`

## Audit Trail

- EXTRACTED: 494 (56%)
- INFERRED: 387 (44%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*