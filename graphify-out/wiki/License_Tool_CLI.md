# License Tool CLI

> 25 nodes · cohesion 0.18

## Key Concepts

- **main_coverage_test.go** (15 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTMainHappyPath()** (9 connections) — `cmd/license-tool/main_coverage_test.go`
- **license-tool/main.go** (7 connections) — `cmd/license-tool/main.go`
- **LicTkey()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTEndToEnd()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **generateJWT()** (7 connections) — `cmd/license-tool/main.go`
- **collectLicenseInfo()** (6 connections) — `cmd/license-tool/main.go`
- **main()** (6 connections) — `cmd/license-tool/main.go`
- **parseDuration()** (6 connections) — `cmd/license-tool/main.go`
- **LicTcaptureStdout()** (5 connections) — `cmd/license-tool/main_coverage_test.go`
- **LicTwithStdin()** (5 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTCollectLicenseInfo()** (5 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTLoadPrivateKey()** (5 connections) — `cmd/license-tool/main_coverage_test.go`
- **loadPrivateKey()** (5 connections) — `cmd/license-tool/main.go`
- **TestLicTGenerateJWT()** (4 connections) — `cmd/license-tool/main_coverage_test.go`
- **findRSAKeys()** (4 connections) — `cmd/license-tool/main.go`
- **LicenseClaims** (4 connections) — `cmd/license-tool/main.go`
- **LicTextractToken()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **LicTwritePEM()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTFindRSAKeys()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTGenerateJWTRefusesATokenWithoutAnExpiry()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTParseDuration()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTParseDurationAcceptsTrailingGarbage()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTParseDurationOverflowsSilently()** (3 connections) — `cmd/license-tool/main_coverage_test.go`
- **jwt.RegisteredClaims** (1 connections)

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (15 shared connections)
- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `cmd/license-tool/main.go`
- `cmd/license-tool/main_coverage_test.go`

## Audit Trail

- EXTRACTED: 61 (82%)
- INFERRED: 13 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*