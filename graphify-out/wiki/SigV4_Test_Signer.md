# SigV4 Test Signer

> 18 nodes · cohesion 0.22

## Key Concepts

- **time.Time** (20 connections)
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **Handler** (8 connections) — `internal/proxy/handlers/health/handler.go`
- **.SignRequest()** (8 connections) — `test/integration/s3_signing_helper.go`
- **SignHTTPRequestForS3()** (6 connections) — `test/integration/s3_signing_helper.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **s3_signing_helper.go** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalHeaders()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalQueryString()** (3 connections) — `test/integration/s3_signing_helper.go`
- **NewAWSV4Signer()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **.hmacSHA256()** (2 connections) — `test/integration/s3_signing_helper.go`
- **health/handler.go** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **.SetRequestTracker()** (1 connections) — `internal/proxy/handlers/health/handler.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (4 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (2 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (2 shared connections)
- [Health Handler Tests](Health_Handler_Tests.md) (2 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (2 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [License Claim Checks](License_Claim_Checks.md) (1 shared connections)
- [SigV4 Auth Service Tests](SigV4_Auth_Service_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 61 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*