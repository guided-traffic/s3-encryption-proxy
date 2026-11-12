# Backend HTTP Client TLS

> 6 nodes · cohesion 0.33

## Key Concepts

- **backendHTTPClient()** (6 connections) — `internal/proxy/server.go`
- **ca_file per Backend Entry** (3 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **TestBackendHTTPClient_SkipVerifyKeepsEverythingElse()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendHTTPClient_VerifiesByDefault()** (3 connections) — `internal/proxy/backend_client_test.go`
- **SSL_CERT_FILE / SSL_CERT_DIR Root Loading** (1 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **github.com/aws/aws-sdk-go-v2/aws/transport/http.BuildableClient** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (1 shared connections)

## Source Files

- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 9 (75%)
- INFERRED: 3 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*