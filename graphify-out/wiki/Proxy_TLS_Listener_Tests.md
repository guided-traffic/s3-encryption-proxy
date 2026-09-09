# Proxy TLS Listener Tests

> 6 nodes · cohesion 0.53

## Key Concepts

- **proxy/tls_test.go** (5 connections) — `internal/proxy/tls_test.go`
- **generateTestCertificates()** (5 connections) — `internal/proxy/tls_test.go`
- **TestServerTLSConfiguration()** (4 connections) — `internal/proxy/tls_test.go`
- **TestServerTLSGracefulShutdown()** (4 connections) — `internal/proxy/tls_test.go`
- **TestTLSConfigurationLogging()** (4 connections) — `internal/proxy/tls_test.go`
- **TestServerTLSInvalidCertificates()** (3 connections) — `internal/proxy/tls_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (5 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (4 shared connections)

## Source Files

- `internal/proxy/tls_test.go`

## Audit Trail

- EXTRACTED: 13 (76%)
- INFERRED: 4 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*