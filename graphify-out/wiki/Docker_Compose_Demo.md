# Docker Compose Demo

> 11 nodes · cohesion 0.24

## Key Concepts

- **s3-encryption-proxy service (container proxy, :8080)** (7 connections) — `docker-compose.demo.yml`
- **Combined Coverage job (unit + integration)** (4 connections) — `.github/workflows/test-pipeline.yml`
- **Demo Stack (docker compose)** (4 connections) — `docker-compose.demo.yml`
- **s3-encryption-proxy-tls service (container proxy-tls, :8443)** (4 connections) — `docker-compose.demo.yml`
- **minio service (HTTPS S3 backend)** (3 connections) — `docker-compose.demo.yml`
- **Integration Tests job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **GOCOVER instrumented proxy build and 45s stop grace** (2 connections) — `docker-compose.demo.yml`
- **Unit Tests job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **s3-explorer-encrypted (encrypted-manager, :8081)** (1 connections) — `docker-compose.demo.yml`
- **Only HTTPS reaches STREAMING-UNSIGNED-PAYLOAD-TRAILER framing** (1 connections) — `docker-compose.demo.yml`
- **vault dev server (no proxy code talks to it)** (1 connections) — `docker-compose.demo.yml`

## Relationships

- [AES Example](AES_Example.md) (2 shared connections)
- [Pipeline](Pipeline.md) (1 shared connections)
- [Values](Values.md) (1 shared connections)

## Source Files

- `.github/workflows/test-pipeline.yml`
- `docker-compose.demo.yml`

## Audit Trail

- EXTRACTED: 15 (88%)
- INFERRED: 2 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*