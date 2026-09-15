# Conformance Paid

> 6 nodes · cohesion 0.33

## Key Concepts

- **Conformance (paid backends) job** (3 connections) — `.github/workflows/conformance-paid.yml`
- **S3EP_AES_KEY supplied from generated .env, no key tracked** (3 connections) — `docker-compose.demo.yml`
- **Secrets read through env, never interpolated into script text** (2 connections) — `.github/workflows/conformance-paid.yml`
- **Conformance (minio, localstack) job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **S3EP_AES_KEY injected from a chart or external Secret** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Billed backends run on a schedule, never on push or pull_request** (1 connections) — `.github/workflows/conformance-paid.yml`

## Relationships

- [Pipeline](Pipeline.md) (1 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (1 shared connections)
- [AES Example](AES_Example.md) (1 shared connections)

## Source Files

- `.github/workflows/conformance-paid.yml`
- `.github/workflows/test-pipeline.yml`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `docker-compose.demo.yml`

## Audit Trail

- EXTRACTED: 5 (62%)
- INFERRED: 3 (38%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*