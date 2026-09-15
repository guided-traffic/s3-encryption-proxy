# Configuration

> 18 nodes · cohesion 0.11

## Key Concepts

- **Upgrading from 3.x or 4.x to 5.x** (8 connections) — `docs/operations/upgrading.md`
- **config/default.yaml (the image's own configuration)** (4 connections) — `docs/operations/configuration.md`
- **optimizations.multipart_part_size** (3 connections) — `docs/operations/configuration.md`
- **Three write paths produce identical bytes** (3 connections) — `docs/operations/s3-api.md`
- **H-8 The AES KEK fingerprint is a plain hash of the key** (3 connections) — `docs/security/hardening-history.md`
- **S3EP_AES_KEY** (2 connections) — `docs/operations/configuration.md`
- **S3EP_BACKEND_ENDPOINT** (2 connections) — `docs/operations/configuration.md`
- **S3EP_LICENSE_TOKEN** (2 connections) — `docs/operations/configuration.md`
- **One instance per release; the chart refuses a second** (2 connections) — `docs/operations/deployment.md`
- **aes_key is base64 of exactly 32 random bytes** (2 connections) — `docs/operations/upgrading.md`
- **The license reaches the proxy two ways only** (2 connections) — `docs/operations/upgrading.md`
- **streaming_segment_size became multipart_part_size** (2 connections) — `docs/operations/upgrading.md`
- **${VAR} environment reference mechanism** (1 connections) — `docs/operations/configuration.md`
- **Keep the key encryption key** (1 connections) — `docs/operations/deployment.md`
- **HeadBucket answers x-amz-bucket-region** (1 connections) — `docs/operations/s3-api.md`
- **Versioned buckets: versionId forwarding** (1 connections) — `docs/operations/s3-api.md`
- **type: "rsa" is gone with its PEM keys** (1 connections) — `docs/operations/upgrading.md`
- **s3_backend became the list s3_backends** (1 connections) — `docs/operations/upgrading.md`

## Relationships

- [Hardening History](Hardening_History.md) (3 shared connections)
- [Integrity](Integrity.md) (2 shared connections)
- [Monitoring](Monitoring.md) (1 shared connections)
- [Conformance Run](Conformance_Run.md) (1 shared connections)

## Source Files

- `docs/operations/configuration.md`
- `docs/operations/deployment.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`
- `docs/security/hardening-history.md`

## Audit Trail

- EXTRACTED: 22 (92%)
- INFERRED: 2 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*