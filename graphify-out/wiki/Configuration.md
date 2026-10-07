# Configuration

> 21 nodes · cohesion 0.10

## Key Concepts

- **Upgrading from 3.x or 4.x to 5.x** (8 connections) — `docs/operations/upgrading.md`
- **config/default.yaml (the image's own configuration)** (4 connections) — `docs/operations/configuration.md`
- **optimizations.multipart_part_size** (3 connections) — `docs/operations/configuration.md`
- **An undefined configuration key refuses the start** (3 connections) — `docs/operations/configuration.md`
- **Three write paths produce identical bytes** (3 connections) — `docs/operations/s3-api.md`
- **S3EP_AES_KEY** (2 connections) — `docs/operations/configuration.md`
- **S3EP_BACKEND_ENDPOINT** (2 connections) — `docs/operations/configuration.md`
- **S3EP_LICENSE_TOKEN** (2 connections) — `docs/operations/configuration.md`
- **One instance per release; the chart refuses a second** (2 connections) — `docs/operations/deployment.md`
- **The license reaches the proxy two ways only** (2 connections) — `docs/operations/upgrading.md`
- **Removed configuration keys now refuse the start** (2 connections) — `docs/operations/upgrading.md`
- **streaming_segment_size became multipart_part_size** (2 connections) — `docs/operations/upgrading.md`
- **${VAR} environment reference mechanism** (1 connections) — `docs/operations/configuration.md`
- **The key reference has one home (README)** (1 connections) — `docs/operations/configuration.md`
- **Keep the key encryption key** (1 connections) — `docs/operations/deployment.md`
- **HeadBucket answers x-amz-bucket-region** (1 connections) — `docs/operations/s3-api.md`
- **Versioned buckets: versionId forwarding** (1 connections) — `docs/operations/s3-api.md`
- **aes_key is base64 of exactly 32 random bytes** (1 connections) — `docs/operations/upgrading.md`
- **type: "none" is gone; the provider is now exit** (1 connections) — `docs/operations/upgrading.md`
- **type: "rsa" is gone with its PEM keys** (1 connections) — `docs/operations/upgrading.md`
- **s3_backend became the list s3_backends** (1 connections) — `docs/operations/upgrading.md`

## Relationships

- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Conformance Run](Conformance_Run.md) (1 shared connections)
- [Monitoring](Monitoring.md) (1 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (1 shared connections)

## Source Files

- `docs/operations/configuration.md`
- `docs/operations/deployment.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`

## Audit Trail

- EXTRACTED: 22 (92%)
- INFERRED: 2 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*