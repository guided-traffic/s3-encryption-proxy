# AES Example

> 9 nodes · cohesion 0.22

## Key Concepts

- **config/aes-example.yaml (demo HTTP proxy configuration)** (5 connections) — `config/aes-example.yaml`
- **s3-encryption-proxy.validateReplicas** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Bounded data-key cache keyed by a digest of the wrapped key (D9)** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **pprof binds loopback only because the heap holds DEKs** (2 connections) — `config/aes-example.yaml`
- **config/aes-tls-example.yaml (TLS listener configuration)** (2 connections) — `config/aes-tls-example.yaml`
- **One instance only: a multipart upload lives in the process that created it** (2 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **All three write paths produce the identical byte layout (D11)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **multipart_part_size must be a whole number of segments; part 10000 reserved** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **The stale-key defect: a cache keyed by identity, not by content** (1 connections) — `docs/adr/0002-one-data-key-per-object.md`

## Relationships

- [Docker Compose Demo](Docker_Compose_Demo.md) (2 shared connections)
- [Conformance Paid](Conformance_Paid.md) (1 shared connections)
- [Deployment](Deployment.md) (1 shared connections)
- [Configmap](Configmap.md) (1 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (1 shared connections)

## Source Files

- `config/aes-example.yaml`
- `config/aes-tls-example.yaml`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`

## Audit Trail

- EXTRACTED: 10 (71%)
- INFERRED: 4 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*