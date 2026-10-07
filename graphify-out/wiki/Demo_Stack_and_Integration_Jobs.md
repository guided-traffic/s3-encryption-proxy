# Demo Stack and Integration Jobs

> 16 nodes · cohesion 0.13

## Key Concepts

- **Integration Tests job** (8 connections) — `.github/workflows/test-pipeline.yml`
- **Demo proxy service (container proxy, :8080)** (5 connections) — `docker-compose.demo.yml`
- **gen-keys.sh** (4 connections) — `scripts/gen-keys.sh`
- **Demo MinIO service (HTTPS, pgsty/minio)** (3 connections) — `docker-compose.demo.yml`
- **Performance summary and badge step** (2 connections) — `.github/workflows/test-pipeline.yml`
- **Demo TLS proxy service (container proxy-tls, :8443)** (2 connections) — `docker-compose.demo.yml`
- **Vault dev server (transit engine)** (2 connections) — `docker-compose.demo.yml`
- **ensure_var()** (2 connections) — `scripts/gen-keys.sh`
- **gen-keys.sh script** (2 connections) — `scripts/gen-keys.sh`
- **Velero e2e MinIO Deployment (HTTPS)** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **gen-certs.sh** (2 connections) — `test/ssl-setup/gen-certs.sh`
- **Proxy healthcheck sidecar** (1 connections) — `docker-compose.demo.yml`
- **S3 explorer through the proxy (encrypted-manager)** (1 connections) — `docker-compose.demo.yml`
- **generate_key()** (1 connections) — `scripts/gen-keys.sh`
- **minio-mkbucket Job (creates velero bucket)** (1 connections) — `test/e2e/velero/manifests/minio.yaml`
- **gen-certs.sh script** (1 connections) — `test/ssl-setup/gen-certs.sh`

## Relationships

- [CI Pipeline and Renovate Jobs](CI_Pipeline_and_Renovate_Jobs.md) (3 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (2 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (1 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)

## Source Files

- `.github/workflows/test-pipeline.yml`
- `docker-compose.demo.yml`
- `scripts/gen-keys.sh`
- `test/e2e/velero/manifests/minio.yaml`
- `test/ssl-setup/gen-certs.sh`

## Audit Trail

- EXTRACTED: 20 (87%)
- INFERRED: 3 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*