# CI and Helm Security

> 16 nodes · cohesion 0.13

## Key Concepts

- **S3 Encryption Proxy Helm Chart** (5 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Two-Layer Key Hierarchy** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **Production Values Profile** (4 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **KEK Fingerprint by HKDF Label** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **KEK Rotation by Fingerprint** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **Helm Chart Release to GitHub Pages** (3 connections) — `.github/workflows/push.yml`
- **S3EP_AES_KEY from an External Secret** (3 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **${VAR} Environment Variable References** (3 connections) — `README.md`
- **The Chart Does Not Roll Pods on a Config Change** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Docker Image Release Workflow** (2 connections) — `.github/workflows/push.yml`
- **A Configuration Change Does Not Restart Pods** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **nginx Body Buffering Turned Off** (2 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **A Published Chart Default That Was a Working Key** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **Plain Push to gh-pages** (1 connections) — `.github/workflows/push.yml`
- **SBOM, Provenance and Docker Scout Scan** (1 connections) — `.github/workflows/push.yml`
- **H-8 The KEK Fingerprint Was a Plain Hash of the Key — closed** (1 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Operator Documentation](Operator_Documentation.md) (6 shared connections)
- [Security Architecture Docs](Security_Architecture_Docs.md) (3 shared connections)
- [Documentation Conventions](Documentation_Conventions.md) (1 shared connections)
- [Performance Baseline Suite](Performance_Baseline_Suite.md) (1 shared connections)
- [Secret Exposure Surface](Secret_Exposure_Surface.md) (1 shared connections)
- [Request Flow Documentation](Request_Flow_Documentation.md) (1 shared connections)

## Source Files

- `.github/workflows/push.yml`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`

## Audit Trail

- EXTRACTED: 20 (69%)
- INFERRED: 9 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*