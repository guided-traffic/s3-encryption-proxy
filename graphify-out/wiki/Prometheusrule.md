# Prometheusrule

> 9 nodes · cohesion 0.22

## Key Concepts

- **prometheusrule.yaml** (7 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **Alert S3EPObjectIntegrityFailure** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **s3ep_object_integrity_failures_total, labelled by reason and phase (D15)** (2 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Every rule tells a human; nothing in the platform acts on one** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **Alert S3EPBackendTransportFailing (share, not count)** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **Alert S3EPLicenseExpired** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **Alert S3EPLicenseExpiringSoon** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- **helm-unittest suite: alerting rules** (1 connections) — `deploy/helm/s3-encryption-proxy/tests/prometheusrule_test.yaml`
- **monitoring.prometheusRule thresholds and windows** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`

## Relationships

- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (1 shared connections)

## Source Files

- `deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml`
- `deploy/helm/s3-encryption-proxy/tests/prometheusrule_test.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*