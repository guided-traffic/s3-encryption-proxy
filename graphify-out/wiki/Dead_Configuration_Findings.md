# Dead Configuration Findings

> 9 nodes · cohesion 0.22

## Key Concepts

- **H-7 Dead Security Configuration Knobs — closed** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **Two Request Metrics Never Reach /metrics** (3 connections) — `README.md`
- **H-10 Three Configuration Decisions Specified and Not Built** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Integrity Is Not Configurable** (2 connections) — `CLAUDE.md`
- **Values Nothing Reads** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **H-5 A Tampered Object Is Delivered — closed** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **ListParts Still Pretends** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **Transport on Both Legs** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **SSL_CERT_FILE Points at the Test CA** (2 connections) — `test/e2e/velero/values-proxy.yaml`

## Relationships

- [Security Architecture Docs](Security_Architecture_Docs.md) (3 shared connections)
- [Documentation Conventions](Documentation_Conventions.md) (1 shared connections)
- [Ranged Read Hardening](Ranged_Read_Hardening.md) (1 shared connections)
- [Request Flow Documentation](Request_Flow_Documentation.md) (1 shared connections)
- [Velero E2E Environment](Velero_E2E_Environment.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `test/e2e/velero/values-proxy.yaml`

## Audit Trail

- EXTRACTED: 9 (60%)
- INFERRED: 6 (40%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*