# Security Architecture Docs

> 17 nodes · cohesion 0.15

## Key Concepts

- **Storage Format s3ep-gcm-seg-v2** (11 connections) — `README.md`
- **KEK/DEK Envelope Architecture** (6 connections) — `CLAUDE.md`
- **The S3 Backend Is Hostile** (6 connections) — `SECURITY_ARCHITECTURE.md`
- **The Three Rules** (6 connections) — `SECURITY_ARCHITECTURE.md`
- **Sizes and Listings Describe the Plaintext** (5 connections) — `README.md`
- **Backend Privilege Footprint** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **No Request Rate Limiting** (3 connections) — `README.md`
- **Operations the Proxy Does Not Implement** (3 connections) — `README.md`
- **No Multi-Tenancy** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Handlers That Refuse Rather Than Pretend** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Roles and Trust Boundaries** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **HeadBucket Through the Proxy Answers 200 for a Missing Bucket** (3 connections) — `test/perf/README.md`
- **Annotated Repository Layout** (2 connections) — `CONTRIBUTING.md`
- **HeadBucket Region Is the Proxy's Statement** (2 connections) — `README.md`
- **Listing Parameter Behaviour** (2 connections) — `README.md`
- **What the Backend Learns Anyway** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **H-3 Rollback and Object Substitution Are Not Prevented** (2 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Operator Documentation](Operator_Documentation.md) (6 shared connections)
- [Dead Configuration Findings](Dead_Configuration_Findings.md) (3 shared connections)
- [Documentation Conventions](Documentation_Conventions.md) (3 shared connections)
- [Performance Baseline Suite](Performance_Baseline_Suite.md) (3 shared connections)
- [CI and Helm Security](CI_and_Helm_Security.md) (3 shared connections)
- [Request Flow Documentation](Request_Flow_Documentation.md) (2 shared connections)
- [Ranged Read Hardening](Ranged_Read_Hardening.md) (2 shared connections)
- [Secret Exposure Surface](Secret_Exposure_Surface.md) (2 shared connections)

## Source Files

- `CLAUDE.md`
- `CONTRIBUTING.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `test/perf/README.md`

## Audit Trail

- EXTRACTED: 33 (73%)
- INFERRED: 11 (24%)
- AMBIGUOUS: 1 (2%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*