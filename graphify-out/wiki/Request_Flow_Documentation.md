# Request Flow Documentation

> 9 nodes · cohesion 0.22

## Key Concepts

- **Exactly Four Metadata Keys** (4 connections) — `CLAUDE.md`
- **64 KiB-Multiple Part Rule** (4 connections) — `README.md`
- **Where the Failure Surfaces** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Client-Driven Multipart Session Flow** (2 connections) — `CLAUDE.md`
- **GET Request Data Flow** (2 connections) — `CLAUDE.md`
- **The Honest Gap: One Forward Pass, No Tail-First Read** (2 connections) — `CLAUDE.md`
- **PUT Request Data Flow** (2 connections) — `CLAUDE.md`
- **Session Expiry Drops Proxy State, Not the Backend Upload** (2 connections) — `README.md`
- **Multipart Session Sweeper Leak, Fixed** (2 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Security Architecture Docs](Security_Architecture_Docs.md) (2 shared connections)
- [Operator Documentation](Operator_Documentation.md) (2 shared connections)
- [Performance Baseline Suite](Performance_Baseline_Suite.md) (1 shared connections)
- [Dead Configuration Findings](Dead_Configuration_Findings.md) (1 shared connections)
- [CI and Helm Security](CI_and_Helm_Security.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`

## Audit Trail

- EXTRACTED: 11 (73%)
- INFERRED: 4 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*