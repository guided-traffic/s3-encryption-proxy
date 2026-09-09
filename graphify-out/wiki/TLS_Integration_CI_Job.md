# TLS Integration CI Job

> 11 nodes · cohesion 0.20

## Key Concepts

- **Integration Tests job** (4 connections) — `.github/workflows/release.yml`
- **H-2 Per-chunk signatures are never verified** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **TLS listener example (config/aes-tls-example.yaml)** (3 connections) — `config/aes-tls-example.yaml`
- **SigV4 validation, header and pre-signed forms** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **TLS integration run (checksum-trailer framing)** (2 connections) — `.github/workflows/release.yml`
- **Pre-signed URL support** (2 connections) — `README.md`
- **Clock skew comes from two different places** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **The payload is not authenticated** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **Performance tests run in isolation** (1 connections) — `.github/workflows/release.yml`
- **aes-envelope provider over TLS (config/aes-tls-example.yaml)** (1 connections) — `config/aes-tls-example.yaml`
- **Client checksums are dropped, never forwarded** (1 connections) — `README.md`

## Relationships

- [Release Workflow Jobs](Release_Workflow_Jobs.md) (1 shared connections)
- [Combined Coverage CI Job](Combined_Coverage_CI_Job.md) (1 shared connections)
- [Integrity Modes and Flows](Integrity_Modes_and_Flows.md) (1 shared connections)

## Source Files

- `.github/workflows/release.yml`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `config/aes-tls-example.yaml`

## Audit Trail

- EXTRACTED: 8 (57%)
- INFERRED: 6 (43%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*