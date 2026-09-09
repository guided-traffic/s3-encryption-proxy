# Envelope Encryption Architecture

> 19 nodes · cohesion 0.15

## Key Concepts

- **Provider comparison: RSA, AES, None** (6 connections) — `README.md`
- **Envelope encryption: KEK and DEK layers** (5 connections) — `CLAUDE.md`
- **Key hierarchy: KEK, DEK, object bytes, HMAC key** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **The six s3ep-* metadata keys** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **KEK providers: aes, rsa, none, tink** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **KEK rotation by fingerprint** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **s3ep-* metadata keys** (3 connections) — `CLAUDE.md`
- **Tink provider is an unreachable stub** (3 connections) — `CLAUDE.md`
- **aes-envelope provider (config/aes-example.yaml)** (3 connections) — `config/aes-example.yaml`
- **rsa-envelope provider config (config/rsa-example.yaml)** (3 connections) — `config/rsa-example.yaml`
- **${VAR} environment variable references** (3 connections) — `README.md`
- **H-8 The AES KEK fingerprint is a plain hash of the key** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **Multi-provider config (aes-current plus rsa-backup)** (2 connections) — `config/multi-example.yaml`
- **none provider config (config/none-example.yaml)** (2 connections) — `config/none-example.yaml`
- **Architecture and security section (stale)** (2 connections) — `CONTRIBUTING.md`
- **Complete configuration reference** (2 connections) — `README.md`
- **Fix: a client can no longer write into the proxy metadata namespace** (1 connections) — `CHANGELOG.md`
- **Start with the knowledge graph (graphify)** (1 connections) — `CLAUDE.md`
- **A published chart default that was a working key** (1 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Integrity Modes and Flows](Integrity_Modes_and_Flows.md) (4 shared connections)
- [Dead Configuration Keys](Dead_Configuration_Keys.md) (2 shared connections)
- [Breaking Change Guard](Breaking_Change_Guard.md) (2 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `config/aes-example.yaml`
- `config/multi-example.yaml`
- `config/none-example.yaml`
- `config/rsa-example.yaml`

## Audit Trail

- EXTRACTED: 19 (58%)
- INFERRED: 14 (42%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*