# SigV4 Authentication Rules

> 40 nodes · cohesion 0.06

## Key Concepts

- **ADR 0014: Authentication is SigV4, no rate limiting** (38 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Request authentication: what is checked before a handler runs** (16 connections) — `docs/security/request-authentication.md`
- **Complete configuration key reference** (8 connections) — `README.md`
- **H-2 Per-chunk signatures are never verified** (7 connections) — `docs/security/request-authentication.md`
- **Client-leg checksum verification** (7 connections) — `docs/security/upload-integrity.md`
- **What is not verified (payload, chunk signatures, replay)** (6 connections) — `docs/security/request-authentication.md`
- **A key exists only if code reads it and the read changes behaviour** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **D8 pprof on its own loopback listener** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **D7 unworkable configuration refuses to start, never repaired** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Client-declared checksums verified, never forwarded** (4 connections) — `docs/operations/integrity.md`
- **SigV4 header and pre-signed forms** (4 connections) — `docs/security/request-authentication.md`
- **Trust boundary between proxy and backend** (4 connections) — `docs/security/threat-model.md`
- **config as one string rendered into the ConfigMap** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **D5 plain-HTTP backend refused under every provider** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **max_clock_skew_seconds governs both forms; 0 refused** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **No rate limiting and no per-address blocking** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **max_presign_expiry_seconds 3600 default, 604800 cap** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **max_request_document_size ceiling on whole-parsed documents** (3 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **pprof on its own loopback-only listener** (3 connections) — `docs/security/request-authentication.md`
- **Inert values (logging.*, monitoring ports)** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **SigV4 Payload Hash Verified When Enabled (D15)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **D9a aws-chunked decoding unconditional** (2 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Per-chunk aws-chunked signatures not verified** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Unsynchronised per-address failure map was a remote kill switch** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **SigV4 header and pre-signed forms, both first-class** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- *... and 15 more nodes in this community*

## Relationships

- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (16 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (13 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (12 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (6 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (5 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (4 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (3 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (2 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (2 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (1 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (1 shared connections)

## Source Files

- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/developer/testing.md`
- `docs/operations/clients/velero.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/security/request-authentication.md`
- `docs/security/threat-model.md`
- `docs/security/upload-integrity.md`

## Audit Trail

- EXTRACTED: 95 (84%)
- INFERRED: 18 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*