# Changelog: Configuration Refusals

> 6 nodes · cohesion 0.33

## Key Concepts

- **Removed keys: integrity_verification, streaming_threshold, clean_*_chunked, use_tls, legacy backend block** (4 connections) — `CHANGELOG.md`
- **Unknown configuration key refuses the start (ADR 0013 D11)** (4 connections) — `CHANGELOG.md`
- **Chart refuses Ingress without TLS and unconsumed Certificate** (3 connections) — `CHANGELOG.md`
- **Chart serviceTLS: TLS at the proxy's own Service (ADR 0026)** (2 connections) — `CHANGELOG.md`
- **Provider config block accepts only the keys its type reads** (2 connections) — `CHANGELOG.md`
- **rsa and tink provider types (removed)** (1 connections) — `CHANGELOG.md`

## Relationships

- [Request: Streaming Decoder Coverage Test](Request-_Streaming_Decoder_Coverage_Test.md) (3 shared connections)
- [Changelog: Providers And Licence](Changelog-_Providers_And_Licence.md) (1 shared connections)
- [Object: Range (2)](Object-_Range_2.md) (1 shared connections)
- [Changelog: Shutdown And Listener Budgets](Changelog-_Shutdown_And_Listener_Budgets.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`

## Audit Trail

- EXTRACTED: 11 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*