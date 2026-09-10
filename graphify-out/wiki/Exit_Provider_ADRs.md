# Exit Provider ADRs

> 24 nodes · cohesion 0.11

## Key Concepts

- **ADR 0017: Stored Data Compatibility Is Not Owed** (23 connections) — `docs/adr/README.md`
- **The exit provider (D1)** (14 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **ADR 0025: Leaving Is a Supported Mode** (7 connections) — `docs/adr/README.md`
- **The read decision is per object, not per provider (D5)** (4 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **The GET path** (4 connections) — `docs/developer/request-paths.md`
- **Backward-compatibility code is deleted, not carried (D9)** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **A removed configuration key is removed, silently (D7)** (3 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **The exit provider passes through on every write branch** (3 connections) — `docs/developer/request-paths.md`
- **The four metadata keys that mark an object as ours** (3 connections) — `docs/developer/storage-format.md`
- **An unworkable configuration value refuses startup (D8)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **No compatibility is owed for data at rest (D1)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **There is no migration: re-upload from source (D3)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Stated precondition and the read-only fallback (D2)** (2 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Both candidate paths are measured, the loser deleted (D2)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **The exit provider holds no key material (D6)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **The exit provider requires no license (D2)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **No fingerprint is special-cased on the read path (D7)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **The pass-through unwrap was a forgery oracle** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **On read the exit provider still decrypts (D4)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **type: none is refused by name (D9)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **On write the exit provider stores what the client sent (D3)** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Under the exit provider there is no session at all** (2 connections) — `docs/developer/multipart.md`
- **One major release costs one migration (D10)** (1 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **An active exit provider warns at every start (D10)** (1 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (12 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (8 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (7 shared connections)
- [Test Strategy Docs](Test_Strategy_Docs.md) (3 shared connections)
- [Ticket Lifecycle ADR](Ticket_Lifecycle_ADR.md) (1 shared connections)
- [Performance Measurement Docs](Performance_Measurement_Docs.md) (1 shared connections)

## Source Files

- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/README.md`
- `docs/developer/multipart.md`
- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 58 (94%)
- INFERRED: 4 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*