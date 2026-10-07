# Upload Length Guards and Exit Provider

> 13 nodes · cohesion 0.15

## Key Concepts

- **exit provider (leaving the product)** (12 connections) — `docs/security/key-management.md`
- **License expiry stops the proxy through the drain path** (6 connections) — `docs/security/operational-security.md`
- **parser.go** (5 connections) — `internal/proxy/request/parser.go`
- **ExitProvider** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **object/operations.go** (4 connections) — `internal/proxy/handlers/object/operations.go`
- **exit.go** (4 connections) — `pkg/encryption/keyencryption/exit.go`
- **fillPart()** (3 connections) — `internal/proxy/handlers/object/operations.go`
- **PUT routes on plaintext length, never wire length** (2 connections) — `docs/developer/request-paths.md`
- **Short-body guard (declared length check, only io.EOF ends a part)** (2 connections) — `docs/developer/request-paths.md`
- **.DecryptDEK()** (2 connections) — `pkg/encryption/keyencryption/exit.go`
- **.EncryptDEK()** (2 connections) — `pkg/encryption/keyencryption/exit.go`
- **.Fingerprint()** (1 connections) — `pkg/encryption/keyencryption/exit.go`
- **.Name()** (1 connections) — `pkg/encryption/keyencryption/exit.go`

## Relationships

- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (3 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (2 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)
- [Filename Encryption Design](Filename_Encryption_Design.md) (1 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [Multipart Complete Handler](Multipart_Complete_Handler.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (1 shared connections)
- [Main](Main.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `docs/security/key-management.md`
- `docs/security/operational-security.md`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/request/parser.go`
- `pkg/encryption/keyencryption/exit.go`

## Audit Trail

- EXTRACTED: 33 (89%)
- INFERRED: 4 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*