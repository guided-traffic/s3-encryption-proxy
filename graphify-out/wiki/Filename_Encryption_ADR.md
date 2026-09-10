# Filename Encryption ADR

> 16 nodes · cohesion 0.17

## Key Concepts

- **Filename encryption (encryption.filename_encryption, off by default)** (13 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **S3EP_AES_KEY is the one name for the local key (D3)** (4 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **AES-SIV-CMAC (RFC 5297) with parent-chain associated data (D4)** (4 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **The transform is applied at exactly one boundary (D8)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **The transform is deterministic, keyed and stateless (D3)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **One 64-byte name key per deployment, wrapped by the KEK (D6)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Enabling on a populated bucket is a rename pass (D14)** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Local key material is generated on demand (D2)** (2 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **Only directory segments are encrypted, the leaf stays clear (D2)** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **A listing prefix is split, the trailing partial leaf passes through (D9)** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Names that do not decrypt are dropped, not failed (D11)** (2 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Backend order is returned, never re-sorted (D12)** (1 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Segment ciphertext is base64url without padding (D5)** (1 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Rejected: a mapping index stored in the bucket** (1 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **The names subcommand: wrap, map, unmap (D16)** (1 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Object key names are the one unprotected part of a stored object** (1 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`

## Relationships

- [Key Management ADRs](Key_Management_ADRs.md) (2 shared connections)
- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (2 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (2 shared connections)

## Source Files

- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`

## Audit Trail

- EXTRACTED: 24 (92%)
- INFERRED: 2 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*