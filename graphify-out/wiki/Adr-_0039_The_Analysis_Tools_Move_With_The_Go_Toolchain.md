# Adr: 0039 The Analysis Tools Move With The Go Toolchain

> 20 nodes · cohesion 0.11

## Key Concepts

- **Separate Go module pinning the analysis tools** (6 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Committed red test blocks the release gate** (5 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Entity tag as opaque change token** (5 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **Test asserts target behaviour, never current behaviour** (3 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **docs/security as one page per perspective** (3 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **Renovate 'Go toolchain' group** (3 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Behaviour an ADR decides is the target** (2 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Enforced known-failure manifest (rejected alternative)** (2 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **H-<n> open-gap identifier beside its mechanism** (2 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **Go 1.27.2 export data version 5 incompatibility** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **golang.org/x/tools required at newest release** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **Go toolchain PR stays red until the tool release exists** (2 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **No emergency release path past red gates** (1 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Red test names its rule and record; suite reports what is still broken** (1 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **Sealed plaintext MD5 digest refused** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **x-amz-checksum-crc32c (proxy-sealed plaintext CRC32C)** (1 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **SECURITY.md vulnerability reporting policy** (1 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **golangci-lint** (1 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **gosec** (1 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`
- **govulncheck** (1 connections) — `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (2 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (2 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)

## Source Files

- `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- `docs/adr/0039-the-analysis-tools-move-with-the-go-toolchain.md`

## Audit Trail

- EXTRACTED: 22 (88%)
- INFERRED: 3 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*