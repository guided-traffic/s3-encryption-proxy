# Architecture Analysis Findings

> 16 nodes · cohesion 0.21

## Key Concepts

- **Architecture Analysis and Optimization Potential** (11 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Quick-Wins Program (about 1400 lines removable)** (6 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **BaseSubResourceHandler Embedding Proposal** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Dead Code: internal/proxy/bucket_handlers.go** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Double Initialization of location/logging Sub-Handlers** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Double Query-Parameter Routing (router.go plus bucket/handler.go)** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Duplicated Bucket Sub-Handler Structs (13 identical shapes)** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Long-Term Refactoring Proposals** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **orchestration.Manager as God Object** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Manager Split into Coordinator, SinglePartEncryptor and StreamingIO** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **MetadataManager Redundant and Unused Methods** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **ProviderManager Duplicate Methods (ClearKeyCache/ClearCache)** (3 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Interface Segregation Proposal (BucketReader, ObjectOperator, MultipartOperator)** (2 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Monolithic S3BackendInterface** (2 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **go-callvis Call Graph Artifacts** (1 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **Package Line Census (78 files, 18464 lines without tests)** (1 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`

## Relationships

- [Baseline Allocation Profile](Baseline_Allocation_Profile.md) (1 shared connections)
- [Baseline Object Allocation Profile](Baseline_Object_Allocation_Profile.md) (1 shared connections)
- [Streaming Throughput Ticket](Streaming_Throughput_Ticket.md) (1 shared connections)

## Source Files

- `docs/architecture/ARCHITECTURE_ANALYSIS.md`

## Audit Trail

- EXTRACTED: 24 (86%)
- INFERRED: 4 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*