# Orchestration Config Access Graph

> 20 nodes · cohesion 0.13

## Key Concepts

- **internal/orchestration.NewManager** (10 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.NewProviderManager** (6 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetActiveProviderAlias** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetLoadedProviders** (4 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/config.Config.GetAllProviders** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.GetProviderAliases** (3 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/config.Config.GetActiveProvider** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.Factory.CreateKeyEncryptorFromConfig** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.Factory.RegisterKeyEncryptor** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetActiveProviderAlias** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetLoadedProviders** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.Manager.GetProviderAliases** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/proxy.NewServer** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.ProviderManager.registerProvider** (2 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/config.Config.GetStreamingSegmentSize** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.Factory.GetRegisteredProviderInfo** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **pkg/encryption/factory.NewFactory** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/validation.NewHMACManager** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.NewMetadataManager** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`
- **internal/orchestration.NewMultipartOperations** (1 connections) — `docs/architecture/callgraph_orchestration_layer.svg`

## Relationships

- [Manager Accessor Graph](Manager_Accessor_Graph.md) (2 shared connections)
- [HMAC Decryption Call Graph](HMAC_Decryption_Call_Graph.md) (1 shared connections)
- [GCM Decryption Call Graph](GCM_Decryption_Call_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`

## Audit Trail

- EXTRACTED: 28 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*