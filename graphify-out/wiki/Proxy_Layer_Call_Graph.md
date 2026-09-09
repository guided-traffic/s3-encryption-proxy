# Proxy Layer Call Graph

> 10 nodes · cohesion 0.22

## Key Concepts

- **proxy.NewServer** (6 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **cmd/s3-encryption-proxy.runProxy** (5 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **Proxy Layer Call Graph (gocallvis)** (4 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **cmd/s3-encryption-proxy.runProxy$5** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/health.Handler.SetShutdownStateHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.SetShutdownStateHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.Start** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **orchestration.Manager.GetLoadedProviders** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **orchestration.NewManager** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.Start$1** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`

## Relationships

- [Middleware Constructor Graph](Middleware_Constructor_Graph.md) (3 shared connections)
- [Bucket Handler Accessor Graph](Bucket_Handler_Accessor_Graph.md) (3 shared connections)

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`

## Audit Trail

- EXTRACTED: 12 (75%)
- INFERRED: 4 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*