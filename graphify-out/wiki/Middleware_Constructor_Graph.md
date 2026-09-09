# Middleware Constructor Graph

> 8 nodes · cohesion 0.29

## Key Concepts

- **proxy.Server.setupMiddleware** (7 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/health.Handler.SetRequestTracker** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.SetRequestTracker** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/middleware.NewRequestTracker** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/middleware.RequestTracker.SetHandlers** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/middleware.NewCORS** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/middleware.NewLogger** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/middleware.NewS3AuthenticationService** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`

## Relationships

- [Proxy Layer Call Graph](Proxy_Layer_Call_Graph.md) (3 shared connections)
- [Bucket Handler Accessor Graph](Bucket_Handler_Accessor_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`

## Audit Trail

- EXTRACTED: 8 (67%)
- INFERRED: 4 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*