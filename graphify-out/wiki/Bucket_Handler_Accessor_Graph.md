# Bucket Handler Accessor Graph

> 20 nodes · cohesion 0.12

## Key Concepts

- **proxy.Server.setupRoutes** (30 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetACLHandler** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetTaggingHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetCopyHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/object.Handler.GetACLHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/object.Handler.GetTaggingHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/object.NewHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetLifecycleHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetNotificationHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetReplicationHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetWebsiteHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.NewHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/health.NewHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetAbortHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetCompleteHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetCreateHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetListHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.Handler.GetUploadHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/multipart.NewHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/root.NewHandler** (1 connections) — `docs/architecture/callgraph_proxy_layer.svg`

## Relationships

- [Bucket Sub-Resource Call Graph](Bucket_Sub-Resource_Call_Graph.md) (7 shared connections)
- [Proxy Layer Call Graph](Proxy_Layer_Call_Graph.md) (3 shared connections)
- [Bucket Location Handler Graph](Bucket_Location_Handler_Graph.md) (1 shared connections)
- [Middleware Constructor Graph](Middleware_Constructor_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`

## Audit Trail

- EXTRACTED: 29 (85%)
- INFERRED: 4 (12%)
- AMBIGUOUS: 1 (3%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*