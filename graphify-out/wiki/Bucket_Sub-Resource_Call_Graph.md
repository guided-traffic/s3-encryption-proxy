# Bucket Sub-Resource Call Graph

> 15 nodes · cohesion 0.16

## Key Concepts

- **proxy/utils.HandleS3Error** (8 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy/utils.ReadRequestBody** (4 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketACL** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketCORS** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketLogging** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketPolicy** (3 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetAccelerateHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetCORSHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetLoggingHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetPolicyHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetRequestPaymentHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **handlers/bucket.Handler.GetVersioningHandler** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketAccelerate** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketRequestPayment** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **proxy.Server.handleBucketVersioning** (2 connections) — `docs/architecture/callgraph_proxy_layer.svg`

## Relationships

- [Bucket Handler Accessor Graph](Bucket_Handler_Accessor_Graph.md) (7 shared connections)
- [Bucket Location Handler Graph](Bucket_Location_Handler_Graph.md) (1 shared connections)

## Source Files

- `docs/architecture/callgraph_proxy_layer.svg`

## Audit Trail

- EXTRACTED: 18 (72%)
- INFERRED: 7 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*