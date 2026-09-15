# Streaming Aws Decoder

> 9 nodes · cohesion 0.33

## Key Concepts

- **streamingAWSChunkedReader** (10 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **streaming_aws_decoder.go** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Read()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readChunkHeader()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readTrailers()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.consumeCRLF()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.recordTrailer()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **bufio.Reader** (1 connections)
- **.Trailers()** (1 connections) — `internal/proxy/request/streaming_aws_decoder.go`

## Relationships

- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (2 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 16 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*