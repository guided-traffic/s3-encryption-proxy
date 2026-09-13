# AWS-Chunked Decoder

> 5 nodes · cohesion 0.60

## Key Concepts

- **streamingAWSChunkedReader** (7 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Read()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.consumeCRLF()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readChunkHeader()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **bufio.Reader** (1 connections)

## Relationships

- [Multipart Handler](Multipart_Handler.md) (1 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*