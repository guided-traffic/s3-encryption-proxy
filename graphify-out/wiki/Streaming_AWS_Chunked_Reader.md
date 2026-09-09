# Streaming AWS Chunked Reader

> 5 nodes · cohesion 0.60

## Key Concepts

- **streamingAWSChunkedReader** (7 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **streaming_aws_decoder.go** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Read()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.consumeCRLF()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readChunkHeader()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`

## Relationships

- [Streaming AWS Chunked Decoder Tests](Streaming_AWS_Chunked_Decoder_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 11 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*