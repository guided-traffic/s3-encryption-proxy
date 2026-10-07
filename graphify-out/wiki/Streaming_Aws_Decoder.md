# Streaming Aws Decoder

> 12 nodes · cohesion 0.23

## Key Concepts

- **streamingAWSChunkedReader** (10 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **Upload checksum verifier reader** (5 connections) — `docs/developer/request-paths.md`
- **streaming_aws_decoder.go** (4 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Read()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readChunkHeader()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readTrailers()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **CompleteMultipartUpload reads body unverified** (2 connections) — `docs/developer/request-paths.md`
- **Verifier holds the final payload byte until the verdict** (2 connections) — `docs/security/upload-integrity.md`
- **.consumeCRLF()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.recordTrailer()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **bufio.Reader** (1 connections)
- **.Trailers()** (1 connections) — `internal/proxy/request/streaming_aws_decoder.go`

## Relationships

- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (3 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (2 shared connections)
- [Checksum](Checksum.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `docs/security/upload-integrity.md`
- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 20 (87%)
- INFERRED: 3 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*