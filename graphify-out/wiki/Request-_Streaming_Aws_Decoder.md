# Request: Streaming Aws Decoder

> 8 nodes · cohesion 0.39

## Key Concepts

- **streamingAWSChunkedReader** (10 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readTrailers()** (4 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.Read()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.readChunkHeader()** (3 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.consumeCRLF()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **.recordTrailer()** (2 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **bufio.Reader** (1 connections)
- **.Trailers()** (1 connections) — `internal/proxy/request/streaming_aws_decoder.go`

## Relationships

- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Request: Streaming Decoder Coverage Test](Request-_Streaming_Decoder_Coverage_Test.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`

## Audit Trail

- EXTRACTED: 11 (73%)
- INFERRED: 4 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*