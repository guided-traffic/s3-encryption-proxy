# GetObjectTorrent Backend Method

> 6 nodes · cohesion 0.53

## Key Concepts

- **.GetObjectTorrent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectTorrentInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectTorrentOutput** (4 connections)
- **.GetObjectTorrent()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObjectTorrent()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObjectTorrent()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (4 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (4 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 16 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*