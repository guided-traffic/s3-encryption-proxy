# Package map

Where things live, and what each package is responsible for. One line per file
where the file's name does not already say it.

## Entry points

| Path | Responsibility |
|---|---|
| `cmd/s3-encryption-proxy/` | The binary: config load, license gate, server lifecycle, graceful shutdown |
| `cmd/keygen/` | Generates an AES-256 key. Built as `build/s3ep-keygen` |
| `cmd/license-tool/` | Generates a license JWT. Needs a key pair that is not in the repository |

## `pkg/encryption/` — crypto primitives, no business logic

| Path | Responsibility |
|---|---|
| `dataencryption/segmented_gcm.go` | The storage format: constants, the AAD builder, the trailer, the size functions, the CRC32C fold |
| `dataencryption/segmented_gcm_io.go` | Sealing writer and sequential opening reader |
| `dataencryption/segmented_gcm_range.go` | The window planner and the ranged reader |
| `keyencryption/aes.go` | The one key provider that encrypts: HKDF-SHA256 derivation, the authenticated DEK wrap, the fingerprint |
| `keyencryption/none.go` | Pass-through |
| `keyencryption/tink.go` | A stub. Config validation refuses `type: tink`, so nothing reaches it |
| `factory/` | Builds a key encryptor from configuration, and is the registry that maps a fingerprint back to its provider |

`dataencryption/aes_ctr.go`, `dataencryption/aes_gcm.go` and `envelope/` belong to
the format the segment chain replaced. Nothing in production reaches them; they
are on the deletion list (H-9 in
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md)).

## `internal/orchestration/` — the encryption facade the handlers call

| Path | Responsibility |
|---|---|
| `manager.go` | The public surface. A handler talks to this and to nothing below it |
| `segmented.go` | Writing and opening one object: the DEK, the codec, the metadata, the foreign-object and key-material refusals |
| `segmented_session.go` | One client-driven multipart upload: the part table, the held short part, the rules Complete enforces |
| `providers.go` | Provider registration, fingerprints, DEK wrap and unwrap, the DEK cache |
| `metadata.go` | Building, reading and filtering the `s3ep-*` keys |
| `rangeread.go` | Range planning on top of the codec's window planner |

`singlepart.go`, `multipart.go` and `streaming_io.go` are the previous format's
paths. Same status as above.

## `internal/proxy/` — the HTTP surface

| Path | Responsibility |
|---|---|
| `server.go`, `router.go`, `middleware_setup.go` | Listener, routes, middleware chain |
| `middleware/` | SigV4 in both forms (header and pre-signed), CORS, logging, request tracking |
| `request/` | Request parsing, aws-chunked and HTTP-chunked body decoding, query parameters |
| `response/` | S3 error documents, backend error mapping, XML helpers |
| `handlers/object/` | GET, PUT, HEAD, DELETE, DeleteObjects, ranged reads, the internal multipart producer |
| `handlers/multipart/` | The client-driven multipart verbs |
| `handlers/bucket/`, `handlers/root/`, `handlers/health/` | Bucket verbs and sub-resources, ListBuckets, health |
| `interfaces/s3_backend.go` | The slice of the AWS SDK's S3 client the handlers compile against. Mocked in the handler unit tests |

## Everything else

| Path | Responsibility |
|---|---|
| `internal/config/` | Viper loading, `${VAR}` expansion, defaults, and all validation. A key that is not validated here is a key nobody checked |
| `internal/license/` | The startup gate |
| `internal/monitoring/` | Prometheus metrics, and pprof on its own loopback listener |
| `internal/validation/` | The previous format's integrity value. No production caller |

## Where the tests are

Unit tests sit next to the code. `*_coverage_test.go` files are ordinary unit
tests from a coverage round and carry no special meaning. Integration and
end-to-end suites have their own layout — see [testing.md](testing.md).
