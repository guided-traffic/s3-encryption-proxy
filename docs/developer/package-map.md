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
| `interfaces.go` | `KeyEncryptor`, the only interface here: wrap a data key, unwrap one, name and fingerprint itself |
| `dataencryption/segmented_gcm.go` | The storage format, `s3ep-gcm-seg-v2` and the only one the tree reads: constants, the AAD builder, the trailer, the size functions, the CRC32C fold. Read [storage-format.md](storage-format.md) before touching it |
| `dataencryption/segmented_gcm_io.go` | Sealing writer and sequential opening reader, plus the part-aligned variants an upload uses |
| `dataencryption/segmented_gcm_range.go` | The window planner and the ranged reader |
| `keyencryption/aes.go` | The one key provider that encrypts: HKDF-SHA256 derivation, the authenticated DEK wrap, the fingerprint |
| `keyencryption/exit.go` | The exit provider: holds no key material and refuses both wrap and unwrap, so the pass-through behaviour lives in the handlers, not here |
| `factory/` | Builds a key encryptor from configuration, and is the registry that maps a fingerprint back to its provider |

A key encryption key held by a KMS is decided
([ADR 0005](../adr/0005-a-kms-key-is-a-provider.md)) and **not built**.
Nothing in this tree talks to a KMS; configuration admits `aes` and `exit`, and
refuses `type: tink` and `type: none` by name.

## `internal/orchestration/` — the encryption facade the handlers call

| Path | Responsibility |
|---|---|
| `manager.go` | The public surface. It also holds the two maps of multipart uploads in flight — the client-driven sessions and the proxy's own producer uploads — and runs the goroutine that ends the idle client-driven ones at the backend before forgetting them. Both maps are swept at shutdown |
| `segmented.go` | Writing and opening one object: the DEK, the codec, the metadata, the range plan, the foreign-object and key-material refusals |
| `segmented_session.go` | One client-driven multipart upload: the part table, the held short part, the rules Complete enforces. See [multipart.md](multipart.md) |
| `providers.go` | Provider registration, fingerprints, DEK wrap and unwrap, the DEK cache (LRU-bounded, no expiry) |
| `metadata.go` | Building and reading the `s3ep-*` keys. Filtering them back out of a client response belongs to the object handler |

A handler talks to this package and, in four files, past it. Two read the format
constants — `handlers/object/range.go` computes the provisional stored range,
`handlers/object/tail.go` the tail and trailer fetch lengths — so a change to the
segment layout touches both. Two more use the format package without touching its
layout: `handlers/object/operations.go` for the corrupt sentinel and the checksum
type, `handlers/bucket/listing.go` for the stored-to-plaintext conversion.

## `internal/proxy/` — the HTTP surface

| Path | Responsibility |
|---|---|
| `server.go`, `router.go`, `middleware_setup.go` | Listener, routes, middleware chain. `Server.Shutdown` is what stops the manager's background sweep |
| `middleware/` | SigV4 in both forms (header and pre-signed), CORS, logging, request tracking, and the authenticated access key id it puts in the request context for the handlers that report an owner. What the signature check does *not* cover is in [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) |
| `request/` | Request parsing, aws-chunked body decoding, upload checksum verification, query parameters, and the `x-amz-expected-bucket-owner` guard every backend call carries on the verbs S3 defines it for ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D14) |
| `response/` | S3 error documents, backend error mapping, XML helpers. See [errors.md](errors.md) |
| `utils/` | One file: the detached, 30-second context that lets a multipart abort finish after the client is gone |
| `handlers/object/` | GET, PUT, HEAD, DELETE, DeleteObjects, ranged reads, the internal multipart producer, and the object sub-resources: `?tagging`, `?retention` and `?legal-hold` forwarded, `?acl`, `?select` and `?torrent` refused |
| `handlers/multipart/` | The client-driven multipart verbs |
| `handlers/bucket/`, `handlers/root/`, `handlers/health/` | Bucket verbs and sub-resources, ListBuckets, `/health` and `/version` |
| `interfaces/s3_backend.go` | The 52 methods of the AWS SDK's S3 client the handlers compile against. Mocked in the handler unit tests. `CopyObject` is deliberately absent: both server-side copy verbs are refused ([ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md) D9) |

What each verb actually does is in [request-paths.md](request-paths.md).

## Everything else

| Path | Responsibility |
|---|---|
| `internal/config/` | Viper loading, `${VAR}` expansion, defaults, and all validation. A key that is not read by code does not exist ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)), and a key that is not validated here is a key nobody checked |
| `internal/license/` | The startup gate, and the hourly runtime check that ends the process when the token expires — through main's drain path, not from the monitoring goroutine |
| `internal/monitoring/` | Prometheus metrics, and pprof on its own loopback listener |

## Where the tests are

Unit tests sit next to the code. `*_coverage_test.go` files are ordinary unit
tests from a coverage round and carry no special meaning. Integration and
end-to-end suites have their own layout — see [testing.md](testing.md).
