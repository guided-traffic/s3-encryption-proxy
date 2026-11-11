# The client library

`github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc` is a Go package that
writes and reads the proxy's stored format directly against S3, with no proxy in
between ([ADR 0041](../adr/0041-the-project-ships-a-client-library-for-its-stored-format.md)).
An object it stores is readable through the proxy, and an object the proxy stored
is readable through it, as long as both use the same `aes_key` and the same
`encryption.metadata_key_prefix`. Every release runs that in both directions
against a real proxy before it ships.

Use it when an application should store encrypted objects without another
network hop, or alongside a proxy that other clients go through.

## Use

```go
import "github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc"

api := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true })

c, err := s3enc.New(api, s3enc.Options{
    ActiveKey:   os.Getenv("S3ENC_KEY"),                    // the proxy's aes_key
    RetiredKeys: []string{os.Getenv("S3ENC_KEY_RETIRED")}, // optional, read-only
})

res, err := c.Put(ctx, "bucket", "dir/file.bin", file, &s3enc.PutOptions{
    ContentType: "application/octet-stream",
    Metadata:    map[string]string{"owner": "tool"},
})
// res.Size, res.CRC32C: plaintext length and CRC32C, sealed into the object

obj, err := c.Get(ctx, "bucket", "dir/file.bin")
defer obj.Close()
_, err = io.Copy(dst, obj) // verified only when this returns without error

part, err := c.GetRange(ctx, "bucket", "dir/file.bin", 1<<20, 4096)
info, err := c.Stat(ctx, "bucket", "dir/file.bin") // authenticated size + CRC32C, 40 bytes read
_, err = c.Copy(ctx, "bucket", "dir/file.bin", "bucket", "dir/renamed.bin")
```

The version is the proxy's release: require the tag of the proxy release whose
format you want to write, `go get github.com/guided-traffic/s3-encryption-proxy/v5@v5.<minor>.<patch>`.

| Option | Default | Meaning |
|---|---|---|
| `ActiveKey` | — (required) | base64 of 32 random bytes; wraps every new object. The proxy's own key rules apply: a passphrase or a low-entropy value is refused. Generate it with `s3ep-keygen` or `openssl rand -base64 32` |
| `RetiredKeys` | none | Open the objects they wrapped, write nothing |
| `MetadataPrefix` | `s3ep-` | Must equal the proxy's `encryption.metadata_key_prefix`, and must match `^[a-z0-9][a-z0-9-]{2,}-$` |
| `PartSize` | `12582912` (12 MiB) | Upload part size, at least 5 MiB. A body of unknown length can be at most `PartSize × 10,000` |
| `Concurrency` | `4` | Parts in flight. Memory per upload is about `PartSize × Concurrency` |

> **Security:** `ActiveKey` is the proxy's master key. The application process
> that holds it can read and write every object under that key, outside every
> control the proxy applies — client authentication included. See
> [docs/security/key-management.md](../security/key-management.md).

## What the caller must know

- **A whole-object read is verified at its end.** Every byte `Read` returns is
  authenticated, but the trailer — length and CRC32C — is checked when the body
  ends. Commit nothing until `Read` has returned `io.EOF`; any other error means
  discard everything read. `Get` is one request; the proxy reads the trailer
  first and can refuse before the first byte, the library leaves that to you.
- **The object key is authenticated.** A server-side `CopyObject` or a rename
  makes an object unreadable (`ErrCorrupt`). Use `Copy`, which re-encrypts,
  streamed, and moves an object from a retired key onto the active one.
- **Objects not in this format are refused** (`ErrNotEncrypted`), never served.
  There is no pass-through and no `exit` mode: the library always encrypts.
- **Listings report stored sizes.** Convert with `s3enc.PlaintextSize`; that is
  the backend's number, and only `Stat` authenticates it.
- **No rollback protection.** A backend that serves an older, genuine version of
  an object under the same key is not detected. That is the proxy's limit too
  ([stored objects, H-3](../security/stored-objects.md#h-3-rollback-and-object-substitution-are-not-prevented)).
- **Uploads send no opportunistic checksum.** The body is the ciphertext stream,
  and the format authenticates every segment, so a request checksum would cost a
  full pass and cover nothing more. It also keeps a plain-HTTP endpoint working.
  What a read sees is still verified against the format, not against S3.

| Error | Meaning |
|---|---|
| `ErrNotEncrypted` | No format metadata: not written by the proxy or by the library |
| `ErrUnknownKey` | Wrapped by a key the client does not hold; add it to `RetiredKeys` |
| `ErrKeyMaterialUnreadable` | Wrapped data key missing or forged; permanent |
| `ErrCorrupt` | Stored bytes fail authentication: tampered, truncated, moved |
| `ErrRangeNotSatisfiable` | The range starts at or after the end |
| `ErrReservedMetadata` | A user metadata key inside the prefix; nothing is stored |

## Compatibility

The library and the proxy are one module and one release line, so a release
cannot ship a library that disagrees with its own proxy. Across a major release
the stored format may change without a read path for the old one
([ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md)), and the module
path moves to the new major
([ADR 0040](../adr/0040-the-go-module-path-carries-the-major-version.md)): crossing
one means rewriting the import and reading the release notes. A change to the
library's Go interface is not a break under ADR 0018 D5; pin an exact version and
move deliberately.

Uploads use `feature/s3/transfermanager` of the AWS SDK, which is still a 0.x
module; `API`, the interface `New` takes, is its client interface and
`*s3.Client` satisfies it.
