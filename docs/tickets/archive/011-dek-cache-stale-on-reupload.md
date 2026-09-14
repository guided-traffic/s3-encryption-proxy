# Ticket 011 — DEK cache returns stale DEK after re-upload

## Problem

`internal/orchestration/providers.go:196` builds the DEK cache key as:

```go
cacheKey := fmt.Sprintf("%s:%s", fingerprint, objectKey)
```

When the same `objectKey` is re-uploaded, it gets a fresh DEK + IV and a fresh HMAC stored in S3 metadata. However the cache still holds the DEK from the previous upload. The next GET hits the cache, decrypts the new ciphertext with the *old* DEK, producing garbage plaintext. HMAC verification then fails and the download aborts with:

```
HMAC verification failed - data integrity compromised
```

## Reproduction

Against a proxy that has already served one GET of an object:

1. Re-upload the same object key with new content (any size — multipart or single-part CTR).
2. GET the object.
3. Download fails with `HMAC integrity verification failed`.

Concretely, running `TestLargeMultipart500MB` (in `test/integration/180-degree-variants/`) twice in a row against the same proxy reproduces it 100% — first run passes (cold cache), second run fails.

The full integration suite passes only because each fixed object key is uploaded exactly once per proxy lifetime.

## Root cause

The cache key is `(fingerprint, objectKey)` but both the encrypted DEK blob and the plaintext DEK change on every upload. The cache entry is never invalidated on PUT / CompleteMultipartUpload, so it goes stale as soon as the object is overwritten.

Cache write site: `internal/orchestration/providers.go:239`
```go
pm.keyCache[cacheKey] = append([]byte(nil), dek...)
```

Cache read site: `internal/orchestration/providers.go:198`
```go
if cachedDEK, exists := pm.keyCache[cacheKey]; exists {
    return append([]byte(nil), cachedDEK...), nil
}
```

There is no invalidation path on the upload side.

## Fix candidates

Pick one — do **not** just disable the cache, it is a real performance win on repeated reads of the same object.

### Option A — include encryptedDEK in the cache key (preferred)

Hash (e.g. SHA-256) the `encryptedDEK` bytes and append to the cache key:

```go
h := sha256.Sum256(encryptedDEK)
cacheKey := fmt.Sprintf("%s:%s:%x", fingerprint, objectKey, h[:8])
```

- Pro: correct by construction — a different encrypted DEK (i.e. a new upload) gets a different cache key, so stale entries are never returned.
- Pro: no coupling to the upload path.
- Con: leaks entries of superseded DEKs. A simple LRU with a modest bound (e.g. 1024) solves this.

### Option B — invalidate on write

On every successful PUT / CompleteMultipartUpload, call `pm.invalidateDEKCache(fingerprint, objectKey)` before returning.

- Pro: cache stays lean.
- Con: must be wired into every write path (single-part PUT, multipart finalize, copy-object …); easy to miss one and regress.

### Option C — drop objectKey from the cache key

Cache by fingerprint of the encryptedDEK only (`hex(sha256(encryptedDEK))`). Two different objects with the same encrypted DEK are impossible in practice (fresh DEKs are generated per object), so this is effectively the same as Option A without the objectKey component.

## Acceptance criteria

- `TestLargeMultipart500MB` passes on the **second** run against the same proxy instance (currently fails).
- A new regression test in `test/integration/` that uploads → downloads → re-uploads different content to the same key → downloads, and asserts the second download matches the second upload.
- Full unit + integration suite still green.
- No measurable regression in repeated-read throughput (Option A preserves cache hits for the same encrypted DEK).

## Notes

- Discovered 2026-04-23 while validating Tier 1.1 (in-place CTR XOR) from ticket 010. The in-place change was a red herring; the bug reproduces on the unchanged baseline.
- Related files: `internal/orchestration/providers.go`, `internal/orchestration/singlepart.go`, `internal/orchestration/multipart.go`.
