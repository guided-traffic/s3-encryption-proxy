//go:build e2e

package harness

import (
	"crypto/md5" // #nosec G501 - Content-MD5 and the S3 entity tag are what these suites are about
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// SHA256File hashes a file. Suites compare hashes rather than contents, so a
// failure never prints a payload dump.
func SHA256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 - path is built by the suite
	require.NoErrorf(t, err, "opening %s", path)
	defer func() { _ = f.Close() }()

	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// SHA256Bytes hashes a buffer.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// MD5File is the digest an S3 client computes over its own file and compares
// with the entity tag it was answered. The suites need it to state, in the
// verdict table, which of the two values a client was looking at.
func MD5File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 - path is built by the suite
	require.NoErrorf(t, err, "opening %s", path)
	defer func() { _ = f.Close() }()

	h := md5.New() // #nosec G401 - not a security use: this is the S3 entity tag
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// WriteRandomFile writes size incompressible bytes and returns the path. The
// payload is random so an entropy check on the stored bytes means something and
// so no backend can deduplicate two cases into one object.
func WriteRandomFile(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o750))
	path := filepath.Join(dir, name)

	f, err := os.Create(path) // #nosec G304 - path is built by the suite
	require.NoErrorf(t, err, "creating %s", path)
	defer func() { require.NoError(t, f.Close()) }()

	_, err = io.CopyN(f, rand.Reader, size)
	require.NoErrorf(t, err, "writing %d bytes to %s", size, path)
	return path
}

// CopyFile duplicates a file, for the cases that need the same payload in two
// directories (a sync source and the file a single put sends).
func CopyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src) // #nosec G304 - path is built by the suite
	require.NoErrorf(t, err, "opening %s", src)
	defer func() { _ = in.Close() }()

	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o750))
	out, err := os.Create(dst) // #nosec G304 - path is built by the suite
	require.NoErrorf(t, err, "creating %s", dst)
	defer func() { require.NoError(t, out.Close()) }()

	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

// MD5Base64File is the same digest as MD5File, base64-encoded. It is the form
// rclone stores in its X-Amz-Meta-Md5chksum annotation, so a suite comparing
// against that header has to use this and not the hex spelling.
func MD5Base64File(t *testing.T, path string) string {
	t.Helper()
	raw, err := hex.DecodeString(MD5File(t, path))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}
