//go:build integration

package variants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// ---------------------------------------------------------------------------
// What a hostile backend can do to a stored object, and what the client sees.
//
// ADR 0001 says the backend is hostile: it can read, edit, reorder, truncate and
// extend every byte it stores, and it can edit the metadata alongside them. The
// segment chain is the answer to that - each segment is sealed under its own key
// with its index and the object's name in the additional data, and a trailer
// closes the object with its plaintext length - so this file attacks a stored
// object the way that adversary would and asserts what reaches the client.
//
// The invariant every case asserts: the client never receives the object it
// asked for. Either the request fails outright, or the body is cut short. What
// it does receive is always a prefix that was individually authenticated, never
// a byte the adversary chose.
//
// The proxy has already sent 200 by the time it reads the first segment, so a
// tamper found mid-stream can only be reported by aborting the body, which the
// client's HTTP stack surfaces as an unexpected EOF. That is the strongest
// signal available once a status line is out, and it is why the assertions here
// are about what the body delivers rather than about a status code.
// ---------------------------------------------------------------------------

// TamBucket holds every object this file writes.
const TamBucket = "segment-tamper-test"

// TamPlaintextSize is three whole segments and a partial one, so a case can aim
// at a first segment, a middle segment, the short last segment or the trailer
// and hit a different part of the chain each time.
const TamPlaintextSize = 3*dataencryption.SegmentSize + 1000

// tamStoredSegment is what one whole segment occupies at rest.
const tamStoredSegment = dataencryption.SegmentSize + dataencryption.SegmentOverhead

// TamEnv is the pair of clients every case needs: the proxy, which is the only
// thing that can read an object, and a direct backend client, which is the
// adversary.
type TamEnv struct {
	Proxy  *s3.Client
	Direct *s3.Client
}

// TamWrite uploads a fresh object through the proxy and returns its key and its
// plaintext. Each case gets its own object so a failure cannot leak into the
// next one.
func (e TamEnv) TamWrite(t *testing.T, ctx context.Context, name string, size int) (string, []byte) {
	t.Helper()

	plaintext := make([]byte, size)
	_, err := rand.Read(plaintext)
	require.NoError(t, err, "failed to generate the plaintext")

	key := fmt.Sprintf("tamper-%s-%d", name, time.Now().UnixNano())
	_, err = e.Proxy.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(TamBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(plaintext),
		ContentLength: aws.Int64(int64(len(plaintext))),
	})
	require.NoErrorf(t, err, "upload of %s", key)
	return key, plaintext
}

// TamStored reads the object as the backend holds it: ciphertext and the
// metadata it is stored with.
func (e TamEnv) TamStored(t *testing.T, ctx context.Context, key string) ([]byte, map[string]string) {
	t.Helper()

	out, err := e.Direct.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(TamBucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "reading %s from the backend", key)
	defer out.Body.Close()

	stored, err := io.ReadAll(out.Body)
	require.NoError(t, err, "reading the stored bytes")

	metadata := make(map[string]string, len(out.Metadata))
	for metaKey, metaValue := range out.Metadata {
		metadata[metaKey] = metaValue
	}
	return stored, metadata
}

// TamReplace writes bytes and metadata back to the backend behind the proxy's
// back, which is what a compromised or malicious storage endpoint can do.
func (e TamEnv) TamReplace(t *testing.T, ctx context.Context, key string, stored []byte, metadata map[string]string) {
	t.Helper()

	_, err := e.Direct.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(TamBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(stored),
		ContentLength: aws.Int64(int64(len(stored))),
		Metadata:      metadata,
	})
	require.NoErrorf(t, err, "writing the tampered %s back", key)
}

// TamRead is one read through the proxy. The two failures it can produce are
// different things and are kept apart: reqErr is a refusal the client gets
// instead of a response, readErr is the body being cut off after a response has
// already begun. Only the second is available once a status line is out.
func (e TamEnv) TamRead(t *testing.T, ctx context.Context, key, rng string) (body []byte, reqErr, readErr error) {
	t.Helper()

	input := &s3.GetObjectInput{Bucket: aws.String(TamBucket), Key: aws.String(key)}
	if rng != "" {
		input.Range = aws.String(rng)
	}
	out, err := e.Proxy.GetObject(ctx, input)
	if err != nil {
		return nil, err, nil
	}
	defer out.Body.Close()
	body, readErr = io.ReadAll(out.Body)
	return body, nil, readErr
}

// TamDigest is how payloads are compared here; they are never dumped.
func TamDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TamAssertRefused is the invariant every case shares: the client never ends up
// holding the object. Either it was refused outright, or the body stopped short.
func TamAssertRefused(t *testing.T, plaintext, body []byte, reqErr, readErr error) {
	t.Helper()

	if reqErr != nil {
		t.Logf("refused before the body: %v", reqErr)
		return
	}
	require.Errorf(t, readErr,
		"the proxy served all %d bytes of a tampered object as if nothing had happened", len(body))
	assert.NotEqual(t, TamDigest(plaintext), TamDigest(body),
		"a tampered object was delivered whole")
	t.Logf("body cut short at %d of %d bytes: %v", len(body), len(plaintext), readErr)
}

// TestSegmentChainRefusesTamperedBytes attacks the ciphertext itself.
func TestSegmentChainRefusesTamperedBytes(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	env := TamSetup(t, ctx)

	cases := []struct {
		name string
		// what the adversary does to the stored bytes
		tamper func(stored []byte) []byte
		// upFront marks the faults the read finds before it answers at all: the
		// object's end is read first, so anything the trailer proves is a refusal
		// with nothing written (ADR 0003 D14).
		upFront bool
		// how much plaintext may reach the client before the damage is found,
		// where the fault is inside a segment and the response is already out.
		// Every byte up to it carried its own tag; the rest is never released.
		released int
	}{
		{
			name:     "a flipped bit in the first segment",
			tamper:   func(b []byte) []byte { b[10] ^= 0xff; return b },
			released: 0,
		},
		{
			name:     "a flipped bit in a middle segment",
			tamper:   func(b []byte) []byte { b[2*tamStoredSegment+10] ^= 0xff; return b },
			released: 2 * dataencryption.SegmentSize,
		},
		{
			name: "two segments swapped",
			// Each segment is sealed under its own index, so a segment that is
			// intact but in the wrong place is as detectable as a corrupted one.
			tamper: func(b []byte) []byte {
				first := append([]byte{}, b[0:tamStoredSegment]...)
				copy(b[0:tamStoredSegment], b[tamStoredSegment:2*tamStoredSegment])
				copy(b[tamStoredSegment:2*tamStoredSegment], first)
				return b
			},
			released: 0,
		},
		{
			name: "the object is truncated",
			// The trailer carries the plaintext length, so bytes removed from the
			// end cannot be passed off as a shorter object.
			tamper:  func(b []byte) []byte { return b[:len(b)-10] },
			upFront: true,
		},
		{
			name: "the object is extended",
			// Nor can bytes appended to it be passed off as a longer one.
			tamper:  func(b []byte) []byte { return append(b, make([]byte, 64)...) },
			upFront: true,
		},
		{
			name:    "a flipped bit in the trailer",
			tamper:  func(b []byte) []byte { b[len(b)-5] ^= 0xff; return b },
			upFront: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			key, plaintext := env.TamWrite(t, ctx, "bytes", TamPlaintextSize)
			stored, metadata := env.TamStored(t, ctx, key)
			env.TamReplace(t, ctx, key, tc.tamper(stored), metadata)

			body, reqErr, readErr := env.TamRead(t, ctx, key, "")

			if tc.upFront {
				// Nothing is written at all: the fault is one the trailer proves,
				// and the trailer is opened before the response begins.
				require.Error(t, reqErr, "a fault the trailer proves must be refused, not streamed")
				assert.Equal(t, TamShape{Status: http.StatusForbidden, Code: "InvalidObjectState"},
					TamInspect(reqErr))
				assert.Empty(t, body)
				return
			}

			require.NoError(t, reqErr, "this case is expected to fail mid-stream, not before")
			TamAssertRefused(t, plaintext, body, reqErr, readErr)

			// What did reach the client has to be the object's own opening bytes,
			// verified segment by segment - not something the adversary chose.
			assert.Equal(t, tc.released, len(body),
				"the proxy released a different amount of plaintext than the chain allows")
			assert.Equal(t, TamDigest(plaintext[:tc.released]), TamDigest(body),
				"the bytes that were released are not the object's own")
		})
	}
}

// TestSegmentChainRefusesTamperedMetadata attacks the metadata instead. It is
// the half of the object the backend can edit without touching a sealed byte.
func TestSegmentChainRefusesTamperedMetadata(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	env := TamSetup(t, ctx)

	cases := []struct {
		name       string
		tamper     func(metadata map[string]string)
		wantStatus int
		wantCode   string
	}{
		{
			// A wrapped key that does not authenticate is a permanent state of the
			// object: it will not unwrap on this attempt or any later one. Reporting
			// it as a 5xx would have the client's SDK retry a read that cannot
			// succeed and file a corrupted object as a passing outage, so it gets
			// the same answer as a missing format marker below.
			name: "the wrapped key is edited",
			tamper: func(m map[string]string) {
				wrapped := []byte(m["s3ep-encrypted-dek"])
				wrapped[len(wrapped)-4] ^= 0x01
				m["s3ep-encrypted-dek"] = string(wrapped)
			},
			wantStatus: 403,
			wantCode:   "InvalidObjectState",
		},
		{
			name:       "the format marker is removed",
			tamper:     func(m map[string]string) { delete(m, "s3ep-dek-algorithm") },
			wantStatus: 403,
			wantCode:   "InvalidObjectState",
		},
		{
			// The object is made to look like one the proxy never wrote. Under an
			// encrypting provider that is refused rather than passed through, or a
			// backend could strip the metadata off every object and have the proxy
			// hand out ciphertext as if it were content.
			name: "every proxy key is removed",
			tamper: func(m map[string]string) {
				for metaKey := range m {
					delete(m, metaKey)
				}
			},
			wantStatus: 403,
			wantCode:   "InvalidObjectState",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			key, plaintext := env.TamWrite(t, ctx, "metadata", TamPlaintextSize)
			stored, metadata := env.TamStored(t, ctx, key)
			tc.tamper(metadata)
			env.TamReplace(t, ctx, key, stored, metadata)

			body, reqErr, readErr := env.TamRead(t, ctx, key, "")
			require.Errorf(t, reqErr, "a read of %d bytes was served instead of refused", len(body))
			TamAssertRefused(t, plaintext, body, reqErr, readErr)

			shape := TamInspect(reqErr)
			assert.Equalf(t, tc.wantStatus, shape.Status, "%s", shape)
			assert.Equalf(t, tc.wantCode, shape.Code, "%s", shape)
		})
	}
}

// TestSegmentChainVerifiesRangedReads is the property the format buys that the
// integrity value it replaced could not: a ranged read is verified like any
// other, because the segments it covers carry their own tags. It also reads only
// those segments, so damage elsewhere in the object is none of its business.
func TestSegmentChainVerifiesRangedReads(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	env := TamSetup(t, ctx)

	t.Run("a range over a tampered segment is refused", func(t *testing.T) {
		key, _ := env.TamWrite(t, ctx, "range-hit", TamPlaintextSize)
		stored, metadata := env.TamStored(t, ctx, key)
		stored[tamStoredSegment+10] ^= 0xff
		env.TamReplace(t, ctx, key, stored, metadata)

		// 70000..80000 lies inside segment 1, the one that was damaged.
		body, reqErr, readErr := env.TamRead(t, ctx, key, "bytes=70000-80000")
		require.NoError(t, reqErr, "the refusal is expected mid-body, not before")
		require.Error(t, readErr, "a tampered segment was served through a ranged read")
		assert.Empty(t, body, "a tampered segment must not reach the client at all")
	})

	t.Run("a suffix range over a tampered tail is refused", func(t *testing.T) {
		key, _ := env.TamWrite(t, ctx, "range-suffix", TamPlaintextSize)
		stored, metadata := env.TamStored(t, ctx, key)
		stored[len(stored)-60] ^= 0xff
		env.TamReplace(t, ctx, key, stored, metadata)

		body, reqErr, readErr := env.TamRead(t, ctx, key, "bytes=-500")
		require.NoError(t, reqErr, "the refusal is expected mid-body, not before")
		require.Error(t, readErr, "a tampered tail was served through a suffix range")
		assert.Empty(t, body, "a tampered tail must not reach the client at all")
	})

	t.Run("a range clear of the damage is served", func(t *testing.T) {
		key, plaintext := env.TamWrite(t, ctx, "range-miss", TamPlaintextSize)
		stored, metadata := env.TamStored(t, ctx, key)
		stored[tamStoredSegment+10] ^= 0xff
		env.TamReplace(t, ctx, key, stored, metadata)

		// A ranged read fetches only the segments its window covers, so a range in
		// segment 0 neither reads nor notices the damage in segment 1. That is the
		// cost of ranged reads under any per-segment format and it is the reason
		// the whole-object read exists.
		body, reqErr, readErr := env.TamRead(t, ctx, key, "bytes=0-1000")
		require.NoError(t, reqErr, "an intact range was refused")
		require.NoError(t, readErr, "an intact range was cut short")
		assert.Equal(t, TamDigest(plaintext[:1001]), TamDigest(body),
			"a range clear of the damage must still round-trip")
	})
}

// TamShape is the client-observable rendering of a refusal.
type TamShape struct {
	Status int
	Code   string
}

func (s TamShape) String() string {
	return fmt.Sprintf("status=%d code=%q", s.Status, s.Code)
}

// TamInspect unwraps the SDK's OperationError -> ResponseError -> APIError onion
// to get at the status and the S3 error code the proxy actually answered with.
func TamInspect(err error) TamShape {
	var out TamShape
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		out.Status = respErr.HTTPStatusCode()
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		out.Code = apiErr.ErrorCode()
	}
	return out
}

// TamSetup prepares the clients and the bucket.
func TamSetup(t *testing.T, ctx context.Context) TamEnv {
	t.Helper()

	proxy, err := integration.CreateProxyClient()
	require.NoError(t, err, "failed to create the proxy client")
	direct, err := integration.CreateMinIOClient()
	require.NoError(t, err, "failed to create the backend client")

	integration.SetupTestBucket(t, ctx, proxy, TamBucket)
	return TamEnv{Proxy: proxy, Direct: direct}
}
