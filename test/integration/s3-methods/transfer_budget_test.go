//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proxy used to carry a fixed 30-second budget on reading a request body and
// another on writing a response body. Both were wall clocks on an *entire*
// transfer, not on a stalled one: the clock ran while bytes were moving at full
// speed, so the largest object the proxy could serve was 30 seconds times the
// client's bandwidth and a healthy transfer was reset mid-stream above it.
//
// The defect survived every benchmark because the suites run on loopback with
// objects that finish in well under a second. These two tests are the ones that
// could have caught it: they move a small object slowly, for longer than the
// budget that used to exist. That is why they are slow on purpose (ADR 0015).
const tbBudgetProbe = 35 * time.Second

// tbTrickleReader delivers payload over the whole of duration, in equal pieces,
// so the transfer is long without ever being stalled.
type tbTrickleReader struct {
	payload []byte
	pieces  int
	pause   time.Duration
	sent    int
}

func (r *tbTrickleReader) Read(p []byte) (int, error) {
	if r.sent >= len(r.payload) {
		return 0, io.EOF
	}
	if r.sent > 0 {
		time.Sleep(r.pause)
	}
	size := (len(r.payload) + r.pieces - 1) / r.pieces
	if size > len(p) {
		size = len(p)
	}
	if r.sent+size > len(r.payload) {
		size = len(r.payload) - r.sent
	}
	n := copy(p, r.payload[r.sent:r.sent+size])
	r.sent += n
	return n, nil
}

// TestTbSlowUploadIsNotCutByAWallClock sends a body over more than the budget
// that used to bound the whole request read.
func TestTbSlowUploadIsNotCutByAWallClock(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// Deliberately several segments: the proxy seals a segment at a time, so a
	// body under one segment reaches the backend only when the client's last
	// byte does, and the backend refuses a request it has heard nothing on for
	// about 25 seconds. That bound is the backend's, is measured on this ticket,
	// and is not what this test is about.
	payload := bytes.Repeat([]byte("a transfer the server must not cut. "), 8192)
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	key := "tb-slow-upload-" + integration.RandomString(8)

	const pieces = 35
	body := &tbTrickleReader{payload: payload, pieces: pieces, pause: tbBudgetProbe / pieces}

	target := fmt.Sprintf("%s/%s/%s", integration.ProxyEndpoint, tc.TestBucket, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, body)
	require.NoError(t, err)
	req.ContentLength = int64(len(payload))

	payloadHash := fmt.Sprintf("%x", sha256.Sum256(payload))
	require.NoError(t, integration.SignHTTPRequestForS3WithCredentials(req, payloadHash))

	started := time.Now()
	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err, "a slow upload must not be reset by the server")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	require.Equal(t, http.StatusOK, resp.StatusCode, "the slow upload must be stored")
	assert.Greater(t, time.Since(started), 30*time.Second,
		"the test only proves anything if the transfer outlived the budget that used to exist")
	assert.Equal(t, want, subrefDigest(t, tc, key),
		"the object must read back byte-identical to what was sent")
}

// TestTbSlowDownloadIsNotCutByAWallClock reads a response over more than the
// budget that used to bound the whole response write.
func TestTbSlowDownloadIsNotCutByAWallClock(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// Large enough that the server cannot hand the whole response to the kernel
	// and walk away. At 18 KiB - what this test used to send - the response fits
	// in the socket buffers, the handler returns before the client has read a
	// byte, and no write ever happens after the deadline a WriteTimeout would
	// set: the regression this test is named for could not be detected. Several
	// MiB leaves the server blocked in Write while the client trickles, which is
	// the state the response wall clock used to kill.
	payload := bytes.Repeat([]byte("a response the server must not cut. "), 8<<20/36)
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	key := "tb-slow-download-" + integration.RandomString(8)
	subrefPutObject(t, tc, key, payload)

	target := fmt.Sprintf("%s/%s/%s", integration.ProxyEndpoint, tc.TestBucket, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(t, err)
	require.NoError(t, integration.SignHTTPRequestForS3WithCredentials(req,
		fmt.Sprintf("%x", sha256.Sum256(nil))))

	started := time.Now()
	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the body in pieces spread over more than the old budget. The server
	// blocks on the write while the client is not reading, which is exactly the
	// state the response wall clock used to kill.
	const pieces = 35
	got := make([]byte, 0, len(payload))
	buf := make([]byte, (len(payload)+pieces-1)/pieces)
	require.Greater(t, len(payload), 4<<20,
		"the payload has to outgrow the socket buffers, or the server never blocks in Write")
	for {
		n, readErr := resp.Body.Read(buf)
		got = append(got, buf[:n]...)
		if readErr == io.EOF {
			break
		}
		require.NoError(t, readErr, "a slow download must not be reset by the server")
		time.Sleep(tbBudgetProbe / pieces)
	}

	assert.Greater(t, time.Since(started), 30*time.Second,
		"the test only proves anything if the transfer outlived the budget that used to exist")
	assert.Equal(t, want, fmt.Sprintf("%x", sha256.Sum256(got)),
		"the whole object must arrive, byte-identical")
}
