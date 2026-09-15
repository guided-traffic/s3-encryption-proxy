//go:build integration
// +build integration

// Package shutdown_test proves the shutdown tail of ADR 0029 in a real process:
// a container that gets a real SIGTERM ends the multipart uploads it is holding
// (ADR 0028) before it exits. The unit tests in cmd/s3-encryption-proxy fix the
// order of the phases and the budget arithmetic; none of them runs a process.
//
// It owns the demo stack rather than sharing it — it destroys the proxy the
// other integration packages talk to — so it is out of INTEGRATION_PKGS and has
// a target of its own, and it puts the stack back on its way out.
package shutdown_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

const (
	// The plain-HTTP proxy of docker-compose.demo.yml. The container name is
	// what docker takes, the service name is what docker compose takes.
	proxyContainer = "proxy"

	// The configuration that container is started with; the suite reads the
	// shutdown budget out of it rather than restating the number.
	demoConfig = "../../../config/aes-example.yaml"

	// One part over the backend's 5 MiB minimum and a whole number of 64 KiB
	// segments, so it is streamed to the backend rather than held for the seal
	// at Complete (ADR 0011 D5).
	partSize = 8 * 1024 * 1024

	// The listener close and the process exit sit outside the operator's
	// budget, so the ceiling for the exit is the budget plus this.
	exitSlack = 15 * time.Second
)

// TestShutdownEndsOpenMultipartUploadsUnderSIGTERM is the end-to-end half of
// ADR 0029: an upload the backend knows about and the proxy holds a session for
// must be ended by the sweep, not left behind as an orphan. Nothing else in the
// tree exercises a signal against a running binary.
func TestShutdownEndsOpenMultipartUploadsUnderSIGTERM(t *testing.T) {
	ctx := preflight(t)

	tc := integration.NewTestContextWithTimeout(t, ctx)
	t.Cleanup(tc.CleanupTestBucket)
	// Registered last so it runs first (cleanups are LIFO): whatever the test
	// did, the next run must find a usable stack.
	t.Cleanup(func() { restartProxy(t) })

	key := "shutdown-sweep-" + integration.RandomString(8)
	created, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "the proxy refused to open a multipart upload")
	uploadID := aws.ToString(created.UploadId)

	part := make([]byte, partSize)
	_, err = rand.Read(part)
	require.NoError(t, err)
	_, err = tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(part),
	})
	require.NoError(t, err, "the proxy refused the part")

	// Without this the run would prove nothing: an upload that never reached
	// the backend cannot be left behind there either.
	require.Contains(t, openUploads(t, ctx, tc), uploadID,
		"the upload is not open at the backend before the signal")

	budget := shutdownBudget(t)
	signalled := time.Now()
	out, err := docker(ctx, "kill", "-s", "TERM", proxyContainer)
	require.NoErrorf(t, err, "docker kill: %s", out)

	waitForExit(t, ctx, budget+exitSlack)
	t.Logf("the proxy exited %s after SIGTERM (shutdown_timeout %s)",
		time.Since(signalled).Round(time.Millisecond), budget)

	require.Empty(t, openUploads(t, ctx, tc),
		"a multipart upload is still open at the backend, so the shutdown sweep did not end it:\n%s", proxyLogs())
}

// preflight fails fast and loudly when the stack this suite destroys and
// restores is not there, rather than leaving the reason in an opaque SDK error.
func preflight(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	state, err := docker(ctx, "inspect", "-f", "{{.State.Running}}", proxyContainer)
	require.NoErrorf(t, err, "the container %q is not there. Run ./start-demo.sh first:\n%s", proxyContainer, state)
	require.Equalf(t, "true", strings.TrimSpace(state),
		"the container %q is not running. Run ./start-demo.sh first.", proxyContainer)

	client, err := integration.CreateProxyClientWithEndpoint(integration.ProxyEndpoint)
	require.NoError(t, err)
	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err, "the proxy is not reachable. Run ./start-demo.sh first.")

	return ctx
}

// openUploads lists the multipart uploads of the test bucket at the backend
// itself. Through the proxy the answer would depend on the process this suite
// is about to kill.
func openUploads(t *testing.T, ctx context.Context, tc *integration.TestContext) []string {
	t.Helper()

	out, err := tc.MinIOClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(tc.TestBucket),
	})
	require.NoError(t, err, "the backend is not reachable directly, so nothing can be checked there")

	ids := make([]string, 0, len(out.Uploads))
	for _, upload := range out.Uploads {
		ids = append(ids, aws.ToString(upload.UploadId))
	}
	return ids
}

// waitForExit holds until the container is gone, and insists it went cleanly:
// a non-zero code means the process was killed rather than shut down, which is
// the whole failure mode this suite exists for.
func waitForExit(t *testing.T, ctx context.Context, within time.Duration) {
	t.Helper()

	deadline := time.Now().Add(within)
	for {
		state, err := docker(ctx, "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", proxyContainer)
		require.NoErrorf(t, err, "docker inspect: %s", state)

		running, code, _ := strings.Cut(strings.TrimSpace(state), " ")
		if running == "false" {
			require.Equalf(t, "0", code, "the proxy did not exit cleanly under SIGTERM:\n%s", proxyLogs())
			return
		}
		if time.Now().After(deadline) {
			require.FailNowf(t, "the proxy is still running",
				"it did not exit within %s of SIGTERM:\n%s", within, proxyLogs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// restartProxy puts the stack back. It runs from a cleanup, so it takes a
// context of its own — the test's may be spent or cancelled by a panic.
func restartProxy(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	out, err := docker(ctx, "start", proxyContainer)
	require.NoErrorf(t, err, "the proxy could not be started again and the stack is broken for the next run: %s", out)

	integration.WaitForHealthCheck(t, integration.ProxyEndpoint)
}

// proxyLogs is 'docker logs proxy | tail -50' inlined into a failure message,
// so the reason is in the test output instead of a second command.
func proxyLogs() string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := docker(ctx, "logs", "--tail", "50", proxyContainer)
	if err != nil {
		return "docker logs failed: " + out
	}
	return out
}

// shutdownBudget reads shutdown_timeout out of the configuration the demo proxy
// runs on. The key is absent there, which is the loader's 30s fallback; reading
// it keeps the ceiling right for anyone who writes one.
func shutdownBudget(t *testing.T) time.Duration {
	t.Helper()

	content, err := os.ReadFile(demoConfig)
	require.NoErrorf(t, err, "the demo configuration %s is not readable", demoConfig)

	match := regexp.MustCompile(`(?m)^shutdown_timeout:\s*(\d+)`).FindStringSubmatch(string(content))
	if match == nil {
		return 30 * time.Second
	}
	seconds, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	return time.Duration(seconds) * time.Second
}

// docker runs one docker command and returns its combined output.
func docker(ctx context.Context, args ...string) (string, error) {
	// #nosec G204 - every argument comes from this file or from a container
	// name it declares.
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}
