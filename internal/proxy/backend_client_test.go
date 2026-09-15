package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	proxyconfig "github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func backendOptions(t *testing.T, cfg proxyconfig.S3BackendConfig) s3.Options {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(discardWriter{})
	var o s3.Options
	backendClientOptions(cfg, logrus.NewEntry(logger))(&o)
	return o
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// The proxy uploads an unseekable ciphertext stream. Opportunistic request
// checksums make the SDK fail outright against a plain-HTTP backend
// ("unseekable stream is not supported without TLS and trailing checksum") and
// cost a full extra pass over every payload against an HTTPS one.
func TestBackendClientOptions_ChecksumsOnlyWhenRequired(t *testing.T) {
	o := backendOptions(t, proxyconfig.S3BackendConfig{TargetEndpoint: "http://minio:9000"})

	assert.Equal(t, aws.RequestChecksumCalculationWhenRequired, o.RequestChecksumCalculation,
		"opportunistic request checksums break streaming uploads to a plain-HTTP backend")
	assert.Equal(t, aws.ResponseChecksumValidationWhenRequired, o.ResponseChecksumValidation,
		"opportunistic response validation costs a pass over every downloaded object")
}

func TestBackendClientOptions_PathStyleAndEndpoint(t *testing.T) {
	o := backendOptions(t, proxyconfig.S3BackendConfig{TargetEndpoint: "https://minio:9000"})

	assert.True(t, o.UsePathStyle, "custom S3 endpoints need path-style addressing")
	require.NotNil(t, o.BaseEndpoint)
	assert.Equal(t, "https://minio:9000", *o.BaseEndpoint)
}

func TestBackendClientOptions_NoEndpointLeavesDefaults(t *testing.T) {
	o := backendOptions(t, proxyconfig.S3BackendConfig{})

	assert.Nil(t, o.BaseEndpoint, "an empty target endpoint must not be set on the client")
	assert.True(t, o.UsePathStyle)
}

// Every configuration gets the observing client, this one included: what
// /status and the backend gauges report is what the real traffic showed, so a
// path that installs the SDK's client unwrapped would make the observation
// partial without saying so (ADR 0034).
func TestBackendClientOptions_EveryPathIsObserved(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  proxyconfig.S3BackendConfig
	}{
		{name: "no endpoint", cfg: proxyconfig.S3BackendConfig{}},
		{name: "endpoint, verifying", cfg: proxyconfig.S3BackendConfig{TargetEndpoint: "https://minio:9000"}},
		{
			name: "endpoint, skipping verification",
			cfg: proxyconfig.S3BackendConfig{
				TargetEndpoint:     "https://minio:9000",
				InsecureSkipVerify: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := backendOptions(t, tc.cfg)

			require.NotNil(t, o.HTTPClient, "the backend leg must run on the observed client")
			_, unwrapped := o.HTTPClient.(*awshttp.BuildableClient)
			assert.False(t, unwrapped, "the SDK's own client reaches the backend unobserved")
		})
	}
}

// insecure_skip_verify has to reach the transport the SDK actually uses, and the
// observation wrapper must not swallow it. Driven against a server holding a
// certificate no root signed, which is the only thing that tells the two apart.
func TestBackendClientOptions_InsecureSkipVerifyReachesTheTransport(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name       string
		skipVerify bool
		wantErr    bool
	}{
		{name: "verification on refuses the self-signed certificate", skipVerify: false, wantErr: true},
		{name: "verification off accepts it", skipVerify: true, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := backendOptions(t, proxyconfig.S3BackendConfig{
				TargetEndpoint:     srv.URL,
				InsecureSkipVerify: tc.skipVerify,
			})

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			resp, err := o.HTTPClient.Do(req)
			if tc.wantErr {
				require.Error(t, err, "a certificate no root signed must not be accepted")
				return
			}
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// The client is built from the SDK's own, with nothing but the TLS
// configuration mutated. A bare http.Transport here used to discard every SDK
// default at once, and assigning a fresh tls.Config would drop the SDK's
// TLS 1.2 minimum back to Go's.
func TestBackendHTTPClient_SkipVerifyKeepsEverythingElse(t *testing.T) {
	transport := backendHTTPClient(true).GetTransport()

	require.NotNil(t, transport)
	require.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify,
		"the transport must actually skip verification when it is configured to")
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion,
		"skipping certificate verification must not also lower the TLS floor")
	assert.NotZero(t, transport.TLSHandshakeTimeout,
		"the SDK's handshake budget must survive; a bare transport has none")
	assert.NotZero(t, transport.IdleConnTimeout,
		"the SDK's connection pool tuning must survive")
}

func TestBackendHTTPClient_VerifiesByDefault(t *testing.T) {
	transport := backendHTTPClient(false).GetTransport()

	require.NotNil(t, transport)
	if transport.TLSClientConfig != nil {
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify,
			"certificate verification is only ever disabled on request")
	}
}
