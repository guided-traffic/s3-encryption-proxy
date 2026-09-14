package proxy

import (
	"crypto/tls"
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
	assert.Nil(t, o.HTTPClient, "no custom transport without an endpoint")
	assert.True(t, o.UsePathStyle)
}

// insecure_skip_verify must install a transport that actually skips
// verification, and must not do so otherwise.
func TestBackendClientOptions_InsecureSkipVerify(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		o := backendOptions(t, proxyconfig.S3BackendConfig{
			TargetEndpoint:     "https://minio:9000",
			InsecureSkipVerify: true,
		})
		require.NotNil(t, o.HTTPClient, "a custom transport is required to skip verification")

		// The client is built from the SDK's own, with nothing but the TLS
		// configuration mutated. A bare http.Transport here used to discard
		// every SDK default at once, and assigning a fresh tls.Config would
		// drop the SDK's TLS 1.2 minimum back to Go's.
		buildable, ok := o.HTTPClient.(*awshttp.BuildableClient)
		require.True(t, ok, "the client must be the SDK's buildable client, got %T", o.HTTPClient)

		transport := buildable.GetTransport()
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
	})

	t.Run("disabled", func(t *testing.T) {
		o := backendOptions(t, proxyconfig.S3BackendConfig{
			TargetEndpoint:     "https://minio:9000",
			InsecureSkipVerify: false,
		})
		assert.Nil(t, o.HTTPClient,
			"without insecure_skip_verify the SDK default transport must be used, which verifies certificates")
	})
}
