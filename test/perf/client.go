//go:build perf

package perf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"
)

// Credentials of the demo stack (docker-compose.demo.yml, config/aes-example.yaml).
const (
	minioAccessKey = "minioadmin"
	minioSecretKey = "minioadmin123"
	proxyAccessKey = "username0"
	proxySecretKey = "this-is-not-very-secure"
	testRegion     = "us-east-1"
)

var (
	caPoolOnce sync.Once
	caPool     *x509.CertPool
)

func testCAPool() *x509.CertPool {
	caPoolOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			return
		}
		for i := 0; i < 6; i++ {
			if pem, readErr := os.ReadFile(filepath.Join(dir, "test", "ssl-setup", "ca.crt")); readErr == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(pem) {
					caPool = pool
				}
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return
			}
			dir = parent
		}
	})
	return caPool
}

// httpClientFor builds a transport sized for a throughput measurement: enough
// idle connections that connection setup is not what is being measured.
func httpClientFor(conns int) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        conns * 2,
		MaxIdleConnsPerHost: conns * 2,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		WriteBufferSize:     256 * 1024,
		ReadBufferSize:      256 * 1024,
	}
	if pool := testCAPool(); pool != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	} else {
		// #nosec G402 - local demo stack only, and only when gen-certs.sh output is absent.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Minute}
}

func newS3Client(endpoint, accessKey, secretKey string, conns int) (*s3.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsconfig.WithRegion(testRegion),
		awsconfig.WithHTTPClient(httpClientFor(conns)),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
		// The proxy sends no response checksum, so the SDK warns once per GET.
		// A full run makes hundreds of thousands of requests; the warnings would
		// be the dominant cost of the measurement.
		o.Logger = logging.Nop{}
	}), nil
}

// leg is one side of a comparison: the proxy path or the direct backend path.
type leg struct {
	subject   string // proxy | direct
	transport string // http | tls | n/a
	client    *s3.Client
	bucket    string
}

// legsFor builds the proxy leg for the given transport and the direct leg it is
// compared against. Both are measured in the same run (ADR 0020 D6).
func legsFor(transport string, conns int) ([]leg, error) {
	endpoint, key, secret := proxyHTTPEndpoint, proxyAccessKey, proxySecretKey
	if transport == "tls" {
		endpoint = proxyTLSEndpoint
	}
	proxyClient, err := newS3Client(endpoint, key, secret, conns)
	if err != nil {
		return nil, err
	}
	directClient, err := newS3Client(minioEndpoint, minioAccessKey, minioSecretKey, conns)
	if err != nil {
		return nil, err
	}
	return []leg{
		{subject: "proxy", transport: transport, client: proxyClient, bucket: "perf-" + transport + "-proxy"},
		{subject: "direct", transport: transport, client: directClient, bucket: "perf-" + transport + "-direct"},
	}, nil
}

// ensureBucket creates the bucket unconditionally and tolerates it already
// existing. It deliberately does not probe with HeadBucket first: the proxy
// answers HeadBucket with 200 for a bucket the backend does not have, so the
// probe would report a bucket that is not there.
func ensureBucket(ctx context.Context, c *s3.Client, bucket string) error {
	_, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	if err != nil && !isAlreadyOwned(err) {
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	return nil
}

func isAlreadyOwned(err error) bool {
	s := err.Error()
	return strings.Contains(s, "BucketAlreadyOwnedByYou") || strings.Contains(s, "BucketAlreadyExists")
}

// emptyBucket removes every object, paging to the end. ADR 0020 D13: a baseline
// measured against a backend that grows on every repetition is not a baseline.
func emptyBucket(ctx context.Context, c *s3.Client, bucket string) error {
	p := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchBucket") {
				return nil
			}
			return err
		}
		if len(page.Contents) == 0 {
			continue
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, o := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: o.Key})
		}
		if _, err := c.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		}); err != nil {
			// Some backends refuse a bulk delete; fall back to one by one.
			for _, id := range ids {
				if _, delErr := c.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(bucket), Key: id.Key,
				}); delErr != nil {
					return delErr
				}
			}
		}
	}
	return nil
}
