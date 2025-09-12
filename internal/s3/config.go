package s3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/sirupsen/logrus"
)

// Config holds S3 client configuration
type Config struct {
	Endpoint       string
	Region         string
	AccessKeyID    string
	SecretKey      string
	MetadataPrefix string
	DisableSSL     bool
	ForcePathStyle bool
	SegmentSize    int64 // Streaming segment size in bytes
}

// Client wraps the AWS S3 client with encryption capabilities
type Client struct {
	s3Client       *s3.Client
	encryptionMgr  *encryption.Manager
	metadataPrefix string
	segmentSize    int64
	logger         *logrus.Entry
	metadata       *MetadataHandler
}

// GetRawS3Client returns the underlying raw S3 client for direct operations
func (c *Client) GetRawS3Client() *s3.Client {
	return c.s3Client
}

// GetMetadataPrefix returns the metadata prefix used for encryption metadata
func (c *Client) GetMetadataPrefix() string {
	return c.metadataPrefix
}

// NewClient creates a new S3 client with encryption capabilities
func NewClient(cfg *Config, encMgr *encryption.Manager, logger *logrus.Logger) (*Client, error) {
	// Create AWS configuration with TLS support for self-signed certificates
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretKey,
			"",
		)),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 - Required for testing with self-signed certificates in development
				},
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom endpoint if provided
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.ForcePathStyle
	})

	return &Client{
		s3Client:       s3Client,
		encryptionMgr:  encMgr,
		metadataPrefix: cfg.MetadataPrefix,
		segmentSize:    cfg.SegmentSize,
		logger:         logger.WithField("component", "s3-client"),
		metadata:       NewMetadataHandler(cfg.MetadataPrefix),
	}, nil
}
