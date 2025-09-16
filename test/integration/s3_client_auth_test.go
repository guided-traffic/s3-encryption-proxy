//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3ClientAuthentication(t *testing.T) {
	// Test S3 client authentication with current configuration

	t.Run("TestAuthenticationEnabled", func(t *testing.T) {
		// With current demo setup (authentication enabled), only valid credentials should work
		ctx := NewTestContext(t)
		defer ctx.CleanupTestBucket()

		// Test that the proxy rejects invalid credentials when authentication is enabled
		customConfig, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				"anycredentials", // invalid access_key_id should NOT work
				"anypassword",    // invalid secret should NOT work
				"",
			)),
			config.WithRegion("us-east-1"),
		)
		require.NoError(t, err)

		customClient := s3.NewFromConfig(customConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String("http://localhost:8080")
			o.UsePathStyle = true
		})

		// Should NOT be able to list buckets with invalid credentials
		_, err = customClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "InvalidAccessKeyId")
	})

	// Test with valid credentials from configuration
	t.Run("TestAuthenticationValidCredentials", func(t *testing.T) {
		// Test with valid credentials from aes-example.yaml
		validConfig, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				"username0", "this-is-not-very-secure", "")),
			config.WithRegion("us-east-1"),
		)
		require.NoError(t, err)

		validClient := s3.NewFromConfig(validConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String("http://localhost:8080")
			o.UsePathStyle = true
		})

		// Should be able to list buckets with valid credentials
		result, err := validClient.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		require.NoError(t, err)
		assert.NotNil(t, result)
		t.Logf("✅ Authentication successful with valid credentials")
	})
}
