package proxy

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MockS3Client provides a mock implementation for testing
type MockS3Client struct {
	// Mock data storage
	bucketACLs map[string]*types.AccessControlPolicy
	bucketCORS map[string]*types.CORSConfiguration
	bucketInfo map[string]map[string]interface{}

	// Error simulation
	shouldError map[string]error
}

// NewMockS3Client creates a new mock S3 client
func NewMockS3Client() *MockS3Client {
	return &MockS3Client{
		bucketACLs:  make(map[string]*types.AccessControlPolicy),
		bucketCORS:  make(map[string]*types.CORSConfiguration),
		bucketInfo:  make(map[string]map[string]interface{}),
		shouldError: make(map[string]error),
	}
}

// SetError configures the mock to return an error for the specified operation
func (m *MockS3Client) SetError(operation string, err error) {
	m.shouldError[operation] = err
}

// GetBucketAcl implements S3ClientInterface
func (m *MockS3Client) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if err, exists := m.shouldError["GetBucketAcl"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if acl, exists := m.bucketACLs[bucket]; exists {
		return &s3.GetBucketAclOutput{
			Owner:  acl.Owner,
			Grants: acl.Grants,
		}, nil
	}

	// Default ACL for testing
	return &s3.GetBucketAclOutput{
		Owner: &types.Owner{
			DisplayName: aws.String("test-owner"),
			ID:          aws.String("test-owner-id"),
		},
		Grants: []types.Grant{
			{
				Grantee: &types.Grantee{
					Type:        types.TypeCanonicalUser,
					ID:          aws.String("test-owner-id"),
					DisplayName: aws.String("test-owner"),
				},
				Permission: types.PermissionFullControl,
			},
		},
	}, nil
}

// PutBucketAcl implements S3ClientInterface
func (m *MockS3Client) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	if err, exists := m.shouldError["PutBucketAcl"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if params.AccessControlPolicy != nil {
		m.bucketACLs[bucket] = params.AccessControlPolicy
	}

	return &s3.PutBucketAclOutput{}, nil
}

// GetBucketCors implements S3ClientInterface
func (m *MockS3Client) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	if err, exists := m.shouldError["GetBucketCors"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if corsConfig, exists := m.bucketCORS[bucket]; exists {
		return &s3.GetBucketCorsOutput{
			CORSRules: corsConfig.CORSRules,
		}, nil
	}

	// Default CORS configuration for testing
	return &s3.GetBucketCorsOutput{
		CORSRules: []types.CORSRule{
			{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET"},
				AllowedHeaders: []string{"*"},
				MaxAgeSeconds:  aws.Int32(3600),
			},
		},
	}, nil
}

// PutBucketCors implements S3ClientInterface
func (m *MockS3Client) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	if err, exists := m.shouldError["PutBucketCors"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if params.CORSConfiguration != nil {
		m.bucketCORS[bucket] = params.CORSConfiguration
	}

	return &s3.PutBucketCorsOutput{}, nil
}

// DeleteBucketCors implements S3ClientInterface
func (m *MockS3Client) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	if err, exists := m.shouldError["DeleteBucketCors"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	delete(m.bucketCORS, bucket)

	return &s3.DeleteBucketCorsOutput{}, nil
}

// GetBucketVersioning implements S3ClientInterface
func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if err, exists := m.shouldError["GetBucketVersioning"]; exists {
		return nil, err
	}

	return &s3.GetBucketVersioningOutput{
		Status: types.BucketVersioningStatusEnabled,
	}, nil
}

// GetBucketAccelerateConfiguration implements S3ClientInterface
func (m *MockS3Client) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketAccelerateConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketAccelerateConfigurationOutput{
		Status: types.BucketAccelerateStatusEnabled,
	}, nil
}

// GetBucketRequestPayment implements S3ClientInterface
func (m *MockS3Client) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	if err, exists := m.shouldError["GetBucketRequestPayment"]; exists {
		return nil, err
	}

	return &s3.GetBucketRequestPaymentOutput{
		Payer: types.PayerBucketOwner,
	}, nil
}

// SetBucketACL sets ACL data for a bucket in the mock
func (m *MockS3Client) SetBucketACL(bucket string, acp *types.AccessControlPolicy) {
	m.bucketACLs[bucket] = acp
}

// SetBucketCORS sets CORS configuration for a bucket in the mock
func (m *MockS3Client) SetBucketCORS(bucket string, corsConfig *types.CORSConfiguration) {
	m.bucketCORS[bucket] = corsConfig
}

// Helper function to create ACL from XML for testing
func CreateACLFromXML(xmlStr string) (*types.AccessControlPolicy, error) {
	var acp types.AccessControlPolicy
	err := xml.Unmarshal([]byte(xmlStr), &acp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACL XML: %w", err)
	}
	return &acp, nil
}

// GetBucketTagging implements S3ClientInterface
func (m *MockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if err, exists := m.shouldError["GetBucketTagging"]; exists {
		return nil, err
	}

	return &s3.GetBucketTaggingOutput{
		TagSet: []types.Tag{
			{Key: aws.String("Environment"), Value: aws.String("test")},
		},
	}, nil
}

// DeleteBucketTagging implements S3ClientInterface
func (m *MockS3Client) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	if err, exists := m.shouldError["DeleteBucketTagging"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketTaggingOutput{}, nil
}

// GetBucketNotificationConfiguration implements S3ClientInterface
func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketNotificationConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketNotificationConfigurationOutput{}, nil
}

// GetBucketLifecycleConfiguration implements S3ClientInterface
func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketLifecycleConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketLifecycleConfigurationOutput{}, nil
}

// DeleteBucketLifecycle implements S3ClientInterface
func (m *MockS3Client) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	if err, exists := m.shouldError["DeleteBucketLifecycle"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketLifecycleOutput{}, nil
}

// GetBucketReplicationConfiguration implements S3ClientInterface
func (m *MockS3Client) GetBucketReplicationConfiguration(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	if err, exists := m.shouldError["GetBucketReplicationConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketReplicationOutput{}, nil
}

// DeleteBucketReplication implements S3ClientInterface
func (m *MockS3Client) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	if err, exists := m.shouldError["DeleteBucketReplication"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketReplicationOutput{}, nil
}

// GetBucketWebsite implements S3ClientInterface
func (m *MockS3Client) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	if err, exists := m.shouldError["GetBucketWebsite"]; exists {
		return nil, err
	}

	return &s3.GetBucketWebsiteOutput{}, nil
}

// DeleteBucketWebsite implements S3ClientInterface
func (m *MockS3Client) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	if err, exists := m.shouldError["DeleteBucketWebsite"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketWebsiteOutput{}, nil
}
