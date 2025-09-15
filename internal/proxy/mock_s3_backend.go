//nolint:revive // Mock S3 client methods follow AWS SDK naming conventions
package proxy

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MockS3Backend provides a mock implementation for testing
type MockS3Backend struct {
	// Mock data storage
	bucketACLs map[string]*types.AccessControlPolicy
	bucketCORS map[string]*types.CORSConfiguration
	bucketInfo map[string]map[string]interface{}

	// Error simulation
	shouldError map[string]error
}

// NewMockS3Backend creates a new mock S3 backend
func NewMockS3Backend() *MockS3Backend {
	return &MockS3Backend{
		bucketACLs:  make(map[string]*types.AccessControlPolicy),
		bucketCORS:  make(map[string]*types.CORSConfiguration),
		bucketInfo:  make(map[string]map[string]interface{}),
		shouldError: make(map[string]error),
	}
}

// SetError configures the mock to return an error for the specified operation
func (m *MockS3Backend) SetError(operation string, err error) {
	m.shouldError[operation] = err
}

// GetBucketAcl implements S3BackendInterface
func (m *MockS3Backend) GetBucketAcl(_ context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
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

// PutBucketAcl implements S3BackendInterface
func (m *MockS3Backend) PutBucketAcl(_ context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	if err, exists := m.shouldError["PutBucketAcl"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if params.AccessControlPolicy != nil {
		m.bucketACLs[bucket] = params.AccessControlPolicy
	}

	return &s3.PutBucketAclOutput{}, nil
}

// GetBucketCors implements S3BackendInterface
func (m *MockS3Backend) GetBucketCors(_ context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
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

// PutBucketCors implements S3BackendInterface
func (m *MockS3Backend) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	if err, exists := m.shouldError["PutBucketCors"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if params.CORSConfiguration != nil {
		m.bucketCORS[bucket] = params.CORSConfiguration
	}

	return &s3.PutBucketCorsOutput{}, nil
}

// DeleteBucketCors implements S3BackendInterface
func (m *MockS3Backend) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	if err, exists := m.shouldError["DeleteBucketCors"]; exists {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	delete(m.bucketCORS, bucket)

	return &s3.DeleteBucketCorsOutput{}, nil
}

// GetBucketVersioning implements S3BackendInterface
func (m *MockS3Backend) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if err, exists := m.shouldError["GetBucketVersioning"]; exists {
		return nil, err
	}

	return &s3.GetBucketVersioningOutput{
		Status: types.BucketVersioningStatusEnabled,
	}, nil
}

// GetBucketAccelerateConfiguration implements S3BackendInterface
func (m *MockS3Backend) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketAccelerateConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketAccelerateConfigurationOutput{
		Status: types.BucketAccelerateStatusEnabled,
	}, nil
}

// GetBucketRequestPayment implements S3BackendInterface
func (m *MockS3Backend) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	if err, exists := m.shouldError["GetBucketRequestPayment"]; exists {
		return nil, err
	}

	return &s3.GetBucketRequestPaymentOutput{
		Payer: types.PayerBucketOwner,
	}, nil
}

// SetBucketACL sets ACL data for a bucket in the mock
func (m *MockS3Backend) SetBucketACL(bucket string, acp *types.AccessControlPolicy) {
	m.bucketACLs[bucket] = acp
}

// SetBucketCORS sets CORS configuration for a bucket in the mock
func (m *MockS3Backend) SetBucketCORS(bucket string, corsConfig *types.CORSConfiguration) {
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

// GetBucketTagging implements S3BackendInterface
func (m *MockS3Backend) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if err, exists := m.shouldError["GetBucketTagging"]; exists {
		return nil, err
	}

	return &s3.GetBucketTaggingOutput{
		TagSet: []types.Tag{
			{Key: aws.String("Environment"), Value: aws.String("test")},
		},
	}, nil
}

// DeleteBucketTagging implements S3BackendInterface
func (m *MockS3Backend) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	if err, exists := m.shouldError["DeleteBucketTagging"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketTaggingOutput{}, nil
}

// GetBucketNotificationConfiguration implements S3BackendInterface
func (m *MockS3Backend) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketNotificationConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketNotificationConfigurationOutput{}, nil
}

// GetBucketLifecycleConfiguration implements S3BackendInterface
func (m *MockS3Backend) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if err, exists := m.shouldError["GetBucketLifecycleConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketLifecycleConfigurationOutput{}, nil
}

// DeleteBucketLifecycle implements S3BackendInterface
func (m *MockS3Backend) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	if err, exists := m.shouldError["DeleteBucketLifecycle"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketLifecycleOutput{}, nil
}

// GetBucketReplicationConfiguration implements S3BackendInterface
func (m *MockS3Backend) GetBucketReplicationConfiguration(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	if err, exists := m.shouldError["GetBucketReplicationConfiguration"]; exists {
		return nil, err
	}

	return &s3.GetBucketReplicationOutput{}, nil
}

// DeleteBucketReplication implements S3BackendInterface
func (m *MockS3Backend) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	if err, exists := m.shouldError["DeleteBucketReplication"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketReplicationOutput{}, nil
}

// GetBucketWebsite implements S3BackendInterface
func (m *MockS3Backend) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	if err, exists := m.shouldError["GetBucketWebsite"]; exists {
		return nil, err
	}

	return &s3.GetBucketWebsiteOutput{}, nil
}

// DeleteBucketWebsite implements S3BackendInterface
func (m *MockS3Backend) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	if err, exists := m.shouldError["DeleteBucketWebsite"]; exists {
		return nil, err
	}

	return &s3.DeleteBucketWebsiteOutput{}, nil
}

// CreateBucket creates a bucket
func (m *MockS3Backend) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	if err := m.shouldError["CreateBucket"]; err != nil {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	if m.bucketInfo[bucket] == nil {
		m.bucketInfo[bucket] = make(map[string]interface{})
	}

	// Create mock response
	output := &s3.CreateBucketOutput{}
	if bucket != "" {
		location := fmt.Sprintf("/%s", bucket)
		output.Location = aws.String(location)
	}

	return output, nil
}

// DeleteBucket deletes a bucket
func (m *MockS3Backend) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	if err := m.shouldError["DeleteBucket"]; err != nil {
		return nil, err
	}

	bucket := aws.ToString(params.Bucket)
	delete(m.bucketInfo, bucket)
	delete(m.bucketACLs, bucket)
	delete(m.bucketCORS, bucket)

	return &s3.DeleteBucketOutput{}, nil
}

// ListBuckets lists all buckets
func (m *MockS3Backend) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := m.shouldError["ListBuckets"]; err != nil {
		return nil, err
	}

	buckets := make([]types.Bucket, 0, len(m.bucketInfo))
	for name := range m.bucketInfo {
		buckets = append(buckets, types.Bucket{
			Name: aws.String(name),
		})
	}

	return &s3.ListBucketsOutput{
		Buckets: buckets,
	}, nil
}

// ListObjectsV2 lists objects using API version 2
func (m *MockS3Backend) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if err := m.shouldError["ListObjectsV2"]; err != nil {
		return nil, err
	}
	return &s3.ListObjectsV2Output{}, nil
}

// ListObjects lists objects
func (m *MockS3Backend) ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error) {
	if err := m.shouldError["ListObjects"]; err != nil {
		return nil, err
	}
	return &s3.ListObjectsOutput{}, nil
}

// CopyObject copies an object
func (m *MockS3Backend) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	if err := m.shouldError["CopyObject"]; err != nil {
		return nil, err
	}
	return &s3.CopyObjectOutput{}, nil
}

// ListParts lists parts of a multipart upload
func (m *MockS3Backend) ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	if err := m.shouldError["ListParts"]; err != nil {
		return nil, err
	}
	return &s3.ListPartsOutput{}, nil
}

// ListMultipartUploads lists multipart uploads
func (m *MockS3Backend) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	if err := m.shouldError["ListMultipartUploads"]; err != nil {
		return nil, err
	}
	return &s3.ListMultipartUploadsOutput{}, nil
}

// GetObjectAcl gets object ACL
func (m *MockS3Backend) GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error) {
	if err := m.shouldError["GetObjectAcl"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectAclOutput{}, nil
}

// PutObjectAcl puts object ACL
func (m *MockS3Backend) PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error) {
	if err := m.shouldError["PutObjectAcl"]; err != nil {
		return nil, err
	}
	return &s3.PutObjectAclOutput{}, nil
}

// GetObjectTagging gets object tagging
func (m *MockS3Backend) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	if err := m.shouldError["GetObjectTagging"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectTaggingOutput{}, nil
}

// PutObjectTagging puts object tagging
func (m *MockS3Backend) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	if err := m.shouldError["PutObjectTagging"]; err != nil {
		return nil, err
	}
	return &s3.PutObjectTaggingOutput{}, nil
}

// DeleteObjectTagging deletes object tagging
func (m *MockS3Backend) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	if err := m.shouldError["DeleteObjectTagging"]; err != nil {
		return nil, err
	}
	return &s3.DeleteObjectTaggingOutput{}, nil
}

// AbortMultipartUpload aborts a multipart upload
func (m *MockS3Backend) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	if err := m.shouldError["AbortMultipartUpload"]; err != nil {
		return nil, err
	}
	return &s3.AbortMultipartUploadOutput{}, nil
}

// CompleteMultipartUpload completes a multipart upload
func (m *MockS3Backend) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	if err := m.shouldError["CompleteMultipartUpload"]; err != nil {
		return nil, err
	}
	return &s3.CompleteMultipartUploadOutput{}, nil
}

// CreateMultipartUpload creates a multipart upload
func (m *MockS3Backend) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	if err := m.shouldError["CreateMultipartUpload"]; err != nil {
		return nil, err
	}
	return &s3.CreateMultipartUploadOutput{
		UploadId: aws.String("mock-upload-id"),
	}, nil
}

// UploadPart uploads a part for multipart upload
func (m *MockS3Backend) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	if err := m.shouldError["UploadPart"]; err != nil {
		return nil, err
	}
	return &s3.UploadPartOutput{
		ETag: aws.String("mock-etag"),
	}, nil
}

// GetObject retrieves an object
func (m *MockS3Backend) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if err := m.shouldError["GetObject"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectOutput{}, nil
}

// PutObject puts an object
func (m *MockS3Backend) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if err := m.shouldError["PutObject"]; err != nil {
		return nil, err
	}
	return &s3.PutObjectOutput{}, nil
}

// HeadObject gets object metadata
func (m *MockS3Backend) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if err := m.shouldError["HeadObject"]; err != nil {
		return nil, err
	}
	return &s3.HeadObjectOutput{}, nil
}

// DeleteObject deletes an object
func (m *MockS3Backend) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if err := m.shouldError["DeleteObject"]; err != nil {
		return nil, err
	}
	return &s3.DeleteObjectOutput{}, nil
}

// Passthrough Operations
// DeleteObjects deletes multiple objects
func (m *MockS3Backend) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	if err := m.shouldError["DeleteObjects"]; err != nil {
		return nil, err
	}
	return &s3.DeleteObjectsOutput{}, nil
}

// GetObjectLegalHold gets object legal hold
func (m *MockS3Backend) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	if err := m.shouldError["GetObjectLegalHold"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectLegalHoldOutput{}, nil
}

// PutObjectLegalHold puts object legal hold
func (m *MockS3Backend) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	if err := m.shouldError["PutObjectLegalHold"]; err != nil {
		return nil, err
	}
	return &s3.PutObjectLegalHoldOutput{}, nil
}

// GetObjectRetention gets object retention
func (m *MockS3Backend) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	if err := m.shouldError["GetObjectRetention"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectRetentionOutput{}, nil
}

// PutObjectRetention puts object retention
func (m *MockS3Backend) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	if err := m.shouldError["PutObjectRetention"]; err != nil {
		return nil, err
	}
	return &s3.PutObjectRetentionOutput{}, nil
}

// GetObjectTorrent gets object torrent
func (m *MockS3Backend) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	if err := m.shouldError["GetObjectTorrent"]; err != nil {
		return nil, err
	}
	return &s3.GetObjectTorrentOutput{}, nil
}

// SelectObjectContent performs S3 Select
func (m *MockS3Backend) SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error) {
	if err := m.shouldError["SelectObjectContent"]; err != nil {
		return nil, err
	}
	return &s3.SelectObjectContentOutput{}, nil
}
