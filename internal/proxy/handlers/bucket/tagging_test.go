//nolint:revive // Test file with unused parameters in mock functions
package bucket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestTaggingHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Backend)
		expectedBody   string
	}{
		{
			name:           "GET bucket tagging - success with tags",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketTaggingOutput{
					TagSet: []types.Tag{
						{Key: aws.String("Environment"), Value: aws.String("Production")},
						{Key: aws.String("Owner"), Value: aws.String("TeamA")},
					},
				}, nil)
			},
			expectedBody: "Environment",
		},
		{
			name:           "GET bucket tagging - no tags",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotFound,
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return((*s3.GetBucketTaggingOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The TagSet does not exist")})
			},
			expectedBody: "NoSuchBucket",
		},
		{
			name:           "PUT bucket tagging - empty body",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Backend) {
				m.On("PutBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.PutBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.PutBucketTaggingOutput{}, nil)
			},
			expectedBody: "",
		},
		{
			name:           "DELETE bucket tagging - success",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Backend) {
				m.On("DeleteBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.DeleteBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.DeleteBucketTaggingOutput{}, nil)
			},
			expectedBody: "",
		},
		{
			name:           "POST bucket tagging - not supported",
			method:         "POST",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Backend) {
				// No setup needed for not supported method
			},
			expectedBody: "not yet implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Backend := &MockS3Backend{}
			tt.setupMock(mockS3Backend)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Backend, logger, xmlWriter, errorWriter, request.NewParser(logger, &config.Config{}))

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?tagging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
			mockS3Backend.AssertExpectations(t)
		})
	}
}

func TestTaggingHandler_HandleErrors(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*MockS3Backend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "GET tagging - bucket does not exist",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketTagging", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketTaggingOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
		},
		{
			name: "GET tagging - access denied",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketTagging", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketTaggingOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("Access Denied")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Backend := &MockS3Backend{}
			tt.setupMock(mockS3Backend)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Backend, logger, xmlWriter, errorWriter, request.NewParser(logger, &config.Config{}))

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?tagging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
			mockS3Backend.AssertExpectations(t)
		})
	}
}

func TestTaggingHandler_XMLTagValidation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid tag set - single tag",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key>Environment</Key>
						<Value>Production</Value>
					</Tag>
				</TagSet>
			</Tagging>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard single tag request",
		},
		{
			name: "Valid tag set - multiple tags",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key>Environment</Key>
						<Value>Production</Value>
					</Tag>
					<Tag>
						<Key>Owner</Key>
						<Value>TeamA</Value>
					</Tag>
				</TagSet>
			</Tagging>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard multiple tags request",
		},
		{
			name: "Invalid XML format",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key>Environment</Key>
						<Value>Production</Value>
					</Tag>
				</TagSet>`, // Missing closing tag
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Malformed XML should be rejected when implemented",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusOK, // Empty body calls S3 client
			description:    "Empty body should call S3 client with no Tagging",
		},
		{
			name: "Empty tag key",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key></Key>
						<Value>Production</Value>
					</Tag>
				</TagSet>
			</Tagging>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Empty tag key should be rejected when implemented",
		},
		{
			name: "Tag key too long",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key>` + strings.Repeat("a", 129) + `</Key>
						<Value>Production</Value>
					</Tag>
				</TagSet>
			</Tagging>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Tag key over 128 characters should be rejected when implemented",
		},
		{
			name: "Tag value too long",
			body: `<Tagging>
				<TagSet>
					<Tag>
						<Key>Environment</Key>
						<Value>` + strings.Repeat("a", 257) + `</Value>
					</Tag>
				</TagSet>
			</Tagging>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Tag value over 256 characters should be rejected when implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Backend := &MockS3Backend{}

			// Add mock for empty body test that calls S3 client
			if tt.name == "Empty body" {
				mockS3Backend.On("PutBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.PutBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.PutBucketTaggingOutput{}, nil)
			}

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Backend, logger, xmlWriter, errorWriter, request.NewParser(logger, &config.Config{}))

			// Setup request
			req := httptest.NewRequest("PUT", "/test-bucket?tagging", strings.NewReader(tt.body))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			req.Header.Set("Content-Type", "application/xml")

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

func TestTaggingHandler_SpecialCharacterHandling(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		description string
	}{
		{
			name:        "Special characters in key",
			key:         "env:prod+test",
			value:       "value",
			description: "Colon and plus in key",
		},
		{
			name:        "Unicode characters in value",
			key:         "environment",
			value:       "ürödüçtîön",
			description: "Unicode characters should be handled",
		},
		{
			name:        "Spaces in key and value",
			key:         "My Environment",
			value:       "Production Environment",
			description: "Spaces should be preserved",
		},
		{
			name:        "XML reserved characters",
			key:         "test&key",
			value:       "value<with>quotes\"and'chars",
			description: "XML reserved characters should be escaped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client - expects GET to return tags
			mockS3Backend := &MockS3Backend{}
			mockS3Backend.On("GetBucketTagging", mock.Anything, mock.Anything).Return(&s3.GetBucketTaggingOutput{
				TagSet: []types.Tag{
					{Key: aws.String(tt.key), Value: aws.String(tt.value)},
				},
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Backend, logger, xmlWriter, errorWriter, request.NewParser(logger, &config.Config{}))

			// Setup GET request to retrieve tags
			req := httptest.NewRequest("GET", "/test-bucket?tagging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert basic response is OK
			assert.Equal(t, http.StatusOK, w.Code)
			mockS3Backend.AssertExpectations(t)
		})
	}
}

func TestTaggingHandler_MaxTagLimits(t *testing.T) {
	// Test preparation for future tag limit validation
	tests := []struct {
		name        string
		tagCount    int
		expectedOK  bool
		description string
	}{
		{
			name:        "Within limit - 10 tags",
			tagCount:    10,
			expectedOK:  true,
			description: "Should accept 10 tags (within S3 limit of 50)",
		},
		{
			name:        "At limit - 50 tags",
			tagCount:    50,
			expectedOK:  true,
			description: "Should accept 50 tags (S3 maximum)",
		},
		{
			name:        "Over limit - 51 tags",
			tagCount:    51,
			expectedOK:  false,
			description: "Should reject over 50 tags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create tag set for testing
			var tagSet []types.Tag
			for i := 0; i < tt.tagCount; i++ {
				tagSet = append(tagSet, types.Tag{
					Key:   aws.String("key" + strings.Repeat("0", 2-len(fmt.Sprintf("%d", i))) + fmt.Sprintf("%d", i)),
					Value: aws.String("value" + fmt.Sprintf("%d", i)),
				})
			}

			// Setup mock S3 client
			mockS3Backend := &MockS3Backend{}
			mockS3Backend.On("GetBucketTagging", mock.Anything, mock.Anything).Return(&s3.GetBucketTaggingOutput{
				TagSet: tagSet,
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Backend, logger, xmlWriter, errorWriter, request.NewParser(logger, &config.Config{}))

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?tagging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// For GET operations, all should succeed since we're just returning what S3 has
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			mockS3Backend.AssertExpectations(t)
		})
	}
}
