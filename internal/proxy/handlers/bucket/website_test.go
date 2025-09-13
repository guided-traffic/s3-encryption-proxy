package bucket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWebsiteHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
		expectedBody   string
	}{
		{
			name:           "GET bucket website - success with configuration",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketWebsiteInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					ErrorDocument: &types.ErrorDocument{
						Key: aws.String("error.html"),
					},
				}, nil)
			},
			expectedBody: "index.html",
		},
		{
			name:           "GET bucket website - no configuration",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotFound,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketWebsiteInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return((*s3.GetBucketWebsiteOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not have a website configuration")})
			},
			expectedBody: "NoSuchWebsiteConfiguration",
		},
		{
			name:           "PUT bucket website - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "DELETE bucket website - not implemented",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "POST bucket website - not supported",
			method:         "POST",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not supported method
			},
			expectedBody: "not yet implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?website", nil)
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
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestWebsiteHandler_HandleErrors(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*MockS3Client)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "GET website - bucket does not exist",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketWebsiteOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
		},
		{
			name: "GET website - access denied",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketWebsiteOutput)(nil),
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
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?website", nil)
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
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestWebsiteHandler_ComplexConfigurations(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockS3Client)
		description string
	}{
		{
			name: "Website with index document only",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
				}, nil)
			},
			description: "Website configuration with only index document",
		},
		{
			name: "Website with error document only",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					ErrorDocument: &types.ErrorDocument{
						Key: aws.String("404.html"),
					},
				}, nil)
			},
			description: "Website configuration with only error document",
		},
		{
			name: "Website with custom index and error documents",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("home.html"),
					},
					ErrorDocument: &types.ErrorDocument{
						Key: aws.String("errors/404.html"),
					},
				}, nil)
			},
			description: "Website configuration with custom index and error documents",
		},
		{
			name: "Website with redirect all requests",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
						HostName: aws.String("example.com"),
						Protocol: types.ProtocolHttps,
					},
				}, nil)
			},
			description: "Website configuration redirecting all requests to another host",
		},
		{
			name: "Website with routing rules",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								KeyPrefixEquals: aws.String("docs/"),
							},
							Redirect: &types.Redirect{
								ReplaceKeyPrefixWith: aws.String("documents/"),
							},
						},
					},
				}, nil)
			},
			description: "Website configuration with routing rules for URL redirection",
		},
		{
			name: "Website with HTTP error code redirect",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								HttpErrorCodeReturnedEquals: aws.String("404"),
							},
							Redirect: &types.Redirect{
								ReplaceKeyWith: aws.String("error.html"),
							},
						},
					},
				}, nil)
			},
			description: "Website configuration with HTTP error code handling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?website", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestWebsiteHandler_XMLValidation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid simple website configuration",
			body: `<WebsiteConfiguration>
				<IndexDocument>
					<Suffix>index.html</Suffix>
				</IndexDocument>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard website configuration with index document",
		},
		{
			name: "Valid website with error document",
			body: `<WebsiteConfiguration>
				<IndexDocument>
					<Suffix>index.html</Suffix>
				</IndexDocument>
				<ErrorDocument>
					<Key>error.html</Key>
				</ErrorDocument>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Website configuration with index and error documents",
		},
		{
			name: "Valid website with redirect all",
			body: `<WebsiteConfiguration>
				<RedirectAllRequestsTo>
					<HostName>example.com</HostName>
					<Protocol>https</Protocol>
				</RedirectAllRequestsTo>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Website configuration redirecting all requests",
		},
		{
			name: "Valid website with routing rules",
			body: `<WebsiteConfiguration>
				<IndexDocument>
					<Suffix>index.html</Suffix>
				</IndexDocument>
				<RoutingRules>
					<RoutingRule>
						<Condition>
							<KeyPrefixEquals>docs/</KeyPrefixEquals>
						</Condition>
						<Redirect>
							<ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith>
						</Redirect>
					</RoutingRule>
				</RoutingRules>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Website configuration with routing rules",
		},
		{
			name: "Invalid XML format",
			body: `<WebsiteConfiguration>
				<IndexDocument>
					<Suffix>index.html</Suffix>
				</IndexDocument>`, // Missing closing tag
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Malformed XML should be rejected when implemented",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Empty body should clear website configuration when implemented",
		},
		{
			name: "Invalid protocol",
			body: `<WebsiteConfiguration>
				<RedirectAllRequestsTo>
					<HostName>example.com</HostName>
					<Protocol>ftp</Protocol>
				</RedirectAllRequestsTo>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Invalid protocol should be rejected when implemented",
		},
		{
			name: "Missing required fields",
			body: `<WebsiteConfiguration>
				<IndexDocument>
				</IndexDocument>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Missing required suffix should be rejected when implemented",
		},
		{
			name: "Invalid hostname",
			body: `<WebsiteConfiguration>
				<RedirectAllRequestsTo>
					<HostName></HostName>
					<Protocol>https</Protocol>
				</RedirectAllRequestsTo>
			</WebsiteConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Empty hostname should be rejected when implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("PUT", "/test-bucket?website", strings.NewReader(tt.body))
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

func TestWebsiteHandler_RoutingRuleTypes(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockS3Client)
		description string
	}{
		{
			name: "Key prefix equals condition",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								KeyPrefixEquals: aws.String("old-path/"),
							},
							Redirect: &types.Redirect{
								ReplaceKeyPrefixWith: aws.String("new-path/"),
							},
						},
					},
				}, nil)
			},
			description: "Routing rule with key prefix equals condition",
		},
		{
			name: "HTTP error code condition",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								HttpErrorCodeReturnedEquals: aws.String("404"),
							},
							Redirect: &types.Redirect{
								ReplaceKeyWith: aws.String("error-pages/404.html"),
							},
						},
					},
				}, nil)
			},
			description: "Routing rule with HTTP error code condition",
		},
		{
			name: "Redirect to external host",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								KeyPrefixEquals: aws.String("external/"),
							},
							Redirect: &types.Redirect{
								HostName: aws.String("external.example.com"),
								Protocol: types.ProtocolHttps,
							},
						},
					},
				}, nil)
			},
			description: "Routing rule redirecting to external host",
		},
		{
			name: "Redirect with HTTP code",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
					IndexDocument: &types.IndexDocument{
						Suffix: aws.String("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Condition: &types.Condition{
								KeyPrefixEquals: aws.String("moved/"),
							},
							Redirect: &types.Redirect{
								ReplaceKeyPrefixWith: aws.String("new-location/"),
								HttpRedirectCode:     aws.String("301"),
							},
						},
					},
				}, nil)
			},
			description: "Routing rule with custom HTTP redirect code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?website", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestWebsiteHandler_DocumentSuffixValidation(t *testing.T) {
	tests := []struct {
		name        string
		suffix      string
		expectValid bool
		description string
	}{
		{
			name:        "Standard HTML index",
			suffix:      "index.html",
			expectValid: true,
			description: "Standard index.html should be valid",
		},
		{
			name:        "Custom file extension",
			suffix:      "home.php",
			expectValid: true,
			description: "PHP files should be valid",
		},
		{
			name:        "No extension",
			suffix:      "index",
			expectValid: true,
			description: "Files without extension should be valid",
		},
		{
			name:        "Nested path",
			suffix:      "app/index.html",
			expectValid: true,
			description: "Nested paths should be valid",
		},
		{
			name:        "Deep nested path",
			suffix:      "app/public/dist/index.html",
			expectValid: true,
			description: "Deep nested paths should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client with the test suffix
			mockS3Client := &MockS3Client{}
			mockS3Client.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{
				IndexDocument: &types.IndexDocument{
					Suffix: aws.String(tt.suffix),
				},
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create website handler
			handler := NewWebsiteHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?website", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// All suffixes should be returned as-is from S3
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			assert.Contains(t, w.Body.String(), tt.suffix)
			mockS3Client.AssertExpectations(t)
		})
	}
}
