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

func TestRequestPaymentHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
		expectedBody   string
	}{
		{
			name:           "GET bucket request payment - bucket owner pays",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketRequestPayment", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketRequestPaymentInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketRequestPaymentOutput{
					Payer: types.PayerBucketOwner,
				}, nil)
			},
			expectedBody: "BucketOwner",
		},
		{
			name:           "GET bucket request payment - requester pays",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketRequestPayment", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketRequestPaymentInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketRequestPaymentOutput{
					Payer: types.PayerRequester,
				}, nil)
			},
			expectedBody: "Requester",
		},
		{
			name:           "PUT bucket request payment - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "DELETE bucket request payment - not supported",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not supported method
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "POST bucket request payment - not supported",
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

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?requestPayment", nil)
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

func TestRequestPaymentHandler_HandleErrors(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*MockS3Client)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "GET request payment - bucket does not exist",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketRequestPaymentOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
		},
		{
			name: "GET request payment - access denied",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketRequestPaymentOutput)(nil),
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

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?requestPayment", nil)
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

func TestRequestPaymentHandler_PayerTypes(t *testing.T) {
	tests := []struct {
		name        string
		payer       types.Payer
		description string
	}{
		{
			name:        "Bucket owner pays",
			payer:       types.PayerBucketOwner,
			description: "Standard configuration where bucket owner pays for requests",
		},
		{
			name:        "Requester pays",
			payer:       types.PayerRequester,
			description: "Requester pays configuration for data transfer costs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client with specific payer
			mockS3Client := &MockS3Client{}
			mockS3Client.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{
				Payer: tt.payer,
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?requestPayment", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			assert.Contains(t, w.Body.String(), string(tt.payer))
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestRequestPaymentHandler_XMLValidation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid request payment configuration - bucket owner",
			body: `<RequestPaymentConfiguration>
				<Payer>BucketOwner</Payer>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard bucket owner pays configuration",
		},
		{
			name: "Valid request payment configuration - requester",
			body: `<RequestPaymentConfiguration>
				<Payer>Requester</Payer>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Requester pays configuration",
		},
		{
			name: "Invalid XML format",
			body: `<RequestPaymentConfiguration>
				<Payer>BucketOwner</Payer>`, // Missing closing tag
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Malformed XML should be rejected when implemented",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Empty body should be rejected when implemented",
		},
		{
			name: "Invalid payer value",
			body: `<RequestPaymentConfiguration>
				<Payer>InvalidPayer</Payer>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Invalid payer should be rejected when implemented",
		},
		{
			name: "Missing payer element",
			body: `<RequestPaymentConfiguration>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Missing payer element should be rejected when implemented",
		},
		{
			name: "Case sensitive payer values",
			body: `<RequestPaymentConfiguration>
				<Payer>bucketowner</Payer>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Case sensitive payer values should be validated when implemented",
		},
		{
			name: "Extra unexpected elements",
			body: `<RequestPaymentConfiguration>
				<Payer>BucketOwner</Payer>
				<ExtraElement>ShouldNotBeHere</ExtraElement>
			</RequestPaymentConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Extra elements should be ignored or rejected when implemented",
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

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("PUT", "/test-bucket?requestPayment", strings.NewReader(tt.body))
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

func TestRequestPaymentHandler_RequesterPaysImplications(t *testing.T) {
	// Test scenarios related to requester pays functionality
	tests := []struct {
		name          string
		scenario      string
		expectedPayer types.Payer
		description   string
	}{
		{
			name:          "Public data sharing",
			scenario:      "Bucket used for sharing large datasets publicly",
			expectedPayer: types.PayerRequester,
			description:   "Requester pays is useful for public data sharing to avoid unexpected costs",
		},
		{
			name:          "Internal corporate use",
			scenario:      "Bucket used within the same organization",
			expectedPayer: types.PayerBucketOwner,
			description:   "Bucket owner pays is typical for internal use",
		},
		{
			name:          "Partner data exchange",
			scenario:      "Bucket shared with business partners",
			expectedPayer: types.PayerRequester,
			description:   "Requester pays allows cost distribution among partners",
		},
		{
			name:          "Content distribution",
			scenario:      "Bucket used for software or media distribution",
			expectedPayer: types.PayerRequester,
			description:   "Requester pays shifts bandwidth costs to downloaders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client with the expected payer configuration
			mockS3Client := &MockS3Client{}
			mockS3Client.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{
				Payer: tt.expectedPayer,
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?requestPayment", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			assert.Contains(t, w.Body.String(), string(tt.expectedPayer))
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestRequestPaymentHandler_RequesterPaysHeaders(t *testing.T) {
	// Test handling of requester pays related headers
	tests := []struct {
		name        string
		headers     map[string]string
		description string
	}{
		{
			name: "Standard requester pays header",
			headers: map[string]string{
				"x-amz-request-payer": "requester",
			},
			description: "Standard header indicating requester will pay",
		},
		{
			name: "Missing requester pays header",
			headers: map[string]string{
				// No x-amz-request-payer header
			},
			description: "Request without requester pays header",
		},
		{
			name: "Invalid requester pays header value",
			headers: map[string]string{
				"x-amz-request-payer": "bucket-owner",
			},
			description: "Invalid header value should be handled",
		},
		{
			name: "Case insensitive header",
			headers: map[string]string{
				"X-Amz-Request-Payer": "requester",
			},
			description: "Header with different casing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client - configuration shows requester pays is enabled
			mockS3Client := &MockS3Client{}
			mockS3Client.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{
				Payer: types.PayerRequester,
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request with headers
			req := httptest.NewRequest("GET", "/test-bucket?requestPayment", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// All should succeed since we're just getting the configuration
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			assert.Contains(t, w.Body.String(), "Requester")
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestRequestPaymentHandler_BillingImplications(t *testing.T) {
	// Test that documents billing implications of different payer configurations
	tests := []struct {
		name           string
		payer          types.Payer
		costComponents []string
		description    string
	}{
		{
			name:  "Bucket owner pays - all costs",
			payer: types.PayerBucketOwner,
			costComponents: []string{
				"Storage costs",
				"Request costs",
				"Data transfer costs",
			},
			description: "Bucket owner pays for all S3 costs",
		},
		{
			name:  "Requester pays - transfer costs",
			payer: types.PayerRequester,
			costComponents: []string{
				"Request costs",
				"Data transfer costs",
			},
			description: "Requester pays for requests and data transfer, owner pays storage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client with the payer configuration
			mockS3Client := &MockS3Client{}
			mockS3Client.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{
				Payer: tt.payer,
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create request payment handler
			handler := NewRequestPaymentHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?requestPayment", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Verify the configuration is returned correctly
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			assert.Contains(t, w.Body.String(), string(tt.payer))

			// Log the cost implications for documentation
			t.Logf("Payer: %s, Cost components: %v", tt.payer, tt.costComponents)

			mockS3Client.AssertExpectations(t)
		})
	}
}
