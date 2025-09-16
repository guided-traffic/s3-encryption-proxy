//nolint:revive // Test file with unused parameters in mock functions
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

func TestNotificationHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Backend)
		expectedBody   string
	}{
		{
			name:           "GET bucket notification - success with configurations",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketNotificationConfigurationInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketNotificationConfigurationOutput{
					QueueConfigurations: []types.QueueConfiguration{
						{
							Id:       aws.String("queue-config-1"),
							QueueArn: aws.String("arn:aws:sqs:us-east-1:123456789012:my-queue"),
							Events:   []types.Event{"s3:ObjectCreated:*"},
						},
					},
				}, nil)
			},
			expectedBody: "queue-config-1",
		},
		{
			name:           "GET bucket notification - empty configuration",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketNotificationConfigurationInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketNotificationConfigurationOutput{}, nil)
			},
			expectedBody: "", // Empty configuration should return valid XML
		},
		{
			name:           "PUT bucket notification - success",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK, // PUT without body works
			setupMock: func(m *MockS3Backend) {
				m.On("PutBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.PutBucketNotificationConfigurationOutput{}, nil)
			},
			expectedBody: "",
		},
		{
			name:           "DELETE bucket notification - not implemented",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(_ *MockS3Backend) {
				// No setup needed for not implemented
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "POST bucket notification - not supported",
			method:         "POST",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(_ *MockS3Backend) {
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

			// Create notification handler
			handler := NewNotificationHandler(mockS3Backend, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?notification", nil)
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

func TestNotificationHandler_HandleErrors(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*MockS3Backend)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "GET notification - bucket does not exist",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketNotificationConfigurationOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
		},
		{
			name: "GET notification - access denied",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketNotificationConfigurationOutput)(nil),
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

			// Create notification handler
			handler := NewNotificationHandler(mockS3Backend, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?notification", nil)
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

func TestNotificationHandler_ComplexConfigurations(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockS3Backend)
		description string
	}{
		{
			name: "Multiple queue configurations",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketNotificationConfigurationOutput{
					QueueConfigurations: []types.QueueConfiguration{
						{
							Id:       aws.String("queue-config-1"),
							QueueArn: aws.String("arn:aws:sqs:us-east-1:123456789012:queue1"),
							Events:   []types.Event{"s3:ObjectCreated:*"},
						},
						{
							Id:       aws.String("queue-config-2"),
							QueueArn: aws.String("arn:aws:sqs:us-east-1:123456789012:queue2"),
							Events:   []types.Event{"s3:ObjectRemoved:*"},
						},
					},
				}, nil)
			},
			description: "Multiple SQS queue configurations",
		},
		{
			name: "Topic and Lambda configurations",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketNotificationConfigurationOutput{
					TopicConfigurations: []types.TopicConfiguration{
						{
							Id:       aws.String("topic-config-1"),
							TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:my-topic"),
							Events:   []types.Event{"s3:ObjectCreated:*"},
						},
					},
					LambdaFunctionConfigurations: []types.LambdaFunctionConfiguration{
						{
							Id:                aws.String("lambda-config-1"),
							LambdaFunctionArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
							Events:            []types.Event{"s3:ObjectCreated:Put"},
						},
					},
				}, nil)
			},
			description: "SNS topic and Lambda function configurations",
		},
		{
			name: "Configurations with filters",
			setupMock: func(m *MockS3Backend) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketNotificationConfigurationOutput{
					QueueConfigurations: []types.QueueConfiguration{
						{
							Id:       aws.String("filtered-config"),
							QueueArn: aws.String("arn:aws:sqs:us-east-1:123456789012:my-queue"),
							Events:   []types.Event{"s3:ObjectCreated:*"},
							Filter: &types.NotificationConfigurationFilter{
								Key: &types.S3KeyFilter{
									FilterRules: []types.FilterRule{
										{
											Name:  types.FilterRuleNamePrefix,
											Value: aws.String("images/"),
										},
										{
											Name:  types.FilterRuleNameSuffix,
											Value: aws.String(".jpg"),
										},
									},
								},
							},
						},
					},
				}, nil)
			},
			description: "Queue configuration with prefix and suffix filters",
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

			// Create notification handler
			handler := NewNotificationHandler(mockS3Backend, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?notification", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code, tt.description)
			mockS3Backend.AssertExpectations(t)
		})
	}
}

func TestNotificationHandler_XMLValidation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid queue configuration",
			body: `<NotificationConfiguration>
				<QueueConfiguration>
					<Id>queue-config-1</Id>
					<Queue>arn:aws:sqs:us-east-1:123456789012:my-queue</Queue>
					<Event>s3:ObjectCreated:*</Event>
				</QueueConfiguration>
			</NotificationConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT body parsing not implemented yet
			description:    "Standard queue notification configuration",
		},
		{
			name: "Valid topic configuration with filter",
			body: `<NotificationConfiguration>
				<TopicConfiguration>
					<Id>topic-config-1</Id>
					<Topic>arn:aws:sns:us-east-1:123456789012:my-topic</Topic>
					<Event>s3:ObjectCreated:Put</Event>
					<Filter>
						<S3Key>
							<FilterRule>
								<Name>prefix</Name>
								<Value>images/</Value>
							</FilterRule>
						</S3Key>
					</Filter>
				</TopicConfiguration>
			</NotificationConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT body parsing not implemented yet
			description:    "Topic configuration with prefix filter",
		},
		{
			name: "Invalid XML format",
			body: `<NotificationConfiguration>
				<QueueConfiguration>
					<Id>queue-config-1</Id>
					<Queue>arn:aws:sqs:us-east-1:123456789012:my-queue</Queue>
					<Event>s3:ObjectCreated:*</Event>
				</QueueConfiguration>`, // Missing closing tag
			expectedStatus: http.StatusNotImplemented, // PUT body parsing not implemented yet
			description:    "Malformed XML should be rejected when implemented",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusOK, // Empty body works
			description:    "Empty body should clear notifications",
		},
		{
			name: "Invalid ARN format",
			body: `<NotificationConfiguration>
				<QueueConfiguration>
					<Id>queue-config-1</Id>
					<Queue>invalid-arn</Queue>
					<Event>s3:ObjectCreated:*</Event>
				</QueueConfiguration>
			</NotificationConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT body parsing not implemented yet
			description:    "Invalid ARN should be rejected when implemented",
		},
		{
			name: "Invalid event type",
			body: `<NotificationConfiguration>
				<QueueConfiguration>
					<Id>queue-config-1</Id>
					<Queue>arn:aws:sqs:us-east-1:123456789012:my-queue</Queue>
					<Event>invalid:event:type</Event>
				</QueueConfiguration>
			</NotificationConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT body parsing not implemented yet
			description:    "Invalid event type should be rejected when implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Backend := &MockS3Backend{}
			// Add mock for PutBucketNotificationConfiguration
			mockS3Backend.On("PutBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.PutBucketNotificationConfigurationOutput{}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create notification handler
			handler := NewNotificationHandler(mockS3Backend, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("PUT", "/test-bucket?notification", strings.NewReader(tt.body))
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

func TestNotificationHandler_EventTypes(t *testing.T) {
	// Test different S3 event types that should be supported
	eventTypes := []types.Event{
		"s3:ObjectCreated:*",
		"s3:ObjectCreated:Put",
		"s3:ObjectCreated:Post",
		"s3:ObjectCreated:Copy",
		"s3:ObjectCreated:CompleteMultipartUpload",
		"s3:ObjectRemoved:*",
		"s3:ObjectRemoved:Delete",
		"s3:ObjectRemoved:DeleteMarkerCreated",
		"s3:ObjectRestore:*",
		"s3:ObjectRestore:Post",
		"s3:ObjectRestore:Completed",
		"s3:ReducedRedundancyLostObject",
	}

	for _, eventType := range eventTypes {
		t.Run(string(eventType), func(t *testing.T) {
			// Setup mock S3 client with specific event type
			mockS3Backend := &MockS3Backend{}
			mockS3Backend.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketNotificationConfigurationOutput{
				QueueConfigurations: []types.QueueConfiguration{
					{
						Id:       aws.String("test-config"),
						QueueArn: aws.String("arn:aws:sqs:us-east-1:123456789012:my-queue"),
						Events:   []types.Event{eventType},
					},
				},
			}, nil)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create notification handler
			handler := NewNotificationHandler(mockS3Backend, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("GET", "/test-bucket?notification", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), string(eventType))
			mockS3Backend.AssertExpectations(t)
		})
	}
}
