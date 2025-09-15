package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// BucketLoggingStatus represents the XML structure for bucket logging configuration
// BucketLoggingStatus represents bucket logging configuration status
//
//nolint:revive // Exported type name matches S3 API context
type BucketLoggingStatus struct {
	XMLName        xml.Name        `xml:"BucketLoggingStatus"`
	LoggingEnabled *LoggingEnabled `xml:"LoggingEnabled,omitempty"`
}

// LoggingEnabled represents the logging configuration
type LoggingEnabled struct {
	TargetBucket *string        `xml:"TargetBucket,omitempty"`
	TargetPrefix *string        `xml:"TargetPrefix,omitempty"`
	TargetGrants *[]TargetGrant `xml:"TargetGrants>Grant,omitempty"`
}

// TargetGrant represents a grant for the target bucket
type TargetGrant struct {
	Grantee    *Grantee `xml:"Grantee,omitempty"`
	Permission *string  `xml:"Permission,omitempty"`
}

// Grantee represents a grantee in the logging configuration
type Grantee struct {
	XMLName      xml.Name `xml:"Grantee"`
	Type         string   `xml:"type,attr"`
	ID           *string  `xml:"ID,omitempty"`
	DisplayName  *string  `xml:"DisplayName,omitempty"`
	EmailAddress *string  `xml:"EmailAddress,omitempty"`
	URI          *string  `xml:"URI,omitempty"`
}

// LoggingHandler handles bucket logging operations
type LoggingHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *LoggingHandler {
	return &LoggingHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket logging operations (?logging)
func (h *LoggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket logging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLogging(w, r, bucket)
	case http.MethodPut:
		h.handlePutLogging(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteLogging(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketLogging_"+r.Method)
	}
}

// handleGetLogging handles GET bucket logging requests
func (h *LoggingHandler) handleGetLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket logging configuration")

	input := &s3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.GetBucketLogging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Convert AWS SDK output to S3 API BucketLoggingStatus format
	loggingStatus := &BucketLoggingStatus{}

	if output.LoggingEnabled != nil {
		loggingEnabled := &LoggingEnabled{}

		if output.LoggingEnabled.TargetBucket != nil {
			loggingEnabled.TargetBucket = output.LoggingEnabled.TargetBucket
		}

		if output.LoggingEnabled.TargetPrefix != nil {
			loggingEnabled.TargetPrefix = output.LoggingEnabled.TargetPrefix
		}

		// Convert grants if present
		if len(output.LoggingEnabled.TargetGrants) > 0 {
			var grants []TargetGrant
			for _, awsGrant := range output.LoggingEnabled.TargetGrants {
				grant := TargetGrant{}

				// Convert permission
				switch awsGrant.Permission {
				case types.BucketLogsPermissionFullControl:
					permission := "FULL_CONTROL"
					grant.Permission = &permission
				case types.BucketLogsPermissionRead:
					permission := "READ"
					grant.Permission = &permission
				case types.BucketLogsPermissionWrite:
					permission := "WRITE"
					grant.Permission = &permission
				}

				// Convert grantee
				if awsGrant.Grantee != nil {
					grantee := &Grantee{}

					switch awsGrant.Grantee.Type {
					case types.TypeCanonicalUser:
						grantee.Type = "CanonicalUser"
						if awsGrant.Grantee.ID != nil {
							grantee.ID = awsGrant.Grantee.ID
						}
						if awsGrant.Grantee.DisplayName != nil {
							grantee.DisplayName = awsGrant.Grantee.DisplayName
						}
					case types.TypeAmazonCustomerByEmail:
						grantee.Type = "AmazonCustomerByEmail"
						if awsGrant.Grantee.EmailAddress != nil {
							grantee.EmailAddress = awsGrant.Grantee.EmailAddress
						}
					case types.TypeGroup:
						grantee.Type = "Group"
						if awsGrant.Grantee.URI != nil {
							grantee.URI = awsGrant.Grantee.URI
						}
					}

					grant.Grantee = grantee
				}

				grants = append(grants, grant)
			}
			loggingEnabled.TargetGrants = &grants
		}

		loggingStatus.LoggingEnabled = loggingEnabled
	}

	h.xmlWriter.WriteXML(w, loggingStatus)
}

// handlePutLogging handles PUT bucket logging requests
func (h *LoggingHandler) handlePutLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket logging configuration")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Validate that body is not empty
	if len(body) == 0 {
		h.logger.WithField("bucket", bucket).Error("Empty logging configuration in request body")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML", "Request body cannot be empty for logging configuration")
		return
	}

	input := &s3.PutBucketLoggingInput{
		Bucket: aws.String(bucket),
	}

	// Parse XML body
	var loggingConfig BucketLoggingStatus
	if err := xml.Unmarshal(body, &loggingConfig); err != nil {
		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"error":  err,
		}).Error("Failed to parse logging configuration XML")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML format")
		return
	}

	// Convert to AWS SDK types
	if loggingConfig.LoggingEnabled != nil {
		loggingEnabled := &types.LoggingEnabled{}

		if loggingConfig.LoggingEnabled.TargetBucket != nil {
			loggingEnabled.TargetBucket = loggingConfig.LoggingEnabled.TargetBucket
		}

		if loggingConfig.LoggingEnabled.TargetPrefix != nil {
			loggingEnabled.TargetPrefix = loggingConfig.LoggingEnabled.TargetPrefix
		}

		// Convert grants if present
		if loggingConfig.LoggingEnabled.TargetGrants != nil {
			var grants []types.TargetGrant
			for _, grant := range *loggingConfig.LoggingEnabled.TargetGrants {
				awsGrant := types.TargetGrant{}

				if grant.Permission != nil {
					switch *grant.Permission {
					case "FULL_CONTROL":
						awsGrant.Permission = types.BucketLogsPermissionFullControl
					case "READ":
						awsGrant.Permission = types.BucketLogsPermissionRead
					case "WRITE":
						awsGrant.Permission = types.BucketLogsPermissionWrite
					}
				}

				if grant.Grantee != nil {
					grantee := &types.Grantee{}

					switch grant.Grantee.Type {
					case "CanonicalUser":
						grantee.Type = types.TypeCanonicalUser
						if grant.Grantee.ID != nil {
							grantee.ID = grant.Grantee.ID
						}
						if grant.Grantee.DisplayName != nil {
							grantee.DisplayName = grant.Grantee.DisplayName
						}
					case "AmazonCustomerByEmail":
						grantee.Type = types.TypeAmazonCustomerByEmail
						if grant.Grantee.EmailAddress != nil {
							grantee.EmailAddress = grant.Grantee.EmailAddress
						}
					case "Group":
						grantee.Type = types.TypeGroup
						if grant.Grantee.URI != nil {
							grantee.URI = grant.Grantee.URI
						}
					}

					awsGrant.Grantee = grantee
				}

				grants = append(grants, awsGrant)
			}
			loggingEnabled.TargetGrants = grants
		}

		input.BucketLoggingStatus = &types.BucketLoggingStatus{
			LoggingEnabled: loggingEnabled,
		}
	} else {
		// Empty logging configuration - disable logging
		input.BucketLoggingStatus = &types.BucketLoggingStatus{}
	}

	_, err = h.s3Client.PutBucketLogging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteLogging handles DELETE bucket logging requests
func (h *LoggingHandler) handleDeleteLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Disabling bucket logging configuration")

	// To disable logging, we send an empty BucketLoggingStatus via PUT
	input := &s3.PutBucketLoggingInput{
		Bucket:              aws.String(bucket),
		BucketLoggingStatus: &types.BucketLoggingStatus{
			// Empty LoggingEnabled means logging is disabled
		},
	}

	_, err := h.s3Client.PutBucketLogging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Return empty logging status to confirm deletion
	loggingStatus := &BucketLoggingStatus{
		// No LoggingEnabled means logging is disabled
	}

	h.xmlWriter.WriteXML(w, loggingStatus)
}
