package proxy

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
)

// HTTP method constants
const (
	httpMethodGET    = "GET"
	httpMethodPUT    = "PUT"
	httpMethodDELETE = "DELETE"
)

// writeS3XMLResponse writes an S3 response as XML
func (s *Server) writeS3XMLResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	if err := xml.NewEncoder(w).Encode(data); err != nil {
		s.logger.WithError(err).Error("Failed to write XML response")
	}
}

// ===== BUCKET MANAGEMENT HANDLERS =====

// handleBucketACL handles bucket ACL operations completely
func (s *Server) handleBucketACL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Check if S3 client is available (for testing)
	if s.s3Client == nil {
		s.writeNotImplementedResponse(w, "BucketACL (no S3 client)")
		return
	}

	switch r.Method {
	case httpMethodGET:
		// Get bucket ACL
		output, err := s.s3Client.GetBucketAcl(r.Context(), &s3.GetBucketAclInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket ACL", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)

	case httpMethodPUT:
		// Put bucket ACL - handle both canned ACL and full ACL XML
		input := &s3.PutBucketAclInput{
			Bucket: aws.String(bucket),
		}

		// Check for canned ACL header
		if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
			// Use canned ACL
			input.ACL = types.BucketCannedACL(cannedACL)
		} else {
			// Parse ACL from request body
			body, err := s.readRequestBody(r, bucket, "")
			if err != nil {
				return // Error already handled by readRequestBody
			}

			if len(body) > 0 {
				// Parse XML ACL from body
				var acp types.AccessControlPolicy
				if err := xml.Unmarshal(body, &acp); err != nil {
					s.logger.WithError(err).WithField("bucket", bucket).Error("Failed to parse ACL XML")
					http.Error(w, "Invalid ACL XML format", http.StatusBadRequest)
					return
				}
				input.AccessControlPolicy = &acp
			}
		}

		// Execute the PUT operation
		_, err := s.s3Client.PutBucketAcl(r.Context(), input)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket ACL", bucket, "")
			return
		}

		// Success - no content response
		w.WriteHeader(http.StatusOK)

	default:
		s.writeNotImplementedResponse(w, "BucketACL_"+r.Method)
	}
}

// handleBucketCORS handles bucket CORS operations
func (s *Server) handleBucketCORS(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Check if S3 client is available (for testing)
	if s.s3Client == nil {
		s.writeNotImplementedResponse(w, "BucketCORS (no S3 client)")
		return
	}

	switch r.Method {
	case httpMethodGET:
		output, err := s.s3Client.GetBucketCors(r.Context(), &s3.GetBucketCorsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket CORS", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case httpMethodPUT:
		// Put bucket CORS configuration from request body
		body, err := s.readRequestBody(r, bucket, "")
		if err != nil {
			return // Error already handled by readRequestBody
		}

		if len(body) == 0 {
			s.logger.WithField("bucket", bucket).Error("Empty CORS configuration in request body")
			http.Error(w, "Missing CORS configuration", http.StatusBadRequest)
			return
		}

		// Parse CORS configuration from XML
		var corsConfig types.CORSConfiguration
		if err := xml.Unmarshal(body, &corsConfig); err != nil {
			s.logger.WithError(err).WithField("bucket", bucket).Error("Failed to parse CORS XML")
			http.Error(w, "Invalid CORS XML format", http.StatusBadRequest)
			return
		}

		// Execute the PUT operation
		_, err = s.s3Client.PutBucketCors(r.Context(), &s3.PutBucketCorsInput{
			Bucket:            aws.String(bucket),
			CORSConfiguration: &corsConfig,
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket CORS", bucket, "")
			return
		}

		// Success - no content response
		w.WriteHeader(http.StatusOK)
	case httpMethodDELETE:
		_, err := s.s3Client.DeleteBucketCors(r.Context(), &s3.DeleteBucketCorsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket CORS", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeNotImplementedResponse(w, "BucketCORS_"+r.Method)
	}
}

// handleBucketVersioning handles bucket versioning operations
func (s *Server) handleBucketVersioning(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Check if S3 client is available (for testing)
	if s.s3Client == nil {
		s.writeNotImplementedResponse(w, "BucketVersioning (no S3 client)")
		return
	}

	switch r.Method {
	case httpMethodGET:
		output, err := s.s3Client.GetBucketVersioning(r.Context(), &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket versioning", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case httpMethodPUT:
		s.writeNotImplementedResponse(w, "PutBucketVersioning")
	default:
		s.writeNotImplementedResponse(w, "BucketVersioning_"+r.Method)
	}
}

// handleBucketPolicy handles bucket policy operations - Not implemented
func (s *Server) handleBucketPolicy(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketPolicy")
}

// handleBucketLocation handles bucket location operations - Not implemented
func (s *Server) handleBucketLocation(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketLocation")
}

// handleBucketLogging handles bucket logging operations - Not implemented
func (s *Server) handleBucketLogging(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketLogging")
}

// handleBucketNotification handles bucket notification operations - Not implemented
func (s *Server) handleBucketNotification(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketNotification")
}

// handleBucketTagging handles bucket tagging operations - Not implemented
func (s *Server) handleBucketTagging(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketTagging")
}

// handleBucketLifecycle handles bucket lifecycle operations - Not implemented
func (s *Server) handleBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketLifecycle")
}

// handleBucketReplication handles bucket replication operations - Not implemented
func (s *Server) handleBucketReplication(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketReplication")
}

// handleBucketWebsite handles bucket website operations - Not implemented
func (s *Server) handleBucketWebsite(w http.ResponseWriter, r *http.Request) {
	s.writeNotImplementedResponse(w, "BucketWebsite")
}

// handleBucketAccelerate handles bucket accelerate operations
func (s *Server) handleBucketAccelerate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Check if S3 client is available (for testing)
	if s.s3Client == nil {
		s.writeNotImplementedResponse(w, "BucketAccelerate (no S3 client)")
		return
	}

	switch r.Method {
	case httpMethodGET:
		output, err := s.s3Client.GetBucketAccelerateConfiguration(r.Context(), &s3.GetBucketAccelerateConfigurationInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket accelerate configuration", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case httpMethodPUT:
		s.writeNotImplementedResponse(w, "PutBucketAccelerate")
	default:
		s.writeNotImplementedResponse(w, "BucketAccelerate_"+r.Method)
	}
}

// handleBucketRequestPayment handles bucket request payment operations
func (s *Server) handleBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Check if S3 client is available (for testing)
	if s.s3Client == nil {
		s.writeNotImplementedResponse(w, "BucketRequestPayment (no S3 client)")
		return
	}

	switch r.Method {
	case httpMethodGET:
		output, err := s.s3Client.GetBucketRequestPayment(r.Context(), &s3.GetBucketRequestPaymentInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket request payment", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case httpMethodPUT:
		s.writeNotImplementedResponse(w, "PutBucketRequestPayment")
	default:
		s.writeNotImplementedResponse(w, "BucketRequestPayment_"+r.Method)
	}
}
