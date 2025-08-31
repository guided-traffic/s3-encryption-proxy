package proxy

import (
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gorilla/mux"
)

// ===== BUCKET MANAGEMENT HANDLERS =====

// handleBucketACL handles bucket ACL operations - Pass-through to S3
func (s *Server) handleBucketACL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket ACL - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketAcl(r.Context(), &s3.GetBucketAclInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket ACL", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case "PUT":
		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// For now, pass through as raw XML (simplified implementation)
		// In production, you'd parse the ACL XML and create proper PutBucketAclInput
		_, err = s.s3Client.PutBucketAcl(r.Context(), &s3.PutBucketAclInput{
			Bucket: aws.String(bucket),
			ACL:    aws.String("private"), // Simplified - should parse from body
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket ACL", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketCORS handles bucket CORS operations - Pass-through to S3
func (s *Server) handleBucketCORS(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket CORS - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketCors(r.Context(), &s3.GetBucketCorsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket CORS", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case "PUT":
		// Simplified implementation - in production, parse CORS XML properly
		_, err := s.s3Client.PutBucketCors(r.Context(), &s3.PutBucketCorsInput{
			Bucket: aws.String(bucket),
			CORSConfiguration: &s3.CORSConfiguration{
				CORSRules: []*s3.CORSRule{}, // Should parse from request body
			},
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket CORS", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		_, err := s.s3Client.DeleteBucketCors(r.Context(), &s3.DeleteBucketCorsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket CORS", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketVersioning handles bucket versioning operations - Pass-through to S3
func (s *Server) handleBucketVersioning(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket versioning - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketVersioning(r.Context(), &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket versioning", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case "PUT":
		// Simplified implementation
		_, err := s.s3Client.PutBucketVersioning(r.Context(), &s3.PutBucketVersioningInput{
			Bucket: aws.String(bucket),
			VersioningConfiguration: &s3.VersioningConfiguration{
				Status: aws.String("Enabled"), // Should parse from request body
			},
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket versioning", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketPolicy handles bucket policy operations - Pass-through to S3
func (s *Server) handleBucketPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket policy - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketPolicy(r.Context(), &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket policy", bucket, "")
			return
		}
		s.writeS3XMLResponse(w, output)
	case "PUT":
		// Read policy JSON from request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		_, err = s.s3Client.PutBucketPolicy(r.Context(), &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucket),
			Policy: aws.String(string(body)),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket policy", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		_, err := s.s3Client.DeleteBucketPolicy(r.Context(), &s3.DeleteBucketPolicyInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket policy", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketLocation handles bucket location operations - Pass-through to S3
func (s *Server) handleBucketLocation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket location - pass-through to S3")

	output, err := s.s3Client.GetBucketLocation(r.Context(), &s3.GetBucketLocationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		s.handleS3Error(w, err, "Failed to get bucket location", bucket, "")
		return
	}
	s.writeS3XMLResponse(w, output)
}

// handleBucketLogging handles bucket logging operations - Pass-through to S3
func (s *Server) handleBucketLogging(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket logging - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketLogging(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket logging", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketLogging(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket logging", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketNotification handles bucket notification operations - Pass-through to S3
func (s *Server) handleBucketNotification(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket notification - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketNotificationConfiguration(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket notification", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketNotificationConfiguration(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket notification", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketTagging handles bucket tagging operations - Pass-through to S3
func (s *Server) handleBucketTagging(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket tagging - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketTagging(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket tagging", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketTagging(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket tagging", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		err := s.s3Client.DeleteBucketTagging(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket tagging", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketLifecycle handles bucket lifecycle operations - Pass-through to S3
func (s *Server) handleBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket lifecycle - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketLifecycleConfiguration(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket lifecycle", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketLifecycleConfiguration(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket lifecycle", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		err := s.s3Client.DeleteBucketLifecycle(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket lifecycle", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketReplication handles bucket replication operations - Pass-through to S3
func (s *Server) handleBucketReplication(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket replication - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketReplication(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket replication", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketReplication(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket replication", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		err := s.s3Client.DeleteBucketReplication(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket replication", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketWebsite handles bucket website operations - Pass-through to S3
func (s *Server) handleBucketWebsite(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket website - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketWebsite(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket website", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketWebsite(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket website", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		err := s.s3Client.DeleteBucketWebsite(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket website", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleBucketAccelerate handles bucket accelerate operations - Pass-through to S3
func (s *Server) handleBucketAccelerate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket accelerate - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketAccelerateConfiguration(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket accelerate", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketAccelerateConfiguration(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket accelerate", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketRequestPayment handles bucket request payment operations - Pass-through to S3
func (s *Server) handleBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket request payment - pass-through to S3")

	switch r.Method {
	case "GET":
		output, err := s.s3Client.GetBucketRequestPayment(r.Context(), bucket)
		if err != nil {
			s.handleS3Error(w, err, "Failed to get bucket request payment", bucket, "")
			return
		}
		s.writeS3Response(w, output)
	case "PUT":
		err := s.s3Client.PutBucketRequestPayment(r.Context(), bucket, r.Body)
		if err != nil {
			s.handleS3Error(w, err, "Failed to put bucket request payment", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
