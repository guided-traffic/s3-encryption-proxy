package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func main() {
	// Configure AWS S3 client to connect to our proxy
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String("us-east-1"),
		Endpoint:         aws.String("http://localhost:8080"),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      credentials.NewStaticCredentials("username0", "this-is-not-very-secure", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	s3Client := s3.New(sess)

	bucketName := "test-logging-bucket"
	objectKey := "test-multipart-object.txt"

	// Create bucket if it doesn't exist
	_, err = s3Client.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		fmt.Printf("Note: Bucket might already exist: %v\n", err)
	}

	// Create multipart upload
	multipartInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}

	createResp, err := s3Client.CreateMultipartUpload(multipartInput)
	if err != nil {
		log.Fatalf("Failed to create multipart upload: %v", err)
	}

	uploadID := *createResp.UploadId
	fmt.Printf("Created multipart upload with ID: %s\n", uploadID)

	// Upload a few parts
	var parts []*s3.CompletedPart
	partSize := 5 * 1024 * 1024 // 5MB per part

	for partNum := 1; partNum <= 3; partNum++ {
		data := bytes.Repeat([]byte(fmt.Sprintf("Part %d data ", partNum)), partSize/20)
		if len(data) > partSize {
			data = data[:partSize]
		}

		uploadPartInput := &s3.UploadPartInput{
			Bucket:     aws.String(bucketName),
			Key:        aws.String(objectKey),
			PartNumber: aws.Int64(int64(partNum)),
			UploadId:   aws.String(uploadID),
			Body:       bytes.NewReader(data),
		}

		uploadPartResp, err := s3Client.UploadPart(uploadPartInput)
		if err != nil {
			log.Fatalf("Failed to upload part %d: %v", partNum, err)
		}

		parts = append(parts, &s3.CompletedPart{
			ETag:       uploadPartResp.ETag,
			PartNumber: aws.Int64(int64(partNum)),
		})

		fmt.Printf("Uploaded part %d with ETag: %s\n", partNum, *uploadPartResp.ETag)
	}

	// Complete multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	_, err = s3Client.CompleteMultipartUpload(completeInput)
	if err != nil {
		log.Fatalf("Failed to complete multipart upload: %v", err)
	}

	fmt.Printf("Successfully completed multipart upload\n")
	fmt.Printf("Check proxy logs for improved metadata logging\n")
}
