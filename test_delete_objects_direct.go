package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {
	// Create S3 client pointing to MinIO
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin123", "")),
		config.WithRegion("us-east-1"),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}),
	)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("https://localhost:9000")
		o.UsePathStyle = true
		// Configure checksum for MinIO compatibility
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
	})

	ctx := context.Background()
	bucketName := "test-delete-bucket"

	// Create bucket
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyExists") {
		fmt.Printf("Error creating bucket: %v\n", err)
		return
	}

	// Upload two test objects
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("object1.txt"),
		Body:   strings.NewReader("content1"),
	})
	if err != nil {
		fmt.Printf("Error uploading object1: %v\n", err)
		return
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("object2.txt"),
		Body:   strings.NewReader("content2"),
	})
	if err != nil {
		fmt.Printf("Error uploading object2: %v\n", err)
		return
	}

	fmt.Println("✅ Objects uploaded successfully")

	// Test Delete Objects directly to MinIO (should work)
	fmt.Println("Testing DeleteObjects directly to MinIO...")
	_, err = client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: aws.String("object1.txt")},
				{Key: aws.String("object2.txt")},
			},
			Quiet: aws.Bool(false),
		},
	})

	if err != nil {
		fmt.Printf("❌ Direct MinIO DeleteObjects failed: %v\n", err)
	} else {
		fmt.Println("✅ Direct MinIO DeleteObjects succeeded")
	}

	fmt.Println("Test completed.")
}
