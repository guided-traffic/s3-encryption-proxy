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
	// Create S3 client pointing to the proxy on localhost:8080
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

	// Create S3 client pointing to proxy
	proxyClient := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://localhost:8080")
		o.UsePathStyle = true
		// Configure checksum for MinIO compatibility
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
	})

	ctx := context.Background()
	bucketName := "test-delete-objects-bucket"

	// Create bucket via proxy
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyExists") {
		fmt.Printf("Error creating bucket: %v\n", err)
		return
	}

	// Upload two test objects via proxy
	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("object1.txt"),
		Body:   strings.NewReader("content1"),
	})
	if err != nil {
		fmt.Printf("Error uploading object1: %v\n", err)
		return
	}

	_, err = proxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("object2.txt"),
		Body:   strings.NewReader("content2"),
	})
	if err != nil {
		fmt.Printf("Error uploading object2: %v\n", err)
		return
	}

	fmt.Println("✅ Objects uploaded via proxy successfully")

	// Test Delete Objects via proxy - this will test our XML implementation!
	fmt.Println("Testing DeleteObjects via proxy...")
	response, err := proxyClient.DeleteObjects(ctx, &s3.DeleteObjectsInput{
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
		fmt.Printf("❌ Proxy DeleteObjects failed: %v\n", err)
	} else {
		fmt.Printf("✅ Proxy DeleteObjects succeeded! Deleted %d objects\n", len(response.Deleted))
		for _, deleted := range response.Deleted {
			fmt.Printf("  - Deleted: %s\n", aws.ToString(deleted.Key))
		}
		if len(response.Errors) > 0 {
			fmt.Printf("Errors: %d\n", len(response.Errors))
			for _, errItem := range response.Errors {
				fmt.Printf("  - Error: %s - %s\n", aws.ToString(errItem.Key), aws.ToString(errItem.Message))
			}
		}
	}

	fmt.Println("Test completed.")
}
