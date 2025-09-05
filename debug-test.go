package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.Background()

	// Configure AWS SDK for both MinIO direct and Proxy with TLS support
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For self-signed certificates
				},
			},
		}),
	)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Test data
	bucketName := "debug-test-bucket"
	objectKey := "debug-test-object.txt"
	testData := "This is a test file for debugging AES-CTR encryption and decryption."

	// Test MinIO directly first
	fmt.Println("=== Testing MinIO directly (port 9000) ===")
	minioClient := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("https://localhost:9000")
		o.UsePathStyle = true
	})

	err = testEndpoint(ctx, minioClient, bucketName+"-direct", objectKey, testData)
	if err != nil {
		log.Printf("MinIO direct test failed: %v", err)
	}

	// Test through encryption proxy
	fmt.Println("\n=== Testing Encryption Proxy (port 8080) ===")
	proxyClient := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://localhost:8080")
		o.UsePathStyle = true
	})

	err = testEndpoint(ctx, proxyClient, bucketName+"-proxy", objectKey, testData)
	if err != nil {
		log.Printf("Encryption proxy test failed: %v", err)
	}
}

func testEndpoint(ctx context.Context, client *s3.Client, bucketName, objectKey, testData string) error {
	fmt.Printf("Testing bucket: %s, object: %s\n", bucketName, objectKey)

	// Create bucket
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		fmt.Printf("Create bucket failed: %v\n", err)
		// Continue anyway, bucket might already exist
	} else {
		fmt.Printf("✓ Created bucket: %s\n", bucketName)
	}

	// Wait a moment for bucket to be ready
	time.Sleep(1 * time.Second)

	// Put object
	fmt.Printf("Uploading object: %s\n", objectKey)
	putResult, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader([]byte(testData)),
	})
	if err != nil {
		return fmt.Errorf("PutObject failed: %w", err)
	}
	fmt.Printf("✓ Uploaded object, ETag: %s\n", aws.ToString(putResult.ETag))

	// Get object
	fmt.Printf("Downloading object: %s\n", objectKey)
	getResult, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("GetObject failed: %w", err)
	}

	// Read response body
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(getResult.Body)
	if err != nil {
		return fmt.Errorf("Reading response body failed: %w", err)
	}
	getResult.Body.Close()

	retrievedData := buf.String()
	fmt.Printf("✓ Downloaded object, size: %d bytes\n", len(retrievedData))
	fmt.Printf("Original data: %q\n", testData)
	fmt.Printf("Retrieved data: %q\n", retrievedData)

	// Print raw bytes for analysis
	rawBytes := buf.Bytes()
	fmt.Printf("Raw bytes (%d):\n", len(rawBytes))
	for i := 0; i < len(rawBytes) && i < 64; i += 16 { // Show first 64 bytes
		end := i + 16
		if end > len(rawBytes) {
			end = len(rawBytes)
		}
		chunk := rawBytes[i:end]
		fmt.Printf("  %04x: %x\n", i, chunk)
	}

	if retrievedData != testData {
		return fmt.Errorf("DATA MISMATCH! Original: %q, Retrieved: %q", testData, retrievedData)
	}

	fmt.Printf("✓ Data integrity verified!\n")

	// Check metadata for encryption proxy
	if getResult.Metadata != nil && len(getResult.Metadata) > 0 {
		fmt.Printf("Object metadata:\n")
		for k, v := range getResult.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Clean up
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		fmt.Printf("Warning: Failed to delete object: %v\n", err)
	}

	return nil
}
