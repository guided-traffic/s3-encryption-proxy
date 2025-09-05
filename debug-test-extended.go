package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

const testData = "This is a test file for debugging AES-CTR encryption and decryption."

func main() {
	ctx := context.Background()

	// Test 1: Manual AES-CTR provider behavior
	fmt.Println("=== Testing AES-CTR Provider Behavior ===")
	testAESCTRProvider(ctx)

	// Test 2: MinIO directly (port 9000)
	fmt.Println("\n=== Testing MinIO directly (port 9000) ===")
	testMinIODirect(ctx)

	// Test 3: Encryption Proxy (port 8080)
	fmt.Println("\n=== Testing Encryption Proxy (port 8080) ===")
	testEncryptionProxy(ctx)
}

func testAESCTRProvider(ctx context.Context) {
	provider := providers.NewAESCTRProvider("Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9v") // base64 encoded 32-byte key

	// Create IV and DEK
	iv, dek, err := provider.GenerateDataKey(ctx)
	if err != nil {
		log.Printf("Failed to generate data key: %v", err)
		return
	}

	fmt.Printf("Original data: %q (%d bytes)\n", testData, len(testData))
	fmt.Printf("DEK: %x\n", dek)
	fmt.Printf("IV: %x\n", iv)

	// Encrypt with counter 0
	encrypted, err := provider.EncryptStream(ctx, []byte(testData), dek, iv, 0)
	if err != nil {
		log.Printf("Failed to encrypt: %v", err)
		return
	}
	fmt.Printf("Encrypted (counter=0): %x\n", encrypted)

	// Decrypt with counter 0
	decrypted, err := provider.DecryptStream(ctx, encrypted, dek, iv, 0)
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		return
	}
	fmt.Printf("Decrypted: %q (%d bytes)\n", string(decrypted), len(decrypted))

	if string(decrypted) == testData {
		fmt.Println("✓ AES-CTR Provider works correctly!")
	} else {
		fmt.Println("✗ AES-CTR Provider has issues!")
	}
}

func testMinIODirect(ctx context.Context) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithEndpointResolverV2(aws.EndpointResolverV2Func(func(ctx context.Context, params aws.EndpointParameters) (aws.Endpoint, error) {
			return aws.Endpoint{
				URI:               "http://localhost:9000",
				HostnameImmutable: true,
			}, nil
		})),
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     "minioadmin",
				SecretAccessKey: "minioadmin",
			}, nil
		})),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucketName := "debug-test-bucket-direct"
	objectKey := "debug-test-object.txt"

	fmt.Printf("Testing bucket: %s, object: %s\n", bucketName, objectKey)

	// Create bucket (ignore errors if already exists)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		fmt.Printf("Create bucket failed: %v\n", err)
	}

	// Upload object
	fmt.Printf("Uploading object: %s\n", objectKey)
	result, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader([]byte(testData)),
	})
	if err != nil {
		log.Printf("Failed to upload object: %v", err)
		return
	}
	fmt.Printf("✓ Uploaded object, ETag: %s\n", aws.ToString(result.ETag))

	// Download object
	fmt.Printf("Downloading object: %s\n", objectKey)
	getResult, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		log.Printf("Failed to download object: %v", err)
		return
	}

	var downloadedData bytes.Buffer
	downloadedData.ReadFrom(getResult.Body)
	getResult.Body.Close()

	fmt.Printf("✓ Downloaded object, size: %d bytes\n", downloadedData.Len())

	fmt.Printf("Original data: %q\n", testData)
	fmt.Printf("Retrieved data: %q\n", downloadedData.String())

	if downloadedData.String() == testData {
		fmt.Println("✓ Data integrity verified!")
	} else {
		log.Printf("MinIO direct test failed: DATA MISMATCH! Original: %q, Retrieved: %q", testData, downloadedData.String())
	}
}

func testEncryptionProxy(ctx context.Context) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithEndpointResolverV2(aws.EndpointResolverV2Func(func(ctx context.Context, params aws.EndpointParameters) (aws.Endpoint, error) {
			return aws.Endpoint{
				URI:               "http://localhost:8080",
				HostnameImmutable: true,
			}, nil
		})),
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     "minioadmin",
				SecretAccessKey: "minioadmin",
			}, nil
		})),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucketName := "debug-test-bucket-proxy"
	objectKey := "debug-test-object.txt"

	fmt.Printf("Testing bucket: %s, object: %s\n", bucketName, objectKey)

	// Create bucket (ignore errors if already exists)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		fmt.Printf("Create bucket failed: %v\n", err)
	}

	// Upload object
	fmt.Printf("Uploading object: %s\n", objectKey)
	result, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader([]byte(testData)),
	})
	if err != nil {
		log.Printf("Failed to upload object: %v", err)
		return
	}
	fmt.Printf("✓ Uploaded object, ETag: %s\n", aws.ToString(result.ETag))

	// Download object
	fmt.Printf("Downloading object: %s\n", objectKey)
	getResult, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		log.Printf("Failed to download object: %v", err)
		return
	}

	var downloadedData bytes.Buffer
	downloadedData.ReadFrom(getResult.Body)
	getResult.Body.Close()

	fmt.Printf("✓ Downloaded object, size: %d bytes\n", downloadedData.Len())

	fmt.Printf("Original data: %q\n", testData)
	fmt.Printf("Retrieved data: %q\n", downloadedData.String())

	if downloadedData.String() == testData {
		fmt.Println("✓ Data integrity verified!")
	} else {
		// Print hex for debugging
		fmt.Printf("Retrieved data (hex): %x\n", downloadedData.Bytes())
		log.Printf("Encryption proxy test failed: DATA MISMATCH! Original: %q, Retrieved: %q", testData, downloadedData.String())
	}
}
