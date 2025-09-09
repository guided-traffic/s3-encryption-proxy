//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// Performance test sizes
const (
	PerfSize10MB  = 10 * 1024 * 1024   // 10 MB
	PerfSize50MB  = 50 * 1024 * 1024   // 50 MB  
	PerfSize100MB = 100 * 1024 * 1024  // 100 MB
	PerfSize500MB = 500 * 1024 * 1024  // 500 MB
)

// PerformanceResult holds the results of a performance test
type PerformanceResult struct {
	FileSize         int64
	UploadTime       time.Duration
	DownloadTime     time.Duration
	UploadThroughput float64 // MB/s
	DownloadThroughput float64 // MB/s
	TotalTime        time.Duration
}

// TestStreamingPerformance tests the performance of streaming upload and download
func TestStreamingPerformance(t *testing.T) {
	// Ensure services are available
	EnsureMinIOAndProxyAvailable(t)

	ctx := context.Background()
	testBucket := fmt.Sprintf("perf-test-%d", time.Now().Unix())

	// Create proxy client
	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	require.NoError(t, err, "Failed to create test bucket")

	// Cleanup
	defer func() {
		CleanupTestBucket(t, proxyClient, testBucket)
	}()

	// Test cases with different file sizes
	testSizes := []struct {
		name string
		size int64
	}{
		{"10MB", PerfSize10MB},
		{"50MB", PerfSize50MB},
		{"100MB", PerfSize100MB},
		{"500MB", PerfSize500MB},
	}

	results := make([]PerformanceResult, 0, len(testSizes))

	t.Log("=== Streaming Performance Test Results ===")
	t.Log("Size\t\tUpload Time\tDownload Time\tUpload MB/s\tDownload MB/s\tTotal Time")
	t.Log("------------------------------------------------------------------------")

	for _, testCase := range testSizes {
		t.Run(fmt.Sprintf("Performance_%s", testCase.name), func(t *testing.T) {
			result := runPerformanceTest(t, ctx, proxyClient, testBucket, testCase.size)
			results = append(results, result)

			// Log results immediately
			t.Logf("%s\t\t%v\t\t%v\t\t%.2f\t\t%.2f\t\t%v",
				testCase.name,
				result.UploadTime.Truncate(time.Millisecond),
				result.DownloadTime.Truncate(time.Millisecond),
				result.UploadThroughput,
				result.DownloadThroughput,
				result.TotalTime.Truncate(time.Millisecond))
		})
	}

	// Print summary
	t.Log("\n=== Performance Summary ===")
	var totalUploadTime, totalDownloadTime time.Duration
	var totalBytes int64
	
	for _, result := range results {
		totalUploadTime += result.UploadTime
		totalDownloadTime += result.DownloadTime
		totalBytes += result.FileSize
	}

	avgUploadThroughput := float64(totalBytes) / (1024 * 1024) / totalUploadTime.Seconds()
	avgDownloadThroughput := float64(totalBytes) / (1024 * 1024) / totalDownloadTime.Seconds()

	t.Logf("Total Bytes Transferred: %d MB", totalBytes/(1024*1024))
	t.Logf("Total Upload Time: %v", totalUploadTime.Truncate(time.Millisecond))
	t.Logf("Total Download Time: %v", totalDownloadTime.Truncate(time.Millisecond))
	t.Logf("Average Upload Throughput: %.2f MB/s", avgUploadThroughput)
	t.Logf("Average Download Throughput: %.2f MB/s", avgDownloadThroughput)
}

// runPerformanceTest performs a single performance test with the given file size
func runPerformanceTest(t *testing.T, ctx context.Context, client *s3.Client, bucket string, fileSize int64) PerformanceResult {
	testKey := fmt.Sprintf("perf-test-%d-bytes-%d", fileSize, time.Now().UnixNano())

	// Generate random test data
	t.Logf("Generating %d MB of test data...", fileSize/(1024*1024))
	testData := make([]byte, fileSize)
	_, err := io.ReadFull(rand.Reader, testData)
	require.NoError(t, err, "Failed to generate test data")

	// Create uploader with proper configuration for performance testing
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		// Use optimal part size for streaming (same as our proxy configuration)
		u.PartSize = 5 * 1024 * 1024 // 5 MB
		u.Concurrency = 3           // Match proxy concurrency
	})

	// Measure upload performance
	t.Logf("Starting upload of %d MB...", fileSize/(1024*1024))
	uploadStart := time.Now()
	
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(testKey),
		Body:   bytes.NewReader(testData),
	})
	require.NoError(t, err, "Failed to upload test file")
	
	uploadTime := time.Since(uploadStart)
	uploadThroughput := float64(fileSize) / (1024 * 1024) / uploadTime.Seconds()

	// Measure download performance  
	t.Logf("Starting download of %d MB...", fileSize/(1024*1024))
	downloadStart := time.Now()
	
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err, "Failed to get test file")
	
	// Read all data to measure actual download time
	downloadedData, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read downloaded data")
	
	downloadTime := time.Since(downloadStart)
	downloadThroughput := float64(fileSize) / (1024 * 1024) / downloadTime.Seconds()

	// Verify data integrity
	require.Equal(t, len(testData), len(downloadedData), "Downloaded data size mismatch")
	require.Equal(t, testData, downloadedData, "Downloaded data content mismatch")

	// Clean up test object
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(testKey),
	})
	require.NoError(t, err, "Failed to delete test object")

	totalTime := uploadTime + downloadTime

	return PerformanceResult{
		FileSize:           fileSize,
		UploadTime:         uploadTime,
		DownloadTime:       downloadTime,
		UploadThroughput:   uploadThroughput,
		DownloadThroughput: downloadThroughput,
		TotalTime:          totalTime,
	}
}

// BenchmarkStreamingUpload provides Go benchmark tests for streaming uploads
func BenchmarkStreamingUpload(b *testing.B) {
	// Skip if not in integration test mode
	EnsureBenchmarkEnvironment(b)

	ctx := context.Background()
	testBucket := fmt.Sprintf("bench-upload-%d", time.Now().Unix())

	// Create proxy client
	proxyClient, err := createProxyClient()
	if err != nil {
		b.Fatalf("Failed to create Proxy client: %v", err)
	}

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	if err != nil {
		b.Fatalf("Failed to create test bucket: %v", err)
	}

	// Cleanup
	defer func() {
		cleanupBenchmarkBucket(b, proxyClient, testBucket)
	}()

	// Generate 10MB test data once
	testData := make([]byte, PerfSize10MB)
	_, err = io.ReadFull(rand.Reader, testData)
	if err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	uploader := manager.NewUploader(proxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
		u.Concurrency = 3
	})

	b.ResetTimer()
	b.SetBytes(PerfSize10MB)

	for i := 0; i < b.N; i++ {
		testKey := fmt.Sprintf("bench-test-%d", i)
		
		_, err := uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket: aws.String(testBucket),
			Key:    aws.String(testKey),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			b.Fatalf("Upload failed: %v", err)
		}

		// Clean up immediately to avoid storage bloat
		_, err = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(testBucket),
			Key:    aws.String(testKey),
		})
		if err != nil {
			b.Fatalf("Cleanup failed: %v", err)
		}
	}
}

// BenchmarkStreamingDownload provides Go benchmark tests for streaming downloads
func BenchmarkStreamingDownload(b *testing.B) {
	// Skip if not in integration test mode
	EnsureBenchmarkEnvironment(b)

	ctx := context.Background()
	testBucket := fmt.Sprintf("bench-download-%d", time.Now().Unix())

	// Create proxy client
	proxyClient, err := createProxyClient()
	if err != nil {
		b.Fatalf("Failed to create Proxy client: %v", err)
	}

	// Setup test bucket
	_, err = proxyClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	if err != nil {
		b.Fatalf("Failed to create test bucket: %v", err)
	}

	// Cleanup
	defer func() {
		cleanupBenchmarkBucket(b, proxyClient, testBucket)
	}()

	// Pre-upload test file
	testData := make([]byte, PerfSize10MB)
	_, err = io.ReadFull(rand.Reader, testData)
	if err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	testKey := "bench-download-test-file"
	uploader := manager.NewUploader(proxyClient)
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String(testKey),
		Body:   bytes.NewReader(testData),
	})
	if err != nil {
		b.Fatalf("Failed to upload test file: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(PerfSize10MB)

	for i := 0; i < b.N; i++ {
		resp, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(testBucket),
			Key:    aws.String(testKey),
		})
		if err != nil {
			b.Fatalf("Download failed: %v", err)
		}

		// Read all data to measure complete download
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			b.Fatalf("Failed to read downloaded data: %v", err)
		}
	}
}

// EnsureBenchmarkEnvironment ensures benchmark tests have proper environment
func EnsureBenchmarkEnvironment(b *testing.B) {
	// Convert testing.B to testing.T for reuse of existing function
	t := &testing.T{}
	EnsureMinIOAndProxyAvailable(t)
	if t.Failed() {
		b.Skip("Required services not available for benchmarking")
	}
}

// cleanupBenchmarkBucket handles cleanup for benchmark tests
func cleanupBenchmarkBucket(b *testing.B, client *s3.Client, bucket string) {
	ctx := context.Background()
	
	// List and delete all objects first
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err == nil && listResp.Contents != nil {
		for _, obj := range listResp.Contents {
			client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			})
		}
	}

	// Delete the bucket
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		b.Logf("Warning: Failed to delete test bucket %s: %v", bucket, err)
	}
}
