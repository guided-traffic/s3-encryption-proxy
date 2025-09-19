//go:build integration
// +build integration

package performance_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	// Import helper functions from the main integration package
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// Performance test sizes
const (
	PerfSize10MB  = 10 * 1024 * 1024  // 10 MB
	PerfSize50MB  = 50 * 1024 * 1024  // 50 MB
	PerfSize100MB = 100 * 1024 * 1024 // 100 MB
	PerfSize500MB = 500 * 1024 * 1024 // 500 MB

	// Test bucket name - consistent across all tests
	PerfTestBucketName = "performance-test-bucket"
)

// PerformanceResult holds the results of a performance test
type PerformanceResult struct {
	FileSize           int64
	UploadTime         time.Duration
	DownloadTime       time.Duration
	UploadThroughput   float64 // MB/s
	DownloadThroughput float64 // MB/s
	TotalTime          time.Duration
}

// TestStreamingPerformance tests the performance of streaming upload and download
func TestStreamingPerformance(t *testing.T) {
	// Ensure services are available
	EnsureMinIOAndProxyAvailable(t)

	// Create test context with MinIO test helper
	tc := NewTestContext(t)
	defer func() {
		// Keep test data for manual inspection - only clean up on explicit request
		if os.Getenv("CLEANUP_AFTER_PERFORMANCE_TEST") == "true" {
			tc.CleanupTestBucket()
			t.Log("Test data cleaned up (CLEANUP_AFTER_PERFORMANCE_TEST=true)")
		} else {
			t.Logf("Test data preserved in bucket '%s' for manual inspection. Set CLEANUP_AFTER_PERFORMANCE_TEST=true to clean up.", tc.TestBucket)
		}
	}()

	// Use consistent bucket name for performance tests
	testBucket := PerfTestBucketName

	// Clear any existing data in the performance test bucket
	clearPerformanceTestBucket(t, tc.ProxyClient, testBucket)

	// Ensure the test bucket exists
	_, err := tc.ProxyClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		require.NoError(t, err, "Failed to create performance test bucket")
	}

	// Test cases with different file sizes
	allTestSizes := []struct {
		size int64
		name string
	}{
		{100 * 1024, "100KB"},        // 100KB
		{500 * 1024, "500KB"},        // 500KB
		{1 * 1024 * 1024, "1MB"},     // 1MB
		{3 * 1024 * 1024, "3MB"},     // 3MB
		{5 * 1024 * 1024, "5MB"},     // 5MB
		{10 * 1024 * 1024, "10MB"},   // 10MB
		{50 * 1024 * 1024, "50MB"},   // 50MB
		{100 * 1024 * 1024, "100MB"}, // 100MB
		{500 * 1024 * 1024, "500MB"}, // 500MB
		{1024 * 1024 * 1024, "1GB"},  // 1GB
	}

	// Filter test sizes based on QUICK_MODE environment variable
	var testSizes []struct {
		size int64
		name string
	}
	if os.Getenv("QUICK_MODE") == "true" {
		// Quick mode: only test up to 10MB
		for _, testSize := range allTestSizes {
			if testSize.size <= 10*1024*1024 {
				testSizes = append(testSizes, testSize)
			}
		}
		t.Log("=== QUICK MODE: Testing files up to 10MB only ===")
	} else {
		testSizes = allTestSizes
		t.Log("=== FULL MODE: Testing files from 100KB to 1GB ===")
	}

	results := make([]PerformanceResult, 0, len(testSizes))

	t.Log("=== Streaming Performance Test Results ===")
	t.Log("Size\t\tUpload Time\tDownload Time\tUpload MB/s\tDownload MB/s\tTotal Time")
	t.Log("------------------------------------------------------------------------")

	for _, testCase := range testSizes {
		t.Run(fmt.Sprintf("Performance_%s", testCase.name), func(t *testing.T) {
			result := runPerformanceTest(t, tc.Ctx, tc.ProxyClient, testBucket, testCase.size, testCase.name)
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
func runPerformanceTest(t *testing.T, ctx context.Context, client *s3.Client, bucket string, fileSize int64, sizeName string) PerformanceResult {
	testKey := fmt.Sprintf("perf-test-%s-%d", sizeName, time.Now().UnixNano())

	// Generate random test data
	t.Logf("Generating %d MB of test data...", fileSize/(1024*1024))
	testData := make([]byte, fileSize)
	_, err := io.ReadFull(rand.Reader, testData)
	require.NoError(t, err, "Failed to generate test data")

	// Create uploader with proper configuration for performance testing
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		// Use optimal part size for streaming (same as our proxy configuration)
		u.PartSize = 5 * 1024 * 1024 // 5 MB
		u.Concurrency = 3            // Match proxy concurrency
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

	// Verify data integrity using SHA256 hash comparison to avoid hexdumps
	require.Equal(t, len(testData), len(downloadedData), "Downloaded data size mismatch")

	originalHash := sha256.Sum256(testData)
	downloadedHash := sha256.Sum256(downloadedData)
	require.Equal(t, originalHash, downloadedHash, "Downloaded data content mismatch - SHA256 hash verification failed")

	// Keep test object for manual inspection - don't delete immediately
	// Only clean up if explicitly requested via environment variable
	if os.Getenv("CLEANUP_OBJECTS_AFTER_PERFORMANCE_TEST") == "true" {
		_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(testKey),
		})
		require.NoError(t, err, "Failed to delete test object")
	}

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

// clearPerformanceTestBucket removes all objects from the performance test bucket
func clearPerformanceTestBucket(t *testing.T, client *s3.Client, bucketName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List all objects in the bucket
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// If bucket doesn't exist, that's fine - it will be created
		if strings.Contains(err.Error(), "NoSuchBucket") {
			t.Logf("Performance test bucket '%s' doesn't exist yet - will be created", bucketName)
			return
		}
		t.Logf("Warning: Failed to list objects in performance test bucket '%s': %v", bucketName, err)
		return
	}

	// Delete all objects
	if len(listResp.Contents) > 0 {
		t.Logf("Clearing %d existing objects from performance test bucket '%s'", len(listResp.Contents), bucketName)
		for _, obj := range listResp.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				t.Logf("Warning: Failed to delete object '%s' from bucket '%s': %v", aws.ToString(obj.Key), bucketName, err)
			}
		}
		t.Logf("Successfully cleared all objects from performance test bucket '%s'", bucketName)
	} else {
		t.Logf("Performance test bucket '%s' is already empty", bucketName)
	}
}

// BenchmarkStreamingUpload provides Go benchmark tests for streaming uploads
func BenchmarkStreamingUpload(b *testing.B) {
	// Skip if not in integration test mode
	EnsureBenchmarkEnvironment(b)

	// Create test context with consistent bucket name
	t := &testing.T{} // Convert for NewTestContext
	tc := NewTestContext(t)
	if t.Failed() {
		b.Skip("Failed to create test context")
	}

	testBucket := PerfTestBucketName

	// Clear any existing data in the performance test bucket
	clearPerformanceTestBucket(t, tc.ProxyClient, testBucket)

	// Ensure the test bucket exists
	_, err := tc.ProxyClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		b.Fatalf("Failed to create performance test bucket: %v", err)
	}

	// No cleanup - keep data for manual inspection
	b.Logf("Using performance test bucket '%s' - data will be preserved for manual inspection", testBucket)

	// Generate 10MB test data once
	testData := make([]byte, PerfSize10MB)
	_, err = io.ReadFull(rand.Reader, testData)
	if err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	uploader := manager.NewUploader(tc.ProxyClient, func(u *manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
		u.Concurrency = 3
	})

	b.ResetTimer()
	b.SetBytes(PerfSize10MB)

	for i := 0; i < b.N; i++ {
		testKey := fmt.Sprintf("bench-test-%d", i)

		_, err := uploader.Upload(tc.Ctx, &s3.PutObjectInput{
			Bucket: aws.String(testBucket),
			Key:    aws.String(testKey),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			b.Fatalf("Upload failed: %v", err)
		}

		// Keep objects for manual inspection - only clean up if explicitly requested
		if os.Getenv("CLEANUP_OBJECTS_AFTER_BENCHMARK") == "true" {
			_, err = tc.ProxyClient.DeleteObject(tc.Ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(testBucket),
				Key:    aws.String(testKey),
			})
			if err != nil {
				b.Fatalf("Cleanup failed: %v", err)
			}
		}
	}
}

// BenchmarkStreamingDownload provides Go benchmark tests for streaming downloads
func BenchmarkStreamingDownload(b *testing.B) {
	// Skip if not in integration test mode
	EnsureBenchmarkEnvironment(b)

	// Create test context with consistent bucket name
	t := &testing.T{} // Convert for NewTestContext
	tc := NewTestContext(t)
	if t.Failed() {
		b.Skip("Failed to create test context")
	}

	testBucket := PerfTestBucketName

	// Clear any existing data in the performance test bucket
	clearPerformanceTestBucket(t, tc.ProxyClient, testBucket)

	// Ensure the test bucket exists
	_, err := tc.ProxyClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		b.Fatalf("Failed to create performance test bucket: %v", err)
	}

	// No cleanup - keep data for manual inspection
	b.Logf("Using performance test bucket '%s' - data will be preserved for manual inspection", testBucket)

	// Pre-upload test file
	testData := make([]byte, PerfSize10MB)
	_, err = io.ReadFull(rand.Reader, testData)
	if err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	testKey := "bench-download-test-file"
	uploader := manager.NewUploader(tc.ProxyClient)
	_, err = uploader.Upload(tc.Ctx, &s3.PutObjectInput{
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
		resp, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
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

// TestPerformanceComparison compares encrypted proxy performance vs unencrypted MinIO
func TestPerformanceComparison(t *testing.T) {
	// Allow skipping performance tests in CI environments where they might be unreliable
	if os.Getenv("SKIP_PERFORMANCE_TESTS") == "true" {
		t.Skip("Skipping performance tests (SKIP_PERFORMANCE_TESTS=true)")
	}

	// Ensure services are available
	EnsureMinIOAndProxyAvailable(t)

	// Create test context with MinIO test helper
	tc := NewTestContext(t)
	defer func() {
		// Keep test data for manual inspection - only clean up on explicit request
		if os.Getenv("CLEANUP_AFTER_PERFORMANCE_TEST") == "true" {
			tc.CleanupTestBucket()
			t.Log("Test data cleaned up (CLEANUP_AFTER_PERFORMANCE_TEST=true)")
		} else {
			t.Logf("Test data preserved in bucket '%s' for manual inspection. Set CLEANUP_AFTER_PERFORMANCE_TEST=true to clean up.", tc.TestBucket)
		}
	}()

	testBucket := PerfTestBucketName

	// Clear any existing data in the performance test bucket
	clearPerformanceTestBucket(t, tc.ProxyClient, testBucket)
	clearPerformanceTestBucket(t, tc.MinIOClient, testBucket+"-unencrypted")

	// Create buckets for both encrypted and unencrypted tests
	_, err := tc.ProxyClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket + "-encrypted"),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		require.NoError(t, err, "Failed to create encrypted test bucket")
	}

	_, err = tc.MinIOClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket + "-unencrypted"),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		require.NoError(t, err, "Failed to create unencrypted test bucket")
	}

	// No cleanup - keep data for manual inspection

	// Test different file sizes - comprehensive range from 100KB to 1GB
	allFileSizes := []struct {
		name string
		size int64
	}{
		{"100KB", 100 * 1024},        // 100KB
		{"500KB", 500 * 1024},        // 500KB
		{"1MB", 1 * 1024 * 1024},     // 1MB
		{"3MB", 3 * 1024 * 1024},     // 3MB
		{"5MB", 5 * 1024 * 1024},     // 5MB
		{"10MB", 10 * 1024 * 1024},   // 10MB
		{"50MB", 50 * 1024 * 1024},   // 50MB
		{"100MB", 100 * 1024 * 1024}, // 100MB
		{"500MB", 500 * 1024 * 1024}, // 500MB
		{"1GB", 1024 * 1024 * 1024},  // 1GB
	}

	// Filter file sizes based on QUICK_MODE environment variable
	var fileSizes []struct {
		name string
		size int64
	}
	if os.Getenv("QUICK_MODE") == "true" {
		// Quick mode: only test up to 10MB
		for _, fileSize := range allFileSizes {
			if fileSize.size <= 10*1024*1024 {
				fileSizes = append(fileSizes, fileSize)
			}
		}
		fmt.Printf("\n=== QUICK MODE: S3 Encryption Proxy vs Plain MinIO (up to 10MB) ===\n\n")
	} else {
		fileSizes = allFileSizes
		fmt.Printf("\n=== S3 Encryption Proxy vs Plain MinIO Performance Comparison ===\n\n")
	}

	fmt.Printf("%-8s | %-12s | %-12s | %-12s | %-12s | %-8s | %-8s\n",
		"Size", "Enc UP MB/s", "Plain UP MB/s", "Enc DN MB/s", "Plain DN MB/s", "UP Eff.", "DN Eff.")
	fmt.Printf("---------|--------------|--------------|--------------|--------------|----------|----------\n")

	var totalResults []ComparisonResult

	for _, fileSize := range fileSizes {
		t.Run(fileSize.name, func(t *testing.T) {
			// Generate test data
			testData := make([]byte, fileSize.size)
			_, err := rand.Read(testData)
			require.NoError(t, err, "Failed to generate test data")

			objectKey := fmt.Sprintf("test-object-%s", fileSize.name)

			// Test encrypted (proxy) performance
			encryptedResult := measureComparisonPerformance(t, tc.Ctx, tc.ProxyClient, testBucket+"-encrypted", objectKey, testData)

			// Test unencrypted (direct MinIO) performance
			unencryptedResult := measureComparisonPerformance(t, tc.Ctx, tc.MinIOClient, testBucket+"-unencrypted", objectKey, testData)

			// Calculate efficiency percentages (how much of unencrypted performance we retain)
			uploadEfficiency := (encryptedResult.UploadThroughput / unencryptedResult.UploadThroughput) * 100
			downloadEfficiency := (encryptedResult.DownloadThroughput / unencryptedResult.DownloadThroughput) * 100

			// Print results
			fmt.Printf("%-8s | %-12.2f | %-12.2f | %-12.2f | %-12.2f | %-7.1f%% | %-7.1f%%\n",
				fileSize.name,
				encryptedResult.UploadThroughput,
				unencryptedResult.UploadThroughput,
				encryptedResult.DownloadThroughput,
				unencryptedResult.DownloadThroughput,
				uploadEfficiency,
				downloadEfficiency)

			// Store results for summary
			totalResults = append(totalResults, ComparisonResult{
				FileSize:           fileSize.name,
				Encrypted:          encryptedResult,
				Unencrypted:        unencryptedResult,
				UploadEfficiency:   uploadEfficiency,
				DownloadEfficiency: downloadEfficiency,
			})

			// Validate that encrypted operations are reasonably performant
			// Allow up to 80% overhead for encryption (minimum 20% efficiency) in CI environments
			// CI environments have variable performance characteristics
			minEfficiency := 20.0
			skipPerformanceChecks := false

			if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
				minEfficiency = 15.0 // Even more lenient in CI
				t.Logf("Running in CI environment - using relaxed performance thresholds (%.1f%%)", minEfficiency)
			}

			// Allow completely skipping performance checks in unstable environments
			if os.Getenv("SKIP_PERFORMANCE_CHECKS") == "true" {
				skipPerformanceChecks = true
				t.Log("Skipping performance validation checks (SKIP_PERFORMANCE_CHECKS=true)")
			}

			if !skipPerformanceChecks {
				require.Greater(t, uploadEfficiency, minEfficiency,
					"Encrypted upload efficiency too low: %.1f%% (%.2f vs %.2f MB/s)",
					uploadEfficiency, encryptedResult.UploadThroughput, unencryptedResult.UploadThroughput)

				require.Greater(t, downloadEfficiency, minEfficiency,
					"Encrypted download efficiency too low: %.1f%% (%.2f vs %.2f MB/s)",
					downloadEfficiency, encryptedResult.DownloadThroughput, unencryptedResult.DownloadThroughput)
			} else {
				t.Logf("Performance validation skipped - Upload: %.1f%%, Download: %.1f%%",
					uploadEfficiency, downloadEfficiency)
			}
		})
	}

	// Print summary
	printComparisonSummary(t, totalResults)
}

// ComparisonResult holds comparison test results
type ComparisonResult struct {
	FileSize           string
	Encrypted          PerformanceResult
	Unencrypted        PerformanceResult
	UploadEfficiency   float64
	DownloadEfficiency float64
}

// measureComparisonPerformance measures upload and download performance for comparison
func measureComparisonPerformance(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) PerformanceResult {
	dataSize := float64(len(data)) / (1024 * 1024) // Size in MB

	// Measure upload time
	uploadStart := time.Now()

	// Use multipart upload for files larger than 5MB to avoid chunk size issues
	if len(data) > 5*1024*1024 {
		// Use AWS S3 Manager for large files (same as streaming performance test)
		uploader := manager.NewUploader(client, func(u *manager.Uploader) {
			u.PartSize = 5 * 1024 * 1024 // 5 MB parts
			u.Concurrency = 3            // Match proxy concurrency
		})

		_, err := uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
		})
		require.NoError(t, err, "Failed to upload large object via multipart")
	} else {
		// Use direct PutObject for smaller files
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
		})
		require.NoError(t, err, "Failed to upload object")
	}

	uploadDuration := time.Since(uploadStart)
	uploadThroughput := dataSize / uploadDuration.Seconds()

	// Measure download time
	downloadStart := time.Now()
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object")

	// Read all data to measure complete download time
	downloadedData, err := io.ReadAll(resp.Body)
	downloadDuration := time.Since(downloadStart)
	resp.Body.Close()

	require.NoError(t, err, "Failed to read downloaded data")
	require.Equal(t, len(data), len(downloadedData), "Downloaded data size mismatch")

	downloadThroughput := dataSize / downloadDuration.Seconds()

	return PerformanceResult{
		FileSize:           int64(len(data)),
		UploadTime:         uploadDuration,
		DownloadTime:       downloadDuration,
		UploadThroughput:   uploadThroughput,
		DownloadThroughput: downloadThroughput,
		TotalTime:          uploadDuration + downloadDuration,
	}
}

// printComparisonSummary prints a summary of the comparison results
func printComparisonSummary(t *testing.T, results []ComparisonResult) {
	fmt.Printf("\n=== Performance Comparison Summary ===\n")

	var totalUploadEff, totalDownloadEff float64
	var encryptedUpload, unencryptedUpload, encryptedDownload, unencryptedDownload float64

	for _, result := range results {
		totalUploadEff += result.UploadEfficiency
		totalDownloadEff += result.DownloadEfficiency
		encryptedUpload += result.Encrypted.UploadThroughput
		unencryptedUpload += result.Unencrypted.UploadThroughput
		encryptedDownload += result.Encrypted.DownloadThroughput
		unencryptedDownload += result.Unencrypted.DownloadThroughput
	}

	avgUploadEff := totalUploadEff / float64(len(results))
	avgDownloadEff := totalDownloadEff / float64(len(results))
	avgEncUpload := encryptedUpload / float64(len(results))
	avgPlainUpload := unencryptedUpload / float64(len(results))
	avgEncDownload := encryptedDownload / float64(len(results))
	avgPlainDownload := unencryptedDownload / float64(len(results))

	fmt.Printf("Average Upload Efficiency: %.1f%% (Encrypted: %.2f MB/s, Plain: %.2f MB/s)\n",
		avgUploadEff, avgEncUpload, avgPlainUpload)
	fmt.Printf("Average Download Efficiency: %.1f%% (Encrypted: %.2f MB/s, Plain: %.2f MB/s)\n",
		avgDownloadEff, avgEncDownload, avgPlainDownload)

	fmt.Printf("Encryption Overhead: Upload %.1f%%, Download %.1f%%\n",
		100-avgUploadEff, 100-avgDownloadEff)

	t.Logf("Performance comparison complete - encryption adds %.1f%% upload overhead and %.1f%% download overhead",
		100-avgUploadEff, 100-avgDownloadEff)
}
