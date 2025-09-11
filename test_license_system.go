package main

import (
	"fmt"
	"os"

	"github.com/guided-traffic/s3-encryption-proxy/internal/license"
	"github.com/sirupsen/logrus"
)

func main() {
	// Set log level to see all messages
	logrus.SetLevel(logrus.DebugLevel)

	fmt.Println("=== Testing License System ===")

	// Test without license token
	fmt.Println("\n1. Testing without license token:")
	licenseToken := license.LoadLicenseFromEnv()
	fmt.Printf("   License token from env: '%s'\n", licenseToken)

	validator := license.NewValidator()
	result := validator.ValidateLicense(licenseToken)

	fmt.Printf("   License valid: %t\n", result.Valid)
	fmt.Printf("   License message: %s\n", result.Message)
	if result.Error != nil {
		fmt.Printf("   License error: %s\n", result.Error.Error())
	}

	// Log license info
	license.LogLicenseInfo(result)

	// Test provider validation
	fmt.Println("\n2. Testing provider validation:")

	providerTypes := []string{"none", "aes", "rsa"}
	for _, providerType := range providerTypes {
		err := validator.ValidateProviderType(providerType)
		fmt.Printf("   Provider '%s': ", providerType)
		if err != nil {
			fmt.Printf("❌ BLOCKED - %s\n", err.Error())
		} else {
			fmt.Printf("✅ ALLOWED\n")
		}

		// Log provider restriction info
		license.LogProviderRestriction(providerType, "test-"+providerType, result.Valid)
	}

	// Test with fake license token
	fmt.Println("\n3. Testing with invalid license token:")
	os.Setenv("S3EP_LICENSE_TOKEN", "fake.jwt.token")
	validator2 := license.NewValidator()
	result2 := validator2.ValidateLicense("fake.jwt.token")

	fmt.Printf("   Fake license valid: %t\n", result2.Valid)
	fmt.Printf("   Fake license message: %s\n", result2.Message)
	if result2.Error != nil {
		fmt.Printf("   Fake license error: %s\n", result2.Error.Error())
	}
}
