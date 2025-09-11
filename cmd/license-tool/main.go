package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type LicenseClaims struct {
	jwt.RegisteredClaims
	LicenseeName        string `json:"licensee_name"`
	LicenseeCompany     string `json:"licensee_company"`
	LicenseNote         string `json:"license_note"`
	KubernetesClusterID string `json:"k8s_cluster_id"`
}

func main() {
	fmt.Println("🔑 S3 Encryption Proxy - License Generator")
	fmt.Println("==========================================")
	fmt.Println()

	// Find RSA key files
	privateKeyPath, publicKeyPath, err := findRSAKeys()
	if err != nil {
		fmt.Printf("❌ Error finding RSA keys: %v\n", err)
		fmt.Println("💡 Make sure license_private_key.pem and license_public_key.pem exist in the same directory as this tool")
		os.Exit(1)
	}

	fmt.Printf("🔍 Found RSA keys:\n")
	fmt.Printf("   Private: %s\n", privateKeyPath)
	fmt.Printf("   Public:  %s\n", publicKeyPath)
	fmt.Println()

	// Load private key
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		fmt.Printf("❌ Error loading private key: %v\n", err)
		os.Exit(1)
	}

	// Collect license information
	claims, err := collectLicenseInfo()
	if err != nil {
		fmt.Printf("❌ Error collecting license info: %v\n", err)
		os.Exit(1)
	}

	// Generate JWT
	token, err := generateJWT(privateKey, claims)
	if err != nil {
		fmt.Printf("❌ Error generating JWT: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Println("\n🎉 License successfully generated!")
	fmt.Println("==================================")
	fmt.Printf("📄 Licensee: %s (%s)\n", claims.LicenseeName, claims.LicenseeCompany)
	fmt.Printf("📝 Note: %s\n", claims.LicenseNote)
	fmt.Printf("☸️  K8s Cluster: %s\n", claims.KubernetesClusterID)
	fmt.Printf("⏰ Valid until: %s\n", claims.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("🆔 License ID: %s\n", claims.ID)
	fmt.Println()
	fmt.Println("🔐 JWT License Token:")
	fmt.Println("=====================")
	fmt.Println(token)
	fmt.Println()
	fmt.Println("💡 Usage:")
	fmt.Println("export S3EP_LICENSE_TOKEN=\"" + token + "\"")
}

func findRSAKeys() (privateKeyPath, publicKeyPath string, err error) {
	// Get current executable directory
	execPath, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	execDir := filepath.Dir(execPath)

	privateKeyPath = filepath.Join(execDir, "license_private_key.pem")
	publicKeyPath = filepath.Join(execDir, "license_public_key.pem")

	// Check if files exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("private key not found: %s", privateKeyPath)
	}
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("public key not found: %s", publicKeyPath)
	}

	return privateKeyPath, publicKeyPath, nil
}

func loadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS1 format first (traditional RSA format)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	return privateKey, nil
}

func collectLicenseInfo() (*LicenseClaims, error) {
	reader := bufio.NewReader(os.Stdin)

	// Collect licensee name
	fmt.Print("👤 Licensee Name: ")
	licenseeName, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	licenseeName = strings.TrimSpace(licenseeName)

	// Collect company name
	fmt.Print("🏢 Company Name: ")
	licenseeCompany, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	licenseeCompany = strings.TrimSpace(licenseeCompany)

	// Collect license note
	fmt.Print("📝 License Note (e.g., 'Production License - 500TB'): ")
	licenseNote, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	licenseNote = strings.TrimSpace(licenseNote)

	// Collect Kubernetes cluster ID
	fmt.Print("☸️  Kubernetes Cluster ID (optional): ")
	k8sClusterID, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	k8sClusterID = strings.TrimSpace(k8sClusterID)

	// Collect license duration
	fmt.Print("⏰ License Duration (e.g., '2y100d', '1y', '365d'): ")
	durationStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	durationStr = strings.TrimSpace(durationStr)

	duration, err := parseDuration(durationStr)
	if err != nil {
		return nil, fmt.Errorf("invalid duration format: %v", err)
	}

	// Create claims
	now := time.Now()
	expiresAt := now.Add(duration)

	claims := &LicenseClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "guided-traffic.com",
			Subject:   "s3-encryption-proxy-license",
			Audience:  []string{"s3-encryption-proxy"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		LicenseeName:        licenseeName,
		LicenseeCompany:     licenseeCompany,
		LicenseNote:         licenseNote,
		KubernetesClusterID: k8sClusterID,
	}

	return claims, nil
}

func parseDuration(durationStr string) (time.Duration, error) {
	// Parse format like "2y100d", "1y", "365d", "30d", etc.
	re := regexp.MustCompile(`(?:(\d+)y)?(?:(\d+)d)?`)
	matches := re.FindStringSubmatch(durationStr)

	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid format, use formats like '2y100d', '1y', '365d'")
	}

	var totalDays int

	// Parse years
	if matches[1] != "" {
		years, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, err
		}
		totalDays += years * 365
	}

	// Parse days
	if matches[2] != "" {
		days, err := strconv.Atoi(matches[2])
		if err != nil {
			return 0, err
		}
		totalDays += days
	}

	if totalDays == 0 {
		return 0, fmt.Errorf("duration must be greater than 0")
	}

	return time.Duration(totalDays) * 24 * time.Hour, nil
}

func generateJWT(privateKey *rsa.PrivateKey, claims *LicenseClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	// Return raw JWT token (not base64 encoded)
	return tokenString, nil
}
