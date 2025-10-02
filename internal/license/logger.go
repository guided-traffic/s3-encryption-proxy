package license

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogLicenseInfo logs license information in a user-friendly format
func LogLicenseInfo(result *ValidationResult) {
	if !result.Valid {
		if result.Error != nil {
			logrus.WithError(result.Error).Warn("License validation failed")
		}
		logrus.Warn("🚨 " + result.Message)
		logrus.Warn("📖 Encryption disabled - only decryption of existing data available")
		logrus.Warn("🌐 To enable encryption, obtain a license from https://s3ep.com")
		return
	}

	info := result.Info
	if info == nil || info.Claims == nil {
		logrus.Warn("No license information available")
		return
	}

	// Log license details with emojis for better visibility
	logrus.Info("===== S3 ENCRYPTION PROXY LICENSE =====")
	logrus.Infof("Licensed to: %s", info.Claims.LicenseeName)

	if info.Claims.LicenseeCompany != "" {
		logrus.Infof("Company: %s", info.Claims.LicenseeCompany)
	}

	if info.Claims.LicenseNote != "" {
		logrus.Infof("License Note: %s", info.Claims.LicenseNote)
	}

	if info.Claims.KubernetesClusterID != "" {
		logrus.Infof("Kubernetes Cluster: %s", info.Claims.KubernetesClusterID)
		// TODO: Implement cluster ID validation in future
		logrus.Debug("Note: Kubernetes Cluster ID validation not yet implemented")
	}

	// Log expiration information
	if !info.ExpiresAt.IsZero() {
		logrus.Infof("License expires: %s", info.ExpiresAt.Format("2006-01-02 15:04:05 MST"))

		if info.TimeRemaining.Total > 0 {
			timeStr := formatTimeRemaining(info.TimeRemaining)
			logrus.Infof("Time remaining: %s", timeStr)

			// Warning for expiring licenses
			if info.TimeRemaining.Total.Hours() < 30*24 { // 30 days
				logrus.Warnf("⚠️  License expires soon! Please renew at https://s3ep.com")
			}
		}
	} else {
		logrus.Info("⏰ License: No expiration date")
	}

}

// formatTimeRemaining formats the remaining time in a human-readable way
func formatTimeRemaining(remaining TimeRemaining) string {
	if remaining.Total <= 0 {
		return "Expired"
	}

	var parts []string

	if remaining.Years > 0 {
		if remaining.Years == 1 {
			parts = append(parts, "1 year")
		} else {
			parts = append(parts, fmt.Sprintf("%d years", remaining.Years))
		}
	}

	if remaining.Days > 0 {
		if remaining.Days == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", remaining.Days))
		}
	}

	if len(parts) == 0 {
		// Less than a day
		hours := int(remaining.Total.Hours())
		if hours > 0 {
			if hours == 1 {
				return "1 hour"
			}
			return fmt.Sprintf("%d hours", hours)
		}
		return "Less than 1 hour"
	}

	return strings.Join(parts, ", ")
}

// LogProviderRestriction logs information about provider restrictions
func LogProviderRestriction(providerType, providerAlias string, licensed bool) {
	if licensed {
		logrus.Infof("Encryption provider '%s' (type: %s) - ✅ Licensed", providerAlias, providerType)
	} else {
		if providerType == "none" {
			logrus.Infof("Pass-through provider '%s' (type: %s) - ✅ Available without license", providerAlias, providerType)
		} else {
			logrus.Errorf("Encryption provider '%s' (type: %s) - ❌ License required", providerAlias, providerType)
		}
	}
}
