package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// envVarPattern matches ${VAR_NAME} patterns in strings.
// Only matches ${...} with curly braces, not bare $VAR references.
var envVarPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// expandEnvVars replaces all ${VAR_NAME} patterns in the input string with
// the corresponding environment variable values. Returns an error if any
// referenced environment variable is not set or empty.
func expandEnvVars(value string) (string, error) {
	matches := envVarPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, nil
	}

	var result strings.Builder
	lastIndex := 0

	for _, match := range matches {
		// match[0]:match[1] = full match "${VAR}"
		// match[2]:match[3] = capture group "VAR"
		varName := value[match[2]:match[3]]
		envVal, ok := os.LookupEnv(varName)
		if !ok || envVal == "" {
			return "", fmt.Errorf("environment variable ${%s} is not set or empty", varName)
		}

		result.WriteString(value[lastIndex:match[0]])
		result.WriteString(envVal)
		lastIndex = match[1]
	}

	result.WriteString(value[lastIndex:])
	return result.String(), nil
}

// expandConfigEnvVars expands ${VAR} references in all supported config fields.
func expandConfigEnvVars(cfg *Config) error {
	// s3_backend credentials
	val, err := expandEnvVars(cfg.S3Backend.AccessKeyID)
	if err != nil {
		return fmt.Errorf("s3_backend.access_key_id: %w", err)
	}
	cfg.S3Backend.AccessKeyID = val

	val, err = expandEnvVars(cfg.S3Backend.SecretKey)
	if err != nil {
		return fmt.Errorf("s3_backend.secret_key: %w", err)
	}
	cfg.S3Backend.SecretKey = val

	// s3_clients credentials
	for i := range cfg.S3Clients {
		val, err = expandEnvVars(cfg.S3Clients[i].AccessKeyID)
		if err != nil {
			return fmt.Errorf("s3_clients[%d].access_key_id: %w", i, err)
		}
		cfg.S3Clients[i].AccessKeyID = val

		val, err = expandEnvVars(cfg.S3Clients[i].SecretKey)
		if err != nil {
			return fmt.Errorf("s3_clients[%d].secret_key: %w", i, err)
		}
		cfg.S3Clients[i].SecretKey = val
	}

	// encryption provider config values
	for i := range cfg.Encryption.Providers {
		for key, val := range cfg.Encryption.Providers[i].Config {
			strVal, ok := val.(string)
			if !ok {
				continue
			}
			expanded, err := expandEnvVars(strVal)
			if err != nil {
				return fmt.Errorf("encryption.providers[%d].config.%s: %w", i, key, err)
			}
			cfg.Encryption.Providers[i].Config[key] = expanded
		}
	}

	return nil
}
