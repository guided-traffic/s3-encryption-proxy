package bucket

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestMainBucketHandler_NewHandlers(t *testing.T) {
	// Test that the main bucket handler correctly initializes all new sub-handlers
	mockS3Backend := &MockS3Backend{}
	logger := logrus.NewEntry(logrus.New())
	cfg := &config.Config{} // Empty config for testing

	handler := NewHandler(mockS3Backend, logger, "test-prefix", cfg)

	// Verify all handlers are initialized
	assert.NotNil(t, handler.GetVersioningHandler())
	assert.NotNil(t, handler.GetTaggingHandler())
	assert.NotNil(t, handler.GetNotificationHandler())
	assert.NotNil(t, handler.GetLifecycleHandler())
	assert.NotNil(t, handler.GetReplicationHandler())
	assert.NotNil(t, handler.GetWebsiteHandler())
	assert.NotNil(t, handler.GetAccelerateHandler())
	assert.NotNil(t, handler.GetRequestPaymentHandler())
	assert.NotNil(t, handler.GetACLHandler())
	assert.NotNil(t, handler.GetCORSHandler())
	assert.NotNil(t, handler.GetPolicyHandler())
	assert.NotNil(t, handler.GetLocationHandler())
	assert.NotNil(t, handler.GetLoggingHandler())
}
