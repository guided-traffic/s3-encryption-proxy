package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactory_CreateProviderFromConfig(t *testing.T) {
	factory := NewFactory()

	// Test none provider
	provider, err := factory.CreateProviderFromConfig(ProviderTypeNone, map[string]interface{}{})
	assert.NoError(t, err)
	assert.NotNil(t, provider)

	// Test unsupported provider type
	provider, err = factory.CreateProviderFromConfig(ProviderType("unsupported"), map[string]interface{}{})
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "unsupported provider type")
}