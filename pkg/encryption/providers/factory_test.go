package providers

import (
"testing"
"github.com/stretchr/testify/assert"
)

func TestFactory_GetSupportedProviders(t *testing.T) {
factory := NewFactory()
providers := factory.GetSupportedProviders()
assert.Contains(t, providers, ProviderTypeAESGCM)
assert.Contains(t, providers, ProviderTypeTink)
}
