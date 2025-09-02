# Encryption Providers

This directory contains the refactored encryption providers for the S3 Encryption Proxy. Each encryption method is now implemented in a separate, focused file, making the code easier to review and maintain.

## Structure

```
pkg/encryption/providers/
├── aes_gcm.go       # Direct AES-256-GCM encryption implementation
├── tink.go          # Google Tink envelope encryption implementation
├── rsa_envelope.go  # RSA envelope encryption implementation
├── factory.go       # Factory for creating providers with validation
├── aes_gcm_test.go  # Tests for AES-GCM provider
├── tink_test.go     # Tests for Tink provider
├── rsa_envelope_test.go # Tests for RSA envelope provider
├── factory_test.go  # Tests for factory and validation
└── README.md        # This file
```

## Encryption Providers

### AES-GCM Provider (`aes_gcm.go`)

**Purpose**: Direct AES-256-GCM encryption without envelope encryption.

**Key Features**:
- Single master key for all operations
- No KMS dependency required
- Fast performance (no envelope overhead)
- 32-byte (256-bit) key requirement
- Base64 key encoding support

**Usage**:
```go
provider, err := providers.NewAESGCMProviderFromBase64(base64Key)
```

**Review Focus**:
- Key validation (must be exactly 32 bytes)
- Nonce generation (crypto/rand)
- GCM authentication
- Error handling

### RSA Envelope Provider (`rsa_envelope.go`)

**Purpose**: RSA-based envelope encryption without KMS dependency.

**Key Features**:
- RSA key pair for DEK encryption (2048/3072/4096-bit keys supported)
- AES-256-GCM for data encryption (new DEK per operation)
- No external KMS required - self-contained encryption
- PEM key format support
- Cross-platform compatibility

**Usage**:
```go
// Generate key pair
privateKey, err := providers.GenerateRSAKeyPair(2048)
provider, err := providers.NewRSAEnvelopeProvider(&privateKey.PublicKey, privateKey)

// Or from PEM config
config := &providers.RSAEnvelopeConfig{
    PublicKeyPEM:  publicKeyPEM,
    PrivateKeyPEM: privateKeyPEM,
    KeySize:       2048,
}
provider, err := providers.NewRSAEnvelopeProviderFromConfig(config)
```

**Review Focus**:
- RSA key validation (minimum 2048 bits)
- DEK generation per operation (AES-256)
- Envelope encryption flow (RSA + AES-GCM)
- PEM parsing security
- Key pair matching validation

### Tink Provider (`tink.go`)

**Purpose**: Envelope encryption using Google's Tink cryptographic library.

**Key Features**:
- KEK (Key Encryption Key) stored in external KMS
- DEK (Data Encryption Key) generated per operation
- DEK encrypted with KEK and stored as metadata
- Built-in key rotation support (planned)

**Usage**:
```go
provider, err := providers.NewTinkProvider(kekHandle)
```

**Review Focus**:
- KEK handle validation
- DEK generation per operation
- Envelope encryption/decryption flow
- Memory management for sensitive data

### Factory (`factory.go`)

**Purpose**: Unified interface for creating and validating encryption providers.

**Key Features**:
- Provider type validation
- Configuration validation
- Centralized provider creation
- Support for future provider types

**Usage**:
```go
factory := providers.NewFactory()
provider, err := factory.CreateProvider(config)
```

**Review Focus**:
- Configuration validation logic
- Provider type mapping
- Error handling and messaging
- KMS integration points

## Interface Compliance

All providers implement the `encryption.Encryptor` interface:

```go
type Encryptor interface {
    Encrypt(ctx context.Context, data []byte, associatedData []byte) (*EncryptionResult, error)
    Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error)
    RotateKEK(ctx context.Context) error
}
```

### RSA Envelope Provider
- **Key Management**: Manual RSA key pair management
- **Key Rotation**: Manual (requires new key pair generation)
- **Performance**: Good (envelope encryption overhead)
- **KMS Integration**: None (self-contained)

## Security Considerations

### AES-GCM Provider
- **Key Management**: Manual key management responsibility
- **Key Rotation**: Not supported (requires new deployment)
- **Performance**: Excellent (no envelope overhead)
- **KMS Integration**: None

### Tink Provider
- **Key Management**: Automated via KMS
- **Key Rotation**: Supported (when implemented)
- **Performance**: Good (envelope encryption overhead)
- **KMS Integration**: Required

## Testing

Each provider has comprehensive tests covering:

- **Functional Tests**: Encrypt/decrypt roundtrip
- **Error Handling**: Invalid inputs, wrong keys, etc.
- **Security Tests**: Wrong associated data, tampering
- **Performance Tests**: Large data handling
- **Cross-Compatibility**: Multiple provider instances

Run tests:
```bash
go test ./pkg/encryption/providers/ -v
```

## Migration from Old Structure

The old structure had encryption logic scattered across:
- `pkg/encryption/aes_gcm.go` → `providers/aes_gcm.go`
- `pkg/envelope/envelope.go` → `providers/tink.go`
- `internal/encryption/manager.go` → Simplified to use factory

Benefits of new structure:
1. **Clear Separation**: Each encryption method in its own file
2. **Easy Reviews**: Focused, single-responsibility files
3. **Consistent Interface**: All providers implement same interface
4. **Validation**: Centralized configuration validation
5. **Testability**: Isolated testing per provider
6. **Extensibility**: Easy to add new providers

## Adding New Providers

To add a new encryption provider:

1. Create `new_provider.go` implementing `encryption.Encryptor`
2. Add provider type constant in `factory.go`
3. Extend factory's `CreateProvider` method
4. Add validation in `ValidateProviderConfig`
5. Create comprehensive tests `new_provider_test.go`

Example skeleton:
```go
type NewProvider struct {
    // Provider-specific fields
}

func NewNewProvider(config *NewProviderConfig) (*NewProvider, error) {
    // Validation and initialization
}

func (p *NewProvider) Encrypt(ctx context.Context, data []byte, associatedData []byte) (*encryption.EncryptionResult, error) {
    // Implementation
}

func (p *NewProvider) Decrypt(ctx context.Context, encryptedData []byte, encryptedDEK []byte, associatedData []byte) ([]byte, error) {
    // Implementation
}

func (p *NewProvider) RotateKEK(ctx context.Context) error {
    // Implementation
}
```
