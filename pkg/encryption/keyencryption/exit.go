package keyencryption

import (
	"context"
	"errors"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// ErrExitProviderKeyUse is returned when something asks the exit provider to
// wrap or unwrap a data key. Neither can legitimately happen: under the exit
// provider a write stores the plaintext and creates no data key, and a read of
// an object this proxy encrypted earlier resolves the key encryptor by the
// fingerprint in the object's own metadata, which names the provider that
// wrapped it. Reaching either method means a write path failed to pass through
// or a fingerprint was accepted that names no real key.
var ErrExitProviderKeyUse = errors.New("the exit provider holds no key material")

// ExitProvider is the provider an operator selects to leave the product.
//
// It writes plaintext and keeps reading what is already encrypted: the object's
// own key fingerprint selects the provider that wrapped its data key, so the
// exit provider itself never touches key material. It is deliberately not a
// key encryptor in any real sense; it satisfies the interface so that the
// active provider can be selected the same way as any other.
type ExitProvider struct{}

// NewExitProvider creates the exit provider. It takes no configuration.
func NewExitProvider(_ map[string]interface{}) (encryption.KeyEncryptor, error) {
	return &ExitProvider{}, nil
}

// EncryptDEK never succeeds. See ErrExitProviderKeyUse.
func (e *ExitProvider) EncryptDEK(_ context.Context, _ []byte) ([]byte, error) {
	return nil, ErrExitProviderKeyUse
}

// DecryptDEK never succeeds. See ErrExitProviderKeyUse.
//
// This is also what closes the forgery a pass-through unwrap would open: a
// backend that labelled an object with this provider's fingerprint would be
// handing the proxy a data key of its own choosing, and the answer is an error
// rather than that key.
func (e *ExitProvider) DecryptDEK(_ context.Context, _ []byte) ([]byte, error) {
	return nil, ErrExitProviderKeyUse
}

// Name returns the provider name.
func (e *ExitProvider) Name() string {
	return "exit"
}

// Fingerprint identifies the exit provider. No object is ever written under it,
// because the exit provider writes plaintext and plaintext carries no metadata.
func (e *ExitProvider) Fingerprint() string {
	return "exit-provider-fingerprint"
}
