package tpm2

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type PlatformSecret struct {
	logger   *logging.Logger
	backend  keystore.KeyBackend
	tpm      tpm2.TrustedPlatformModule
	keyAttrs *keystore.KeyAttributes
	keystore.Password
}

// TPM 2.0 AES symmetric encryption and wrapping operations
func NewPlatformSecret(
	backend keystore.KeyBackend,
	tpm tpm2.TrustedPlatformModule,
	keyAttrs *keystore.KeyAttributes) keystore.Password {

	return PlatformSecret{
		backend:  backend,
		tpm:      tpm,
		keyAttrs: keyAttrs}
}

// Returns the secret as a string
func (p PlatformSecret) String() (string, error) {
	secret, err := p.Bytes()
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

// Returns the secret as bytes
func (p PlatformSecret) Bytes() ([]byte, error) {
	if p.keyAttrs.Debug {
		p.logger.Debugf(
			"keystore/tpm2: retrieving platform secret: %s",
			p.keyAttrs.CN)
	}
	// Copy the key attributes to a new "secret attributes"
	// object so it can be loaded from the backend using the
	// key type
	secretAttrs := *p.keyAttrs
	secretAttrs.CN = fmt.Sprintf("%s.secret", secretAttrs.CN)
	secretAttrs.KeyType = keystore.KEY_TYPE_SECRET
	return p.tpm.Unseal(&secretAttrs, p.backend)
}
