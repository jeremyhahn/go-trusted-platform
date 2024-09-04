package tpm2

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type PlatformKeyStorer interface {
	CreatePassword(keyAttrs *keystore.KeyAttributes, backend keystore.KeyBackend) error
	KeyAttributes() *keystore.KeyAttributes
	Password(keyAttrs *keystore.KeyAttributes) (keystore.Password, error)
	SRKAttributes() *keystore.KeyAttributes
	TPM2() tpm2.TrustedPlatformModule
	keystore.KeyStorer
}
