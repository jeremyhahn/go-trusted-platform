package keystore

import (
	"crypto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/pkcs11"
)

type PKCS11KeyStore struct {
	config   pkcs11.Config
	password []byte
	KeyStorer
}

func NewKeyStorePKCS11(config pkcs11.Config) KeyStorer {
	return PKCS11KeyStore{
		config: config,
	}
}

// Returns the key store type
func (store PKCS11KeyStore) Type() StoreType {
	return STORE_PKCS11
}

// Returns a PKCS #11 crypto.Signer
func (store PKCS11KeyStore) Signer(attrs KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}

// Returns a PKCS #11 crypto.Decrypter
func (store PKCS11KeyStore) Decrypter(attrs KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}
