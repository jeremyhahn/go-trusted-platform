package tpm2

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/password"
)

type PlatformPassword struct {
	backend  keystore.KeyBackend
	logger   *logging.Logger
	tpm      TrustedPlatformModule
	keyAttrs *keystore.KeyAttributes
	keystore.Password
}

// Just-in-time password retrieval of TPM keyed hash (HMAC) objects
// used for password storage. This object keeps the password sealed
// to  the TPM and retrieves it when the String() or Bytes() method
// is called, using the platform PCR authorization session policy.
func NewPlatformPassword(
	logger *logging.Logger,
	tpm TrustedPlatformModule,
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) keystore.Password {

	return PlatformPassword{
		backend:  backend,
		logger:   logger,
		tpm:      tpm,
		keyAttrs: keyAttrs}
}

// Returns the secret as a string
func (p PlatformPassword) String() (string, error) {
	secret, err := p.Bytes()
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

// Returns the secret as bytes
func (p PlatformPassword) Bytes() ([]byte, error) {
	if p.keyAttrs.Debug {
		p.logger.Debugf(
			"keystore/tpm2: retrieving platform password: %s",
			p.keyAttrs.CN)
	}
	// Copy the key attributes to a new "secret attributes"
	// object so it can be loaded from the backend using the
	// key type
	secretAttrs := *p.keyAttrs
	secretAttrs.KeyType = keystore.KEY_TYPE_HMAC
	return p.tpm.Unseal(&secretAttrs, p.backend)
}

// Seals a password to the TPM as a keyed hash object. If the key
// attributes have the platform policy defined, a PlatformSecret is
// returned, otherwise, RequiredPassword which returns ErrPasswordRequired
// when it's member methods are invoked. If the provided password is the
// default platform password, a random 32 byte (AES-256) key is generated.
func (p PlatformPassword) Create() error {

	var passwd []byte
	var err error
	if p.keyAttrs.Password == nil {
		p.keyAttrs.Password = keystore.NewClearPassword(nil)
		return nil
	} else {
		passwd, err = p.keyAttrs.Password.Bytes()
		if err != nil {
			return err
		}
		if string(passwd) == keystore.DEFAULT_PASSWORD {
			passwd = aesgcm.NewAESGCM(p.tpm).GenerateKey()
			p.keyAttrs.Password = keystore.NewClearPassword(passwd)
		}
	}
	if _, err := p.tpm.Seal(p.keyAttrs, p.backend, false); err != nil {
		return err
	}
	if p.keyAttrs.PlatformPolicy {
		p.keyAttrs.Password = p
	} else {
		p.keyAttrs.Password = password.NewRequiredPassword()
	}
	return nil
}
