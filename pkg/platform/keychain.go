package platform

import (
	"crypto"
	"errors"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/op/go-logging"

	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

var (
	ErrInvalidKeyChainCN       = errors.New("keychain: invalid configuration, missing CN")
	ErrInvalidPlatformKeyStore = errors.New("keychain: invalid platform key store")
)

type KeyChainConfig struct {
	CN           string               `yaml:"cn" json:"cn" mapstructure:"cn"`
	PKCS8Config  *pkcs8.Config        `yaml:"pkcs8" json:"pkcs8" mapstructure:"pkcs8"`
	PKCS11Config *pkcs11.Config       `yaml:"pkcs11" json:"pkcs11" mapstructure:"pkcs11"`
	TPMConfig    *tpm2.KeyStoreConfig `yaml:"tpm2" json:"tpm2" mapstructure:"tpm2"`
}

// The KeyChain provides access to all of the underlying Key Store Modules
// through a common API that abstracts away the implementation details of
// the underlying store. The KeyChain also implements the key store interface
// itself, using the StoreType property in the KeyAttributes to route the
// operation to the correct Key Store Module.
type KeyChain struct {
	backend    keystore.KeyBackend
	logger     *logging.Logger
	config     *KeyChainConfig
	platformKS tpm2ks.PlatformKeyStorer
	storeMap   map[keystore.StoreType]keystore.KeyStorer
	tpm        tpm2.TrustedPlatformModule
	keystore.KeyStorer
}

// Generates a new keychain using the provided configuration to instantiate
// the underlying key store modules.
func NewKeyChain(
	logger *logging.Logger,
	debugSecrets bool,
	rootDir string,
	random io.Reader,
	config *KeyChainConfig,
	keyBackend keystore.KeyBackend,
	blobStore blob.BlobStorer,
	signerStore keystore.SignerStorer,
	tpm tpm2.TrustedPlatformModule,
	platformKS tpm2ks.PlatformKeyStorer,
	soPIN keystore.Password,
	userPIN keystore.Password) (keychain *KeyChain, err error) {

	// // Ensure PIN meets requirements
	// userPIN, err = ensurePIN(logger, debugSecrets, random, userPIN)
	// if err != nil {
	// 	return nil, err
	// }

	if platformKS == nil {
		return nil, ErrInvalidPlatformKeyStore
	}

	if config.CN == "" {
		return nil, ErrInvalidKeyChainCN
	}

	// Set the TPM key store name to the name of the CA
	if config.TPMConfig != nil {
		config.TPMConfig.CN = config.CN
	}
	if config.PKCS11Config != nil {
		config.PKCS11Config.CN = config.CN
	}
	if config.PKCS8Config != nil {
		config.PKCS8Config.CN = config.CN
	}

	// Provides O(1) constant time store lookups
	storeMap := make(map[keystore.StoreType]keystore.KeyStorer, 0)

	// Generate TPM 2.0 key store
	if config.TPMConfig != nil {
		params := &tpm2ks.Params{
			Backend:          keyBackend,
			Logger:           logger,
			DebugSecrets:     debugSecrets,
			Config:           config.TPMConfig,
			PlatformKeyStore: platformKS,
			SignerStore:      signerStore,
			TPM:              tpm,
		}
		tpmks, err := tpm2ks.NewKeyStore(params)
		if err != nil {
			if err == keystore.ErrNotInitalized {
				if err := tpmks.Initialize(soPIN, userPIN); err != nil {
					params.Logger.Error(err)
					return nil, err
				}
			} else {
				return nil, err
			}
		}
		storeMap[keystore.STORE_TPM2] = tpmks
	}

	// Generate PKCS #8 key store
	if config.PKCS8Config != nil {
		params := &pkcs8.Params{
			DebugSecrets: debugSecrets,
			Logger:       logger,
			Config:       config.PKCS8Config,
			Random:       random,
			Backend:      keyBackend,
			SignerStore:  signerStore,
			BlobStore:    blobStore,
			TPMKS:        platformKS,
		}
		pkcs8Store, err := pkcs8.NewKeyStore(params)
		if err != nil {
			if err == keystore.ErrNotInitalized {
				if err := pkcs8Store.Initialize(soPIN, userPIN); err != nil {
					params.Logger.Error(err)
					return nil, err
				}
			} else {
				return nil, err
			}
		}
		storeMap[keystore.STORE_PKCS8] = pkcs8Store
	}

	// Generate PKCS #11 key store
	if config.PKCS11Config != nil {
		params := &pkcs11.Params{
			Backend:      keyBackend,
			Config:       config.PKCS11Config,
			DebugSecrets: debugSecrets,
			Logger:       logger,
			Random:       random,
			SignerStore:  signerStore,
			TPMKS:        platformKS,
		}
		pkcs11Store, err := pkcs11.NewKeyStore(params)
		if err != nil {
			if err == keystore.ErrNotInitalized {
				if err := pkcs11Store.Initialize(soPIN, userPIN); err != nil {
					params.Logger.Error(err)
					return nil, err
				}
			} else {
				return nil, err
			}
		}
		storeMap[keystore.STORE_PKCS11] = pkcs11Store
	}

	return &KeyChain{
		backend:    keyBackend,
		logger:     logger,
		config:     config,
		platformKS: platformKS,
		storeMap:   storeMap,
		tpm:        tpm}, nil
}

// Returns a sealed key password from the TPM using the platform
// PCR authorization policy. The returned secret object performs
// just-in-time retrieval using a PCR session policy instead of
// caching it on the heap. If the key  doesn't have any data sealed,
// ErrPasswordRequired is returned so the password may be provided
// by the user.
func (keychain *KeyChain) Password(
	attrs *keystore.KeyAttributes) (keystore.Password, error) {

	if attrs.Parent == nil {
		srkAttrs := keychain.platformKS.SRKAttributes()
		attrs.Parent = srkAttrs
	}
	return tpm2.NewPlatformPassword(
		keychain.logger,
		keychain.tpm,
		attrs,
		keychain.platformKS.Backend(),
	), nil
}

// Calls close on each of the key stores and deletes
// the store from the internal store map.
func (keychain *KeyChain) Close() {
	for k, v := range keychain.storeMap {
		if err := v.Close(); err != nil {
			keychain.logger.Error(err)
		}
		delete(keychain.storeMap, k)
	}
}

// Returns the configured key stores in the key chain
func (keychain *KeyChain) Stores() []keystore.KeyStorer {
	stores := make([]keystore.KeyStorer, 0)
	for _, v := range keychain.storeMap {
		stores = append(stores, v)
	}
	return stores
}

// Returns the PKCS #8 key store
func (keychain *KeyChain) PKCS8() keystore.KeyStorer {
	pkcs8, _ := keychain.storeMap[keystore.STORE_PKCS8]
	return pkcs8
}

// Returns the PKCS #11 key store
func (keychain *KeyChain) PKCS11() keystore.KeyStorer {
	pkcs11, _ := keychain.storeMap[keystore.STORE_PKCS11]
	return pkcs11
}

// Returns the TPM 2.0 key store
func (keychain *KeyChain) TPM2() keystore.KeyStorer {
	tpm, _ := keychain.storeMap[keystore.STORE_TPM2]
	return tpm
}

// Generates a new key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer and
// crypto.Decrypter backed by the underlying Key Store Module.
func (keychain *KeyChain) GenerateKey(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.GenerateKey(attrs)
}

// Returns a RSA OpaqueKey for the provided key attributes. The
// underlying Key Store Module must support the algorithm.
func (keychain *KeyChain) GenerateRSA(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.GenerateRSA(attrs)
}

// Returns an ECDSA OpaqueKey for the provided key attributes. The
// underlying Key Store Module must support the algorithm.
func (keychain *KeyChain) GenerateECDSA(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.GenerateECDSA(attrs)
}

// Returns an Ed25519 OpaqueKey for the provided key attributes. The
// underlying Key Store Module must support the algorithm.
func (keychain *KeyChain) GenerateEd25519(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.GenerateEd25519(attrs)
}

// Deletes the key pair associated with the provided key attributes
func (keychain *KeyChain) Delete(attrs *keystore.KeyAttributes) error {
	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return keystore.ErrInvalidKeyStore
	}
	if err := s.Delete(attrs); err != nil {
		return err
	}
	return keychain.platformKS.Delete(attrs)
}

// Returns a crypto.Decrypter for the provided key attributes
func (keychain *KeyChain) Decrypter(
	attrs *keystore.KeyAttributes) (crypto.Decrypter, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.Decrypter(attrs)
}

// Returns an OpaqueKey  for the provided key attributes
func (keychain *KeyChain) Key(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.Key(attrs)
}

// Returns a crypto.Signer for the provided key attributes
func (keychain *KeyChain) Signer(
	attrs *keystore.KeyAttributes) (crypto.Signer, error) {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		return nil, keystore.ErrInvalidKeyStore
	}
	return s.Signer(attrs)
}

// Returns a software runtime verifier to perform
// signature verifications. The verifier supports
// RSA PKCS1v15, RSA-PSS, ECDSA, and Ed25519.
func (keychain *KeyChain) Verifier(
	attrs *keystore.KeyAttributes,
	opts *keystore.VerifyOpts) keystore.Verifier {

	s, ok := keychain.storeMap[attrs.StoreType]
	if !ok {
		panic(keystore.ErrInvalidKeyStore)
	}
	return s.Verifier(attrs, opts)
}
