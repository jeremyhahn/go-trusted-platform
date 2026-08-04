// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package platform

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// Compile-time interface check.
var _ xkmssdk.PlatformKeyStorer = (*PlatformKeyStore)(nil)

var (
	ErrInvalidXKMSCN           = errors.New("xkms: invalid configuration, missing CN")
	ErrInvalidPlatformKeyStore = errors.New("xkms: invalid platform key store")
	ErrInvalidStoreType        = errors.New("xkms: invalid store type")
	ErrBackendNotConfigured    = errors.New("xkms: backend not configured")
	ErrXKMSNotInitialized      = errors.New("xkms: not initialized")
	ErrInvalidBackendType      = errors.New("xkms: invalid backend type")
	ErrCertStorageRequired     = errors.New("xkms: certificate storage required")
	ErrTPMRequired             = errors.New("xkms: TPM required for platform key store")
	ErrBackendRequired         = errors.New("xkms: backend required for platform key store")
)

// ErrUnsupportedKeyAlgorithm is returned when a key algorithm is not supported
// by the GenerateKey dispatch.
type ErrUnsupportedKeyAlgorithm struct {
	Algorithm x509.PublicKeyAlgorithm
}

// Error returns the error message.
func (e ErrUnsupportedKeyAlgorithm) Error() string {
	return fmt.Sprintf("xkms: unsupported key algorithm: %v", e.Algorithm)
}

// Type aliases for backward compatibility
// KeyringConfig is an alias for XKMSConfig for backward compatibility.
type KeyringConfig = XKMSConfig

// Keyring is an alias for XKMS for backward compatibility.
type Keyring = XKMS

// TPMSigner implements crypto.Signer for TPM2-backed keys.
// It wraps the TPM module and key attributes to provide signing operations.
type TPMSigner struct {
	tpm       xkmssdk.TrustedPlatformModule
	attrs     *xkmssdk.KeyAttributes
	backend   xkmssdk.TPMKeyBackend
	publicKey crypto.PublicKey
}

// Public returns the public key corresponding to the TPM key.
// For TPM keys, the public key may be resolved lazily if not set during construction.
func (s *TPMSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the TPM key.
func (s *TPMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signerOpts := &xkmssdk.TPMSignerOpts{
		KeyAttributes: s.attrs,
		Backend:       s.backend,
	}
	return s.tpm.Sign(rand, digest, signerOpts)
}

// NewTPMSigner creates a new TPM signer for the given key attributes.
// It attempts to resolve the public key from the key attributes.
func NewTPMSigner(
	tpm xkmssdk.TrustedPlatformModule,
	attrs *xkmssdk.KeyAttributes,
	backend xkmssdk.TPMKeyBackend) *TPMSigner {
	signer := &TPMSigner{
		tpm:     tpm,
		attrs:   attrs,
		backend: backend,
	}
	// Try to resolve the public key from TPMAttributes
	if attrs.TPMAttributes != nil && len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
		pubKey, err := tpm.ParsePublicKey(attrs.TPMAttributes.PublicKeyBytes)
		if err == nil {
			signer.publicKey = pubKey
		}
	}
	return signer
}

// PlatformKeyStore implements xkmssdk.PlatformKeyStorer interface.
// It provides access to the Platform KeyStore Storage Root Key (SRK) attributes
// and the key backend for TPM-backed platform key operations.
//
// IMPORTANT: The Platform KeyStore has its own dedicated SRK at handle 0x81000002
// (configurable via PlatformSRKConfig.SRKHandle). This is DIFFERENT from the SSRK
// at handle 0x81000001 which should NOT have any auth policies.
//
// The Platform KeyStore SRK can optionally have a PCR policy (when PlatformPolicy=true)
// to bind keys to the measured boot state. When PlatformPolicy=false, PIN auth is used.
type PlatformKeyStore struct {
	tpm         xkmssdk.TrustedPlatformModule
	backend     xkmssdk.TPMKeyBackend
	config      *xkmssdk.PlatformSRKConfig
	pinBackend  xkmssdk.PINBackend
	initialized atomic.Bool
}

// NewPlatformKeyStore creates a new PlatformKeyStore using the provided
// TPM, key backend, and configuration. All parameters are required.
//
// This function checks if the Platform KeyStore SRK exists at the configured
// handle. If it doesn't exist, it returns ErrXKMSNotInitialized and the
// caller should call Initialize() to create the SRK.
func NewPlatformKeyStore(
	tpm xkmssdk.TrustedPlatformModule,
	backend xkmssdk.TPMKeyBackend,
	config *xkmssdk.PlatformSRKConfig) (*PlatformKeyStore, error) {

	if tpm == nil {
		return nil, ErrTPMRequired
	}
	if backend == nil {
		return nil, ErrBackendRequired
	}
	if config == nil {
		return nil, errors.New("xkms: PlatformSRKConfig required for platform key store")
	}
	if config.SRKHandle == 0 {
		return nil, errors.New("xkms: SRKHandle must be configured (default: 0x81000002)")
	}

	ks := &PlatformKeyStore{
		tpm:     tpm,
		backend: backend,
		config:  config,
	}

	// Check if the Platform KeyStore SRK exists at the configured handle
	_, err := tpm.KeyAttributes(xkmssdk.TPMHandle(config.SRKHandle))
	if err != nil {
		// TPM_RC_HANDLE (0x18b) or TPM_RC_VALUE (0x184) means the key doesn't exist
		// Return ErrNotInitialized so caller knows to call Initialize()
		return ks, ErrXKMSNotInitialized
	}

	ks.initialized.Store(true)
	return ks, nil
}

// Initialize creates the Platform KeyStore SRK at the configured handle.
// This must be called once after provisioning the TPM's SSRK.
//
// The SRK is created with the following characteristics:
// - Handle: PlatformSRKConfig.SRKHandle (default 0x81000002)
// - Parent: EK (Endorsement Key)
// - Auth: userPIN (sealed to the Platform KeyStore backend)
// - Platform Policy: PlatformSRKConfig.PlatformPolicy determines if PCR policy is applied
func (p *PlatformKeyStore) Initialize(soPIN, userPIN string) error {
	if p.config.CN == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidXKMSCN, Cause: &MessageError{Msg: "missing required CN"}}
	}

	// Get EK attributes as parent
	ekAttrs, err := p.tpm.EKAttributes()
	if err != nil {
		return &WrappedError{Msg: "failed to get EK attributes", Err: err}
	}

	// Build SRK attributes from config
	srkAttrs, srkErr := p.buildSRKAttributes()
	if srkErr != nil {
		return srkErr
	}
	srkAttrs.Parent = ekAttrs
	srkAttrs.Password = xkmssdk.NewPasswordFromString(userPIN)
	if srkAttrs.TPMAttributes == nil {
		return errors.New("xkms: failed to build SRK attributes")
	}
	srkAttrs.TPMAttributes.HierarchyAuth = xkmssdk.NewPasswordFromString(soPIN)

	// Create the Platform KeyStore SRK
	if err := p.tpm.CreateSRK(srkAttrs); err != nil {
		return &WrappedError{Msg: "failed to create Platform KeyStore SRK", Err: err}
	}

	p.initialized.Store(true)
	return nil
}

// InitializeWithDefaults creates the Platform KeyStore SRK using empty (default)
// TPM hierarchy auth, skipping PIN backend setup entirely. This is used when
// the user chose not to set TPM hierarchy authorization passwords.
func (p *PlatformKeyStore) InitializeWithDefaults() error {
	if p.config.CN == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidXKMSCN, Cause: &MessageError{Msg: "missing required CN"}}
	}

	// Get EK attributes as parent
	ekAttrs, err := p.tpm.EKAttributes()
	if err != nil {
		return &WrappedError{Msg: "failed to get EK attributes", Err: err}
	}

	// Build SRK attributes from config
	srkAttrs, srkErr := p.buildSRKAttributes()
	if srkErr != nil {
		return srkErr
	}
	srkAttrs.Parent = ekAttrs
	srkAttrs.Password = xkmssdk.NewPassword(nil)
	if srkAttrs.TPMAttributes == nil {
		return errors.New("xkms: failed to build SRK attributes")
	}
	srkAttrs.TPMAttributes.HierarchyAuth = xkmssdk.NewPassword(nil)

	// Create the Platform KeyStore SRK
	if err := p.tpm.CreateSRK(srkAttrs); err != nil {
		return &WrappedError{Msg: "failed to create Platform KeyStore SRK", Err: err}
	}

	p.initialized.Store(true)
	return nil
}

// IsInitialized returns true if the platform key store has been initialized
// with PINs and SRK.
func (p *PlatformKeyStore) IsInitialized() bool {
	return p.initialized.Load()
}

// EnrollPlatformSRK performs a one-shot first-boot enrollment of the Platform
// SRK, binding the operator-supplied userPIN as its authorization value.
// It is idempotent: xkmssdk.ErrPlatformSRKAlreadyEnrolled is returned when the
// SRK auth is already in a known-good state so a daemon can skip enrollment on
// subsequent boots without treating the condition as a failure.
// An empty userPIN is rejected with xkmssdk.ErrPlatformSRKEnrollEmptyPIN.
func (p *PlatformKeyStore) EnrollPlatformSRK(userPIN string) error {
	if userPIN == "" {
		return xkmssdk.ErrPlatformSRKEnrollEmptyPIN
	}
	if p.IsAuthReady() {
		return xkmssdk.ErrPlatformSRKAlreadyEnrolled
	}
	return p.Initialize("", userPIN)
}

// PlatformPolicyEnabled returns true if TPM platform policy is enabled
// in the key store configuration.
func (p *PlatformKeyStore) PlatformPolicyEnabled() bool {
	if p.config == nil {
		return false
	}
	return p.config.PlatformPolicy
}

// buildSRKAttributes creates KeyAttributes for the Platform KeyStore SRK
// based on the PlatformSRKConfig settings.
//
// When PlatformPolicy=true in config, the SRK is created with a PCR auth policy.
// This means any operation using this SRK as parent requires a PCR policy session
// (via PlatformPolicySession) to satisfy the auth policy. The go-xkms's
// CreateSession() function handles this automatically when Parent.PlatformPolicy=true.
func (p *PlatformKeyStore) buildSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	srkHandle := xkmssdk.TPMHandle(p.config.SRKHandle)

	// Use RSA SRK template as default (from go-xkms SDK re-exports)
	srkTemplate := xkmssdk.RSASRKTemplate
	srkTemplate.NameAlg = p.tpm.AlgID()
	srkTemplate.ObjectAttributes.NoDA = false

	// Apply PCR auth policy to the SRK template when PlatformPolicy=true
	// This binds the SRK to the platform PCR state - any use of this SRK
	// requires a PCR policy session to authorize access
	if p.config.PlatformPolicy {
		digest, err := p.tpm.PlatformPolicyDigest()
		if err != nil {
			return nil, ErrPlatformPolicyFailed{Cause: err}
		}
		srkTemplate.AuthPolicy = digest
	}

	return &xkmssdk.KeyAttributes{
		CN:             p.config.CN,
		KeyAlgorithm:   x509.RSA,
		KeyType:        xkmssdk.KeyTypeStorage,
		PlatformPolicy: p.config.PlatformPolicy,
		StoreType:      xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:     srkHandle,
			HandleType: xkmssdk.TPMHTPersistent,
			Hierarchy:  xkmssdk.TPMRHOwner,
			Template:   srkTemplate,
		},
	}, nil
}

// SRKAttributes returns the Platform KeyStore Storage Root Key attributes.
// This returns the SRK at the configured handle (default 0x81000002),
// NOT the SSRK at 0x81000001.
//
// Returns nil if the Platform KeyStore SRK is not initialized or cannot be retrieved.
func (p *PlatformKeyStore) SRKAttributes() *xkmssdk.KeyAttributes {
	srkHandle := xkmssdk.TPMHandle(p.config.SRKHandle)

	// Try to get attributes from the persisted key
	attrs, err := p.tpm.KeyAttributes(srkHandle)
	if err != nil {
		// Key doesn't exist - return built attributes without TPM public/name
		// This allows callers to attempt initialization
		builtAttrs, buildErr := p.buildSRKAttributes()
		if buildErr != nil {
			return nil
		}
		return builtAttrs
	}

	// Merge persisted attributes with config
	srkAttrs, srkBuildErr := p.buildSRKAttributes()
	if srkBuildErr != nil {
		return nil
	}
	if attrs.TPMAttributes != nil {
		srkAttrs.TPMAttributes.Name = attrs.TPMAttributes.Name
		srkAttrs.TPMAttributes.Public = attrs.TPMAttributes.Public
	}

	// Get EK as parent
	ekAttrs, err := p.tpm.EKAttributes()
	if err == nil {
		srkAttrs.Parent = ekAttrs
	}

	return srkAttrs
}

// Backend returns the key backend used for TPM key storage operations.
func (p *PlatformKeyStore) Backend() xkmssdk.TPMKeyBackend {
	return p.backend
}

// PINBackend returns the modern PIN backend for this key store.
// Returns nil when the key store has not been initialized with a PIN backend.
func (p *PlatformKeyStore) PINBackend() xkmssdk.PINBackend {
	return p.pinBackend
}

// VerifyAuth verifies the user PIN against the PlatformSRK's password auth.
// Uses TPM2_Create as a parent auth check via the TPM module.
func (p *PlatformKeyStore) VerifyAuth(userPIN string) error {
	if !p.initialized.Load() {
		return ErrXKMSNotInitialized
	}
	srkAttrs := p.SRKAttributes()
	if srkAttrs == nil || srkAttrs.TPMAttributes == nil {
		return ErrXKMSNotInitialized
	}
	return p.tpm.VerifyAuth(srkAttrs.TPMAttributes.Handle, []byte(userPIN))
}

// ChangeAuth changes the PlatformSRK's password auth (user PIN change).
func (p *PlatformKeyStore) ChangeAuth(currentPIN, newPIN string) error {
	if !p.initialized.Load() {
		return ErrXKMSNotInitialized
	}
	return p.tpm.ChangeAuth(
		xkmssdk.TPMHandle(p.config.SRKHandle),
		[]byte(currentPIN),
		[]byte(newPIN),
	)
}

// GetLockoutInfo returns real TPM dictionary attack lockout counters by
// querying the TPM's fixed properties.
func (p *PlatformKeyStore) GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error) {
	props, err := p.tpm.FixedProperties()
	if err != nil || props == nil {
		return 0, 10, 0, 300, err
	}
	return int(props.LockoutCounter),
		int(props.MaxAuthFail),
		int(props.LockoutInterval),
		int(props.LockoutRecovery),
		nil
}

// DictionaryAttackLockoutReset resets the TPM DA lockout counter.
func (p *PlatformKeyStore) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return p.tpm.DictionaryAttackLockoutReset(lockoutAuth)
}

// IsProvisioned returns true if the TPM has been provisioned.
func (p *PlatformKeyStore) IsProvisioned() bool {
	return p.initialized.Load()
}

// IsAuthReady returns true if the PlatformSRK's auth value is in a known good state.
func (p *PlatformKeyStore) IsAuthReady() bool {
	return p.initialized.Load()
}

// SetAuthReady explicitly sets the auth-ready state.
func (p *PlatformKeyStore) SetAuthReady(ready bool) {
	p.initialized.Store(ready)
}

// XKMSConfig contains configuration for XKMS.
// It supports multiple backend configurations for flexible key management.
// Implements ca.XKMSConfigurable interface.
type XKMSConfig struct {
	// CN is the common name identifier for this XKMS backend
	CN string `yaml:"cn" json:"cn" mapstructure:"cn"`

	// DefaultBackend specifies which backend to use by default
	DefaultBackend string `yaml:"default-backend" json:"default_backend" mapstructure:"default-backend"`

	// SoftwareConfig configures the software-based backend (uses xkmssdk.SoftwareBackendConfig for unified operations)
	SoftwareConfig *xkmssdk.SoftwareBackendConfig `yaml:"software" json:"software" mapstructure:"software"`

	// TPMConfig configures the TPM 2.0 backend
	TPMConfig *xkmssdk.TPMConfig `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
}

// GetCN returns the Common Name for this XKMS configuration.
// Implements ca.XKMSConfigurable interface.
func (k *XKMSConfig) GetCN() string {
	return k.CN
}

// SetCN sets the Common Name for this XKMS configuration.
// Implements ca.XKMSConfigurable interface.
func (k *XKMSConfig) SetCN(cn string) {
	k.CN = cn
}

// XKMS provides unified access to cryptographic key storage backends
// through go-xkms's KeyStore interface. It abstracts away backend
// implementation details and provides a consistent API for key operations.
type XKMS struct {
	logger      *slog.Logger
	config      *XKMSConfig
	keyBackend  xkmssdk.TPMKeyBackend
	platformKS  xkmssdk.PlatformKeyStorer
	keystores   map[string]xkmssdk.ServiceBackend
	backends    map[xkmssdk.StoreType]xkmssdk.ServiceBackend
	tpm         xkmssdk.TrustedPlatformModule
	certStorage xkmssdk.StorageBackend
}

// NewXKMS creates a new XKMS using the provided configuration.
// It initializes all configured backends and creates KeyStore wrappers.
func NewXKMS(
	logger *slog.Logger,
	config *XKMSConfig,
	keyBackend xkmssdk.TPMKeyBackend,
	keyStorage xkmssdk.StorageBackend,
	certStorage xkmssdk.StorageBackend,
	tpm xkmssdk.TrustedPlatformModule,
	platformKS xkmssdk.PlatformKeyStorer) (*XKMS, error) {

	if logger == nil {
		logger = slog.Default()
	}

	if config.CN == "" {
		return nil, ErrInvalidXKMSCN
	}

	if certStorage == nil {
		return nil, ErrCertStorageRequired
	}

	keystores := make(map[string]xkmssdk.ServiceBackend)
	backends := make(map[xkmssdk.StoreType]xkmssdk.ServiceBackend)

	// Initialize software backend if configured (unified asymmetric + symmetric operations)
	if config.SoftwareConfig != nil {
		if config.SoftwareConfig.KeyStorage == nil {
			config.SoftwareConfig.KeyStorage = keyStorage
		}
		softwareBackend, err := xkmssdk.NewSoftwareBackend(config.SoftwareConfig)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to initialize software backend", Err: err}
		}

		// Create xkmssdk.ServiceBackend wrapper for the software key provider.
		// The xkmssdk.ServiceBackend composes the key provider with certificate storage.
		ks, ksErr := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
			Backend:     softwareBackend,
			CertStorage: certStorage,
		})
		if ksErr != nil {
			return nil, &WrappedError{Msg: "failed to create software keystore", Err: ksErr}
		}

		// Store the xkmssdk.ServiceBackend wrapper (not the raw key provider) in the
		// backends map, since the map type is map[xkmssdk.StoreType]xkmssdk.ServiceBackend.
		backends[xkmssdk.StoreSoftware] = ks
		backends[xkmssdk.StoreUnknown] = ks

		keystores["software"] = ks
	}

	return &XKMS{
		logger:      logger,
		config:      config,
		keyBackend:  keyBackend,
		platformKS:  platformKS,
		keystores:   keystores,
		backends:    backends,
		tpm:         tpm,
		certStorage: certStorage,
	}, nil
}

// Config returns the XKMS configuration.
func (kc *XKMS) Config() *XKMSConfig {
	return kc.config
}

// Backend returns the key backend used by XKMS.
func (kc *XKMS) Backend() xkmssdk.TPMKeyBackend {
	return kc.keyBackend
}

// KeyStore returns the KeyStore for the specified backend name.
// If no name is provided, returns the default KeyStore.
func (kc *XKMS) KeyStore(name ...string) (xkmssdk.ServiceBackend, error) {
	if len(name) > 0 && name[0] != "" {
		ks, ok := kc.keystores[name[0]]
		if !ok {
			return nil, &SentinelCauseError{Sentinel: ErrBackendNotConfigured, Cause: &MessageError{Msg: fmt.Sprintf("%s", name[0])}}
		}
		return ks, nil
	}

	// Return default backend
	defaultName := kc.config.DefaultBackend
	if defaultName == "" {
		// If no default specified, use first available
		for _, ks := range kc.keystores {
			return ks, nil
		}
		return nil, ErrXKMSNotInitialized
	}

	ks, ok := kc.keystores[defaultName]
	if !ok {
		return nil, &SentinelCauseError{Sentinel: ErrBackendNotConfigured, Cause: &MessageError{Msg: fmt.Sprintf("%s", defaultName)}}
	}
	return ks, nil
}

// Password returns a sealed key password from the TPM.
func (kc *XKMS) Password(attrs *xkmssdk.KeyAttributes) (xkmssdk.Password, error) {
	if kc.tpm == nil {
		return nil, errors.New("xkms: TPM not configured")
	}
	if attrs.Parent == nil && kc.platformKS != nil {
		srkAttrs := kc.platformKS.SRKAttributes()
		attrs.Parent = srkAttrs
	}
	return xkmssdk.NewPlatformPassword(
		kc.logger,
		kc.tpm,
		attrs,
		kc.platformKS.Backend(),
	), nil
}

// Close releases resources held by all backends.
func (kc *XKMS) Close() error {
	var lastErr error
	for name, ks := range kc.keystores {
		if err := ks.Close(); err != nil {
			kc.logger.Error("failed to close keystore", "error", err, "name", name)
			lastErr = err
		}
		delete(kc.keystores, name)
	}
	for k := range kc.backends {
		delete(kc.backends, k)
	}
	return lastErr
}

// Stores returns all configured backends.
func (kc *XKMS) Stores() []xkmssdk.ServiceBackend {
	stores := make([]xkmssdk.ServiceBackend, 0, len(kc.backends))
	seen := make(map[xkmssdk.ServiceBackend]bool)
	for _, v := range kc.backends {
		if !seen[v] {
			stores = append(stores, v)
			seen[v] = true
		}
	}
	return stores
}

// Store returns the backend for the given store type.
func (kc *XKMS) Store(storeType string) (xkmssdk.ServiceBackend, error) {
	backend, ok := kc.backends[xkmssdk.StoreType(storeType)]
	if !ok {
		return nil, ErrInvalidStoreType
	}
	return backend, nil
}

// Software returns the software backend.
func (kc *XKMS) Software() xkmssdk.ServiceBackend {
	return kc.backends[xkmssdk.StoreSoftware]
}

// TPM returns the TPM module.
func (kc *XKMS) TPM() xkmssdk.TrustedPlatformModule {
	return kc.tpm
}

// GenerateKey generates a new key using the appropriate backend.
// If PlatformPolicy is true and the key has a password, the password
// is sealed to TPM before generating the key.
func (kc *XKMS) GenerateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return nil, xkmssdk.ErrInvalidKeyStore
	}

	// For keys with platform policy, seal the password to TPM before generating
	if attrs.PlatformPolicy && attrs.Password != nil && kc.tpm != nil && kc.platformKS != nil {
		// Ensure parent SRK attributes are set
		if attrs.Parent == nil {
			attrs.Parent = kc.platformKS.SRKAttributes()
		}

		// Create platform password and seal to TPM
		platformPassword := xkmssdk.NewPlatformPassword(
			kc.logger,
			kc.tpm,
			attrs,
			kc.platformKS.Backend(),
		)

		// Cast to get access to Create() method
		if pp, ok := platformPassword.(*xkmssdk.PlatformPassword); ok {
			if err := pp.Create(); err != nil {
				return nil, &WrappedError{Msg: "failed to seal password to TPM", Err: err}
			}
		}
		// The Create() method updates attrs.Password to the PlatformPassword
	}

	// Dispatch to algorithm-specific generation methods
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return backend.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		return backend.GenerateECDSA(ctx, attrs)
	case x509.Ed25519:
		return backend.GenerateEd25519(ctx, attrs)
	default:
		return nil, ErrUnsupportedKeyAlgorithm{Algorithm: attrs.KeyAlgorithm}
	}
}

// GetKey retrieves an existing key.
func (kc *XKMS) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return nil, xkmssdk.ErrInvalidKeyStore
	}
	return backend.GetKey(ctx, attrs)
}

// DeleteKey removes a key.
func (kc *XKMS) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return xkmssdk.ErrInvalidKeyStore
	}
	return backend.DeleteKey(ctx, attrs)
}

// Signer returns a crypto.Signer for the key.
func (kc *XKMS) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	// Handle TPM2 keys using TPMSigner wrapper
	if attrs.StoreType == xkmssdk.StoreTPM2 {
		if kc.tpm == nil {
			return nil, errors.New("xkms: TPM not configured for TPM2 key")
		}
		return NewTPMSigner(kc.tpm, attrs, kc.keyBackend), nil
	}

	// Use backend for other store types
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return nil, xkmssdk.ErrInvalidKeyStore
	}
	return backend.Signer(ctx, attrs)
}

// Decrypter returns a crypto.Decrypter for the key.
func (kc *XKMS) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return nil, xkmssdk.ErrInvalidKeyStore
	}
	return backend.Decrypter(ctx, attrs)
}

// RotateKey rotates the key.
func (kc *XKMS) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	backend, ok := kc.backends[attrs.StoreType]
	if !ok {
		return xkmssdk.ErrInvalidKeyStore
	}
	_, err := backend.RotateKey(ctx, attrs)
	return err
}
