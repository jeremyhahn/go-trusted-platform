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

package common

import (
	"crypto/x509"
	"fmt"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// KeyConfig is a YAML/JSON-serializable configuration for cryptographic keys.
// It uses string representations for enums and types to support configuration files.
// Convert to xkmssdk.KeyAttributes using ToKeyAttributes() before use with backends.
type KeyConfig struct {
	CN                 string               `yaml:"cn,omitempty" json:"cn,omitempty" mapstructure:"cn"`
	Debug              bool                 `yaml:"debug,omitempty" json:"debug,omitempty" mapstructure:"debug"`
	Hash               string               `yaml:"hash,omitempty" json:"hash,omitempty" mapstructure:"hash"`
	KeyAlgorithm       string               `yaml:"algorithm,omitempty" json:"algorithm,omitempty" mapstructure:"algorithm"`
	Password           string               `yaml:"password,omitempty" json:"password,omitempty" mapstructure:"password" secret:"true"`
	PasswordCache      *PasswordCacheConfig `yaml:"password-cache,omitempty" json:"password_cache,omitempty" mapstructure:"password-cache"`
	PlatformPolicy     bool                 `yaml:"platform-policy,omitempty" json:"platform_policy,omitempty" mapstructure:"platform-policy"`
	SignatureAlgorithm string               `yaml:"signature-algorithm,omitempty" json:"signature_algorithm,omitempty" mapstructure:"signature-algorithm"`
	StoreType          string               `yaml:"store,omitempty" json:"store,omitempty" mapstructure:"store"`
	ECCConfig          *ECCConfig           `yaml:"ecc,omitempty" json:"ecc,omitempty" mapstructure:"ecc"`
	RSAConfig          *RSAConfig           `yaml:"rsa,omitempty" json:"rsa,omitempty" mapstructure:"rsa"`
	AESConfig          *AESConfig           `yaml:"aes,omitempty" json:"aes,omitempty" mapstructure:"aes"`
	Exportable         bool                 `yaml:"exportable,omitempty" json:"exportable,omitempty" mapstructure:"exportable"`
}

// ECCConfig contains Elliptic Curve Cryptography configuration parameters.
type ECCConfig struct {
	Curve string `yaml:"curve" json:"curve" mapstructure:"curve"`
}

// RSAConfig contains RSA configuration parameters.
type RSAConfig struct {
	KeySize int `yaml:"keysize" json:"keysize" mapstructure:"keysize"`
}

// AESConfig contains AES configuration parameters.
type AESConfig struct {
	KeySize   int `yaml:"keysize" json:"keysize" mapstructure:"keysize"`
	NonceSize int `yaml:"nonce-size,omitempty" json:"nonce_size,omitempty" mapstructure:"nonce-size"`
}

// PasswordCacheConfig holds configuration for platform password caching.
// When caching is enabled, the unsealed password is stored in memory
// to avoid repeated TPM unsealing operations.
type PasswordCacheConfig struct {
	// Enabled determines whether password caching is active.
	// When false, every password access will unseal from the TPM.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// TTL is the time-to-live for cached passwords in seconds.
	// After this duration, the cache is invalidated and the password
	// will be unsealed again on the next access.
	// If zero and Enabled is true, defaults to 300 (5 minutes).
	TTL int `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl"`
}

// ToKeyAttributes converts KeyConfig to xkmssdk.KeyAttributes for use with backends.
func (kc *KeyConfig) ToKeyAttributes() (*xkmssdk.KeyAttributes, error) {
	attrs := &xkmssdk.KeyAttributes{
		CN:             kc.CN,
		Debug:          kc.Debug,
		PlatformPolicy: kc.PlatformPolicy,
		Exportable:     kc.Exportable,
	}

	// Parse hash algorithm
	// Normalize hash string: remove hyphens (e.g., "SHA-256" -> "SHA256")
	if kc.Hash != "" {
		normalizedHash := strings.ReplaceAll(kc.Hash, "-", "")
		hash := xkmssdk.ParseHash(normalizedHash)
		if hash == 0 {
			return nil, &MessageError{Msg: fmt.Sprintf("invalid hash algorithm: %s", kc.Hash)}
		}
		attrs.Hash = hash
	}

	// Parse key algorithm
	if kc.KeyAlgorithm != "" {
		keyAlg, err := xkmssdk.ParseKeyAlgorithm(kc.KeyAlgorithm)
		if err != nil {
			return nil, &WrappedError{Msg: "invalid key algorithm", Err: err}
		}
		attrs.KeyAlgorithm = keyAlg
	}

	// Parse signature algorithm
	if kc.SignatureAlgorithm != "" {
		sigAlg, err := xkmssdk.ParseSignatureAlgorithm(kc.SignatureAlgorithm)
		if err != nil {
			return nil, &WrappedError{Msg: "invalid signature algorithm", Err: err}
		}
		attrs.SignatureAlgorithm = sigAlg
	}

	// Parse store type
	if kc.StoreType != "" {
		storeType := xkmssdk.ParseStoreType(kc.StoreType)
		if storeType == xkmssdk.StoreUnknown {
			return nil, &MessageError{Msg: fmt.Sprintf("invalid store type: %s", kc.StoreType)}
		}
		attrs.StoreType = storeType
	}

	// Parse ECC configuration
	if kc.ECCConfig != nil {
		curve, err := xkmssdk.ParseCurve(kc.ECCConfig.Curve)
		if err != nil {
			return nil, &WrappedError{Msg: "invalid ECC curve", Err: err}
		}
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{
			Curve: curve,
		}
	}

	// Parse RSA configuration
	if kc.RSAConfig != nil {
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{
			KeySize: kc.RSAConfig.KeySize,
		}
	}

	// Parse AES configuration
	if kc.AESConfig != nil {
		attrs.SymmetricAlgorithm = keySizeToSymmetricAlgorithm(kc.AESConfig.KeySize)
	}

	// Set password
	if kc.Password != "" {
		attrs.Password = xkmssdk.NewPasswordFromString(kc.Password)
	}

	// Set password cache configuration
	if kc.PasswordCache != nil {
		attrs.PasswordCache = &xkmssdk.PasswordCacheConfig{
			Enabled: kc.PasswordCache.Enabled,
			TTL:     kc.PasswordCache.TTL,
		}
	}

	return attrs, nil
}

// NewKeyConfigFromAttributes creates a KeyConfig from xkmssdk.KeyAttributes.
func NewKeyConfigFromAttributes(attrs *xkmssdk.KeyAttributes) *KeyConfig {
	kc := &KeyConfig{
		CN:             attrs.CN,
		Debug:          attrs.Debug,
		Hash:           attrs.Hash.String(),
		KeyAlgorithm:   attrs.KeyAlgorithm.String(),
		PlatformPolicy: attrs.PlatformPolicy,
		StoreType:      attrs.StoreType.String(),
		Exportable:     attrs.Exportable,
	}

	if attrs.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		kc.SignatureAlgorithm = attrs.SignatureAlgorithm.String()
	}

	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		kc.ECCConfig = &ECCConfig{
			Curve: attrs.ECCAttributes.Curve.Params().Name,
		}
	}

	if attrs.RSAAttributes != nil {
		kc.RSAConfig = &RSAConfig{
			KeySize: attrs.RSAAttributes.KeySize,
		}
	}

	if attrs.SymmetricAlgorithm != "" {
		kc.AESConfig = &AESConfig{
			KeySize:   attrs.SymmetricAlgorithm.KeySize(),
			NonceSize: attrs.SymmetricAlgorithm.NonceSize(),
		}
	}

	if attrs.Password != nil {
		if pw, err := attrs.Password.String(); err == nil {
			kc.Password = pw
		}
	}

	if attrs.PasswordCache != nil {
		kc.PasswordCache = &PasswordCacheConfig{
			Enabled: attrs.PasswordCache.Enabled,
			TTL:     attrs.PasswordCache.TTL,
		}
	}

	return kc
}

// Default password constant for development
const DEFAULT_PASSWORD = xkmssdk.DEFAULT_PASSWORD

// keySizeToSymmetricAlgorithm maps AES key sizes (in bits) to the corresponding
// SymmetricAlgorithm constant. Defaults to AES-256-GCM for unsupported sizes.
func keySizeToSymmetricAlgorithm(keySize int) xkmssdk.SymmetricAlgorithm {
	switch keySize {
	case 128:
		return xkmssdk.SymmetricAES128GCM
	case 192:
		return xkmssdk.SymmetricAES192GCM
	case 256:
		return xkmssdk.SymmetricAES256GCM
	default:
		return xkmssdk.SymmetricAES256GCM
	}
}
