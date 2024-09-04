package tpm2

import (
	"crypto/x509"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type HierarchyType string

var (
	ErrInvalidHierarchyType = errors.New("tpm2: invalid hierarchy type")
)

const (
	HIERARCHY_TYPE_ENDORSEMENT = "ENDORSEMENT"
	HIERARCHY_TYPE_OWNER       = "OWNER"
	HIERARCHY_TYPE_PLATFORM    = "PLATFORM"
)

type Config struct {
	Device         string          `yaml:"device" json:"device" mapstructure:"device"`
	EncryptSession bool            `yaml:"encrypt-sessions" json:"encrypt_sessions" mapstructure:"encrypt-sessions"`
	EK             *EKConfig       `yaml:"ek" json:"ek" mapstructure:"ek"`
	FileIntegrity  []string        `yaml:"file-integrity" json:"file_integrity" mapstructure:"file-integrity"`
	Hash           string          `yaml:"hash" json:"hash" mapstructure:"hash"`
	IAK            *IAKConfig      `yaml:"iak" json:"iak" mapstructure:"iak"`
	IDevID         *IDevIDConfig   `yaml:"idevid" json:"idevid" mapstructure:"idevid"`
	KeyStore       *KeyStoreConfig `yaml:"keystore" json:"keystore" mapstructure:"keystore"`
	LockoutAuth    string          `yaml:"lockout-auth" json:"lockout-auth" mapstructure:"lockout-auth"`
	PlatformPCR    uint            `yaml:"platform-pcr" json:"platform_pcr" mapstructure:"platform-pcr"`
	SSRK           *SRKConfig      `yaml:"ssrk" json:"ssrk" mapstructure:"ssrk"`
	UseEntropy     bool            `yaml:"entropy" json:"entropy" mapstructure:"entropyr"`
	UseSimulator   bool            `yaml:"simulator" json:"simulator" mapstructure:"simulator"`
}

type KeyStoreConfig struct {
	CN             string `yaml:"cn" json:"cn" mapstructure:"cn"`
	SRKAuth        string `yaml:"srk-auth" json:"srk_auth" mapstructure:"srk-auth"`
	SRKHandle      uint32 `yaml:"srk-handle" json:"srk-handle" mapstructure:"srk-handle"`
	PlatformPolicy bool   `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}

type EKConfig struct {
	CertHandle     uint32              `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN             string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug          bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig      *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle         uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	HierarchyAuth  string              `yaml:"hierarchy-auth" json:"hierarchy_auth" mapstructure:"hierarchy-auth"`
	KeyAlgorithm   string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password       string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig      *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
}

type SRKConfig struct {
	CN             string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug          bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig      *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle         uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	HierarchyAuth  string              `yaml:"hierarchy-auth" json:"hierarchy-auth" mapstructure:"hierarchy-auth"`
	KeyAlgorithm   string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password       string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig      *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
}

type IDevIDConfig struct {
	CertHandle         uint32              `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug              bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle             uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string              `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Model              string              `yaml:"model" json:"model" mapstructure:"model"`
	Pad                bool                `yaml:"pad" json:"pad" mapstructure:"pad"`
	Password           string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy     bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	Serial             string              `yaml:"serial" json:"serial" mapstructure:"serial"`
	SignatureAlgorithm string              `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

type IAKConfig struct {
	CertHandle         uint32              `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug              bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle             uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string              `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password           string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy     bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	SignatureAlgorithm string              `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

type LDevIDConfig struct {
	CertHandle         uint32              `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug              bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle             uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string              `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Model              string              `yaml:"model" json:"model" mapstructure:"model"`
	Pad                bool                `yaml:"pad" json:"pad" mapstructure:"pad"`
	Password           string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy     bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	Serial             string              `yaml:"serial" json:"serial" mapstructure:"serial"`
	SignatureAlgorithm string              `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

type LAKConfig struct {
	CertHandle         uint32              `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string              `yaml:"cn" json:"cn" mapstructure:"cn"`
	Debug              bool                `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *keystore.ECCConfig `yaml:"ecc" json:"ecc" mapstructure:"ecc"`
	Handle             uint32              `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string              `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string              `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password           string              `yaml:"password" json:"password" mapstructure:"password"`
	PlatformPolicy     bool                `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *keystore.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	SignatureAlgorithm string              `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

func EKAttributesFromConfig(config EKConfig, policyDigest *tpm2.TPM2BDigest) (*keystore.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "ek"
	}

	algorithm, err := keystore.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		if config.RSAConfig != nil {
			algorithm = x509.RSA
		} else if config.ECCConfig != nil {
			algorithm = x509.ECDSA
		} else {
			return nil, err
		}
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	attrs := &keystore.KeyAttributes{
		CN:             config.CN,
		Debug:          config.Debug,
		KeyAlgorithm:   algorithm,
		KeyType:        keystore.KEY_TYPE_ENDORSEMENT,
		Password:       keystore.NewClearPassword([]byte(config.Password)),
		PlatformPolicy: config.PlatformPolicy,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			CertHandle:    tpm2.TPMHandle(config.CertHandle),
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMHandle(tpm2.TPMRHEndorsement),
			HierarchyAuth: keystore.NewClearPassword([]byte(config.HierarchyAuth)),
			Template:      ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		if config.KeyAlgorithm == "" {
			config.KeyAlgorithm = x509.ECDSA.String()
		}
		curve, err := keystore.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		if config.KeyAlgorithm == "" {
			config.KeyAlgorithm = x509.RSA.String()
		}
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func SRKAttributesFromConfig(config SRKConfig, policyDigest *tpm2.TPM2BDigest) (*keystore.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "srk"
	}

	algorithm, err := keystore.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		if config.RSAConfig != nil {
			algorithm = x509.RSA
		} else if config.ECCConfig != nil {
			algorithm = x509.ECDSA
		} else {
			return nil, err
		}
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	attrs := &keystore.KeyAttributes{
		CN:             config.CN,
		Debug:          config.Debug,
		KeyAlgorithm:   algorithm,
		KeyType:        keystore.KEY_TYPE_STORAGE,
		Password:       keystore.NewClearPassword([]byte(config.Password)),
		PlatformPolicy: config.PlatformPolicy,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMHandle(tpm2.TPMRHOwner),
			HierarchyAuth: keystore.NewClearPassword([]byte(config.HierarchyAuth)),
			Template:      ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		curve, err := keystore.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func IAKAttributesFromConfig(
	soPIN keystore.Password,
	config *IAKConfig,
	policyDigest *tpm2.TPM2BDigest) (*keystore.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "iak"
	}

	algorithm, err := keystore.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		if config.RSAConfig != nil {
			algorithm = x509.RSA
		} else if config.ECCConfig != nil {
			algorithm = x509.ECDSA
		} else {
			return nil, err
		}
	}

	hash, err := keystore.ParseHash(config.Hash)
	if err != nil {
		return nil, err
	}

	sigAlgo, err := keystore.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	tpmHashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	attrs := &keystore.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            keystore.KEY_TYPE_ATTESTATION,
		Password:           keystore.NewClearPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			CertHandle:    tpm2.TPMHandle(config.CertHandle),
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			HashAlg:       tpmHashAlg,
			Hierarchy:     tpm2.TPMRHEndorsement,
			HierarchyAuth: soPIN,
			Template:      ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		curve, err := keystore.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func IDevIDAttributesFromConfig(
	config IDevIDConfig,
	policyDigest *tpm2.TPM2BDigest) (*keystore.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "idevid"
	}

	algorithm, err := keystore.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		if config.RSAConfig != nil {
			algorithm = x509.RSA
		} else if config.ECCConfig != nil {
			algorithm = x509.ECDSA
		} else {
			return nil, err
		}
	}

	hash, err := keystore.ParseHash(config.Hash)
	if err != nil {
		return nil, err
	}

	sigAlgo, err := keystore.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	hashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	attrs := &keystore.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            keystore.KEY_TYPE_IDEVID,
		Password:           keystore.NewClearPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:     tpm2.TPMHandle(config.Handle),
			HandleType: tpm2.TPMHTPersistent,
			HashAlg:    hashAlg,
			Hierarchy:  tpm2.TPMRHEndorsement,
			Template:   ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		curve, err := keystore.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func LDevIDAttributesFromConfig(
	config LDevIDConfig,
	policyDigest *tpm2.TPM2BDigest) (*keystore.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "ldevid"
	}

	algorithm, err := keystore.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		if config.RSAConfig != nil {
			algorithm = x509.RSA
		} else if config.ECCConfig != nil {
			algorithm = x509.ECDSA
		} else {
			return nil, err
		}
	}

	hash, err := keystore.ParseHash(config.Hash)
	if err != nil {
		return nil, err
	}

	sigAlgo, err := keystore.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	hashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	attrs := &keystore.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            keystore.KEY_TYPE_IDEVID,
		Password:           keystore.NewClearPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:     tpm2.TPMHandle(config.Handle),
			HandleType: tpm2.TPMHTPersistent,
			HashAlg:    hashAlg,
			Hierarchy:  tpm2.TPMRHEndorsement,
			Template:   ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		curve, err := keystore.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func ParseHierarchy(hierarchyType string) (tpm2.TPMIRHHierarchy, error) {
	switch hierarchyType {
	case "ENDORSEMENT":
		return tpm2.TPMRHEndorsement, nil
	case "OWNER":
		return tpm2.TPMRHOwner, nil
	case "PLATFORM":
		return tpm2.TPMRHPlatform, nil
	}
	return 0, ErrInvalidHierarchyType
}
