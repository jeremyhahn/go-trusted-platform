package ca

import (
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

	"github.com/op/go-logging"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	pkcs8store "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
)

type Config struct {
	Home                      string     `yaml:"home" json:"home" mapstructure:"home"`
	AutoImportIssuingCA       bool       `yaml:"auto-import-issuing-ca" json:"auto_import_issuing_ca" mapstructure:"auto-import-issuing-ca"`
	SystemCertPool            bool       `yaml:"system-cert-pool" json:"system_cert_pool" mapstructure:"system-cert-pool"`
	Identity                  []Identity `yaml:"identity" json:"identity" mapstructure:"identity"`
	ValidDays                 int        `yaml:"issued-valid" json:"issued-valid" mapstructure:"issued-valid"`
	IncludeLocalhostInSANS    bool       `yaml:"sans-include-localhost" json:"sans-include-localhost" mapstructure:"sans-include-localhost"`
	DefaultKeyAlgorithm       string     `yaml:"key-algorithm" json:"key-algorithm" mapstructure:"key-algorithm"`
	KeyAlgorithms             []string   `yaml:"key-algorithms" json:"key-algorithms" mapstructure:"key-algorithms"`
	KeyStore                  string     `yaml:"key-store" json:"key-store" mapstructure:"key-store"`
	Hash                      string     `yaml:"hash" json:"hash" mapstructure:"hash"`
	SignatureAlgorithm        string     `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
	EllipticalCurve           string     `yaml:"elliptic-curve" json:"elliptic-curve" mapstructure:"elliptic-curve"`
	RequirePrivateKeyPassword bool       `yaml:"require-pkcs8-password" json:"require-pkcs8-password" mapstructure:"require-pkcs8-password"`
	PasswordPolicy            string     `yaml:"password-policy" json:"password-policy" mapstructure:"password-policy"`
	RetainRevokedCertificates bool       `yaml:"retain-revoked-certificates" json:"retain-revoked-certificates" mapstructure:"retain-revoked-certificates"`
	ExportableKeys            bool       `yaml:"exportable-keys" json:"exportable_keys" mapstructure:"exportable-keys"`
	DefaultCA                 int        `yaml:"default-ca" json:"default-ca" mapstructure:"default-ca"`
}

type Identity struct {
	KeyPassword string                   `yaml:"key-password" json:"key_password" mapstructure:"key-password"`
	KeySize     int                      `yaml:"key-size" json:"key_size" mapstructure:"key-size"`
	Valid       int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
	Subject     Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	SANS        *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
}

type Subject struct {
	CommonName         string `yaml:"cn" json:"cn" mapstructure:"cn"`
	Organization       string `yaml:"organization" json:"organization" mapstructure:"organization"`
	OrganizationalUnit string `yaml:"organizational-unit" json:"organizational_unit" mapstructure:"organizational-unit"`
	Country            string `yaml:"country" json:"country" mapstructure:"country"`
	Province           string `yaml:"province" json:"province" mapstructure:"province"`
	Locality           string `yaml:"locality" json:"locality" mapstructure:"locality"`
	Address            string `yaml:"address" json:"address" mapstructure:"address"`
	PostalCode         string `yaml:"postal-code" json:"postal_code" mapstructure:"postal-code"`
}

type SubjectAlternativeNames struct {
	DNS   []string `yaml:"dns" json:"dns" mapstructure:"dns"`
	IPs   []string `yaml:"ips" json:"ips" mapstructure:"ips"`
	Email []string `yaml:"email" json:"email" mapstructure:"email"`
}

type CAParams struct {
	Debug        bool
	DebugSecrets bool
	Logger       *logging.Logger
	Domain       string
	Config       Config
	SelectedCA   int
	Random       io.Reader
	Backend      store.Backend
	CertStore    CertificateStorer
	KeyStore     keystore.KeyStorer
	SignerStore  store.SignerStorer
	BlobStore    blobstore.BlobStorer
	Identity     Identity
	PKCS11Config pkcs11.Config
}

// Create a CA key and certificate store for a selected CA
func initStores(params CAParams) CAParams {
	params.Backend = initBackend(params)
	params.BlobStore = initBlobStore(params)
	params.CertStore = initCertStore(params)
	params.KeyStore = initKeyStore(params)
	params.SignerStore = initSignerStore(params)
	return params
}

// Create the platform signer store for signed blobs
func initBackend(params CAParams) store.Backend {
	return store.NewFileBackend(params.Logger, caDir(params))
}

// Create the platform signer store for signed blobs
func initSignerStore(params CAParams) store.SignerStorer {
	blobStore := initBlobStore(params)
	return store.NewSignerStore(blobStore)
}

// Create the platform blob store
func initBlobStore(params CAParams) blobstore.BlobStorer {
	store, err := blobstore.NewFSBlobStore(params.Logger, caDir(params))
	if err != nil {
		params.Logger.Fatal(err)
	}
	return store
}

// Creates a new key store for the selected CA
func initKeyStore(params CAParams) keystore.KeyStorer {
	blobStore := initBlobStore(params)
	signerSore := initSignerStore(params)
	if params.Config.KeyStore == string(keystore.STORE_PKCS8) {
		pkcs8Params := pkcs8.Params{
			Logger:         params.Logger,
			KeyDir:         caDir(params),
			DefaultKeySize: params.Identity.KeySize,
			Random:         params.Random,
			Backend:        params.Backend,
			SignerStore:    signerSore,
			BlobStore:      blobStore,
		}
		return pkcs8store.NewKeyStorePKCS8(pkcs8Params)
	} else if params.Config.KeyStore == string(keystore.STORE_PKCS11) {
		return keystore.NewKeyStorePKCS11(params.PKCS11Config)
	}
	params.Logger.Fatal(keystore.ErrInvalidKeyStore)
	return nil
}

// Creates a new certificate store for the selected CA
func initCertStore(params CAParams) CertificateStorer {
	caCN := params.Identity.Subject.CommonName
	certStore, err := NewFileSystemCertStore(
		params.Logger,
		params.Backend,
		caDir(params),
		caCN,
		params.Config.RetainRevokedCertificates)
	if err != nil {
		params.Logger.Fatal(err)
	}
	return certStore
}

// Create file system directory for the Certificate Authority
// based on the platform configuration file. Any errors encountered
// are treated as Fatal.
func caDir(params CAParams) string {
	caCN := params.Identity.Subject.CommonName
	if caCN == "" {
		params.Logger.Fatal("invalid CAParams, missing Identity")
	}
	caDir := fmt.Sprintf("%s/%s", params.Config.Home, caCN)
	if err := os.MkdirAll(caDir, os.ModePerm); err != nil {
		params.Logger.Fatal(err)
	}
	return caDir
}

// Parses the Certificate Authority params and config and returns
// a set of key attributes using the provided algorithms, hash function, etc.
func CAKeyAttributesFromParams(params CAParams) (keystore.KeyAttributes, error) {

	hashes := keystore.AvailableHashes()
	hash, ok := hashes[params.Config.Hash]
	if !ok {
		params.Logger.Fatalf("%s: %s",
			keystore.ErrInvalidHashFunction, params.Config.Hash)
	}

	keyAlgorithm, err := keystore.ParseKeyAlgorithm(params.Config.DefaultKeyAlgorithm)
	if err != nil {
		return keystore.KeyAttributes{}, err
	}

	signatureAlgorithm, err := keystore.ParseSignatureAlgorithm(params.Config.SignatureAlgorithm)
	if err != nil {
		return keystore.KeyAttributes{}, err
	}

	curve, err := ConfiguredCurve(params.Config)
	if err != nil {
		return keystore.KeyAttributes{}, err
	}

	attrs := keystore.KeyAttributes{
		Domain:             params.Identity.Subject.CommonName,
		CN:                 params.Identity.Subject.CommonName,
		Hash:               hash,
		KeyAlgorithm:       keyAlgorithm,
		KeyType:            keystore.KEY_TYPE_CA,
		Password:           []byte(params.Config.Identity[params.SelectedCA].KeyPassword),
		SignatureAlgorithm: signatureAlgorithm,
	}

	if keyAlgorithm == x509.RSA {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: params.Identity.KeySize,
		}
	}

	if keyAlgorithm == x509.ECDSA {
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: curve,
		}
	}

	return attrs, nil
}

// Returns the elliptic curve specified in the platform configuration file
// or ErrInvalidCurve if the curve is invalid.
func ConfiguredCurve(config Config) (elliptic.Curve, error) {
	switch config.EllipticalCurve {
	case "P224":
		return elliptic.P224(), nil
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%s: %s", keystore.ErrInvalidCurve, config.EllipticalCurve)
	}
	// return elliptic.P256(), nil
}

// Returns a default RSA config
func DefaultConfigRSA(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm:        x509.SHA256WithRSA.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.RSA.String(),
			x509.ECDSA.String(),
			x509.Ed25519.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal RSA config with RSA configured as the only
// signing algorithm
func MinimalConfigRSA(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm:        x509.SHA256WithRSA.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.RSA.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a default ECDSA config
func DefaultConfigECDSA(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.ECDSA.String(),
		SignatureAlgorithm:        x509.ECDSAWithSHA256.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.RSA.String(),
			x509.ECDSA.String(),
			x509.Ed25519.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal ECDSA config with ECDSA configured
// as the only signing algorithm
func MinimalConfigECDSA(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.ECDSA.String(),
		SignatureAlgorithm:        x509.ECDSAWithSHA256.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.ECDSA.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a default Ed25519 config
func DefaultConfigEd25119(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.Ed25519.String(),
		SignatureAlgorithm:        x509.PureEd25519.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.RSA.String(),
			x509.ECDSA.String(),
			x509.Ed25519.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal Ed25519 config with Ed25119 configured
// as the only signing algorithm
func MinimalConfigEd25119(caDir string, rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		Home:                      caDir,
		KeyStore:                  string(keystore.STORE_PKCS8),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       x509.Ed25519.String(),
		SignatureAlgorithm:        x509.PureEd25519.String(),
		Hash:                      crypto.SHA256.String(),
		EllipticalCurve:           "P256",
		RetainRevokedCertificates: true,
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		KeyAlgorithms: []string{
			x509.Ed25519.String(),
		},
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Debug prints the secure, supported TLD cipher suites
func DebugCipherSuites(logger *logging.Logger) {
	logger.Debug("Secure, Supported TLS Cipher Suites")
	for _, suite := range tls.CipherSuites() {
		logger.Debugf("  ID: %d", suite.ID)
		logger.Debugf("  Name: %s", suite.Name)
		logger.Debugf("  Versions: %d", suite.SupportedVersions)
	}
}

// Debug prints the insecure, unsupported TLs cipher suites
func DebugInsecureCipherSuites(logger *logging.Logger) {
	logger.Debug("INSECURE, UNSUPPORTED TLS Cipher Suites")
	for _, suite := range tls.InsecureCipherSuites() {
		logger.Debugf("  ID: %d", suite.ID)
		logger.Debugf("  Name: %s", suite.Name)
		logger.Debugf("  Versions: %d", suite.SupportedVersions)
	}
}
