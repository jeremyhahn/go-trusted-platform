package ca

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"

	"github.com/op/go-logging"

	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
)

type Config struct {
	AutoImportIssuingCA   bool       `yaml:"auto-import-issuing-ca" json:"auto_import_issuing_ca" mapstructure:"auto-import-issuing-ca"`
	DefaultValidityPeriod int        `yaml:"default-validity" json:"default_validity" mapstructure:"default-validity"`
	DefaultIDevIDCN       string     `yaml:"default-idevid-cn" json:"default_idevid_cn" mapstructure:"default-idevid-cn"`
	Identity              []Identity `yaml:"identity" json:"identity" mapstructure:"identity"`
	IncludeLocalhostSANS  bool       `yaml:"sans-include-localhost" json:"sans_include_localhost" mapstructure:"sans-include-localhost"`
	PlatformCA            int        `yaml:"platform-ca" json:"platform_ca" mapstructure:"platform-ca"`
	RequireKeyPassword    bool       `yaml:"require-password" json:"require-password" mapstructure:"require-password"`
	SystemCertPool        bool       `yaml:"system-cert-pool" json:"system_cert_pool" mapstructure:"system-cert-pool"`
}

type Identity struct {
	KeyChainConfig *platform.KeyChainConfig `yaml:"keystores" json:"keystores" mapstructure:"keystores"`
	Keys           []*keystore.KeyConfig    `yaml:"keys" json:"keys" mapstructure:"keys"`
	SANS           *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject        Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid          int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
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
	Backend      keystore.KeyBackend
	BlobStore    blobstore.BlobStorer
	CertStore    certstore.CertificateStorer
	Config       Config
	Debug        bool
	DebugSecrets bool
	Home         string
	Identity     Identity
	KeyChain     *platform.KeyChain
	Logger       *logging.Logger
	Random       io.Reader
	SelectedCA   int
	SignerStore  keystore.SignerStorer
	TPM          tpm2.TrustedPlatformModule
}

// Returns a default RSA config
func DefaultConfigRSA(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal RSA config with RSA configured as the only
// signing algorithm
func MinimalConfigRSA(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a default ECDSA config
func DefaultConfigECDSA(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal ECDSA config with ECDSA configured
// as the only signing algorithm
func MinimalConfigECDSA(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a default Ed25519 config
func DefaultConfigEd25119(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}
}

// Returns a minimal Ed25519 config with Ed25119 configured
// as the only signing algorithm
func MinimalConfigEd25119(rootIdentity, intermediateIdentity Identity) Config {
	return Config{
		AutoImportIssuingCA: true,
		RequireKeyPassword:  true,
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

// Parses the home directory for the provided CA parameters and platform
// root directory.
func HomeDirectory(platformDir, cn string) string {
	caDir := fmt.Sprintf("%s/ca/%s", platformDir, cn)
	if err := os.MkdirAll(caDir, os.ModePerm); err != nil {
		panic(err)
	}
	return caDir
}
