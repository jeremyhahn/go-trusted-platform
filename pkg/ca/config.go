package ca

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/afero"

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
	KeyringConfig *platform.KeyringConfig  `yaml:"keystores" json:"keystores" mapstructure:"keystores"`
	Keys          []*keystore.KeyConfig    `yaml:"keys" json:"keys" mapstructure:"keys"`
	SANS          *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject       Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid         int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
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
	Fs           afero.Fs
	Home         string
	Identity     Identity
	Keyring      *platform.Keyring
	Logger       *logging.Logger
	Random       io.Reader
	SelectedCA   int
	SignerStore  keystore.SignerStorer
	TPM          tpm2.TrustedPlatformModule
}

var (

	// Default PKCS #8, PKCS #11, and TPM 2.0 key stores
	DefaultPKCS11Config = Config{
		AutoImportIssuingCA:   true,
		RequireKeyPassword:    true,
		PlatformCA:            1,
		DefaultValidityPeriod: 10,
		DefaultIDevIDCN:       "default-device-id",
		IncludeLocalhostSANS:  true,
		SystemCertPool:        false,
		Identity: []Identity{
			// Root CA
			{
				Valid: 1, // year
				Subject: Subject{
					CommonName:   "root-ca",
					Organization: "Example Corporation",
					Country:      "US",
					Locality:     "Miami",
					Address:      "123 acme street",
					PostalCode:   "12345"},
				SANS: &SubjectAlternativeNames{
					DNS: []string{
						"root-ca",
						"root-ca.localhost",
						"root-ca.localhost.localdomain",
					},
					IPs: []string{
						"127.0.0.1",
					},
					Email: []string{
						"root@localhost",
						"root@test.com",
					},
				},
				KeyringConfig: pkcs11Keyring,
				Keys:          append(keys, pkcs11Keys...),
			},
			// Intermediate CA
			{
				Valid: 1, // year
				Subject: Subject{
					CommonName:   "intermediate-ca",
					Organization: "Example Corporation",
					Country:      "US",
					Locality:     "Miami",
					Address:      "123 acme street",
					PostalCode:   "12345"},
				SANS: &SubjectAlternativeNames{
					DNS: []string{
						"intermediate-ca",
						"intermediate-ca.localhost",
						"intermediate-ca.localhost.localdomain",
					},
					IPs: []string{
						"127.0.0.1",
					},
					Email: []string{
						"root@localhost",
						"root@test.com",
					},
				},
				KeyringConfig: pkcs11Keyring,
				Keys:          append(keys, pkcs11Keys...),
			}},
	}

	pkcs11Keys = []*keystore.KeyConfig{
		{
			Debug:              true,
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.RSA.String(),
			StoreType:      string(keystore.STORE_PKCS11),
			Hash:           "SHA-256",
		},
		{
			Debug:              true,
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
			ECCConfig: &keystore.ECCConfig{
				Curve: elliptic.P256().Params().Name,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.ECDSA.String(),
			StoreType:      string(keystore.STORE_PKCS11),
			Hash:           "SHA-256",
		},
	}

	slot          = 0
	pkcs11Keyring = &platform.KeyringConfig{
		PKCS8Config: &pkcs8.Config{
			PlatformPolicy: true,
		},
		PKCS11Config: &pkcs11.Config{
			Library:        "/usr/local/lib/softhsm/libsofthsm2.so",
			LibraryConfig:  "trusted-data/etc/softhsm.conf",
			Slot:           &slot,
			TokenLabel:     "SoftHSM",
			SOPin:          keystore.DEFAULT_PASSWORD,
			Pin:            keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
		},
		TPMConfig: &tpm2.KeyStoreConfig{
			SRKHandle:      0x81000003,
			SRKAuth:        keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
		},
	}

	// Default PKCS #8 and TPM 2.0 key store configuration
	DefaultConfig = Config{
		AutoImportIssuingCA:   true,
		RequireKeyPassword:    true,
		PlatformCA:            1,
		DefaultValidityPeriod: 10,
		DefaultIDevIDCN:       "default-device-id",
		IncludeLocalhostSANS:  true,
		SystemCertPool:        false,
		Identity: []Identity{
			// Root CA
			{
				Valid: 1, // year
				Subject: Subject{
					CommonName:   "root-ca",
					Organization: "Example Corporation",
					Country:      "US",
					Locality:     "Miami",
					Address:      "123 acme street",
					PostalCode:   "12345"},
				SANS: &SubjectAlternativeNames{
					DNS: []string{
						"root-ca",
						"root-ca.localhost",
						"root-ca.localhost.localdomain",
					},
					IPs: []string{
						"127.0.0.1",
					},
					Email: []string{
						"root@localhost",
						"root@test.com",
					},
				},
				KeyringConfig: keyring,
				Keys:          keys,
			},
			// Intermediate CA
			{
				Valid: 1, // year
				Subject: Subject{
					CommonName:   "intermediate-ca",
					Organization: "Example Corporation",
					Country:      "US",
					Locality:     "Miami",
					Address:      "123 acme street",
					PostalCode:   "12345"},
				SANS: &SubjectAlternativeNames{
					DNS: []string{
						"intermediate-ca",
						"intermediate-ca.localhost",
						"intermediate-ca.localhost.localdomain",
					},
					IPs: []string{
						"127.0.0.1",
					},
					Email: []string{
						"root@localhost",
						"root@test.com",
					},
				},
				KeyringConfig: keyring,
				Keys:          keys,
			}},
	}

	keys = []*keystore.KeyConfig{
		// PKCS #8 keys
		{
			Debug:              true,
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.RSA.String(),
			StoreType:      string(keystore.STORE_PKCS8),
			Hash:           "SHA-256",
		},
		{
			Debug:              true,
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
			ECCConfig: &keystore.ECCConfig{
				Curve: elliptic.P256().Params().Name,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.ECDSA.String(),
			StoreType:      string(keystore.STORE_PKCS8),
			Hash:           "SHA-256",
		},
		{
			Debug:              true,
			SignatureAlgorithm: x509.PureEd25519.String(),
			Password:           keystore.DEFAULT_PASSWORD,
			PlatformPolicy:     true,
			KeyAlgorithm:       x509.Ed25519.String(),
			StoreType:          string(keystore.STORE_PKCS8),
			Hash:               "SHA-256",
		},
		// TPM 2.0 keys
		{
			Debug:              true,
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.RSA.String(),
			StoreType:      string(keystore.STORE_TPM2),
			Hash:           "SHA-256",
		},
		{
			Debug:              true,
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
			ECCConfig: &keystore.ECCConfig{
				Curve: elliptic.P256().Params().Name,
			},
			Password:       keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
			KeyAlgorithm:   x509.ECDSA.String(),
			StoreType:      string(keystore.STORE_TPM2),
			Hash:           "SHA-256",
		},
	}

	keyring = &platform.KeyringConfig{
		PKCS8Config: &pkcs8.Config{
			PlatformPolicy: true,
		},
		TPMConfig: &tpm2.KeyStoreConfig{
			SRKHandle:      0x81000003,
			SRKAuth:        keystore.DEFAULT_PASSWORD,
			PlatformPolicy: true,
		},
	}
)

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
func HomeDirectory(fs afero.Fs, platformDir, cn string) string {
	caDir := fmt.Sprintf("%s/ca/%s", platformDir, cn)
	if err := fs.MkdirAll(caDir, os.ModePerm); err != nil {
		panic(err)
	}
	return caDir
}
