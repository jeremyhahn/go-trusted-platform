package webservice

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	DefaultConfig = config.WebService{
		Home:          "public_html",
		Port:          8080,
		JWTExpiration: 525960, // 1 year
		TLSPort:       8443,
		Certificate: config.Identity{
			Valid: 365, // days
			Subject: ca.Subject{
				CommonName:         "www.example.com",
				Organization:       "Trusted Platform",
				OrganizationalUnit: "IoT",
				Country:            "USA",
				Province:           "Kernel",
				Locality:           "Hypervisor",
				Address:            "123 Example Street",
				PostalCode:         "12345",
			},
			SANS: &ca.SubjectAlternativeNames{
				DNS: []string{
					"www.example.com",
					"localhost",
					"localhost.localdomain",
				},
				IPs: []string{
					"127.0.0.1",
				},
				Email: []string{
					"root@localhost",
					"root@localhost.localdomain",
				},
			},
		},
	}

	DefaultConfigRSA     = DefaultConfig
	DefaultConfigECDSA   = DefaultConfig
	DefaultConfigEd25519 = DefaultConfig
)

func init() {

	DefaultConfigRSA.Key = &keystore.KeyConfig{
		Hash:           crypto.SHA256.String(),
		KeyAlgorithm:   x509.RSA.String(),
		Password:       "123456",
		PlatformPolicy: true,
		RSAConfig: &keystore.RSAConfig{
			KeySize: 2048,
		},
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		StoreType:          keystore.STORE_TPM2.String(),
	}

	DefaultConfigECDSA.Key = &keystore.KeyConfig{
		ECCConfig: &keystore.ECCConfig{
			Curve: elliptic.P256().Params().Name,
		},
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.ECDSA.String(),
		Password:           "123456",
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		StoreType:          keystore.STORE_TPM2.String(),
	}

	DefaultConfigEd25519.Key = &keystore.KeyConfig{
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.PureEd25519.String(),
		Password:           "123456",
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.Ed25519.String(),
		StoreType:          keystore.STORE_PKCS8.String(),
	}
}
