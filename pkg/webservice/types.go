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

package webservice

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	DefaultConfig = v1.Config{
		Home: "public_html",
		Port: 8080,
		JWT: v1.JWT{
			Expiration: 525960, // 1 year
		},
		TLSPort: 8443,
		Certificate: v1.Identity{
			Valid: 365, // days
			Subject: trustedca.CASubject{
				CommonName:         "www.example.com",
				Organization:       "Trusted Platform",
				OrganizationalUnit: "IoT",
				Country:            "USA",
				Province:           "Kernel",
				Locality:           "Hypervisor",
				Address:            "123 Example Street",
				PostalCode:         "12345",
			},
			SANS: &trustedca.CASubjectAlternativeNames{
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

	DefaultConfigRSA.Key = &common.KeyConfig{
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		PlatformPolicy:     true,
		RSAConfig:          &common.RSAConfig{KeySize: 2048},
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		StoreType:          xkmssdk.StoreTPM2.String(),
	}

	DefaultConfigECDSA.Key = &common.KeyConfig{
		ECCConfig:          &common.ECCConfig{Curve: elliptic.P256().Params().Name},
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.ECDSA.String(),
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		StoreType:          xkmssdk.StoreTPM2.String(),
	}

	DefaultConfigEd25519.Key = &common.KeyConfig{
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.PureEd25519.String(),
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.Ed25519.String(),
		StoreType:          xkmssdk.StoreSoftware.String(),
	}
}
