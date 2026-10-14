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
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("has correct default values", func(t *testing.T) {
		assert.Equal(t, "public_html", DefaultConfig.Home)
		assert.Equal(t, 8080, DefaultConfig.Port)
		assert.Equal(t, 8443, DefaultConfig.TLSPort)
		assert.Equal(t, int64(60), DefaultConfig.JWT.Expiration)
	})

	t.Run("has valid certificate subject", func(t *testing.T) {
		assert.Equal(t, "www.example.com", DefaultConfig.Certificate.Subject.CommonName)
		assert.Equal(t, "Trusted Platform", DefaultConfig.Certificate.Subject.Organization)
		assert.Equal(t, "IoT", DefaultConfig.Certificate.Subject.OrganizationalUnit)
		assert.Equal(t, "USA", DefaultConfig.Certificate.Subject.Country)
		assert.Equal(t, "Kernel", DefaultConfig.Certificate.Subject.Province)
		assert.Equal(t, "Hypervisor", DefaultConfig.Certificate.Subject.Locality)
		assert.Equal(t, "123 Example Street", DefaultConfig.Certificate.Subject.Address)
		assert.Equal(t, "12345", DefaultConfig.Certificate.Subject.PostalCode)
	})

	t.Run("has valid certificate validity", func(t *testing.T) {
		assert.Equal(t, 365, DefaultConfig.Certificate.Valid)
	})

	t.Run("has valid SANS configuration", func(t *testing.T) {
		require.NotNil(t, DefaultConfig.Certificate.SANS)

		// DNS names
		assert.Contains(t, DefaultConfig.Certificate.SANS.DNS, "www.example.com")
		assert.Contains(t, DefaultConfig.Certificate.SANS.DNS, "localhost")
		assert.Contains(t, DefaultConfig.Certificate.SANS.DNS, "localhost.localdomain")

		// IPs
		assert.Contains(t, DefaultConfig.Certificate.SANS.IPs, "127.0.0.1")

		// Emails
		assert.Contains(t, DefaultConfig.Certificate.SANS.Email, "root@localhost")
		assert.Contains(t, DefaultConfig.Certificate.SANS.Email, "root@localhost.localdomain")
	})
}

func TestDefaultConfigRSA(t *testing.T) {
	t.Run("inherits base config", func(t *testing.T) {
		assert.Equal(t, DefaultConfig.Home, DefaultConfigRSA.Home)
		assert.Equal(t, DefaultConfig.Port, DefaultConfigRSA.Port)
		assert.Equal(t, DefaultConfig.TLSPort, DefaultConfigRSA.TLSPort)
	})

	t.Run("has RSA key configuration", func(t *testing.T) {
		require.NotNil(t, DefaultConfigRSA.Key)

		assert.Equal(t, crypto.SHA256.String(), DefaultConfigRSA.Key.Hash)
		assert.Equal(t, x509.RSA.String(), DefaultConfigRSA.Key.KeyAlgorithm)
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigRSA.Key.TPMPolicy)
		assert.Equal(t, x509.SHA256WithRSAPSS.String(), DefaultConfigRSA.Key.SignatureAlgorithm)
		assert.Equal(t, xkmssdk.StoreTPM2.String(), DefaultConfigRSA.Key.StoreType)
	})

	t.Run("has RSA-specific config", func(t *testing.T) {
		require.NotNil(t, DefaultConfigRSA.Key.RSAConfig)
		assert.Equal(t, 2048, DefaultConfigRSA.Key.RSAConfig.KeySize)
	})
}

func TestDefaultConfigECDSA(t *testing.T) {
	t.Run("inherits base config", func(t *testing.T) {
		assert.Equal(t, DefaultConfig.Home, DefaultConfigECDSA.Home)
		assert.Equal(t, DefaultConfig.Port, DefaultConfigECDSA.Port)
		assert.Equal(t, DefaultConfig.TLSPort, DefaultConfigECDSA.TLSPort)
	})

	t.Run("has ECDSA key configuration", func(t *testing.T) {
		require.NotNil(t, DefaultConfigECDSA.Key)

		assert.Equal(t, crypto.SHA256.String(), DefaultConfigECDSA.Key.Hash)
		assert.Equal(t, x509.ECDSA.String(), DefaultConfigECDSA.Key.KeyAlgorithm)
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigECDSA.Key.TPMPolicy)
		assert.Equal(t, x509.ECDSAWithSHA256.String(), DefaultConfigECDSA.Key.SignatureAlgorithm)
		assert.Equal(t, xkmssdk.StoreTPM2.String(), DefaultConfigECDSA.Key.StoreType)
	})

	t.Run("has ECDSA-specific config", func(t *testing.T) {
		require.NotNil(t, DefaultConfigECDSA.Key.ECCConfig)
		assert.Equal(t, elliptic.P256().Params().Name, DefaultConfigECDSA.Key.ECCConfig.Curve)
	})
}

func TestDefaultConfigEd25519(t *testing.T) {
	t.Run("inherits base config", func(t *testing.T) {
		assert.Equal(t, DefaultConfig.Home, DefaultConfigEd25519.Home)
		assert.Equal(t, DefaultConfig.Port, DefaultConfigEd25519.Port)
		assert.Equal(t, DefaultConfig.TLSPort, DefaultConfigEd25519.TLSPort)
	})

	t.Run("has Ed25519 key configuration", func(t *testing.T) {
		require.NotNil(t, DefaultConfigEd25519.Key)

		assert.Equal(t, crypto.SHA256.String(), DefaultConfigEd25519.Key.Hash)
		assert.Equal(t, x509.PureEd25519.String(), DefaultConfigEd25519.Key.KeyAlgorithm)
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigEd25519.Key.TPMPolicy)
		assert.Equal(t, x509.Ed25519.String(), DefaultConfigEd25519.Key.SignatureAlgorithm)
		// Ed25519 uses software store since TPM2 doesn't support Ed25519
		assert.Equal(t, xkmssdk.StoreSoftware.String(), DefaultConfigEd25519.Key.StoreType)
	})
}

func TestInitFunction(t *testing.T) {
	t.Run("init sets up all default configs", func(t *testing.T) {
		// The init function runs automatically
		// Verify that all configs have their Key field set
		require.NotNil(t, DefaultConfigRSA.Key)
		require.NotNil(t, DefaultConfigECDSA.Key)
		require.NotNil(t, DefaultConfigEd25519.Key)
	})

	t.Run("configs are independent after init", func(t *testing.T) {
		// Verify that modifying one doesn't affect others
		assert.NotEqual(t, DefaultConfigRSA.Key.KeyAlgorithm, DefaultConfigECDSA.Key.KeyAlgorithm)
		assert.NotEqual(t, DefaultConfigECDSA.Key.KeyAlgorithm, DefaultConfigEd25519.Key.KeyAlgorithm)
		assert.NotEqual(t, DefaultConfigRSA.Key.KeyAlgorithm, DefaultConfigEd25519.Key.KeyAlgorithm)
	})
}

func TestKeyAlgorithmDifferences(t *testing.T) {
	t.Run("each config uses different algorithms", func(t *testing.T) {
		algorithms := map[string]bool{
			DefaultConfigRSA.Key.KeyAlgorithm:     true,
			DefaultConfigECDSA.Key.KeyAlgorithm:   true,
			DefaultConfigEd25519.Key.KeyAlgorithm: true,
		}
		// Should have 3 unique algorithms
		assert.Len(t, algorithms, 3)
	})

	t.Run("signature algorithms match key algorithms", func(t *testing.T) {
		// RSA uses RSA-PSS signature
		assert.Contains(t, DefaultConfigRSA.Key.SignatureAlgorithm, "RSA")

		// ECDSA uses ECDSA signature
		assert.Contains(t, DefaultConfigECDSA.Key.SignatureAlgorithm, "ECDSA")

		// Ed25519 uses Ed25519 signature
		assert.Contains(t, DefaultConfigEd25519.Key.SignatureAlgorithm, "Ed25519")
	})
}

func TestStoreTypeConfiguration(t *testing.T) {
	t.Run("RSA uses TPM2 store", func(t *testing.T) {
		assert.Equal(t, xkmssdk.StoreTPM2.String(), DefaultConfigRSA.Key.StoreType)
	})

	t.Run("ECDSA uses TPM2 store", func(t *testing.T) {
		assert.Equal(t, xkmssdk.StoreTPM2.String(), DefaultConfigECDSA.Key.StoreType)
	})

	t.Run("Ed25519 uses software store", func(t *testing.T) {
		// Ed25519 is not supported by TPM2, so it uses software store
		assert.Equal(t, xkmssdk.StoreSoftware.String(), DefaultConfigEd25519.Key.StoreType)
	})
}

func TestTPMPolicyConfiguration(t *testing.T) {
	t.Run("all configs bind the platform TPM policy", func(t *testing.T) {
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigRSA.Key.TPMPolicy)
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigECDSA.Key.TPMPolicy)
		assert.Equal(t, common.TPMPolicyPlatform, DefaultConfigEd25519.Key.TPMPolicy)
	})
}

func TestHashConfiguration(t *testing.T) {
	t.Run("all configs use SHA256", func(t *testing.T) {
		assert.Equal(t, crypto.SHA256.String(), DefaultConfigRSA.Key.Hash)
		assert.Equal(t, crypto.SHA256.String(), DefaultConfigECDSA.Key.Hash)
		assert.Equal(t, crypto.SHA256.String(), DefaultConfigEd25519.Key.Hash)
	})
}
