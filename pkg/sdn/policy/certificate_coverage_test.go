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

package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestX509PolicyExtractor_ExtractACLsWithExtensions tests ACL extraction from extensions
func TestX509PolicyExtractor_ExtractACLsWithExtensions(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Extract ACLs from extensions", func(t *testing.T) {
		// Create ACL strings
		aclStrings := []string{
			"priority=100,proto=tcp,dst_port=443,action=allow",
			"priority=90,proto=udp,dst_port=53,action=allow",
		}

		// Encode as ASN.1
		aclBytes, err := asn1.Marshal(aclStrings)
		require.NoError(t, err)

		// Create certificate with ACL extension
		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDACLs,
					Value: aclBytes,
				},
			},
		})

		acls, err := extractor.ExtractACLs(cert)
		assert.NoError(t, err)
		assert.Len(t, acls, 2)

		// Verify first ACL
		assert.Equal(t, 100, acls[0].Priority)
		assert.Equal(t, uint8(6), acls[0].Match.IPProto)
		assert.Equal(t, uint16(443), acls[0].Match.TCPDst)

		// Verify second ACL
		assert.Equal(t, 90, acls[1].Priority)
		assert.Equal(t, uint8(17), acls[1].Match.IPProto)
		assert.Equal(t, uint16(53), acls[1].Match.UDPDst)
	})

	t.Run("Extract ACLs with invalid extension data", func(t *testing.T) {
		// Create certificate with invalid ACL extension
		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDACLs,
					Value: []byte{0x00, 0x01, 0x02}, // Invalid ASN.1
				},
			},
		})

		// Should return default ACLs when extension parsing fails
		acls, err := extractor.ExtractACLs(cert)
		assert.NoError(t, err)
		assert.NotEmpty(t, acls)
		assert.Equal(t, FlowActionNormal, acls[0].Action.Type)
	})
}

// TestX509PolicyExtractor_ExtractVLANFromExtension tests VLAN extraction from extensions
func TestX509PolicyExtractor_ExtractVLANFromExtension(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Extract VLAN from extension", func(t *testing.T) {
		// Encode VLAN as ASN.1 integer
		vlanBytes, err := asn1.Marshal(100)
		require.NoError(t, err)

		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDVLAN,
					Value: vlanBytes,
				},
			},
		})

		vlan, err := extractor.ExtractVLAN(cert)
		assert.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)
	})

	t.Run("Extract invalid VLAN from extension", func(t *testing.T) {
		// Encode invalid VLAN (too high)
		vlanBytes, err := asn1.Marshal(5000)
		require.NoError(t, err)

		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDVLAN,
					Value: vlanBytes,
				},
			},
		})

		_, err = extractor.ExtractVLAN(cert)
		assert.ErrorIs(t, err, ErrInvalidVLAN)
	})

	t.Run("Extract VLAN with invalid ASN.1", func(t *testing.T) {
		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDVLAN,
					Value: []byte{0xFF, 0xFF}, // Invalid ASN.1
				},
			},
		})

		// Should fallback to OrganizationalUnit
		_, err := extractor.ExtractVLAN(cert)
		assert.ErrorIs(t, err, ErrMissingVLAN)
	})
}

// TestX509PolicyExtractor_ExtractTenantIDFromExtension tests tenant ID extraction from extensions
func TestX509PolicyExtractor_ExtractTenantIDFromExtension(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Extract tenant ID from extension", func(t *testing.T) {
		// Encode tenant ID as ASN.1 string
		tenantBytes, err := asn1.Marshal("tenant-ext-123")
		require.NoError(t, err)

		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDTenantID,
					Value: tenantBytes,
				},
			},
		})

		tenantID, err := extractor.ExtractTenantID(cert)
		assert.NoError(t, err)
		assert.Equal(t, "tenant-ext-123", tenantID)
	})

	t.Run("Extract tenant ID with invalid extension", func(t *testing.T) {
		cert := createTestCertificateWithExtensions(t, x509.Certificate{
			Extensions: []pkix.Extension{
				{
					Id:    extractor.OIDTenantID,
					Value: []byte{0xFF}, // Invalid ASN.1
				},
			},
		})

		// Should fallback to Organization
		_, err := extractor.ExtractTenantID(cert)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})
}

// TestParseACLRuleEdgeCases tests edge cases in parseACLRule
func TestParseACLRuleEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		index    int
		validate func(t *testing.T, acl ACLRule, err error)
	}{
		{
			name:  "Empty rule",
			input: "",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 100, acl.Priority) // Default
			},
		},
		{
			name:  "Rule with src_ip",
			input: "proto=tcp,src_ip=192.168.1.0/24,action=allow",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "192.168.1.0/24", acl.Match.IPv4Src)
			},
		},
		{
			name:  "Rule with description",
			input: "description=Allow HTTPS,proto=tcp,dst_port=443",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "Allow HTTPS", acl.Description)
			},
		},
		{
			name:  "TCP src_port",
			input: "proto=tcp,src_port=8080,action=allow",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				assert.Equal(t, uint16(8080), acl.Match.TCPSrc)
			},
		},
		{
			name:  "UDP src_port",
			input: "proto=udp,src_port=5353,action=allow",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				assert.Equal(t, uint16(5353), acl.Match.UDPSrc)
			},
		},
		{
			name:  "Invalid key-value pair",
			input: "invalidformat,proto=tcp",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				// Should skip invalid parts and parse valid ones
				assert.Equal(t, uint8(6), acl.Match.IPProto)
			},
		},
		{
			name:  "Priority with invalid value",
			input: "priority=invalid,proto=tcp",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				// Should use default priority (100 - index)
				assert.Equal(t, 100, acl.Priority)
			},
		},
		{
			name:  "Port with invalid value",
			input: "proto=tcp,dst_port=invalid",
			index: 0,
			validate: func(t *testing.T, acl ACLRule, err error) {
				assert.NoError(t, err)
				// Port should remain 0
				assert.Equal(t, uint16(0), acl.Match.TCPDst)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := parseACLRule(tt.input, tt.index)
			tt.validate(t, acl, err)
		})
	}
}

// TestDefaultCertificateValidator_ValidateCertificateChain tests certificate chain verification
func TestDefaultCertificateValidator_ValidateCertificateChain(t *testing.T) {
	t.Run("Valid certificate with root", func(t *testing.T) {
		// Create root CA
		rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		rootTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
		require.NoError(t, err)

		rootCert, err := x509.ParseCertificate(rootDER)
		require.NoError(t, err)

		// Create client certificate
		clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		clientTemplate := x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: "Test Client",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(24 * time.Hour),
			KeyUsage:  x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
		}

		clientDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, rootCert, &clientKey.PublicKey, rootKey)
		require.NoError(t, err)

		clientCert, err := x509.ParseCertificate(clientDER)
		require.NoError(t, err)

		// Create validator with root
		roots := x509.NewCertPool()
		roots.AddCert(rootCert)
		validator := NewDefaultCertificateValidator(roots, x509.NewCertPool())

		// Validate client certificate
		err = validator.ValidateCertificate(clientCert)
		assert.NoError(t, err)
	})

	t.Run("Certificate with revocation check", func(t *testing.T) {
		// Create a simple certificate
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(12345),
		})

		validator := setupTestValidator(t)

		// Add to revocation list
		validator.AddRevoked("12345")

		// Validate should fail
		err := validator.ValidateCertificate(cert)
		assert.ErrorIs(t, err, ErrCertificateRevoked)
	})

	t.Run("Certificate chain verification failure", func(t *testing.T) {
		// Create self-signed cert
		cert := createTestCertificate(t, x509.Certificate{})

		// Create validator with empty root pool
		validator := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())

		// Validation should fail (no trusted root)
		err := validator.ValidateCertificate(cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate verification failed")
	})
}

// Helper to create certificate with custom extensions
func createTestCertificateWithExtensions(t *testing.T, template x509.Certificate) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(24 * time.Hour)
	}

	// Preserve ExtraExtensions for custom OID extensions
	template.ExtraExtensions = template.Extensions

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
