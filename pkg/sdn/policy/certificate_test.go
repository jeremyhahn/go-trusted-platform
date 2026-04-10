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
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewX509PolicyExtractor(t *testing.T) {
	extractor := NewX509PolicyExtractor()
	assert.NotNil(t, extractor)
	assert.NotNil(t, extractor.OIDTenantID)
	assert.NotNil(t, extractor.OIDVLAN)
	assert.NotNil(t, extractor.OIDACLs)
}

func TestX509PolicyExtractor_ExtractTenantID(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := extractor.ExtractTenantID(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("From Organization", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-123"},
			},
		})

		tenantID, err := extractor.ExtractTenantID(cert)
		assert.NoError(t, err)
		assert.Equal(t, "tenant-123", tenantID)
	})

	t.Run("From CommonName", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				CommonName: "tenant-456.example.com",
			},
		})

		tenantID, err := extractor.ExtractTenantID(cert)
		assert.NoError(t, err)
		assert.Equal(t, "tenant-456", tenantID)
	})

	t.Run("Missing TenantID", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{},
		})

		_, err := extractor.ExtractTenantID(cert)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})
}

func TestX509PolicyExtractor_ExtractVLAN(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := extractor.ExtractVLAN(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("From OrganizationalUnit", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"vlan=100"},
			},
		})

		vlan, err := extractor.ExtractVLAN(cert)
		assert.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)
	})

	t.Run("Invalid VLAN too low", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"vlan=0"},
			},
		})

		_, err := extractor.ExtractVLAN(cert)
		assert.ErrorIs(t, err, ErrInvalidVLAN)
	})

	t.Run("Invalid VLAN too high", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"vlan=5000"},
			},
		})

		_, err := extractor.ExtractVLAN(cert)
		assert.ErrorIs(t, err, ErrInvalidVLAN)
	})

	t.Run("Missing VLAN", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{},
		})

		_, err := extractor.ExtractVLAN(cert)
		assert.ErrorIs(t, err, ErrMissingVLAN)
	})
}

func TestX509PolicyExtractor_ExtractACLs(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := extractor.ExtractACLs(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Default ACLs", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{})

		acls, err := extractor.ExtractACLs(cert)
		assert.NoError(t, err)
		assert.NotEmpty(t, acls)
		assert.Equal(t, FlowActionNormal, acls[0].Action.Type)
	})
}

func TestX509PolicyExtractor_ExtractPolicy(t *testing.T) {
	extractor := NewX509PolicyExtractor()

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := extractor.ExtractPolicy(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Complete policy", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization:       []string{"tenant-789"},
				OrganizationalUnit: []string{"vlan=200"},
			},
		})

		policy, err := extractor.ExtractPolicy(cert)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
		assert.Equal(t, "tenant-789", policy.TenantID)
		assert.Equal(t, uint16(200), policy.VLAN)
		assert.NotNil(t, policy.Certificate)
		assert.NotNil(t, policy.Metadata)
	})

	t.Run("Missing VLAN", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-123"},
			},
		})

		_, err := extractor.ExtractPolicy(cert)
		assert.ErrorIs(t, err, ErrMissingVLAN)
	})
}

func TestParseACLRule(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		index    int
		validate func(t *testing.T, acl ACLRule)
	}{
		{
			name:  "TCP rule",
			input: "priority=100,proto=tcp,dst_port=443,action=allow",
			index: 0,
			validate: func(t *testing.T, acl ACLRule) {
				assert.Equal(t, 100, acl.Priority)
				assert.Equal(t, uint8(6), acl.Match.IPProto)
				assert.Equal(t, uint16(443), acl.Match.TCPDst)
				assert.Equal(t, FlowActionAllow, acl.Action.Type)
			},
		},
		{
			name:  "UDP rule",
			input: "priority=90,proto=udp,src_port=53,dst_ip=10.0.0.1/24,action=deny",
			index: 1,
			validate: func(t *testing.T, acl ACLRule) {
				assert.Equal(t, 90, acl.Priority)
				assert.Equal(t, uint8(17), acl.Match.IPProto)
				assert.Equal(t, uint16(53), acl.Match.UDPSrc)
				assert.Equal(t, "10.0.0.1/24", acl.Match.IPv4Dst)
				assert.Equal(t, FlowActionDeny, acl.Action.Type)
			},
		},
		{
			name:  "Default priority",
			input: "proto=tcp,action=allow",
			index: 5,
			validate: func(t *testing.T, acl ACLRule) {
				assert.Equal(t, 95, acl.Priority) // 100 - index
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := parseACLRule(tt.input, tt.index)
			assert.NoError(t, err)
			tt.validate(t, acl)
		})
	}
}

func TestNewDefaultCertificateValidator(t *testing.T) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	validator := NewDefaultCertificateValidator(roots, intermediates)
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.Roots)
	assert.NotNil(t, validator.Intermediates)
	assert.NotNil(t, validator.RevocationList)
}

func TestDefaultCertificateValidator_ValidateCertificate(t *testing.T) {
	validator := setupTestValidator(t)

	t.Run("Nil certificate", func(t *testing.T) {
		err := validator.ValidateCertificate(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Expired certificate", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})

		err := validator.ValidateCertificate(cert)
		assert.ErrorIs(t, err, ErrCertificateExpired)
	})

	t.Run("Not yet valid certificate", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			NotBefore: time.Now().Add(24 * time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		})

		err := validator.ValidateCertificate(cert)
		assert.ErrorIs(t, err, ErrCertificateExpired)
	})
}

func TestDefaultCertificateValidator_IsRevoked(t *testing.T) {
	validator := setupTestValidator(t)

	t.Run("Nil certificate", func(t *testing.T) {
		_, err := validator.IsRevoked(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Not revoked", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{})

		revoked, err := validator.IsRevoked(cert)
		assert.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("Revoked certificate", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(12345),
		})

		validator.AddRevoked("12345")

		revoked, err := validator.IsRevoked(cert)
		assert.NoError(t, err)
		assert.True(t, revoked)
	})
}

func TestDefaultCertificateValidator_CheckExpiry(t *testing.T) {
	validator := setupTestValidator(t)

	t.Run("Nil certificate", func(t *testing.T) {
		err := validator.CheckExpiry(nil, 24*time.Hour)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Already expired", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			NotAfter: time.Now().Add(-1 * time.Hour),
		})

		err := validator.CheckExpiry(cert, 24*time.Hour)
		assert.ErrorIs(t, err, ErrCertificateExpired)
	})

	t.Run("Expires within threshold", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			NotAfter: time.Now().Add(12 * time.Hour),
		})

		err := validator.CheckExpiry(cert, 24*time.Hour)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expires within")
	})

	t.Run("Valid with time remaining", func(t *testing.T) {
		cert := createTestCertificate(t, x509.Certificate{
			NotAfter: time.Now().Add(48 * time.Hour),
		})

		err := validator.CheckExpiry(cert, 24*time.Hour)
		assert.NoError(t, err)
	})
}

func TestDefaultCertificateValidator_RevocationList(t *testing.T) {
	validator := setupTestValidator(t)

	t.Run("Add and remove revoked", func(t *testing.T) {
		serialNumber := "98765"

		validator.AddRevoked(serialNumber)
		assert.True(t, validator.RevocationList[serialNumber])

		validator.RemoveRevoked(serialNumber)
		assert.False(t, validator.RevocationList[serialNumber])
	})
}

// Helper functions

func createTestCertificate(t *testing.T, template x509.Certificate) *x509.Certificate {
	t.Helper()

	// Generate a test key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Set default values if not provided
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(24 * time.Hour)
	}

	// Create self-signed certificate
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

func setupTestValidator(t *testing.T) *DefaultCertificateValidator {
	t.Helper()

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	return NewDefaultCertificateValidator(roots, intermediates)
}
