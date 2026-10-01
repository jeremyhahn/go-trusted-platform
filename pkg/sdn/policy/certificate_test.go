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

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewX509PolicyExtractor(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()
	assert.NotNil(t, e)
}

func TestNewX509PolicyExtractor_WithOptions(t *testing.T) {
	t.Parallel()
	zones := zone.Defaults()
	e := NewX509PolicyExtractor(
		WithPolicyExtractorZones(zones),
	)
	assert.NotNil(t, e)
	assert.Len(t, e.zones, len(zones))
}

// TestExtractTenantID verifies tenant extraction from org and CN.
func TestX509PolicyExtractor_ExtractTenantID(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	t.Run("nil cert", func(t *testing.T) {
		_, err := e.ExtractTenantID(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("from organisation", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			Subject: pkix.Name{Organization: []string{"acme-corp"}},
		})
		got, err := e.ExtractTenantID(cert)
		require.NoError(t, err)
		assert.Equal(t, "acme-corp", got)
	})

	t.Run("from common name", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			Subject: pkix.Name{CommonName: "tenant-42.example.com"},
		})
		got, err := e.ExtractTenantID(cert)
		require.NoError(t, err)
		assert.Equal(t, "tenant-42", got)
	})

	t.Run("missing", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{Subject: pkix.Name{}})
		_, err := e.ExtractTenantID(cert)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})
}

// TestExtractZone verifies zone extraction using the canonical OIDTPNetworkZone extension.
func TestX509PolicyExtractor_ExtractZone(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	t.Run("nil cert", func(t *testing.T) {
		_, err := e.ExtractZone(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("extension present", func(t *testing.T) {
		ext, err := quicbaasca.CreateNetworkZoneExtension("control-plane")
		require.NoError(t, err)

		cert := selfSignedCert(t, x509.Certificate{
			ExtraExtensions: []pkix.Extension{ext},
		})

		got, err := e.ExtractZone(cert)
		require.NoError(t, err)
		assert.Equal(t, "control-plane", got)
	})

	t.Run("extension absent", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		_, err := e.ExtractZone(cert)
		assert.ErrorIs(t, err, ErrMissingZoneExtension)
	})
}

// TestExtractPolicy_HappyPath verifies zone propagation in the returned policy.
func TestX509PolicyExtractor_ExtractPolicy_HappyPath(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	e := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	ext, err := quicbaasca.CreateNetworkZoneExtension(string(zone.ZoneControlPlane))
	require.NoError(t, err)

	cert := selfSignedCert(t, x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"corp"},
		},
		ExtraExtensions: []pkix.Extension{ext},
	})

	pol, err := e.ExtractPolicy(cert)
	require.NoError(t, err)
	assert.Equal(t, zone.Zone(zone.ZoneControlPlane), pol.Zone)
	assert.Equal(t, "corp", pol.TenantID)
	assert.NotNil(t, pol.Certificate)
}

// TestExtractPolicy_MissingExtension verifies backward-compatible behaviour
// when no zone extension is present (zone stays empty, no error).
func TestX509PolicyExtractor_ExtractPolicy_MissingExtension(t *testing.T) {
	t.Parallel()

	e := NewX509PolicyExtractor()
	cert := selfSignedCert(t, x509.Certificate{
		Subject: pkix.Name{Organization: []string{"org"}},
	})

	pol, err := e.ExtractPolicy(cert)
	require.NoError(t, err)
	assert.Equal(t, zone.Zone(""), pol.Zone)
}

// TestExtractPolicy_NilCert verifies the nil guard.
func TestX509PolicyExtractor_ExtractPolicy_NilCert(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()
	_, err := e.ExtractPolicy(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestExtractPolicy_UndeclaredZone_FailClosed verifies that a zone value not
// in the resolved set triggers quarantine placement and an ErrZoneNotDeclared.
func TestX509PolicyExtractor_ExtractPolicy_UndeclaredZone_FailClosed(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	e := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	ext, err := quicbaasca.CreateNetworkZoneExtension("totally-unknown-zone")
	require.NoError(t, err)

	cert := selfSignedCert(t, x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"tenant"},
		},
		ExtraExtensions: []pkix.Extension{ext},
	})

	pol, err := e.ExtractPolicy(cert)
	require.Error(t, err)

	var notDeclared ErrZoneNotDeclared
	require.ErrorAs(t, err, &notDeclared)

	// The returned policy must carry the quarantine zone, not the bad one.
	quarantine, qErr := zone.ZoneForRole(zones, zone.LifecycleRoleQuarantine)
	require.NoError(t, qErr)
	assert.Equal(t, quarantine, pol.Zone)
}

// TestExtractACLs verifies default ACL behaviour.
func TestX509PolicyExtractor_ExtractACLs(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	t.Run("nil cert", func(t *testing.T) {
		_, err := e.ExtractACLs(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("returns default allow rule", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		acls, err := e.ExtractACLs(cert)
		require.NoError(t, err)
		require.NotEmpty(t, acls)
		assert.Equal(t, FlowActionNormal, acls[0].Action.Type)
	})
}

// TestDefaultCertificateValidator tests the validator helpers.
func TestNewDefaultCertificateValidator(t *testing.T) {
	t.Parallel()
	v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())
	assert.NotNil(t, v)
	assert.NotNil(t, v.RevocationList)
}

func TestDefaultCertificateValidator_ValidateCertificate(t *testing.T) {
	t.Parallel()
	v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())

	t.Run("nil cert", func(t *testing.T) {
		err := v.ValidateCertificate(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("expired", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-1 * time.Hour),
		})
		assert.ErrorIs(t, v.ValidateCertificate(cert), ErrCertificateExpired)
	})

	t.Run("not yet valid", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			NotBefore: time.Now().Add(24 * time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		})
		assert.ErrorIs(t, v.ValidateCertificate(cert), ErrCertificateExpired)
	})
}

func TestDefaultCertificateValidator_IsRevoked(t *testing.T) {
	t.Parallel()
	v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())

	t.Run("nil cert", func(t *testing.T) {
		_, err := v.IsRevoked(nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("not revoked", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		revoked, err := v.IsRevoked(cert)
		require.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("revoked", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			SerialNumber: big.NewInt(12345),
		})
		v.AddRevoked("12345")
		revoked, err := v.IsRevoked(cert)
		require.NoError(t, err)
		assert.True(t, revoked)
		v.RemoveRevoked("12345")
	})
}

func TestDefaultCertificateValidator_CheckExpiry(t *testing.T) {
	t.Parallel()
	v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())

	t.Run("nil cert", func(t *testing.T) {
		assert.ErrorIs(t, v.CheckExpiry(nil, time.Hour), ErrInvalidCertificate)
	})

	t.Run("already expired", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			NotAfter: time.Now().Add(-time.Hour),
		})
		assert.ErrorIs(t, v.CheckExpiry(cert, time.Hour), ErrCertificateExpired)
	})

	t.Run("expires within threshold", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			NotAfter: time.Now().Add(12 * time.Hour),
		})
		err := v.CheckExpiry(cert, 24*time.Hour)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expires within")
	})

	t.Run("valid with margin", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			NotAfter: time.Now().Add(48 * time.Hour),
		})
		assert.NoError(t, v.CheckExpiry(cert, 24*time.Hour))
	})
}

// selfSignedCert creates an in-memory self-signed ECDSA P-256 certificate for
// testing purposes. It is fast (<1 ms) and requires no external resources.
func selfSignedCert(t *testing.T, tmpl x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Minute)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// createTestCertificate is retained for use by coverage tests that build the
// full ExtraExtensions slice themselves.
func createTestCertificate(t *testing.T, template x509.Certificate) *x509.Certificate {
	t.Helper()
	return selfSignedCert(t, template)
}

// Verify unused asn1 import is referenced so tests don't break if coverage
// tests use it.
var _ = asn1.Marshal
