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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestX509PolicyExtractor_ExtractZoneFromExtension verifies the zone is
// correctly decoded from the canonical OIDTPNetworkZone extension.
func TestX509PolicyExtractor_ExtractZoneFromExtension(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	t.Run("valid zone extension", func(t *testing.T) {
		ext, err := quicbaasca.CreateNetworkZoneExtension("production")
		require.NoError(t, err)

		cert := selfSignedCert(t, x509.Certificate{
			ExtraExtensions: []pkix.Extension{ext},
		})

		got, err := e.ExtractZone(cert)
		require.NoError(t, err)
		assert.Equal(t, "production", got)
	})

	t.Run("multiple extensions, zone present", func(t *testing.T) {
		zoneExt, err := quicbaasca.CreateNetworkZoneExtension("trusted")
		require.NoError(t, err)

		cert := selfSignedCert(t, x509.Certificate{
			ExtraExtensions: []pkix.Extension{
				{Id: quicbaasca.OIDTPNetworkZone[:len(quicbaasca.OIDTPNetworkZone)-1], Value: []byte("other")},
				zoneExt,
			},
		})
		got, err := e.ExtractZone(cert)
		require.NoError(t, err)
		assert.Equal(t, "trusted", got)
	})

	t.Run("extension absent", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		_, err := e.ExtractZone(cert)
		assert.ErrorIs(t, err, ErrMissingZoneExtension)
	})
}

// TestX509PolicyExtractor_ExtractACLsDefaultBehaviour exercises the default
// ACL path since the implementation returns a default allow rule.
func TestX509PolicyExtractor_ExtractACLsDefaultBehaviour(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	cert := selfSignedCert(t, x509.Certificate{})
	acls, err := e.ExtractACLs(cert)
	require.NoError(t, err)
	require.Len(t, acls, 1)
	assert.Equal(t, FlowActionNormal, acls[0].Action.Type)
	assert.Equal(t, 100, acls[0].Priority)
}

// TestX509PolicyExtractor_ExtractTenantIDFromExtension tests org/CN fallbacks.
func TestX509PolicyExtractor_ExtractTenantIDFromExtension(t *testing.T) {
	t.Parallel()
	e := NewX509PolicyExtractor()

	t.Run("fallback to org", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{
			Subject: pkix.Name{Organization: []string{"tenant-ext-123"}},
		})
		tid, err := e.ExtractTenantID(cert)
		require.NoError(t, err)
		assert.Equal(t, "tenant-ext-123", tid)
	})

	t.Run("missing returns error", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		_, err := e.ExtractTenantID(cert)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})
}

// TestDefaultCertificateValidator_ValidateCertificateChain tests certificate
// chain verification and revocation.
func TestDefaultCertificateValidator_ValidateCertificateChain(t *testing.T) {
	t.Parallel()

	t.Run("revoked certificate", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())
		v.AddRevoked(cert.SerialNumber.String())
		assert.ErrorIs(t, v.ValidateCertificate(cert), ErrCertificateRevoked)
	})

	t.Run("untrusted root", func(t *testing.T) {
		cert := selfSignedCert(t, x509.Certificate{})
		v := NewDefaultCertificateValidator(x509.NewCertPool(), x509.NewCertPool())
		err := v.ValidateCertificate(cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate verification failed")
	})
}

// TestIsZoneDeclared_Private exercises the private helper via ExtractPolicy.
func TestIsZoneDeclared_Private(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	e := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	// A declared zone should not fail closed.
	ext, err := quicbaasca.CreateNetworkZoneExtension(string(zone.ZoneTrusted))
	require.NoError(t, err)

	cert := selfSignedCert(t, x509.Certificate{
		Subject:         pkix.Name{Organization: []string{"org"}},
		ExtraExtensions: []pkix.Extension{ext},
	})

	pol, err := e.ExtractPolicy(cert)
	require.NoError(t, err)
	assert.Equal(t, zone.Zone(zone.ZoneTrusted), pol.Zone)
}
