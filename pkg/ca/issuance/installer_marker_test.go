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

package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signTestClientCertificate self-signs a client certificate carrying extra,
// so the test reads the extension back the way a TLS peer parses it.
func signTestClientCertificate(t *testing.T, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "installer"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// The marker extension parses back as one critical extended key usage
// extension carrying id-kp-clientAuth and tp-pxeInstaller (#1362).
func TestInstallerMarkerExtension_ParsesBackAsACriticalClientAuthEKU(t *testing.T) {
	marker, err := InstallerMarkerExtension()
	require.NoError(t, err)

	cert := signTestClientCertificate(t, marker)

	var ekus []pkix.Extension
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidExtensionExtKeyUsage) {
			ekus = append(ekus, extension)
		}
	}
	require.Len(t, ekus, 1, "the marker replaces the extension ExtKeyUsage would produce")
	assert.True(t, ekus[0].Critical)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, cert.ExtKeyUsage)
	require.Len(t, cert.UnknownExtKeyUsage, 1)
	assert.True(t, cert.UnknownExtKeyUsage[0].Equal(OIDPXEInstaller))
	assert.Empty(t, cert.UnhandledCriticalExtensions, "Go processes the extended key usage extension")
	assert.True(t, HasInstallerMarker(cert))
}

func TestHasInstallerMarker_RefusesCertificatesWithoutTheMarker(t *testing.T) {
	assert.False(t, HasInstallerMarker(signTestClientCertificate(t)), "a plain client certificate")
	assert.False(t, HasInstallerMarker(nil))
	other := &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 29377, 101, 21}}}
	assert.False(t, HasInstallerMarker(other), "another private OID is not the marker")
}

func TestInstallerMarkerEncodeError(t *testing.T) {
	cause := errors.New("bad oid")
	err := &InstallerMarkerEncodeError{Err: cause}
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "installer marker")
}
