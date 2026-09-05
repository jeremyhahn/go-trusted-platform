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

package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// newEKCertForTest returns a self-signed certificate PEM with the given
// serial, standing in for a device's EK certificate.
func newEKCertForTest(t *testing.T, serial int64) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestBindingFromDevice_DerivesFromTheEKCertificate pins the derivation: the
// EK serial is the certificate's decimal serial and the certificate itself is
// prestaged, with explicit values winning over derived ones.
func TestBindingFromDevice_DerivesFromTheEKCertificate(t *testing.T) {
	certPEM := newEKCertForTest(t, 1234567890)
	dev := &entities.Device{ID: 970392025956353, Serial: "lab-node-5-compute-01", EKCert: certPEM}

	binding, err := BindingFromDevice(dev, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "1234567890", binding.EKSerial)
	assert.Equal(t, certPEM, binding.EKCert)
	assert.Empty(t, binding.MAC)

	explicit, err := BindingFromDevice(dev, "OTHER", "aa:bb:cc:dd:ee:ff", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
	require.NoError(t, err)
	assert.Equal(t, "OTHER", explicit.EKSerial, "an explicit EK serial wins over the derived one")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", explicit.MAC)
	assert.NotEqual(t, certPEM, explicit.EKCert, "an explicit certificate wins over the stored one")
}

// TestBindingFromDevice_Failures pins the typed errors: no device, a device
// with no EK certificate and nothing explicit, and an unparseable stored
// certificate — which is reported, not skipped.
func TestBindingFromDevice_Failures(t *testing.T) {
	_, err := BindingFromDevice(nil, "", "", "")
	assert.ErrorIs(t, err, ErrDeviceRequired{})

	_, err = BindingFromDevice(&entities.Device{ID: 7}, "", "", "")
	var noCert ErrDeviceHasNoEKCert
	require.True(t, errors.As(err, &noCert))
	assert.Equal(t, uint64(7), noCert.DeviceID)

	// Without an EK certificate an explicit identity is still a valid binding.
	binding, err := BindingFromDevice(&entities.Device{ID: 7}, "", "aa:bb:cc:dd:ee:ff", "")
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", binding.MAC)
	assert.Empty(t, binding.EKSerial)

	_, err = BindingFromDevice(&entities.Device{ID: 8, EKCert: "not a certificate"}, "", "", "")
	assert.ErrorIs(t, err, entities.ErrEKCertNotPEM{})
}
