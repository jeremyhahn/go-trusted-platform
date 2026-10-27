// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package pxe

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateFingerprintOf(t *testing.T) {
	// SHA-256("abc"), FIPS 180-2 Appendix B.1.
	cert := &x509.Certificate{Raw: []byte("abc")}
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", CertificateFingerprintOf(cert))

	other := &x509.Certificate{Raw: []byte("abd")}
	assert.NotEqual(t, CertificateFingerprintOf(cert), CertificateFingerprintOf(other),
		"certificates that differ in any DER byte must differ in fingerprint")
}

func TestNormalizeCertificateFingerprint(t *testing.T) {
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	accepted := map[string]string{
		"lowercase hex":         want,
		"openssl colon form":    "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD",
		"uppercase, no colons":  strings.ToUpper(want),
		"empty means no record": "",
	}
	for name, in := range accepted {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeCertificateFingerprint(in)
			require.NoError(t, err)
			if in == "" {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, want, got)
		})
	}

	refused := map[string]string{
		"not hex":       strings.Repeat("zz", 32),
		"SHA-1 length":  strings.Repeat("ab", 20),
		"odd length":    want + "a",
		"one byte long": want + "ab",
	}
	for name, in := range refused {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeCertificateFingerprint(in)
			require.Error(t, err)
			assert.Empty(t, got)
			var typed ErrInvalidCertificateFingerprint
			require.True(t, errors.As(err, &typed))
			assert.Equal(t, in, typed.Fingerprint)
		})
	}
}
