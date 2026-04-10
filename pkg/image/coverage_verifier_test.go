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

package image

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetermineAlgorithmFromCert_RSA(t *testing.T) {
	v, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	alg := v.determineAlgorithmFromCert(cert)
	assert.Equal(t, AlgorithmRSA256, alg)
}

func TestDetermineAlgorithmFromCert_ECDSA(t *testing.T) {
	v, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	alg := v.determineAlgorithmFromCert(cert)
	assert.Equal(t, AlgorithmECDSA256, alg)
}

func TestDetermineAlgorithmFromCert_Unknown(t *testing.T) {
	v, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	_, pubKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: pubKey}
	alg := v.determineAlgorithmFromCert(cert)
	assert.Equal(t, AlgorithmRSA256, alg) // default fallback
}
