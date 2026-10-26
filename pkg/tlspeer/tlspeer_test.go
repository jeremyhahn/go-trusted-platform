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

package tlspeer

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifiedLeaf_ReturnsTheVerifiedLeaf(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "node-01"}}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "platform-ca"}}
	state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}

	got, err := VerifiedLeaf(state)

	require.NoError(t, err)
	assert.Same(t, leaf, got)
}

// TestVerifiedLeaf_RefusesWithoutAVerifiedChain pins that an unverified
// certificate is never an identity: a connection that sent a certificate the
// TLS stack did not verify (PeerCertificates set, VerifiedChains empty) is
// refused exactly like one that sent none.
func TestVerifiedLeaf_RefusesWithoutAVerifiedChain(t *testing.T) {
	sent := &x509.Certificate{Subject: pkix.Name{CommonName: "attacker"}}
	cases := map[string]*tls.ConnectionState{
		"no TLS connection":      nil,
		"no certificate":         {},
		"unverified certificate": {PeerCertificates: []*x509.Certificate{sent}},
		"empty verified chain":   {VerifiedChains: [][]*x509.Certificate{{}}},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := VerifiedLeaf(state)

			require.Error(t, err)
			assert.Nil(t, got)
			var noPeer ErrNoVerifiedPeer
			require.True(t, errors.As(err, &noPeer))
			assert.NotEmpty(t, noPeer.Reason)
			// The webhook's refusal carries this message to the caller.
			assert.Equal(t, noPeer.Reason, err.Error())
		})
	}
}
