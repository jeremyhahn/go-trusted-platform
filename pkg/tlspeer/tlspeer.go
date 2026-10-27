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

// Package tlspeer reads the authenticated peer of a TLS connection: the leaf
// of the client certificate chain the TLS stack verified.
//
// # Why VerifiedChains and not PeerCertificates
//
// PeerCertificates holds whatever the peer sent, verified or not; under
// tls.VerifyClientCertIfGiven an unverifiable certificate fails the
// handshake, but reading PeerCertificates would still be reading an
// attacker-controlled field under any future ClientAuth setting.
// VerifiedChains is non-empty only after the TLS stack has built and
// verified a chain to the configured ClientCAs, so it is the only
// authenticated source of a peer identity.
//
// The gateway control plane (pkg/webservice/v1/rest/gateway) and the PXE
// install-completion webhook (pkg/api/daemon) both bind their caller to a
// record through this one function.
package tlspeer

import (
	"crypto/tls"
	"crypto/x509"
)

// VerifiedLeaf returns the leaf certificate of the first chain the TLS stack
// verified for the peer. A nil state (no TLS connection) or a connection
// without a verified chain is an error: there is no authenticated peer, and
// the caller refuses the request rather than defaulting an identity.
func VerifiedLeaf(state *tls.ConnectionState) (*x509.Certificate, error) {
	if state == nil {
		return nil, ErrNoVerifiedPeer{Reason: "connection is not TLS"}
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, ErrNoVerifiedPeer{Reason: "no verified client certificate was presented"}
	}
	return state.VerifiedChains[0][0], nil
}

// ErrNoVerifiedPeer signals that a connection carries no verified client
// certificate to take a peer identity from.
type ErrNoVerifiedPeer struct {
	Reason string
}

func (e ErrNoVerifiedPeer) Error() string {
	return e.Reason
}
