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

package login

import (
	"net/http"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// MTLSBinder binds a single-shot certificate login to the unified
// backbone.
//
// mTLS is a SINGLE-SHOT factor: possession was proven by the TLS
// handshake before the request body was read, so there is no challenge to
// issue and nothing for the client to sign. Begin and finish therefore
// happen in one request, which is why Challenge returns nil.
//
// The backbone derives the lookup key from the VERIFIED peer certificate
// and never from the request body — a client must not be able to assert
// "log me in as the holder of certificate X" by naming X's key. Supplying
// that certificate is the caller's job, and on the platform's embedded
// transport it is currently impossible: quicbaas's sdk/go re-exports
// neither the peer-certificate context helper nor the key derivation, so
// an embedded caller is trusted to supply the lookup key while having no
// sanctioned way to compute one (jeremyhahn/go-quicbaas#857). Until that
// re-export lands this binder reaches the backbone with no lookup key and
// the ceremony refuses the login, which is the correct failure: the
// platform must not substitute a key it derived itself and cannot keep in
// step with the enrollment side.
type MTLSBinder struct{}

// NewMTLSBinder constructs the certificate-login binder.
func NewMTLSBinder() *MTLSBinder {
	return &MTLSBinder{}
}

// Type returns the mTLS factor type.
func (b *MTLSBinder) Type() quicbaas.FactorType {
	return quicbaas.FactorTypeMTLS
}

// Begin opens the login attempt. The attempt carries no hint: an mTLS
// login resolves from the certificate the peer already presented, so
// there is nothing for the caller to name.
func (b *MTLSBinder) Begin(r *http.Request) (quicbaas.BeginLoginRequest, error) {
	return quicbaas.BeginLoginRequest{Type: quicbaas.FactorTypeMTLS}, nil
}

// Challenge returns nil: a single-shot factor has no challenge, and the
// nil tells the driver to complete the ceremony in this same request.
func (b *MTLSBinder) Challenge(begin *quicbaas.BeginLoginResponse) (any, error) {
	return nil, nil
}

// Finish completes the ceremony against the session the driver just
// opened. No proof is carried: the handshake was the proof, and the
// backbone proceeds on it once the lookup key resolves.
func (b *MTLSBinder) Finish(r *http.Request, sessionID string) (quicbaas.FinishLoginRequest, error) {
	if sessionID == "" {
		return quicbaas.FinishLoginRequest{}, &MissingSessionError{}
	}
	return quicbaas.FinishLoginRequest{
		SessionID: sessionID,
		Type:      quicbaas.FactorTypeMTLS,
	}, nil
}
