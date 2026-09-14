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
// that certificate is the caller's job, and the platform currently has no
// sanctioned way to do it: quicbaas's sdk/go re-exports neither the
// peer-certificate context helper nor the key derivation
// (jeremyhahn/go-quicbaas#857).
//
// So this binder DECLINES the ceremony rather than opening one it cannot
// bind. That is not tidiness, it is the safe answer, and the unsafe one is
// specific: the platform's SDK client can be configured in remote
// transport mode (pkg/app/app.go QuicBaaSSDKClient), and on a NETWORK
// transport the backbone populates the verified peer certificate from the
// connection it actually sees — which is PLATFORMD's client certificate,
// not the browser's. A ceremony opened here would then resolve whatever
// identity platformd's own certificate is enrolled as, and hand it to an
// unauthenticated caller of /api/v1/login. On the embedded transport the
// same request is merely refused for an empty lookup key, so the hole is
// invisible until someone points the daemon at a remote control plane.
//
// Refusing locally means no FinishLogin bearing an identity the platform
// did not intend ever leaves the process. The binder starts working, with
// no change here beyond deleting the refusal, when #857 lands and the
// caller's certificate can be bound to the ceremony.
type MTLSBinder struct{}

// NewMTLSBinder constructs the certificate-login binder.
func NewMTLSBinder() *MTLSBinder {
	return &MTLSBinder{}
}

// Type returns the mTLS factor type.
func (b *MTLSBinder) Type() quicbaas.FactorType {
	return quicbaas.FactorTypeMTLS
}

// Begin declines the ceremony: see the type comment. The refusal is here,
// at the first step, so nothing reaches the backbone — a ceremony opened
// and then abandoned would still have told the backbone to resolve an
// identity from whatever certificate it could see.
//
// An mTLS login carries no hint even when it works: it resolves from the
// certificate the peer already presented, so there is nothing to name.
func (b *MTLSBinder) Begin(r *http.Request) (quicbaas.BeginLoginRequest, error) {
	return quicbaas.BeginLoginRequest{}, b.unavailable()
}

// unavailable is the single refusal both verbs answer with, so they cannot
// drift into disagreeing about whether the factor is usable.
func (b *MTLSBinder) unavailable() error {
	return &FactorUnavailableError{
		Type: quicbaas.FactorTypeMTLS,
		Reason: "the caller's peer certificate cannot be bound to the ceremony " +
			"through sdk/go (jeremyhahn/go-quicbaas#857), and opening one anyway " +
			"would let a remote transport resolve the platform's own certificate",
	}
}

// Challenge returns nil: a single-shot factor has no challenge, and the
// nil tells the driver to complete the ceremony in this same request.
func (b *MTLSBinder) Challenge(begin *quicbaas.BeginLoginResponse) (any, error) {
	return nil, nil
}

// Finish declines for the same reason Begin does.
//
// The driver reaches Finish only through Begin for a single-shot factor,
// so this is unreachable today — and it refuses anyway, because a binder
// with one open verb and one closed one is a binder whose safety depends
// on the caller's control flow. When #857 lands both refusals go together:
// Finish then carries the session and no proof, the handshake having been
// the proof.
func (b *MTLSBinder) Finish(r *http.Request, sessionID string) (quicbaas.FinishLoginRequest, error) {
	return quicbaas.FinishLoginRequest{}, b.unavailable()
}
