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

// Binder adapts one factor type's HTTP surface to the unified ceremony.
// It owns only the translation between an HTTP request and the two
// ceremony requests — never the ceremony sequence itself, which is the
// Driver's, and never the cryptographic verification, which is the
// backbone's.
//
// Factors come in two shapes and Binder covers both:
//
//   - A CHALLENGE factor (fido2, piv) needs a client round trip: the
//     driver answers Begin with Challenge's projection, and the client
//     comes back to Finish with the hardware's proof.
//   - A SINGLE-SHOT factor (mtls) has already proven possession out of
//     band — the TLS handshake — so there is nothing to challenge. Its
//     Challenge returns nil and the driver runs the whole ceremony in the
//     one request.
type Binder interface {
	// Type is the factor type this binder speaks. The driver dispatches
	// on it, so it must be stable and match the type used in Begin.
	Type() quicbaas.FactorType

	// Begin builds the ceremony's begin request from the HTTP request.
	Begin(r *http.Request) (quicbaas.BeginLoginRequest, error)

	// Challenge projects the backbone's challenge onto the body this
	// factor's client consumes, or returns nil for a single-shot factor
	// to tell the driver to finish the ceremony in the same request.
	Challenge(begin *quicbaas.BeginLoginResponse) (any, error)

	// Finish builds the finish request from the proof on the HTTP
	// request.
	//
	// sessionID is the ceremony session the driver already holds. It is
	// non-empty only for a single-shot factor, whose begin and finish
	// share one request; a challenge binder reads the session its client
	// echoed back and ignores this argument.
	Finish(r *http.Request, sessionID string) (quicbaas.FinishLoginRequest, error)
}

// binders indexes the registered binders by factor type for O(1)
// dispatch. Population happens once, at driver construction.
type binders map[quicbaas.FactorType]Binder
