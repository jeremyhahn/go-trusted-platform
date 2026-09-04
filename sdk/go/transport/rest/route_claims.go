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

package rest

// RouteClaim is one REST route this client believes the server serves.
//
// The two route tables in this package are the client's complete set of
// route-shaped claims: every gRPC method the REST transport can carry resolves
// through one of them. A claim that no server route satisfies is a method that
// fails at runtime with a 404 — which is #265, #266 and #321, each found by a
// person tripping over it rather than by a check.
//
// This accessor exists so a test can compare the claims against the routes the
// server actually builds. It is read-only and allocates a fresh slice per call:
// the tables themselves stay unexported and immutable.
type RouteClaim struct {
	// GRPCMethod is the "/package.Service/Method" key the claim is filed under.
	GRPCMethod string

	// Method is the HTTP method the client will send.
	Method string

	// Path is the REST path template. It may contain {placeholder} segments
	// that the client substitutes from request fields before sending, so a
	// consumer comparing these against server routes must match by ROUTING a
	// concrete path, not by string equality — see #321, where a client sending
	// a collection path where the server serves an item path returned the wrong
	// resource rather than an error.
	Path string

	// Templated reports whether the claim came from the templated table, whose
	// entries substitute path parameters, rather than the flat table.
	Templated bool
}

// RouteClaims returns every route-shaped claim the REST transport makes, from
// both the templated and flat tables.
//
// Order is unspecified; callers that need determinism should sort.
func RouteClaims() []RouteClaim {
	claims := make([]RouteClaim, 0, len(templatedRouteTable)+len(grpcMethodToRESTMap))

	for grpcMethod, entry := range templatedRouteTable {
		claims = append(claims, RouteClaim{
			GRPCMethod: grpcMethod,
			Method:     entry.method,
			Path:       entry.path,
			Templated:  true,
		})
	}

	for grpcMethod, entry := range grpcMethodToRESTMap {
		claims = append(claims, RouteClaim{
			GRPCMethod: grpcMethod,
			Method:     entry.method,
			Path:       entry.path,
		})
	}

	return claims
}
