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

package middleware

import "net/http"

// Authenticator adapts an AuthMiddleware to the gorilla/mux and
// alice-style `func(http.Handler) http.Handler` shape, so the same auth
// seam the negroni-wrapped system routes use can also be mounted with
// mux.Router.Use.
//
// It returns nil for a nil middleware. A caller must treat that as a
// configuration failure and refuse to register the routes it was going to
// protect — silently mounting the routes without it would publish an
// unauthenticated surface.
func Authenticator(m AuthMiddleware) func(http.Handler) http.Handler {
	if m == nil {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.Verify(w, r, next.ServeHTTP)
		})
	}
}
