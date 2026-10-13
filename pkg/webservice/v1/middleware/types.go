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

import (
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
)

type JsonWebTokenMiddleware interface {
	CreateSession(w http.ResponseWriter, r *http.Request) (service.Session, error)
	GenerateToken(w http.ResponseWriter, req *http.Request)
	AuthMiddleware
}

type AuthMiddleware interface {
	RefreshToken(w http.ResponseWriter, req *http.Request)
	Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc)
}

// ScopeAuthorizer is an AuthMiddleware whose verified requests carry granted
// scopes, so a route can require one on top of its role gate. The platform
// token middleware is one; the legacy JWT handler carries no scopes.
type ScopeAuthorizer interface {
	RequireScope(scope string) func(http.Handler) http.Handler
}
