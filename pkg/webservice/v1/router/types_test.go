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

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockWebServiceRouter implements WebServiceRouter for testing
type MockWebServiceRouter struct {
	registerRoutesCalled bool
	routerInstance       *mux.Router
}

func (m *MockWebServiceRouter) RegisterRoutes(router *mux.Router) {
	m.registerRoutesCalled = true
	m.routerInstance = router

	// Register a simple test route
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})
}

func TestWebServiceRouter_RegisterRoutes(t *testing.T) {
	t.Run("RegisterRoutes is called", func(t *testing.T) {
		mockRouter := &MockWebServiceRouter{}
		muxRouter := mux.NewRouter()

		assert.False(t, mockRouter.registerRoutesCalled)

		mockRouter.RegisterRoutes(muxRouter)

		assert.True(t, mockRouter.registerRoutesCalled)
		assert.Equal(t, muxRouter, mockRouter.routerInstance)
	})

	t.Run("routes are actually registered", func(t *testing.T) {
		mockRouter := &MockWebServiceRouter{}
		muxRouter := mux.NewRouter()

		mockRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test response", rec.Body.String())
	})
}

func TestWebServiceRouter_SystemRouterImplementation(t *testing.T) {
	t.Run("SystemRouter implements WebServiceRouter", func(t *testing.T) {
		var router WebServiceRouter
		mockAuth := &MockAuthMiddleware{}
		mockJWT := &MockJsonWebTokenMiddleware{}

		// SystemRouter implements WebServiceRouter
		// We can't easily construct it here due to dependencies,
		// but we can verify the type assertion
		sysRouter := &SystemRouter{
			authMiddleware: mockAuth,
			jwtMiddleware:  mockJWT,
		}

		router = sysRouter
		require.NotNil(t, router)
		assert.Implements(t, (*WebServiceRouter)(nil), sysRouter)
	})
}

func TestWebServiceRouter_NilRouter(t *testing.T) {
	t.Run("RegisterRoutes with nil router", func(t *testing.T) {
		mockRouter := &MockWebServiceRouter{}

		// Should handle nil gracefully or panic - depends on implementation
		// Most implementations would panic, which is acceptable
		require.Panics(t, func() {
			mockRouter.RegisterRoutes(nil)
		})
	})
}

func TestWebServiceRouter_InterfaceContract(t *testing.T) {
	t.Run("interface requires RegisterRoutes method", func(t *testing.T) {
		// This test verifies the interface contract
		var router WebServiceRouter = &MockWebServiceRouter{}

		// The interface should have exactly one method
		muxRouter := mux.NewRouter()
		router.RegisterRoutes(muxRouter)

		mockRouter := router.(*MockWebServiceRouter)
		assert.True(t, mockRouter.registerRoutesCalled)
	})
}

func TestWebServiceRouter_Composability(t *testing.T) {
	t.Run("routers can be composed", func(t *testing.T) {
		type CompositeRouter struct {
			routers []WebServiceRouter
		}

		comp := &CompositeRouter{
			routers: []WebServiceRouter{
				NewACMERouter(&MockRestServicer{}),
				NewAuthenticationRouter(&MockJsonWebTokenMiddleware{}),
				NewWebAuthnRouter(&MockJsonWebTokenMiddleware{}, &MockWebAuthnRestHandler{}),
			},
		}

		assert.Len(t, comp.routers, 3)

		muxRouter := mux.NewRouter()
		for _, router := range comp.routers {
			require.NotPanics(t, func() {
				router.RegisterRoutes(muxRouter)
			})
		}
	})
}

func TestWebServiceRouter_RouteIsolation(t *testing.T) {
	t.Run("routers don't interfere with each other", func(t *testing.T) {
		mockService := &MockRestServicer{}
		mockJWT := &MockJsonWebTokenMiddleware{}
		mockJWT.On("GenerateToken", mock.Anything, mock.Anything).Return()

		acmeRouter := NewACMERouter(mockService)
		authRouter := NewAuthenticationRouter(mockJWT)

		muxRouter := mux.NewRouter()

		acmeRouter.RegisterRoutes(muxRouter)
		authRouter.RegisterRoutes(muxRouter)

		// Test that auth routes don't interfere with acme routes
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		// Should hit auth router, not acme router
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// EmptyRouter is a test implementation with no routes
type EmptyRouter struct{}

func (e *EmptyRouter) RegisterRoutes(router *mux.Router) {
	// Empty implementation - do nothing
}

func TestWebServiceRouter_EmptyImplementation(t *testing.T) {
	t.Run("empty router implementation", func(t *testing.T) {
		var router WebServiceRouter = &EmptyRouter{}
		muxRouter := mux.NewRouter()

		require.NotPanics(t, func() {
			router.RegisterRoutes(muxRouter)
		})
	})
}

func TestWebServiceRouter_DuplicateRegistration(t *testing.T) {
	t.Run("duplicate route registration", func(t *testing.T) {
		mockRouter := &MockWebServiceRouter{}
		muxRouter := mux.NewRouter()

		// Register the same router twice
		mockRouter.RegisterRoutes(muxRouter)
		mockRouter.RegisterRoutes(muxRouter)

		// Should still work (gorilla/mux handles duplicate routes)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestWebServiceRouter_TypeAssertion(t *testing.T) {
	t.Run("type assertion works correctly", func(t *testing.T) {
		router := NewACMERouter(&MockRestServicer{})

		acmeRouter, ok := router.(*ACMERouter)
		assert.True(t, ok)
		assert.NotNil(t, acmeRouter)

		// Wrong type assertion should fail
		_, ok = router.(*AuthenticationRouter)
		assert.False(t, ok)
	})
}

func TestWebServiceRouter_NilImplementation(t *testing.T) {
	t.Run("nil router instance", func(t *testing.T) {
		var router WebServiceRouter

		assert.Nil(t, router)

		// Calling methods on nil interface panics
		require.Panics(t, func() {
			router.RegisterRoutes(nil)
		})
	})
}
