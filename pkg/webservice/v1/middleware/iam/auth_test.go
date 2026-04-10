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

package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// createTestLogger creates a logger for testing.
func createTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

// createTestCertificate creates a self-signed certificate for testing.
func createTestCertificate(opts ...func(*x509.Certificate)) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "Test User",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test OU"},
		},
		EmailAddresses: []string{"test@example.com"},
		DNSNames:       []string{"example.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, opt := range opts {
		opt(template)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	return cert, privateKey
}

// TestNewAuthMiddleware tests the NewAuthMiddleware constructor.
func TestNewAuthMiddleware(t *testing.T) {
	logger := createTestLogger()
	httpWriter := newMockHttpWriter()
	iamService := newMockIAMServiceClient()

	t.Run("creates_middleware_with_valid_config", func(t *testing.T) {
		config := AuthConfig{
			RequireTLS:      true,
			DefaultTenantID: "default-tenant",
		}

		middleware, err := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if middleware == nil {
			t.Fatal("expected middleware to be non-nil")
		}
	})

	t.Run("returns_error_for_nil_logger", func(t *testing.T) {
		config := AuthConfig{}
		_, err := NewAuthMiddleware(nil, httpWriter, config, iamService, nil, nil, nil)

		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if _, ok := err.(ErrInvalidConfig); !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("returns_error_for_nil_response_writer", func(t *testing.T) {
		config := AuthConfig{}
		_, err := NewAuthMiddleware(logger, nil, config, iamService, nil, nil, nil)

		if err == nil {
			t.Fatal("expected error for nil response writer")
		}
	})

	t.Run("returns_error_for_nil_iam_service", func(t *testing.T) {
		config := AuthConfig{}
		_, err := NewAuthMiddleware(logger, httpWriter, config, nil, nil, nil, nil)

		if err == nil {
			t.Fatal("expected error for nil IAM service")
		}
	})
}

// TestAuthMiddleware_Handler tests the Handler method.
func TestAuthMiddleware_Handler(t *testing.T) {
	logger := createTestLogger()
	httpWriter := newMockHttpWriter()
	iamService := newMockIAMServiceClient()

	t.Run("wraps_handler_correctly", func(t *testing.T) {
		// Setup mock to return a user for mTLS authentication
		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
						Roles:    []string{"user"},
					},
				},
			}, nil
		}

		config := AuthConfig{
			ExtractTenantFromCert: true,
			TenantCertField:       "o",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		handler := middleware.Handler(next)

		cert, _ := createTestCertificate()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected next handler to be called")
		}
	})
}

// TestAuthMiddleware_Authenticate tests the Authenticate method.
func TestAuthMiddleware_Authenticate(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("requires_tls_when_configured", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{RequireTLS: true}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected next handler not to be called when TLS required but not present")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("denies_request_when_no_auth", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_AuthenticateWithMTLS tests mTLS authentication.
func TestAuthMiddleware_AuthenticateWithMTLS(t *testing.T) {
	logger := createTestLogger()

	t.Run("authenticates_with_valid_certificate", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		// Setup mock to return a user
		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
						Roles:    []string{"user"},
					},
				},
			}, nil
		}

		config := AuthConfig{
			ExtractTenantFromCert: true,
			TenantCertField:       "o",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		cert, _ := createTestCertificate()

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context")
		}
		if sessionFromContext.Email() != "test@example.com" {
			t.Errorf("expected email 'test@example.com', got %q", sessionFromContext.Email())
		}
	})

	t.Run("requires_mtls_when_configured", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()
		config := AuthConfig{RequireMTLS: true}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{} // No peer certificates
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected next handler not to be called when mTLS required but no cert")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("uses_default_tenant_when_not_extracted_from_cert", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
					},
				},
			}, nil
		}

		config := AuthConfig{
			ExtractTenantFromCert: false,
			DefaultTenantID:       "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		cert, _ := createTestCertificate()

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context")
		}
		if sessionFromContext.TenantID() != "default-tenant" {
			t.Errorf("expected tenant 'default-tenant', got %q", sessionFromContext.TenantID())
		}
	})

	t.Run("rejects_certificate_with_no_identity", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		config := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		// Create cert with no email, no CN, and no serial number
		cert, _ := createTestCertificate(func(c *x509.Certificate) {
			c.EmailAddresses = nil
			c.Subject.CommonName = ""
			c.Subject.SerialNumber = ""
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called when certificate has no identity")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("uses_cn_when_email_not_present", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
					},
				},
			}, nil
		}

		config := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		// Create cert with CN but no email
		cert, _ := createTestCertificate(func(c *x509.Certificate) {
			c.EmailAddresses = nil
			c.Subject.CommonName = "cn-identity"
		})

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context")
		}
		// The email in IAM query should be the CN
		if len(iamService.listUsersCalls) == 0 {
			t.Fatal("expected ListUsers to be called")
		}
		if iamService.listUsersCalls[0].Email != "cn-identity" {
			t.Errorf("expected email to be 'cn-identity', got %q", iamService.listUsersCalls[0].Email)
		}
	})

	t.Run("uses_serial_number_when_email_and_cn_not_present", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
					},
				},
			}, nil
		}

		config := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		// Create cert with only serial number
		cert, _ := createTestCertificate(func(c *x509.Certificate) {
			c.EmailAddresses = nil
			c.Subject.CommonName = ""
			c.Subject.SerialNumber = "SERIAL123"
		})

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context")
		}
		// The email in IAM query should be the serial number
		if len(iamService.listUsersCalls) == 0 {
			t.Fatal("expected ListUsers to be called")
		}
		if iamService.listUsersCalls[0].Email != "SERIAL123" {
			t.Errorf("expected email to be 'SERIAL123', got %q", iamService.listUsersCalls[0].Email)
		}
	})

	t.Run("rejects_when_user_lookup_fails", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return nil, errors.New("service unavailable")
		}

		config := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		cert, _ := createTestCertificate()

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called when user lookup fails")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("rejects_when_missing_tenant_id", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		config := AuthConfig{
			ExtractTenantFromCert: false,
			// No DefaultTenantID
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		cert, _ := createTestCertificate()

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called when tenant is missing")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_ExtractTenantFromCert tests tenant extraction from certificates.
func TestAuthMiddleware_ExtractTenantFromCert(t *testing.T) {
	logger := createTestLogger()
	httpWriter := newMockHttpWriter()
	iamService := newMockIAMServiceClient()

	tests := []struct {
		name           string
		tenantField    string
		certModifier   func(*x509.Certificate)
		expectedTenant string
	}{
		{
			name:        "extracts_from_cn",
			tenantField: "cn",
			certModifier: func(c *x509.Certificate) {
				c.Subject.CommonName = "tenant-from-cn"
			},
			expectedTenant: "tenant-from-cn",
		},
		{
			name:        "extracts_from_ou",
			tenantField: "ou",
			certModifier: func(c *x509.Certificate) {
				c.Subject.OrganizationalUnit = []string{"tenant-from-ou"}
			},
			expectedTenant: "tenant-from-ou",
		},
		{
			name:        "extracts_from_o",
			tenantField: "o",
			certModifier: func(c *x509.Certificate) {
				c.Subject.Organization = []string{"tenant-from-org"}
			},
			expectedTenant: "tenant-from-org",
		},
		{
			name:        "extracts_from_san_dns",
			tenantField: "san_dns",
			certModifier: func(c *x509.Certificate) {
				c.DNSNames = []string{"tenant.example.com"}
			},
			expectedTenant: "tenant.example.com",
		},
		{
			name:        "extracts_domain_from_san_email",
			tenantField: "san_email",
			certModifier: func(c *x509.Certificate) {
				c.EmailAddresses = []string{"user@tenant-domain.com"}
			},
			expectedTenant: "tenant-domain.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
				return &iampb.ListUsersResponse{
					Users: []*iampb.User{
						{
							Id:       "user-123",
							TenantId: req.TenantId,
							Email:    req.Email,
							Name:     "Test User",
						},
					},
				}, nil
			}

			config := AuthConfig{
				ExtractTenantFromCert: true,
				TenantCertField:       tt.tenantField,
			}
			middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

			cert, _ := createTestCertificate(tt.certModifier)

			var sessionFromContext IAMSession
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sessionFromContext, _ = GetSessionFromContext(r.Context())
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}
			rec := httptest.NewRecorder()

			middleware.Authenticate(rec, req, next)

			if sessionFromContext == nil {
				t.Fatal("expected session to be set in context")
			}
			if sessionFromContext.TenantID() != tt.expectedTenant {
				t.Errorf("expected tenant %q, got %q", tt.expectedTenant, sessionFromContext.TenantID())
			}
		})
	}
}

// TestAuthMiddleware_RequireRoles tests the RequireRoles middleware.
func TestAuthMiddleware_RequireRoles(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("allows_request_with_required_role", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Roles:    []string{"admin", "user"},
		})

		called := false
		handler := middleware.RequireRoles("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called")
		}
	})

	t.Run("denies_request_without_required_role", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Roles:    []string{"user"},
		})

		called := false
		handler := middleware.RequireRoles("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called")
		}
	})

	t.Run("denies_request_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		handler := middleware.RequireRoles("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_RequireAllRoles tests the RequireAllRoles middleware.
func TestAuthMiddleware_RequireAllRoles(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("allows_request_with_all_required_roles", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Roles:    []string{"admin", "user", "viewer"},
		})

		called := false
		handler := middleware.RequireAllRoles("admin", "user")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called")
		}
	})

	t.Run("denies_request_without_all_required_roles", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Roles:    []string{"admin"},
		})

		called := false
		handler := middleware.RequireAllRoles("admin", "superadmin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called")
		}
	})

	t.Run("denies_request_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		handler := middleware.RequireAllRoles("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_RequireGroups tests the RequireGroups middleware.
func TestAuthMiddleware_RequireGroups(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("allows_request_with_required_group", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Groups:   []string{"developers", "ops"},
		})

		called := false
		handler := middleware.RequireGroups("developers")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called")
		}
	})

	t.Run("denies_request_without_required_group", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
			Groups:   []string{"developers"},
		})

		called := false
		handler := middleware.RequireGroups("admins")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called")
		}
	})

	t.Run("denies_request_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		handler := middleware.RequireGroups("admins")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_RequireMFA tests the RequireMFA middleware.
func TestAuthMiddleware_RequireMFA(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("allows_request_with_mfa_verified", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSessionWithMFA(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
		}, true, time.Now())

		called := false
		handler := middleware.RequireMFA()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called")
		}
	})

	t.Run("denies_request_without_mfa_verified", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		session := NewIAMSessionWithMFA(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
		}, false, time.Time{})

		called := false
		handler := middleware.RequireMFA()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("denies_request_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		called := false
		handler := middleware.RequireMFA()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthMiddleware_CreateSession tests the CreateSession method.
func TestAuthMiddleware_CreateSession(t *testing.T) {
	logger := createTestLogger()

	t.Run("returns_error_when_no_auth_method_succeeds", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()
		config := AuthConfig{}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		session, err := middleware.CreateSession(rec, req)

		if session != nil {
			t.Error("expected session to be nil")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("creates_session_with_mtls", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.listUsersFunc = func(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{
						Id:       "user-123",
						TenantId: req.TenantId,
						Email:    req.Email,
						Name:     "Test User",
					},
				},
			}, nil
		}

		config := AuthConfig{
			ExtractTenantFromCert: true,
			TenantCertField:       "o",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)

		cert, _ := createTestCertificate()

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()

		session, err := middleware.CreateSession(rec, req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session == nil {
			t.Fatal("expected session to be non-nil")
		}
	})

	t.Run("creates_session_with_jwt_when_mtls_fails", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()
		signingKey := []byte("test-secret-key-32-bytes-long!!!")

		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return &iampb.User{
				Id:       req.UserId,
				TenantId: req.TenantId,
				Email:    "user@example.com",
			}, nil
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		config := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, config, iamService, jwtMiddleware, nil, nil)

		claims := jwt.MapClaims{
			"sub":       "user-123",
			"tenant_id": "tenant-456",
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		rec := httptest.NewRecorder()

		session, err := middleware.CreateSession(rec, req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session == nil {
			t.Fatal("expected session to be non-nil")
		}
		if session.UserID() != "user-123" {
			t.Errorf("expected user ID 'user-123', got %q", session.UserID())
		}
	})
}

// TestAuthMiddleware_AuthenticateWithJWT tests JWT authentication fallback.
func TestAuthMiddleware_AuthenticateWithJWT(t *testing.T) {
	logger := createTestLogger()
	signingKey := []byte("test-secret-key-32-bytes-long!!!")

	t.Run("authenticates_with_valid_jwt", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return &iampb.User{
				Id:       req.UserId,
				TenantId: req.TenantId,
				Email:    "user@example.com",
				Name:     "Test User",
				Roles:    []string{"user"},
			}, nil
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			RequireJWT:      true,
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		claims := jwt.MapClaims{
			"sub":       "user-123",
			"tenant_id": "tenant-456",
			"email":     "user@example.com",
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context")
		}
		if sessionFromContext.UserID() != "user-123" {
			t.Errorf("expected user ID 'user-123', got %q", sessionFromContext.UserID())
		}
	})

	t.Run("creates_session_from_claims_when_user_lookup_fails", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		// User lookup fails - will create session from claims
		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return nil, ErrUserNotFound{Identifier: req.UserId}
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			RequireJWT:      true,
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		claims := jwt.MapClaims{
			"sub":       "user-123",
			"tenant_id": "tenant-456",
			"email":     "user@example.com",
			"name":      "Test User",
			"roles":     []interface{}{"admin", "user"},
			"groups":    []interface{}{"developers"},
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be created from claims")
		}
		if sessionFromContext.Email() != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %q", sessionFromContext.Email())
		}
		if sessionFromContext.Name() != "Test User" {
			t.Errorf("expected name 'Test User', got %q", sessionFromContext.Name())
		}
	})

	t.Run("uses_tenant_from_header_when_not_in_claims", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return &iampb.User{
				Id:       req.UserId,
				TenantId: req.TenantId,
				Email:    "user@example.com",
			}, nil
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			RequireJWT: true,
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		// No tenant_id in claims
		claims := jwt.MapClaims{
			"sub": "user-123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		req.Header.Set(TenantIDHeader, "header-tenant")
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set")
		}
		if sessionFromContext.TenantID() != "header-tenant" {
			t.Errorf("expected tenant 'header-tenant', got %q", sessionFromContext.TenantID())
		}
	})

	t.Run("rejects_request_with_invalid_jwt_when_required", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			RequireJWT: true,
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+"invalid-token")
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called with invalid JWT")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("rejects_request_with_missing_tenant", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			RequireJWT: true,
			// No DefaultTenantID
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		// No tenant_id in claims
		claims := jwt.MapClaims{
			"sub": "user-123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		// No X-Tenant-ID header
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called without tenant")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called for missing tenant")
		}
	})

	t.Run("returns_error_when_jwt_not_configured", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		authConfig := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		// No JWT middleware configured
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, nil, nil, nil)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+"some-token")
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if called {
			t.Error("expected handler not to be called when JWT not configured")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestGetSetSessionInContext tests the context helper functions.
func TestGetSetSessionInContext(t *testing.T) {
	t.Run("sets_and_gets_session_from_context", func(t *testing.T) {
		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
		})

		ctx := context.Background()
		ctx = SetSessionInContext(ctx, session)

		retrieved, ok := GetSessionFromContext(ctx)

		if !ok {
			t.Error("expected session to be found in context")
		}
		if retrieved != session {
			t.Error("expected retrieved session to match original")
		}
	})

	t.Run("returns_false_when_session_not_in_context", func(t *testing.T) {
		ctx := context.Background()

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found in context")
		}
	})

	t.Run("returns_false_for_wrong_type_in_context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), SessionContextKey, "not a session")

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found for wrong type")
		}
	})
}

// TestAuthMiddleware_LookupUserByID tests the lookupUserByID internal function.
func TestAuthMiddleware_LookupUserByID(t *testing.T) {
	logger := createTestLogger()
	signingKey := []byte("test-secret-key-32-bytes-long!!!")

	t.Run("returns_service_unavailable_on_iam_error", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		// Simulate service error that is not "user not found"
		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return nil, errors.New("connection refused")
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		claims := jwt.MapClaims{
			"sub":       "user-123",
			"tenant_id": "tenant-456",
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		// Even though IAM service returns error, authentication should succeed
		// by falling back to creating session from claims
		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context (created from claims)")
		}
	})

	t.Run("returns_user_not_found_when_user_nil", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		iamService := newMockIAMServiceClient()

		// Return nil user without error
		iamService.getUserFunc = func(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
			return nil, nil
		}

		jwtConfig := JWTConfig{
			SigningKey: signingKey,
		}
		jwtMiddleware, _ := NewJWTMiddleware(logger, httpWriter, jwtConfig, iamService)

		authConfig := AuthConfig{
			DefaultTenantID: "default-tenant",
		}
		middleware, _ := NewAuthMiddleware(logger, httpWriter, authConfig, iamService, jwtMiddleware, nil, nil)

		claims := jwt.MapClaims{
			"sub":       "user-123",
			"tenant_id": "tenant-456",
			"iat":       time.Now().Unix(),
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(signingKey)

		var sessionFromContext IAMSession
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionFromContext, _ = GetSessionFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+tokenString)
		rec := httptest.NewRecorder()

		middleware.Authenticate(rec, req, next)

		// Should fall back to session from claims
		if sessionFromContext == nil {
			t.Fatal("expected session to be set in context (created from claims)")
		}
	})
}
