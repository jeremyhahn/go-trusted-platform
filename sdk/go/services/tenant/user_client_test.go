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

package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

func TestNewUserClient(t *testing.T) {
	t.Run("returns error for nil config", func(t *testing.T) {
		client, err := NewUserClient(nil)
		if err != common.ErrNilClient {
			t.Errorf("NewUserClient(nil) error = %v, want %v", err, common.ErrNilClient)
		}
		if client != nil {
			t.Error("NewUserClient(nil) should return nil client")
		}
	})

	t.Run("creates REST client with valid config", func(t *testing.T) {
		client, err := NewUserClient(&UserClientConfig{
			Transport:   UserTransportREST,
			RESTBaseURL: "https://example.com/api/v1",
			AuthToken:   "test-token",
		})
		if err != nil {
			t.Fatalf("NewUserClient() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewUserClient() returned nil client")
		}
		if client.transport != UserTransportREST {
			t.Errorf("client.transport = %v, want %v", client.transport, UserTransportREST)
		}
	})

	t.Run("returns error for REST without base URL", func(t *testing.T) {
		client, err := NewUserClient(&UserClientConfig{
			Transport: UserTransportREST,
		})
		if err == nil {
			t.Error("NewUserClient() should fail for REST without base URL")
		}
		if client != nil {
			t.Error("NewUserClient() should return nil client on error")
		}
	})

	t.Run("returns error for gRPC without transport", func(t *testing.T) {
		client, err := NewUserClient(&UserClientConfig{
			Transport: UserTransportGRPC,
		})
		if err == nil {
			t.Error("NewUserClient() should fail for gRPC without transport")
		}
		if client != nil {
			t.Error("NewUserClient() should return nil client on error")
		}
	})
}

func TestNewRESTUserClient(t *testing.T) {
	t.Run("creates client with base URL and token", func(t *testing.T) {
		client, err := NewRESTUserClient("https://example.com/api/v1", "test-token")
		if err != nil {
			t.Fatalf("NewRESTUserClient() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewRESTUserClient() returned nil client")
		}
		if client.authToken != "test-token" {
			t.Errorf("client.authToken = %v, want 'test-token'", client.authToken)
		}
	})
}

func TestUserClient_SetAuthToken(t *testing.T) {
	t.Run("updates auth token", func(t *testing.T) {
		client, _ := NewRESTUserClient("https://example.com/api/v1", "initial-token")
		client.SetAuthToken("new-token")
		if client.authToken != "new-token" {
			t.Errorf("authToken = %v, want 'new-token'", client.authToken)
		}
	})
}

func TestUserClient_GetTenant(t *testing.T) {
	t.Run("retrieves current user tenant", func(t *testing.T) {
		now := time.Now().UTC()
		expectedTenant := &TenantInfo{
			ID:          "tenant-123",
			Name:        "tenant-123",
			DisplayName: "Test Tenant",
			State:       "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Method = %v, want GET", r.Method)
			}
			if r.URL.Path != "/api/v1/me/tenant" {
				t.Errorf("Path = %v, want /api/v1/me/tenant", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Error("Authorization header missing or incorrect")
			}

			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(expectedTenant); err != nil {
				t.Fatalf("Failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		tenant, err := client.GetTenant(context.Background())

		if err != nil {
			t.Fatalf("GetTenant() error = %v", err)
		}
		if tenant.ID != expectedTenant.ID {
			t.Errorf("TenantInfo.ID = %v, want %v", tenant.ID, expectedTenant.ID)
		}
		if tenant.DisplayName != expectedTenant.DisplayName {
			t.Errorf("TenantInfo.DisplayName = %v, want %v", tenant.DisplayName, expectedTenant.DisplayName)
		}
		if tenant.State != expectedTenant.State {
			t.Errorf("TenantInfo.State = %v, want %v", tenant.State, expectedTenant.State)
		}
	})

	t.Run("returns ErrUserNotInTenant for 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		_, err := client.GetTenant(context.Background())

		var notInTenantErr *ErrUserNotInTenant
		if !errors.As(err, &notInTenantErr) {
			t.Errorf("GetTenant() error type = %T, want *ErrUserNotInTenant", err)
		}
	})

	t.Run("handles server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		_, err := client.GetTenant(context.Background())

		if err == nil {
			t.Error("GetTenant() should return error on server error")
		}
	})
}

func TestUserClient_IsTenantOwner(t *testing.T) {
	t.Run("returns true when user is owner", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Method = %v, want GET", r.Method)
			}
			if r.URL.Path != "/api/v1/me/tenant/owner" {
				t.Errorf("Path = %v, want /api/v1/me/tenant/owner", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Error("Authorization header missing or incorrect")
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]bool{"is_owner": true})
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		isOwner, err := client.IsTenantOwner(context.Background())

		if err != nil {
			t.Fatalf("IsTenantOwner() error = %v", err)
		}
		if !isOwner {
			t.Error("IsTenantOwner() = false, want true")
		}
	})

	t.Run("returns false when user is not owner", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]bool{"is_owner": false})
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		isOwner, err := client.IsTenantOwner(context.Background())

		if err != nil {
			t.Fatalf("IsTenantOwner() error = %v", err)
		}
		if isOwner {
			t.Error("IsTenantOwner() = true, want false")
		}
	})

	t.Run("returns ErrUserNotInTenant for 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		_, err := client.IsTenantOwner(context.Background())

		var notInTenantErr *ErrUserNotInTenant
		if !errors.As(err, &notInTenantErr) {
			t.Errorf("IsTenantOwner() error type = %T, want *ErrUserNotInTenant", err)
		}
	})

	t.Run("handles server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")
		_, err := client.IsTenantOwner(context.Background())

		if err == nil {
			t.Error("IsTenantOwner() should return error on server error")
		}
	})
}

func TestUserClient_ContextCancellation(t *testing.T) {
	t.Run("respects context cancellation on GetTenant", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Slow server: answer only once the client gives up
			<-r.Context().Done()
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.GetTenant(ctx)

		if err == nil {
			t.Error("GetTenant() should return error on cancelled context")
		}
	})

	t.Run("respects context cancellation on IsTenantOwner", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Slow server: answer only once the client gives up
			<-r.Context().Done()
		}))
		defer server.Close()

		client, _ := NewRESTUserClient(server.URL+"/api/v1", "test-token")

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.IsTenantOwner(ctx)

		if err == nil {
			t.Error("IsTenantOwner() should return error on cancelled context")
		}
	})
}

func TestUserClientErrors(t *testing.T) {
	t.Run("ErrUserClientValidation formats with field", func(t *testing.T) {
		err := &ErrUserClientValidation{Field: "RESTBaseURL", Reason: "required"}
		want := "user client validation failed for RESTBaseURL: required"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("ErrUserClientValidation formats without field", func(t *testing.T) {
		err := &ErrUserClientValidation{Reason: "invalid config"}
		want := "user client validation failed: invalid config"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("ErrGetUserTenantFailed formats and unwraps", func(t *testing.T) {
		cause := errors.New("network error")
		err := &ErrGetUserTenantFailed{Cause: cause}
		want := "failed to get user tenant: network error"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrUserNotInTenant formats correctly", func(t *testing.T) {
		err := &ErrUserNotInTenant{}
		want := "user is not associated with a tenant"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("ErrCheckOwnershipFailed formats and unwraps", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrCheckOwnershipFailed{Cause: cause}
		want := "failed to check tenant ownership: timeout"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})
}
