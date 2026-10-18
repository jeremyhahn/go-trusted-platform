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

package invitation

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

func TestNewClient(t *testing.T) {
	t.Run("returns error for nil config", func(t *testing.T) {
		client, err := NewClient(nil)
		if err != common.ErrNilClient {
			t.Errorf("NewClient(nil) error = %v, want %v", err, common.ErrNilClient)
		}
		if client != nil {
			t.Error("NewClient(nil) should return nil client")
		}
	})

	t.Run("creates REST client with valid config", func(t *testing.T) {
		client, err := NewClient(&ClientConfig{
			Transport:   TransportREST,
			RESTBaseURL: "https://example.com/api/v1",
			AuthToken:   "test-token",
		})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewClient() returned nil client")
		}
		if client.transport != TransportREST {
			t.Errorf("client.transport = %v, want %v", client.transport, TransportREST)
		}
	})

	t.Run("returns error for REST without base URL", func(t *testing.T) {
		client, err := NewClient(&ClientConfig{
			Transport: TransportREST,
		})
		if err == nil {
			t.Error("NewClient() should fail for REST without base URL")
		}
		if client != nil {
			t.Error("NewClient() should return nil client on error")
		}
	})

	t.Run("returns error for gRPC without transport", func(t *testing.T) {
		client, err := NewClient(&ClientConfig{
			Transport: TransportGRPC,
		})
		if err == nil {
			t.Error("NewClient() should fail for gRPC without transport")
		}
		if client != nil {
			t.Error("NewClient() should return nil client on error")
		}
	})
}

func TestNewRESTClient(t *testing.T) {
	t.Run("creates client with base URL and token", func(t *testing.T) {
		client, err := NewRESTClient("https://example.com/api/v1", "test-token")
		if err != nil {
			t.Fatalf("NewRESTClient() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewRESTClient() returned nil client")
		}
		if client.authToken != "test-token" {
			t.Errorf("client.authToken = %v, want 'test-token'", client.authToken)
		}
	})
}

func TestClient_SetAuthToken(t *testing.T) {
	t.Run("updates auth token", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "initial-token")
		client.SetAuthToken("new-token")
		if client.authToken != "new-token" {
			t.Errorf("authToken = %v, want 'new-token'", client.authToken)
		}
	})
}

func TestClient_Create(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "token")
		_, err := client.Create(context.Background(), nil)
		if err == nil {
			t.Error("Create(nil) should return error")
		}
	})

	t.Run("validates request before sending", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "token")
		_, err := client.Create(context.Background(), &CreateInvitationRequest{
			Email: "",
			Role:  "member",
		})
		if err == nil {
			t.Error("Create() should fail validation for missing email")
		}
		var validErr *ErrValidationFailed
		if !errors.As(err, &validErr) {
			t.Errorf("Create() error type = %T, want *ErrValidationFailed", err)
		}
	})

	t.Run("creates invitation via REST", func(t *testing.T) {
		now := time.Now().UTC()
		expectedInv := &Invitation{
			ID:          12345,
			Token:       "test-token-abc",
			TenantID:    "tenant-123",
			Email:       "test@example.com",
			Role:        "member",
			Status:      StatusPending,
			InvitedByID: 1,
			ExpiresAt:   now.Add(7 * 24 * time.Hour),
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != http.MethodPost {
				t.Errorf("Method = %v, want POST", r.Method)
			}
			if r.URL.Path != "/api/v1/invitations" {
				t.Errorf("Path = %v, want /api/v1/invitations", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("Authorization header missing or incorrect")
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type header = %v, want application/json", r.Header.Get("Content-Type"))
			}

			// Decode request body
			var req CreateInvitationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("Failed to decode request: %v", err)
			}
			if req.Email != "test@example.com" {
				t.Errorf("Request email = %v, want test@example.com", req.Email)
			}
			if req.Role != "member" {
				t.Errorf("Request role = %v, want member", req.Role)
			}

			// Send response
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(expectedInv); err != nil {
				t.Fatalf("Failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		inv, err := client.Create(context.Background(), &CreateInvitationRequest{
			Email: "test@example.com",
			Role:  "member",
		})

		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if inv.ID != expectedInv.ID {
			t.Errorf("Invitation.ID = %v, want %v", inv.ID, expectedInv.ID)
		}
		if inv.Email != expectedInv.Email {
			t.Errorf("Invitation.Email = %v, want %v", inv.Email, expectedInv.Email)
		}
		if inv.Status != StatusPending {
			t.Errorf("Invitation.Status = %v, want %v", inv.Status, StatusPending)
		}
	})

	t.Run("handles server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		_, err := client.Create(context.Background(), &CreateInvitationRequest{
			Email: "test@example.com",
			Role:  "member",
		})

		if err == nil {
			t.Error("Create() should return error on server error")
		}
	})
}

func TestClient_Get(t *testing.T) {
	t.Run("returns error for zero ID", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "token")
		_, err := client.Get(context.Background(), 0)
		if err == nil {
			t.Error("Get(0) should return error")
		}
	})

	t.Run("retrieves invitation by ID", func(t *testing.T) {
		expectedInv := &Invitation{
			ID:       12345,
			Token:    "test-token",
			TenantID: "tenant-123",
			Email:    "test@example.com",
			Role:     "member",
			Status:   StatusPending,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Method = %v, want GET", r.Method)
			}
			if r.URL.Path != "/api/v1/invitations/12345" {
				t.Errorf("Path = %v, want /api/v1/invitations/12345", r.URL.Path)
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedInv)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		inv, err := client.Get(context.Background(), 12345)

		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if inv.ID != expectedInv.ID {
			t.Errorf("Invitation.ID = %v, want %v", inv.ID, expectedInv.ID)
		}
	})

	t.Run("returns ErrInvitationNotFound for 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		_, err := client.Get(context.Background(), 99999)

		var notFoundErr *ErrInvitationNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("Get() error type = %T, want *ErrInvitationNotFound", err)
		}
	})
}

func TestClient_GetByToken(t *testing.T) {
	t.Run("returns error for empty token", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "auth-token")
		_, err := client.GetByToken(context.Background(), "")
		if err == nil {
			t.Error("GetByToken('') should return error")
		}
	})

	t.Run("retrieves invitation by token", func(t *testing.T) {
		expectedInv := &Invitation{
			ID:       12345,
			Token:    "secure-token-abc",
			TenantID: "tenant-123",
			Email:    "test@example.com",
			Role:     "member",
			Status:   StatusPending,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Method = %v, want GET", r.Method)
			}
			if r.URL.Path != "/api/v1/invitations/token/secure-token-abc" {
				t.Errorf("Path = %v, want /api/v1/invitations/token/secure-token-abc", r.URL.Path)
			}
			// GetByToken is public, should not require auth
			// (but we don't fail if it's there)

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedInv)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		inv, err := client.GetByToken(context.Background(), "secure-token-abc")

		if err != nil {
			t.Fatalf("GetByToken() error = %v", err)
		}
		if inv.Token != expectedInv.Token {
			t.Errorf("Invitation.Token = %v, want %v", inv.Token, expectedInv.Token)
		}
	})

	t.Run("returns ErrInvitationNotFound for 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		_, err := client.GetByToken(context.Background(), "nonexistent-token")

		var notFoundErr *ErrInvitationNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("GetByToken() error type = %T, want *ErrInvitationNotFound", err)
		}
	})
}

func TestClient_List(t *testing.T) {
	t.Run("lists invitations", func(t *testing.T) {
		expectedInvs := []*Invitation{
			{ID: 1, Email: "test1@example.com", Status: StatusPending},
			{ID: 2, Email: "test2@example.com", Status: StatusAccepted},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("Method = %v, want GET", r.Method)
			}
			if r.URL.Path != "/api/v1/invitations" {
				t.Errorf("Path = %v, want /api/v1/invitations", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Error("Authorization header missing")
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(ListInvitationsResponse{
				Invitations: expectedInvs,
				Total:       2,
			})
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		invs, err := client.List(context.Background())

		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(invs) != len(expectedInvs) {
			t.Errorf("List() returned %d invitations, want %d", len(invs), len(expectedInvs))
		}
	})

	t.Run("handles server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		_, err := client.List(context.Background())

		if err == nil {
			t.Error("List() should return error on server error")
		}
	})
}

func TestClient_Revoke(t *testing.T) {
	t.Run("returns error for zero ID", func(t *testing.T) {
		client, _ := NewRESTClient("https://example.com/api/v1", "token")
		err := client.Revoke(context.Background(), 0)
		if err == nil {
			t.Error("Revoke(0) should return error")
		}
	})

	t.Run("revokes invitation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("Method = %v, want DELETE", r.Method)
			}
			if r.URL.Path != "/api/v1/invitations/12345" {
				t.Errorf("Path = %v, want /api/v1/invitations/12345", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Error("Authorization header missing")
			}

			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		err := client.Revoke(context.Background(), 12345)

		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
	})

	t.Run("returns ErrInvitationNotFound for 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		err := client.Revoke(context.Background(), 99999)

		var notFoundErr *ErrInvitationNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("Revoke() error type = %T, want *ErrInvitationNotFound", err)
		}
	})

	t.Run("handles 204 No Content response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")
		err := client.Revoke(context.Background(), 12345)

		if err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
	})
}

func TestClient_ContextCancellation(t *testing.T) {
	t.Run("respects context cancellation on create", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Slow server: answer only once the client gives up
			<-r.Context().Done()
		}))
		defer server.Close()

		client, _ := NewRESTClient(server.URL+"/api/v1", "test-token")

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.Create(ctx, &CreateInvitationRequest{
			Email: "test@example.com",
			Role:  "member",
		})

		if err == nil {
			t.Error("Create() should return error on cancelled context")
		}
	})
}
