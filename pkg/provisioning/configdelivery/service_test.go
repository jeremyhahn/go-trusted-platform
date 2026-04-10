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

package configdelivery

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// mockProfileResolver implements ProfileResolver for testing.
type mockProfileResolver struct {
	findConfigFunc func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)
	getFunc        func(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
}

func (m *mockProfileResolver) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	if m.findConfigFunc != nil {
		return m.findConfigFunc(ctx, ekSerial, mac)
	}
	return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
}

func (m *mockProfileResolver) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, id)
	}
	return &entities.DeviceProfile{ID: id, Config: "test-config"}, nil
}

// mockEABService implements eab.Service for testing.
type mockEABService struct {
	validateFunc func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error)
}

func (m *mockEABService) Generate(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) Get(ctx context.Context, id uint64) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) Revoke(ctx context.Context, id uint64) error {
	return nil
}

func (m *mockEABService) MarkUsed(ctx context.Context, id uint64) error {
	return nil
}

func (m *mockEABService) Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, keyID, hmacKey)
	}
	return &eab.Credential{ID: 1, KeyID: keyID, Status: eab.StatusActive}, nil
}

func (m *mockEABService) ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) CleanupExpired(ctx context.Context) (int, error) {
	return 0, nil
}

func (m *mockEABService) Delete(ctx context.Context, id uint64) error {
	return nil
}

func (m *mockEABService) Count(ctx context.Context) (int, error) {
	return 0, nil
}

func (m *mockEABService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*eab.Credential], error) {
	return datastore.PageResult[*eab.Credential]{}, nil
}

// testService creates a Service with mock dependencies for testing.
func testService(t *testing.T, profileSvc ProfileResolver, eabSvc eab.Service) *Service {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: profileSvc,
		EABService:     eabSvc,
		BaseURL:        "https://platform.example.com",
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	return svc
}

func issueValidNonce(t *testing.T, svc *Service) string {
	t.Helper()
	nonce, err := svc.IssueNonce()
	if err != nil {
		t.Fatalf("unexpected error issuing nonce: %v", err)
	}
	return nonce
}

func validEABHMAC() string {
	return base64.RawURLEncoding.EncodeToString([]byte("test-hmac-key-32-bytes-long-xxxx"))
}

func TestService_IssueNonce(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})

	nonce, err := svc.IssueNonce()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
}

func TestService_CreateSession(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})

	session := svc.CreateSession("ek-123", "aa:bb:cc:dd:ee:ff")

	if session.ID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if session.EKSerial != "ek-123" {
		t.Fatalf("expected ek_serial=ek-123, got %s", session.EKSerial)
	}
	if session.MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected mac_address=aa:bb:cc:dd:ee:ff, got %s", session.MACAddress)
	}
	if session.Fulfilled {
		t.Fatal("expected session to not be fulfilled")
	}
	if session.CreatedAt.IsZero() {
		t.Fatal("expected non-zero created_at")
	}
	if session.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero expires_at")
	}
	if !session.ExpiresAt.After(session.CreatedAt) {
		t.Fatal("expected expires_at to be after created_at")
	}
}

func TestService_ListSessions(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})

	svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	svc.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")

	sessions := svc.ListSessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestService_ListSessions_ExcludesExpired(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		BaseURL:        "https://platform.example.com",
		SessionTTL:     1 * time.Nanosecond,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	// Sessions with 1ns TTL should be expired by now.
	sessions := svc.ListSessions()
	if len(sessions) != 0 {
		t.Fatalf("expected 0 active sessions, got %d", len(sessions))
	}
}

func TestService_GetSession_NotFound(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})

	_, err := svc.GetSession("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}

	var notFound ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrSessionNotFound, got %T: %v", err, err)
	}
}

func TestService_FulfillSession(t *testing.T) {
	profileSvc := &mockProfileResolver{
		getFunc: func(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: id, Config: "test-config"}, nil
		},
	}
	svc := testService(t, profileSvc, &mockEABService{})

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	ctx := context.Background()
	err := svc.FulfillSession(ctx, session.ID, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := svc.GetSession(session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated.Fulfilled {
		t.Fatal("expected session to be fulfilled")
	}
	if updated.ProfileID != 42 {
		t.Fatalf("expected profile_id=42, got %d", updated.ProfileID)
	}
	if updated.Profile == nil {
		t.Fatal("expected non-nil profile")
	}
}

func TestService_FulfillSession_NotFound(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	ctx := context.Background()

	err := svc.FulfillSession(ctx, "nonexistent-id", 1)
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}

	var notFound ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrSessionNotFound, got %T: %v", err, err)
	}
}

func TestService_FulfillSession_Expired(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		BaseURL:        "https://platform.example.com",
		SessionTTL:     1 * time.Nanosecond,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	ctx := context.Background()
	err = svc.FulfillSession(ctx, session.ID, 1)
	if err == nil {
		t.Fatal("expected error for expired session")
	}

	var expired ErrSessionExpired
	if !errors.As(err, &expired) {
		t.Fatalf("expected ErrSessionExpired, got %T: %v", err, err)
	}
}

func TestService_FulfillSession_AlreadyFulfilled(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	// Manually fulfill the session.
	svc.sessionsMu.Lock()
	session.Fulfilled = true
	session.Profile = &entities.DeviceProfile{ID: 1, Config: "test-config"}
	svc.sessionsMu.Unlock()

	ctx := context.Background()
	err := svc.FulfillSession(ctx, session.ID, 2)
	if err == nil {
		t.Fatal("expected error for already fulfilled session")
	}

	var alreadyFulfilled ErrSessionAlreadyFulfilled
	if !errors.As(err, &alreadyFulfilled) {
		t.Fatalf("expected ErrSessionAlreadyFulfilled, got %T: %v", err, err)
	}
}

func TestService_PollSession_Pending(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	ctx := context.Background()
	resp, err := svc.PollSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for pending session")
	}
}

func TestService_PollSession_Fulfilled(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	expectedConfig := map[string]string{"key": "value"}

	svc.sessionsMu.Lock()
	session.Fulfilled = true
	session.Profile = &entities.DeviceProfile{ID: 1, Config: expectedConfig}
	svc.sessionsMu.Unlock()

	ctx := context.Background()
	resp, err := svc.PollSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response for fulfilled session")
	}
	if resp.Status != "ok" {
		t.Fatalf("expected status=ok, got %s", resp.Status)
	}
}

func TestService_PollSession_Expired(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		BaseURL:        "https://platform.example.com",
		SessionTTL:     1 * time.Nanosecond,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	ctx := context.Background()
	_, err = svc.PollSession(ctx, session.ID)
	if err == nil {
		t.Fatal("expected error for expired session")
	}

	var expired ErrSessionExpired
	if !errors.As(err, &expired) {
		t.Fatalf("expected ErrSessionExpired, got %T: %v", err, err)
	}
}

func TestService_PollSession_NotFound(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})

	ctx := context.Background()
	_, err := svc.PollSession(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}

	var notFound ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrSessionNotFound, got %T: %v", err, err)
	}
}

func TestService_ResolveConfig_Found(t *testing.T) {
	expectedConfig := map[string]string{"platform": "config"}
	profileSvc := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 1, Config: expectedConfig}, nil
		},
	}
	svc := testService(t, profileSvc, &mockEABService{})

	nonce := issueValidNonce(t, svc)
	ctx := context.Background()

	req := &ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	}

	configResp, pendingResp, err := svc.ResolveConfig(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pendingResp != nil {
		t.Fatal("expected nil pending response")
	}
	if configResp == nil {
		t.Fatal("expected non-nil config response")
	}
	if configResp.Status != "ok" {
		t.Fatalf("expected status=ok, got %s", configResp.Status)
	}
}

func TestService_ResolveConfig_NotFound(t *testing.T) {
	profileSvc := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
		},
	}
	svc := testService(t, profileSvc, &mockEABService{})

	nonce := issueValidNonce(t, svc)
	ctx := context.Background()

	req := &ConfigRequest{
		EKSerial: "ek-unknown",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	}

	configResp, pendingResp, err := svc.ResolveConfig(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configResp != nil {
		t.Fatal("expected nil config response")
	}
	if pendingResp == nil {
		t.Fatal("expected non-nil pending response")
	}
	if pendingResp.SessionID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if pendingResp.PollInterval != defaultPollInterval {
		t.Fatalf("expected poll_interval=%d, got %d", defaultPollInterval, pendingResp.PollInterval)
	}
}

func TestService_ResolveConfig_MissingFields(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	ctx := context.Background()

	tests := []struct {
		name string
		req  *ConfigRequest
	}{
		{
			name: "missing eab_key_id",
			req: &ConfigRequest{
				EKSerial: "ek-123",
				EABHMAC:  validEABHMAC(),
				Nonce:    "some-nonce",
			},
		},
		{
			name: "missing eab_hmac",
			req: &ConfigRequest{
				EKSerial: "ek-123",
				EABKeyID: "key-1",
				Nonce:    "some-nonce",
			},
		},
		{
			name: "missing nonce",
			req: &ConfigRequest{
				EKSerial: "ek-123",
				EABKeyID: "key-1",
				EABHMAC:  validEABHMAC(),
			},
		},
		{
			name: "missing device identity",
			req: &ConfigRequest{
				EABKeyID: "key-1",
				EABHMAC:  validEABHMAC(),
				Nonce:    "some-nonce",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.ResolveConfig(ctx, tc.req)
			if err == nil {
				t.Fatal("expected error for missing fields")
			}
		})
	}
}

func TestService_ResolveConfig_InvalidNonce(t *testing.T) {
	svc := testService(t, &mockProfileResolver{}, &mockEABService{})
	ctx := context.Background()

	req := &ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    "invalid-nonce",
	}

	_, _, err := svc.ResolveConfig(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid nonce")
	}

	var nonceExpired ErrNonceExpired
	if !errors.As(err, &nonceExpired) {
		t.Fatalf("expected ErrNonceExpired, got %T: %v", err, err)
	}
}

func TestService_ResolveConfig_InvalidEAB(t *testing.T) {
	eabSvc := &mockEABService{
		validateFunc: func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
			return nil, eab.ErrInvalidCredential{Reason: "hmac mismatch"}
		},
	}
	svc := testService(t, &mockProfileResolver{}, eabSvc)
	ctx := context.Background()

	nonce := issueValidNonce(t, svc)

	req := &ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	}

	_, _, err := svc.ResolveConfig(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid EAB")
	}

	var eabFailed ErrEABValidationFailed
	if !errors.As(err, &eabFailed) {
		t.Fatalf("expected ErrEABValidationFailed, got %T: %v", err, err)
	}
}

func TestNewService_MissingLogger(t *testing.T) {
	_, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
	})
	if err == nil {
		t.Fatal("expected error for missing logger")
	}

	var missing ErrMissingLogger
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrMissingLogger, got %T: %v", err, err)
	}
}

func TestNewService_OptionalProfileService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		EABService: &mockEABService{},
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Service should work without ProfileService — nonce and session endpoints
	// still function for the interactive QR provisioning flow.
	nonce, err := svc.IssueNonce()
	if err != nil {
		t.Fatalf("IssueNonce should work without ProfileService: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
}

func TestNewService_OptionalEABService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Service should work without EABService — sessions still function.
	session := svc.CreateSession("ek-123", "aa:bb:cc:dd:ee:ff")
	if session == nil {
		t.Fatal("expected session to be created")
	}
	if session.ID == "" {
		t.Fatal("expected session ID")
	}
}
