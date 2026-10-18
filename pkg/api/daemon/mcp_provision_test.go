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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
)

// newProvisionMCPProvider builds an MCPServiceProvider wired only with the
// given config delivery service, mirroring how createMCPServer wires it.
func newProvisionMCPProvider(svc *configdelivery.Service) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		ConfigDeliveryService: svc,
		Logger:                slog.Default(),
	})
}

// provisionValidIdentity returns a ProvisionFetchConfigRequest carrying valid
// EAB fields and a freshly issued nonce for the backing service.
func provisionValidIdentity(t *testing.T, backing *configdelivery.Service, ekSerial string) *mcp.ProvisionFetchConfigRequest {
	t.Helper()
	return &mcp.ProvisionFetchConfigRequest{
		EKSerial: ekSerial,
		EABKeyID: "key-1",
		EABHMAC:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	}
}

// =============================================================================
// requireService guard
// =============================================================================

func TestMCPProvision_NilService_AllMethods(t *testing.T) {
	p := newProvisionMCPProvider(nil)
	ctx := context.Background()

	calls := map[string]func() error{
		"ProvisionGetNonce": func() error {
			_, err := p.ProvisionGetNonce(ctx)
			return err
		},
		"ProvisionFetchConfig": func() error {
			_, err := p.ProvisionFetchConfig(ctx, &mcp.ProvisionFetchConfigRequest{})
			return err
		},
		"ProvisionSignDigest": func() error {
			_, err := p.ProvisionSignDigest(ctx, &mcp.ProvisionSignDigestRequest{})
			return err
		},
		"ProvisionPollSession": func() error {
			_, err := p.ProvisionPollSession(ctx, "sess-1")
			return err
		},
		"ProvisionFulfillSession": func() error {
			_, err := p.ProvisionFulfillSession(ctx, "sess-1", 7)
			return err
		},
		"ProvisionListSessions": func() error {
			_, err := p.ProvisionListSessions(ctx)
			return err
		},
		"ProvisionGetSession": func() error {
			_, err := p.ProvisionGetSession(ctx, "sess-1")
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			var unavailable ErrConfigDeliveryServiceNotAvailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrConfigDeliveryServiceNotAvailable", err)
			}
		})
	}
}

// =============================================================================
// ProvisionGetNonce
// =============================================================================

func TestMCPProvision_GetNonce_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	result, err := p.ProvisionGetNonce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nonceResp, ok := result.(*configdelivery.NonceResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.NonceResponse", result)
	}
	if nonceResp.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
}

// =============================================================================
// ProvisionFetchConfig
// =============================================================================

func TestMCPProvision_FetchConfig_Delivered(t *testing.T) {
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{
				ID:     3,
				Config: map[string]any{"hostname": "node1", "role": "compute"},
			}, nil
		},
	}
	backing := newCDTestService(t, resolver, nil)
	p := newProvisionMCPProvider(backing)

	result, err := p.ProvisionFetchConfig(context.Background(), provisionValidIdentity(t, backing, "ek-123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	configResp, ok := result.(*configdelivery.ConfigResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.ConfigResponse", result)
	}
	if configResp.Status != "ok" {
		t.Fatalf("status = %q, want ok", configResp.Status)
	}
	config, ok := configResp.Config.(map[string]any)
	if !ok {
		t.Fatalf("config type = %T, want map", configResp.Config)
	}
	if config["hostname"] != "node1" || config["role"] != "compute" {
		t.Fatalf("unexpected config payload: %v", config)
	}
}

func TestMCPProvision_FetchConfig_Pending(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	result, err := p.ProvisionFetchConfig(context.Background(), provisionValidIdentity(t, backing, "ek-unmatched"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pending, ok := result.(*configdelivery.PendingResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.PendingResponse", result)
	}
	if pending.SessionID == "" {
		t.Fatal("expected non-empty session_id")
	}
	if pending.PollInterval <= 0 {
		t.Fatalf("poll interval = %d, want > 0", pending.PollInterval)
	}
}

func TestMCPProvision_FetchConfig_InvalidRequest(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	// Missing eab_key_id fails field validation inside the service; the
	// typed error must pass through unchanged.
	_, err := p.ProvisionFetchConfig(context.Background(), &mcp.ProvisionFetchConfigRequest{
		EKSerial: "ek-123",
		EABHMAC:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	})
	var invalid configdelivery.ErrInvalidRequest
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want configdelivery.ErrInvalidRequest", err)
	}
}

func TestMCPProvision_FetchConfig_NilRequest(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	// A nil request must not panic; the empty request fails service-side
	// validation with a typed error.
	if _, err := p.ProvisionFetchConfig(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

// =============================================================================
// ProvisionSignDigest
// =============================================================================

func TestMCPProvision_SignDigest_Success(t *testing.T) {
	profile := cdRemoteSignProfile()
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return profile, nil
		},
	}
	signer := &cdFakeDBKeySigner{signature: []byte("sig-bytes"), certPEM: []byte("db-cert-pem")}
	backing := newCDTestService(t, resolver, signer)
	p := newProvisionMCPProvider(backing)

	result, err := p.ProvisionSignDigest(context.Background(), &mcp.ProvisionSignDigestRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
		Digest:   []byte("uki-digest"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	signResp, ok := result.(*configdelivery.SignResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.SignResponse", result)
	}
	if string(signResp.Signature) != "sig-bytes" {
		t.Fatalf("signature = %q, want sig-bytes", signResp.Signature)
	}
	if string(signResp.CertPEM) != "db-cert-pem" {
		t.Fatalf("cert_pem = %q, want db-cert-pem", signResp.CertPEM)
	}
}

func TestMCPProvision_SignDigest_SignerUnavailable(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	_, err := p.ProvisionSignDigest(context.Background(), &mcp.ProvisionSignDigestRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
		Digest:   []byte("digest"),
	})
	var unavailable configdelivery.ErrSignerUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want configdelivery.ErrSignerUnavailable", err)
	}
}

func TestMCPProvision_SignDigest_NilRequest(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	if _, err := p.ProvisionSignDigest(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

// =============================================================================
// ProvisionPollSession
// =============================================================================

func TestMCPProvision_PollSession_Pending(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	result, err := p.ProvisionPollSession(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pending, ok := result.(*configdelivery.PollPendingResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.PollPendingResponse", result)
	}
	if pending.Status != pollSessionPendingStatus {
		t.Fatalf("status = %q, want %q", pending.Status, pollSessionPendingStatus)
	}
}

func TestMCPProvision_PollSession_Delivered(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	ctx := context.Background()
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	if err := backing.FulfillSession(ctx, session.ID, 7); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	result, err := p.ProvisionPollSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	configResp, ok := result.(*configdelivery.ConfigResponse)
	if !ok {
		t.Fatalf("result type = %T, want *configdelivery.ConfigResponse", result)
	}
	if configResp.Status != "ok" {
		t.Fatalf("status = %q, want ok", configResp.Status)
	}
}

func TestMCPProvision_PollSession_NotFound(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	_, err := p.ProvisionPollSession(context.Background(), "missing-session")
	var notFound configdelivery.ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want configdelivery.ErrSessionNotFound", err)
	}
}

// =============================================================================
// ProvisionFulfillSession
// =============================================================================

func TestMCPProvision_FulfillSession_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	result, err := p.ProvisionFulfillSession(context.Background(), session.ID, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ack, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("result type = %T, want map[string]string", result)
	}
	if ack["status"] != fulfillSessionStatus {
		t.Fatalf("status = %q, want %q", ack["status"], fulfillSessionStatus)
	}
}

func TestMCPProvision_FulfillSession_NotFound(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	_, err := p.ProvisionFulfillSession(context.Background(), "missing-session", 7)
	var notFound configdelivery.ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want configdelivery.ErrSessionNotFound", err)
	}
}

func TestMCPProvision_FulfillSession_ZeroProfileID(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	_, err := p.ProvisionFulfillSession(context.Background(), session.ID, 0)

	var required configdelivery.ErrProfileIDRequired
	if !errors.As(err, &required) {
		t.Fatalf("err = %v, want configdelivery.ErrProfileIDRequired", err)
	}
	var classified ErrConfigDeliveryClassified
	if !errors.As(err, &classified) || classified.Code != codes.InvalidArgument {
		t.Fatalf("err = %v, want ErrConfigDeliveryClassified with InvalidArgument", err)
	}
}

// =============================================================================
// ProvisionListSessions / ProvisionGetSession
// =============================================================================

func TestMCPProvision_ListSessions_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	backing.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")

	result, err := p.ProvisionListSessions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	sessions, ok := resultMap["sessions"].([]*configdelivery.Session)
	if !ok {
		t.Fatalf("sessions type = %T, want []*configdelivery.Session", resultMap["sessions"])
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions) = %d, want 2", len(sessions))
	}
}

func TestMCPProvision_ListSessions_Empty(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	result, err := p.ProvisionListSessions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	sessions, ok := resultMap["sessions"].([]*configdelivery.Session)
	if !ok {
		t.Fatalf("sessions type = %T, want []*configdelivery.Session", resultMap["sessions"])
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) = %d, want 0", len(sessions))
	}
}

func TestMCPProvision_GetSession_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)
	created := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	result, err := p.ProvisionGetSession(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	session, ok := resultMap["session"].(*configdelivery.Session)
	if !ok {
		t.Fatalf("session type = %T, want *configdelivery.Session", resultMap["session"])
	}
	if session.ID != created.ID {
		t.Fatalf("session.ID = %q, want %q", session.ID, created.ID)
	}
	if session.EKSerial != "ek-1" {
		t.Fatalf("session.EKSerial = %q, want ek-1", session.EKSerial)
	}
}

func TestMCPProvision_GetSession_NotFound(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	p := newProvisionMCPProvider(backing)

	_, err := p.ProvisionGetSession(context.Background(), "missing-session")
	var notFound configdelivery.ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want configdelivery.ErrSessionNotFound", err)
	}
}
