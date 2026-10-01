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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkprovision "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// cdMockProfileResolver implements configdelivery.ProfileResolver for tests.
type cdMockProfileResolver struct {
	findConfigFunc func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)
	getFunc        func(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
}

func (m *cdMockProfileResolver) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	if m.findConfigFunc != nil {
		return m.findConfigFunc(ctx, ekSerial, mac)
	}
	return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
}

func (m *cdMockProfileResolver) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, id)
	}
	return &entities.DeviceProfile{ID: id, Config: map[string]any{"hostname": "fulfilled-node"}}, nil
}

// cdFakeDBKeySigner implements configdelivery.DBKeySigner for tests.
type cdFakeDBKeySigner struct {
	signature []byte
	certPEM   []byte
	signErr   error
	certErr   error
}

func (f *cdFakeDBKeySigner) SignDigest(_ context.Context, keyURI string, digest []byte) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signature, nil
}

func (f *cdFakeDBKeySigner) Certificate(_ context.Context, certRef string) ([]byte, error) {
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.certPEM, nil
}

// newCDTestService builds a configdelivery.Service for gRPC service tests.
// The EAB service is nil, so EAB HMAC validation is skipped while field
// presence and nonce validation remain enforced. EK matching is disabled so
// EK-serial/MAC resolution drives the happy paths.
func newCDTestService(t *testing.T, resolver configdelivery.ProfileResolver, signer configdelivery.DBKeySigner) *configdelivery.Service {
	t.Helper()
	requireEK := false
	svc, err := configdelivery.NewService(configdelivery.ServiceParams{
		ProfileService: resolver,
		BaseURL:        "https://cp.example.com",
		RequireEKMatch: &requireEK,
		DBKeySigner:    signer,
		Logger:         logging.NewLogger(slog.LevelError, nil),
	})
	if err != nil {
		t.Fatalf("unexpected error creating config delivery service: %v", err)
	}
	return svc
}

func newCDGRPCService(t *testing.T, svc *configdelivery.Service) *ConfigDeliveryGRPCService {
	t.Helper()
	return NewConfigDeliveryGRPCService(svc, slog.Default())
}

func cdIssueNonce(t *testing.T, svc *configdelivery.Service) string {
	t.Helper()
	nonce, err := svc.IssueNonce()
	if err != nil {
		t.Fatalf("unexpected error issuing nonce: %v", err)
	}
	return nonce
}

func cdValidEABHMAC() string {
	return base64.RawURLEncoding.EncodeToString([]byte("test-hmac-key-32-bytes-long-xxxx"))
}

// cdRemoteSignProfile returns a device profile whose platform config enables
// remote Secure Boot DB signing.
func cdRemoteSignProfile() *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID: 7,
		Config: map[string]any{
			"secure-boot": map[string]any{
				"enabled":     true,
				"resign-mode": "remote",
				"db": map[string]any{
					"cn":      "Trusted Platform Secure Boot DB",
					"key-uri": "kms://platform/secureboot/db",
				},
			},
		},
	}
}

func assertGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC error with code %v, got nil", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != want {
		t.Fatalf("expected code %v, got %v (message: %s)", want, st.Code(), st.Message())
	}
}

func TestNewConfigDeliveryGRPCService_NilLogger(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.logger == nil {
		t.Fatal("expected default logger to be set")
	}
	if svc.conv == nil {
		t.Fatal("expected profile converter to be set")
	}
}

func TestConfigDeliveryGRPC_RequireServiceGuard(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, slog.Default())
	ctx := context.Background()

	calls := map[string]func() error{
		"GetNonce": func() error {
			_, err := svc.GetNonce(ctx, &platformv1.GetNonceRequest{})
			return err
		},
		"FetchConfig": func() error {
			_, err := svc.FetchConfig(ctx, &platformv1.FetchConfigRequest{})
			return err
		},
		"SignDigest": func() error {
			_, err := svc.SignDigest(ctx, &platformv1.SignDigestRequest{})
			return err
		},
		"PollSession": func() error {
			_, err := svc.PollSession(ctx, &platformv1.PollSessionRequest{SessionId: "x"})
			return err
		},
		"FulfillSession": func() error {
			_, err := svc.FulfillSession(ctx, &platformv1.FulfillSessionRequest{SessionId: "x"})
			return err
		},
		"ListSessions": func() error {
			_, err := svc.ListSessions(ctx, &platformv1.ListSessionsRequest{})
			return err
		},
		"GetSession": func() error {
			_, err := svc.GetSession(ctx, &platformv1.GetSessionRequest{SessionId: "x"})
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			assertGRPCCode(t, err, codes.Unavailable)
			if !strings.Contains(err.Error(), ErrConfigDeliveryServiceNotAvailable{}.Error()) {
				t.Fatalf("expected typed unavailable message, got: %v", err)
			}
		})
	}
}

func TestConfigDeliveryGRPC_GetNonce(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	resp, err := svc.GetNonce(context.Background(), &platformv1.GetNonceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetNonce() == "" {
		t.Fatal("expected non-empty nonce")
	}
}

func TestConfigDeliveryGRPC_FetchConfig_Delivered(t *testing.T) {
	wantConfig := map[string]any{"hostname": "node1", "role": "compute"}
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 42, Config: wantConfig}, nil
		},
	}
	backing := newCDTestService(t, resolver, nil)
	svc := newCDGRPCService(t, backing)

	resp, err := svc.FetchConfig(context.Background(), &platformv1.FetchConfigRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered result, got: %v", resp)
	}
	if delivered.GetStatus() != "ok" {
		t.Fatalf("expected status ok, got %q", delivered.GetStatus())
	}
	var got map[string]any
	if unmarshalErr := json.Unmarshal(delivered.GetConfigJson(), &got); unmarshalErr != nil {
		t.Fatalf("config_json did not decode: %v", unmarshalErr)
	}
	if got["hostname"] != "node1" || got["role"] != "compute" {
		t.Fatalf("unexpected config payload: %v", got)
	}
}

func TestConfigDeliveryGRPC_FetchConfig_Pending(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)

	resp, err := svc.FetchConfig(context.Background(), &platformv1.FetchConfigRequest{
		EkSerial: "ek-unmatched",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pending := resp.GetPending()
	if pending == nil {
		t.Fatalf("expected pending result, got: %v", resp)
	}
	if pending.GetSessionId() == "" {
		t.Fatal("expected non-empty session_id")
	}
	if !strings.Contains(pending.GetProvisionUrl(), pending.GetSessionId()) {
		t.Fatalf("expected provision_url to reference the session, got %q", pending.GetProvisionUrl())
	}
	if pending.GetPollIntervalSeconds() <= 0 {
		t.Fatalf("expected positive poll interval, got %d", pending.GetPollIntervalSeconds())
	}
}

func TestConfigDeliveryGRPC_FetchConfig_InvalidArgument(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)

	// Missing eab_key_id fails field validation.
	_, err := svc.FetchConfig(context.Background(), &platformv1.FetchConfigRequest{
		EkSerial: "ek-123",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_FetchConfig_NonceExpired(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)

	_, err := svc.FetchConfig(context.Background(), &platformv1.FetchConfigRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    "never-issued",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_SignDigest_Success(t *testing.T) {
	profile := cdRemoteSignProfile()
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return profile, nil
		},
	}
	signer := &cdFakeDBKeySigner{signature: []byte("sig-bytes"), certPEM: []byte("db-cert-pem")}
	backing := newCDTestService(t, resolver, signer)
	svc := newCDGRPCService(t, backing)

	resp, err := svc.SignDigest(context.Background(), &platformv1.SignDigestRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
		Digest:   []byte("uki-digest"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.GetSignature()) != "sig-bytes" {
		t.Fatalf("unexpected signature: %q", resp.GetSignature())
	}
	if string(resp.GetCertPem()) != "db-cert-pem" {
		t.Fatalf("unexpected cert_pem: %q", resp.GetCertPem())
	}
}

func TestConfigDeliveryGRPC_SignDigest_SignerUnavailable(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)

	_, err := svc.SignDigest(context.Background(), &platformv1.SignDigestRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
		Digest:   []byte("digest"),
	})
	assertGRPCCode(t, err, codes.Unavailable)
}

func TestConfigDeliveryGRPC_SignDigest_MissingDigest(t *testing.T) {
	signer := &cdFakeDBKeySigner{signature: []byte("sig")}
	backing := newCDTestService(t, &cdMockProfileResolver{}, signer)
	svc := newCDGRPCService(t, backing)

	_, err := svc.SignDigest(context.Background(), &platformv1.SignDigestRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_SignDigest_NotConfigured(t *testing.T) {
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 9, Config: map[string]any{"hostname": "no-sb"}}, nil
		},
	}
	signer := &cdFakeDBKeySigner{signature: []byte("sig")}
	backing := newCDTestService(t, resolver, signer)
	svc := newCDGRPCService(t, backing)

	_, err := svc.SignDigest(context.Background(), &platformv1.SignDigestRequest{
		EkSerial: "ek-123",
		EabKeyId: "key-1",
		EabHmac:  cdValidEABHMAC(),
		Nonce:    cdIssueNonce(t, backing),
		Digest:   []byte("digest"),
	})
	assertGRPCCode(t, err, codes.FailedPrecondition)
}

func TestConfigDeliveryGRPC_PollSession_Pending(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp, err := svc.PollSession(context.Background(), &platformv1.PollSessionRequest{SessionId: session.ID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetPendingStatus() != pollSessionPendingStatus {
		t.Fatalf("expected pending status %q, got %v", pollSessionPendingStatus, resp)
	}
}

func TestConfigDeliveryGRPC_PollSession_Delivered(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
	if err := backing.FulfillSession(context.Background(), session.ID, 42); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	resp, err := svc.PollSession(context.Background(), &platformv1.PollSessionRequest{SessionId: session.ID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered result, got: %v", resp)
	}
	var got map[string]any
	if unmarshalErr := json.Unmarshal(delivered.GetConfigJson(), &got); unmarshalErr != nil {
		t.Fatalf("config_json did not decode: %v", unmarshalErr)
	}
	if got["hostname"] != "fulfilled-node" {
		t.Fatalf("unexpected config payload: %v", got)
	}
}

// TestConfigDeliveryGRPC_PollSession_ProfileMissing verifies that polling a
// session fulfilled without a resolvable profile (no profile service wired)
// maps the typed invalid-state error to codes.Internal instead of panicking.
func TestConfigDeliveryGRPC_PollSession_ProfileMissing(t *testing.T) {
	backing := newCDTestService(t, nil, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
	if err := backing.FulfillSession(context.Background(), session.ID, 42); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	_, err := svc.PollSession(context.Background(), &platformv1.PollSessionRequest{SessionId: session.ID})
	assertGRPCCode(t, err, codes.Internal)
	st, _ := status.FromError(err)
	want := configdelivery.ErrSessionProfileMissing{SessionID: session.ID}.Error()
	if st.Message() != want {
		t.Fatalf("expected message %q, got %q", want, st.Message())
	}
}

func TestConfigDeliveryGRPC_PollSession_NotFound(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.PollSession(context.Background(), &platformv1.PollSessionRequest{SessionId: "missing"})
	assertGRPCCode(t, err, codes.NotFound)
}

func TestConfigDeliveryGRPC_PollSession_MissingSessionID(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.PollSession(context.Background(), &platformv1.PollSessionRequest{})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_FulfillSession_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp, err := svc.FulfillSession(context.Background(), &platformv1.FulfillSessionRequest{
		SessionId: session.ID,
		ProfileId: 42,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetStatus() != fulfillSessionStatus {
		t.Fatalf("expected status %q, got %q", fulfillSessionStatus, resp.GetStatus())
	}
}

func TestConfigDeliveryGRPC_FulfillSession_NotFound(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.FulfillSession(context.Background(), &platformv1.FulfillSessionRequest{
		SessionId: "missing",
		ProfileId: 42,
	})
	assertGRPCCode(t, err, codes.NotFound)
}

func TestConfigDeliveryGRPC_FulfillSession_AlreadyFulfilled(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
	if err := backing.FulfillSession(context.Background(), session.ID, 42); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	_, err := svc.FulfillSession(context.Background(), &platformv1.FulfillSessionRequest{
		SessionId: session.ID,
		ProfileId: 43,
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_FulfillSession_MissingSessionID(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.FulfillSession(context.Background(), &platformv1.FulfillSessionRequest{ProfileId: 42})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestConfigDeliveryGRPC_ListSessions(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	first := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	second := backing.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")

	resp, err := svc.ListSessions(context.Background(), &platformv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetSessions()) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(resp.GetSessions()))
	}
	ids := map[string]bool{}
	for _, session := range resp.GetSessions() {
		ids[session.GetId()] = true
	}
	if !ids[first.ID] || !ids[second.ID] {
		t.Fatalf("expected sessions %s and %s, got %v", first.ID, second.ID, ids)
	}
}

func TestConfigDeliveryGRPC_GetSession_Success(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	svc := newCDGRPCService(t, backing)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp, err := svc.GetSession(context.Background(), &platformv1.GetSessionRequest{SessionId: session.ID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := resp.GetSession()
	if got.GetId() != session.ID {
		t.Fatalf("expected session id %s, got %s", session.ID, got.GetId())
	}
	if got.GetEkSerial() != "ek-1" || got.GetMacAddress() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected session identity: %v", got)
	}
	if got.GetCreatedAt() == nil || got.GetExpiresAt() == nil {
		t.Fatal("expected created_at and expires_at timestamps")
	}
}

func TestConfigDeliveryGRPC_GetSession_NotFound(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.GetSession(context.Background(), &platformv1.GetSessionRequest{SessionId: "missing"})
	assertGRPCCode(t, err, codes.NotFound)
}

func TestConfigDeliveryGRPC_GetSession_MissingSessionID(t *testing.T) {
	svc := newCDGRPCService(t, newCDTestService(t, &cdMockProfileResolver{}, nil))

	_, err := svc.GetSession(context.Background(), &platformv1.GetSessionRequest{})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestPbToConfigDeliveryRequest(t *testing.T) {
	pb := &platformv1.FetchConfigRequest{
		EkSerial:   "ek-1",
		MacAddress: "aa:bb:cc:dd:ee:ff",
		EkCert:     "cert-b64",
		EabKeyId:   "key-1",
		EabHmac:    "hmac-1",
		Nonce:      "nonce-1",
	}
	got := pbToConfigDeliveryRequest(pb)
	if got.EKSerial != "ek-1" || got.MACAddress != "aa:bb:cc:dd:ee:ff" ||
		got.EKCert != "cert-b64" || got.EABKeyID != "key-1" ||
		got.EABHMAC != "hmac-1" || got.Nonce != "nonce-1" {
		t.Fatalf("unexpected conversion result: %+v", got)
	}
}

func TestPbToConfigDeliveryRequest_Nil(t *testing.T) {
	got := pbToConfigDeliveryRequest(nil)
	if got == nil {
		t.Fatal("expected zero-value request, got nil")
	}
	if got.EKSerial != "" || got.Nonce != "" {
		t.Fatalf("expected zero-value request, got %+v", got)
	}
}

func TestPbToSignRequest(t *testing.T) {
	pb := &platformv1.SignDigestRequest{
		EkSerial:   "ek-1",
		MacAddress: "aa:bb:cc:dd:ee:ff",
		EkCert:     "cert-b64",
		EabKeyId:   "key-1",
		EabHmac:    "hmac-1",
		Nonce:      "nonce-1",
		Digest:     []byte("digest"),
		KeyRef:     "db",
	}
	got := pbToSignRequest(pb)
	if got.EKSerial != "ek-1" || got.MACAddress != "aa:bb:cc:dd:ee:ff" ||
		got.EKCert != "cert-b64" || got.EABKeyID != "key-1" ||
		got.EABHMAC != "hmac-1" || got.Nonce != "nonce-1" ||
		string(got.Digest) != "digest" || got.KeyRef != "db" {
		t.Fatalf("unexpected conversion result: %+v", got)
	}
}

func TestPbToSignRequest_Nil(t *testing.T) {
	got := pbToSignRequest(nil)
	if got == nil {
		t.Fatal("expected zero-value request, got nil")
	}
	if got.EKSerial != "" || len(got.Digest) != 0 {
		t.Fatalf("expected zero-value request, got %+v", got)
	}
}

func TestPendingResponseToPb(t *testing.T) {
	got := pendingResponseToPb(&configdelivery.PendingResponse{
		SessionID:    "session-1",
		ProvisionURL: "https://cp.example.com/api/v1/provisioning/sessions/session-1",
		PollInterval: 5,
	})
	if got.GetSessionId() != "session-1" {
		t.Fatalf("unexpected session_id: %q", got.GetSessionId())
	}
	if got.GetProvisionUrl() != "https://cp.example.com/api/v1/provisioning/sessions/session-1" {
		t.Fatalf("unexpected provision_url: %q", got.GetProvisionUrl())
	}
	if got.GetPollIntervalSeconds() != 5 {
		t.Fatalf("unexpected poll interval: %d", got.GetPollIntervalSeconds())
	}
}

func TestPendingResponseToPb_Nil(t *testing.T) {
	if got := pendingResponseToPb(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestConfigResponseToDelivered(t *testing.T) {
	got, err := configResponseToDelivered(&configdelivery.ConfigResponse{
		Config: map[string]any{"hostname": "node1"},
		Status: "ok",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetStatus() != "ok" {
		t.Fatalf("unexpected status: %q", got.GetStatus())
	}
	var decoded map[string]any
	if unmarshalErr := json.Unmarshal(got.GetConfigJson(), &decoded); unmarshalErr != nil {
		t.Fatalf("config_json did not decode: %v", unmarshalErr)
	}
	if decoded["hostname"] != "node1" {
		t.Fatalf("unexpected config payload: %v", decoded)
	}
}

func TestConfigResponseToDelivered_NilResponse(t *testing.T) {
	got, err := configResponseToDelivered(nil)
	if err == nil {
		t.Fatal("expected error for nil response")
	}
	var typed ErrConfigSerializationFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrConfigSerializationFailed, got %T: %v", err, err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %v", got)
	}
}

func TestConfigResponseToDelivered_Unserializable(t *testing.T) {
	_, err := configResponseToDelivered(&configdelivery.ConfigResponse{
		Config: make(chan int),
		Status: "ok",
	})
	if err == nil {
		t.Fatal("expected error for unserializable config")
	}
	var typed ErrConfigSerializationFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrConfigSerializationFailed, got %T: %v", err, err)
	}
}

func TestSessionToPb(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, slog.Default())
	now := time.Now().UTC()
	got := svc.sessionToPb(&configdelivery.Session{
		ID:         "session-1",
		EKSerial:   "ek-1",
		MACAddress: "aa:bb:cc:dd:ee:ff",
		TenantID:   "tenant-1",
		ProfileID:  42,
		Profile:    &entities.DeviceProfile{ID: 42, Name: "profile-42", TenantID: "tenant-1"},
		Fulfilled:  true,
		CreatedAt:  now,
		ExpiresAt:  now.Add(30 * time.Minute),
	})

	if got.GetId() != "session-1" || got.GetEkSerial() != "ek-1" ||
		got.GetMacAddress() != "aa:bb:cc:dd:ee:ff" || got.GetTenantId() != "tenant-1" ||
		got.GetProfileId() != 42 || !got.GetFulfilled() {
		t.Fatalf("unexpected session conversion: %v", got)
	}
	if got.GetProfile().GetId() != 42 || got.GetProfile().GetName() != "profile-42" {
		t.Fatalf("unexpected profile conversion: %v", got.GetProfile())
	}
	if !got.GetCreatedAt().AsTime().Equal(now) {
		t.Fatalf("unexpected created_at: %v", got.GetCreatedAt().AsTime())
	}
	if !got.GetExpiresAt().AsTime().Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("unexpected expires_at: %v", got.GetExpiresAt().AsTime())
	}
}

// TestSessionCrossTransportParity verifies that the gRPC/QUIC path
// (sessionToPb over the pb wire) and the REST/MCP path (domain session JSON
// decoded by the SDK wire decoder) produce identical pb ProvisioningSession
// messages, including the embedded device profile's config, identity, and
// assignment fields.
func TestSessionCrossTransportParity(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, slog.Default())
	assignedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	createdAt := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	session := &configdelivery.Session{
		ID:         "parity-session",
		EKSerial:   "EK-PARITY",
		MACAddress: "aa:bb:cc:dd:ee:99",
		TenantID:   "tenant-p",
		ProfileID:  42,
		Fulfilled:  true,
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(30 * time.Minute),
		Profile: &entities.DeviceProfile{
			ID:         42,
			TenantID:   "tenant-p",
			Name:       "parity-profile",
			Model:      "X10SDV",
			Role:       entities.DeviceRoleServer,
			Zone:       "control-plane",
			EKSerial:   "EK-PARITY",
			EKCert:     newEKCertPEMForTest(t),
			MACAddress: "aa:bb:cc:dd:ee:99",
			Assigned:   true,
			AssignedAt: assignedAt,
			Config: map[string]any{
				"hostname": "lab-node-2",
				"secure-boot": map[string]any{
					"enabled": true,
				},
			},
			Networks: map[string]*entities.NetworkPhaseConfig{
				"provisioning": {VLAN: 100, AuthMethod: entities.AuthMethodNone, DHCP: true},
			},
		},
	}

	// gRPC/QUIC path: the canonical converter.
	grpcPb := svc.sessionToPb(session)

	// REST/MCP path: the domain JSON the REST handler serves, decoded by
	// the SDK wire decoder.
	restJSON, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("unexpected error marshaling session: %v", err)
	}
	restResp, err := sdkprovision.DecodeGetSessionJSON(restJSON)
	if err != nil {
		t.Fatalf("unexpected error decoding session JSON: %v", err)
	}
	restPb := restResp.GetSession()

	if !proto.Equal(grpcPb, restPb) {
		t.Fatalf("cross-transport session mismatch:\ngRPC: %v\nREST: %v", grpcPb, restPb)
	}

	// Pin the fields this parity test exists for: the profile payload must
	// actually be populated, not merely equal-because-empty.
	profile := restPb.GetProfile()
	if len(profile.GetConfig()) == 0 {
		t.Fatal("profile.config must be populated on both transports")
	}
	if profile.GetEkSerial() != "EK-PARITY" || profile.GetMacAddress() != "aa:bb:cc:dd:ee:99" {
		t.Fatalf("profile identity fields missing: %v", profile)
	}
	if profile.GetEkCert() == "" {
		t.Fatal("profile.ek_cert (prestaged EK certificate) must survive both transports")
	}
	if !profile.GetAssigned() || profile.GetAssignedAt() == nil {
		t.Fatalf("profile assignment fields missing: %v", profile)
	}
}

// TestSessionCrossTransportParity_UnassignedNilConfig verifies parity holds
// for the sparse case: no config, unassigned profile (zero assigned_at must
// stay unset on both transports).
func TestSessionCrossTransportParity_UnassignedNilConfig(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, slog.Default())
	session := &configdelivery.Session{
		ID:        "parity-sparse",
		EKSerial:  "EK-SPARSE",
		CreatedAt: time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 8, 1, 10, 30, 0, 0, time.UTC),
		Profile:   &entities.DeviceProfile{ID: 7, Name: "sparse"},
	}

	grpcPb := svc.sessionToPb(session)

	restJSON, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("unexpected error marshaling session: %v", err)
	}
	restResp, err := sdkprovision.DecodeGetSessionJSON(restJSON)
	if err != nil {
		t.Fatalf("unexpected error decoding session JSON: %v", err)
	}

	if !proto.Equal(grpcPb, restResp.GetSession()) {
		t.Fatalf("cross-transport sparse session mismatch:\ngRPC: %v\nREST: %v",
			grpcPb, restResp.GetSession())
	}
	profile := restResp.GetSession().GetProfile()
	if profile.GetConfig() != nil || profile.GetAssignedAt() != nil {
		t.Fatalf("sparse profile must have unset config/assigned_at: %v", profile)
	}
}

func TestSessionToPb_NilAndZeroTimestamps(t *testing.T) {
	svc := NewConfigDeliveryGRPCService(nil, slog.Default())
	if got := svc.sessionToPb(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	got := svc.sessionToPb(&configdelivery.Session{ID: "session-2"})
	if got.GetCreatedAt() != nil || got.GetExpiresAt() != nil {
		t.Fatalf("expected nil timestamps for zero times, got %v / %v", got.GetCreatedAt(), got.GetExpiresAt())
	}
	if got.GetProfile() != nil {
		t.Fatalf("expected nil profile, got %v", got.GetProfile())
	}
}

func TestConfigDeliveryErrorToStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		matchers []configDeliveryErrorMatcher
		want     codes.Code
	}{
		{"fetch invalid request", configdelivery.ErrInvalidRequest{Reason: "x"}, fetchConfigErrorMatchers, codes.InvalidArgument},
		{"fetch nonce required", configdelivery.ErrNonceRequired{}, fetchConfigErrorMatchers, codes.InvalidArgument},
		{"fetch nonce expired", configdelivery.ErrNonceExpired{}, fetchConfigErrorMatchers, codes.InvalidArgument},
		{"fetch eab failed", configdelivery.ErrEABValidationFailed{Cause: errors.New("bad")}, fetchConfigErrorMatchers, codes.Unauthenticated},
		{"fetch ek parse failed", configdelivery.ErrEKCertParseFailed{Cause: errors.New("bad")}, fetchConfigErrorMatchers, codes.InvalidArgument},
		{"fetch ek required", configdelivery.ErrEKCertRequired{}, fetchConfigErrorMatchers, codes.PermissionDenied},
		{"fetch ek mismatch", configdelivery.ErrEKCertMismatch{}, fetchConfigErrorMatchers, codes.PermissionDenied},
		{"fetch eab profile mismatch", configdelivery.ErrEABProfileMismatch{}, fetchConfigErrorMatchers, codes.PermissionDenied},
		{"sign eab profile mismatch", configdelivery.ErrEABProfileMismatch{}, signDigestErrorMatchers, codes.PermissionDenied},
		{"fetch unknown", errors.New("boom"), fetchConfigErrorMatchers, codes.Internal},
		{"fetch wrapped known", fmt.Errorf("wrapped: %w", configdelivery.ErrNonceExpired{}), fetchConfigErrorMatchers, codes.InvalidArgument},

		{"sign invalid request", configdelivery.ErrInvalidRequest{Reason: "x"}, signDigestErrorMatchers, codes.InvalidArgument},
		{"sign nonce required", configdelivery.ErrNonceRequired{}, signDigestErrorMatchers, codes.InvalidArgument},
		{"sign nonce expired", configdelivery.ErrNonceExpired{}, signDigestErrorMatchers, codes.InvalidArgument},
		{"sign ek parse failed", configdelivery.ErrEKCertParseFailed{Cause: errors.New("bad")}, signDigestErrorMatchers, codes.InvalidArgument},
		{"sign eab failed", configdelivery.ErrEABValidationFailed{Cause: errors.New("bad")}, signDigestErrorMatchers, codes.PermissionDenied},
		{"sign ek required", configdelivery.ErrEKCertRequired{}, signDigestErrorMatchers, codes.PermissionDenied},
		{"sign ek mismatch", configdelivery.ErrEKCertMismatch{}, signDigestErrorMatchers, codes.PermissionDenied},
		{"sign not configured", configdelivery.ErrRemoteSignNotConfigured{Reason: "x"}, signDigestErrorMatchers, codes.FailedPrecondition},
		{"sign signer unavailable", configdelivery.ErrSignerUnavailable{}, signDigestErrorMatchers, codes.Unavailable},
		{"sign missing profile service", configdelivery.ErrMissingProfileService{}, signDigestErrorMatchers, codes.Unavailable},
		{"sign failed unknown", configdelivery.ErrSignFailed{Cause: errors.New("kms down")}, signDigestErrorMatchers, codes.Internal},

		{"session not found", configdelivery.ErrSessionNotFound{SessionID: "x"}, sessionErrorMatchers, codes.NotFound},
		{"session profile not found", configdelivery.ErrProfileNotFound{ProfileID: 1}, sessionErrorMatchers, codes.NotFound},
		{"session expired", configdelivery.ErrSessionExpired{SessionID: "x"}, sessionErrorMatchers, codes.InvalidArgument},
		{"session already fulfilled", configdelivery.ErrSessionAlreadyFulfilled{SessionID: "x"}, sessionErrorMatchers, codes.InvalidArgument},
		{"session profile missing", configdelivery.ErrSessionProfileMissing{SessionID: "x"}, sessionErrorMatchers, codes.Internal},
		{"session unknown", errors.New("boom"), sessionErrorMatchers, codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configDeliveryErrorToStatus(tt.err, tt.matchers)
			assertGRPCCode(t, got, tt.want)
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("expected status error, got %T", got)
			}
			if st.Message() != tt.err.Error() {
				t.Fatalf("expected message %q, got %q", tt.err.Error(), st.Message())
			}
		})
	}
}

func TestErrConfigDeliveryServiceNotAvailable(t *testing.T) {
	err := ErrConfigDeliveryServiceNotAvailable{}
	if err.Error() != "config delivery service is not available" {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}

func TestErrConfigSerializationFailed(t *testing.T) {
	cause := errors.New("cyclic value")
	err := ErrConfigSerializationFailed{Cause: cause}
	if !strings.Contains(err.Error(), "cyclic value") {
		t.Fatalf("unexpected message: %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to expose the cause")
	}
}
