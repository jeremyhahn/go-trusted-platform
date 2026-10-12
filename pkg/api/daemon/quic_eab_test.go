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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Test Helpers
// =============================================================================

// newEABQUICHandler builds a QUIC handler backed by an EABGRPCService
// over the shared fakes. A nil servicer exercises the unavailable guard.
func newEABQUICHandler(t *testing.T, configured bool) (*QUICServiceHandler, *fakeEABService, *fakeEABDelivery) {
	t.Helper()
	handler := NewQUICServiceHandler(nil)
	if !configured {
		return handler, nil, nil
	}
	grpcSvc, svc, del := newEABGRPCFixture()
	handler.SetEABService(grpcSvc)
	return handler, svc, del
}

// eabQUICRequest builds an OpProvisioningCategory request carrying an
// EAB sub-opcode and optional pb body, encoded exactly as the SDK QUIC
// transport does (the platformv1 proto struct directly).
func eabQUICRequest(t *testing.T, sub byte, body interface{}) *quicwire.Request {
	t.Helper()
	payload := []byte{sub}
	if body != nil {
		encoded, err := quicwire.EncodePayload(body)
		if err != nil {
			t.Fatalf("encode %T: %v", body, err)
		}
		payload = append(payload, encoded...)
	}
	return &quicwire.Request{Opcode: quicwire.OpProvisioningCategory, Payload: payload}
}

// decodeEABOK asserts StatusOK and decodes the response payload.
func decodeEABOK(t *testing.T, resp *quicwire.Response, out interface{}) {
	t.Helper()
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("expected StatusOK, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
	if err := quicwire.DecodePayload(resp.Payload, out); err != nil {
		t.Fatalf("decode response into %T: %v", out, err)
	}
}

// =============================================================================
// Sub-opcode allocation
// =============================================================================

// TestEABSubOpcodesDoNotCollideWithProvisioning pins the shared-category
// contract: no EAB sub-opcode may collide with a config delivery
// sub-opcode, because both families multiplex under 0xCF.
func TestEABSubOpcodesDoNotCollideWithProvisioning(t *testing.T) {
	provisioningSubs := map[byte]string{
		quicwire.ProvisioningSubGetNonce:       "GetNonce",
		quicwire.ProvisioningSubFetchConfig:    "FetchConfig",
		quicwire.ProvisioningSubSignDigest:     "SignDigest",
		quicwire.ProvisioningSubPollSession:    "PollSession",
		quicwire.ProvisioningSubFulfillSession: "FulfillSession",
		quicwire.ProvisioningSubListSessions:   "ListSessions",
		quicwire.ProvisioningSubGetSession:     "GetSession",
	}
	for sub := range eabQUICDispatch {
		if name, clash := provisioningSubs[sub]; clash {
			t.Errorf("EAB sub-opcode 0x%02x collides with provisioning %s", sub, name)
		}
	}
	if len(eabQUICDispatch) != 11 {
		t.Errorf("expected 11 EAB sub-opcodes, got %d", len(eabQUICDispatch))
	}
}

// =============================================================================
// Guards
// =============================================================================

func TestEABQUIC_NilServiceUnavailable(t *testing.T) {
	handler, _, _ := newEABQUICHandler(t, false)
	resp := handler.HandleRequest(context.Background(),
		eabQUICRequest(t, quicwire.EABSubGetCredential, &platformv1.GetEABCredentialRequest{CredentialId: 1}))
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected StatusUnavailable, got 0x%02x", resp.Status)
	}
}

func TestEABQUIC_NonEABSubFallsThroughToProvisioning(t *testing.T) {
	// A provisioning sub-opcode on a handler with only EAB wired must
	// reach the config delivery guard (unavailable), NOT the EAB path.
	handler, _, _ := newEABQUICHandler(t, true)
	resp := handler.HandleRequest(context.Background(),
		eabQUICRequest(t, quicwire.ProvisioningSubGetNonce, nil))
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected config delivery unavailable, got 0x%02x", resp.Status)
	}
}

func TestEABQUIC_UnknownSubOpcode(t *testing.T) {
	// 0x7F is in neither dispatch family: it falls through to the config
	// delivery dispatcher, whose nil-service guard fires first on this
	// EAB-only handler.
	handler, _, _ := newEABQUICHandler(t, true)
	resp := handler.HandleRequest(context.Background(), eabQUICRequest(t, 0x7F, nil))
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected StatusUnavailable (config delivery guard), got 0x%02x", resp.Status)
	}
}

func TestEABQUIC_MalformedPayloadInvalidRequest(t *testing.T) {
	handler, _, _ := newEABQUICHandler(t, true)
	resp := handler.HandleRequest(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpProvisioningCategory,
		Payload: append([]byte{quicwire.EABSubGetCredential}, 0xc1, 0xc1, 0xc1),
	})
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Errorf("expected StatusInvalidRequest, got 0x%02x", resp.Status)
	}
}

// =============================================================================
// Round Trips (pb encode -> QUIC dispatch -> pb decode)
// =============================================================================

func TestEABQUIC_CreateGetRoundTrip(t *testing.T) {
	handler, _, _ := newEABQUICHandler(t, true)
	ctx := context.Background()

	var createResp platformv1.CreateEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubCreateCredential,
		&platformv1.CreateEABCredentialRequest{
			ProfileId:        7,
			TenantId:         "tenant-1",
			ExpiresInSeconds: 3600,
		})), &createResp)
	if createResp.GetCredential().GetHmacKey() == "" {
		t.Error("expected hmac_key on create")
	}
	id := createResp.GetCredential().GetId()
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	var getResp platformv1.GetEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubGetCredential,
		&platformv1.GetEABCredentialRequest{CredentialId: id})), &getResp)
	if getResp.GetCredential().GetId() != id {
		t.Errorf("get id = %d, want %d", getResp.GetCredential().GetId(), id)
	}
	if getResp.GetCredential().GetHmacKey() != "" {
		t.Error("get leaked hmac_key")
	}

	var byKeyResp platformv1.GetEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubGetCredentialByKeyID,
		&platformv1.GetEABCredentialByKeyIDRequest{
			KeyId: createResp.GetCredential().GetKeyId(),
		})), &byKeyResp)
	if byKeyResp.GetCredential().GetId() != id {
		t.Errorf("get-by-key id = %d, want %d", byKeyResp.GetCredential().GetId(), id)
	}
}

func TestEABQUIC_ListRoundTrip(t *testing.T) {
	handler, svc, _ := newEABQUICHandler(t, true)
	ctx := context.Background()
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t1"})
	_, _ = svc.Generate(ctx, eab.GenerateParams{ProfileID: 2, TenantID: "t2"})

	var listResp platformv1.ListEABCredentialsResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubListCredentials,
		&platformv1.ListEABCredentialsRequest{
			TenantId:   "t1",
			Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 1},
		})), &listResp)
	if listResp.GetTotal() != 2 {
		t.Errorf("total = %d, want 2", listResp.GetTotal())
	}
	if len(listResp.GetCredentials()) != 1 {
		t.Errorf("page size = %d, want 1", len(listResp.GetCredentials()))
	}
	if listResp.GetPagination().GetTotalPages() != 2 {
		t.Errorf("total pages = %d, want 2", listResp.GetPagination().GetTotalPages())
	}
}

func TestEABQUIC_ValidateRoundTrip(t *testing.T) {
	handler, svc, _ := newEABQUICHandler(t, true)
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	var validResp platformv1.ValidateEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubValidateCredential,
		&platformv1.ValidateEABCredentialRequest{
			KeyId:   cred.KeyID,
			HmacKey: base64.RawURLEncoding.EncodeToString(cred.HMACKey),
		})), &validResp)
	if !validResp.GetValid() {
		t.Error("expected valid=true")
	}

	// Unknown key: in-band valid=false, still StatusOK.
	var invalidResp platformv1.ValidateEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubValidateCredential,
		&platformv1.ValidateEABCredentialRequest{
			KeyId:   "missing",
			HmacKey: base64.RawURLEncoding.EncodeToString([]byte{1}),
		})), &invalidResp)
	if invalidResp.GetValid() {
		t.Error("expected valid=false")
	}

	// Malformed base64 maps to StatusInvalidArgument via the shared
	// gRPC-code translation.
	resp := handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubValidateCredential,
		&platformv1.ValidateEABCredentialRequest{KeyId: "k", HmacKey: "!!!"}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Errorf("bad base64: expected StatusInvalidArgument, got 0x%02x", resp.Status)
	}
}

func TestEABQUIC_LifecycleRoundTrip(t *testing.T) {
	handler, svc, _ := newEABQUICHandler(t, true)
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	var usedResp platformv1.MarkEABCredentialUsedResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubMarkCredentialUsed,
		&platformv1.MarkEABCredentialUsedRequest{CredentialId: cred.ID})), &usedResp)
	if !usedResp.GetStatus().GetSuccess() {
		t.Error("mark-used: expected success")
	}

	var revokeResp platformv1.RevokeEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubRevokeCredential,
		&platformv1.RevokeEABCredentialRequest{CredentialId: cred.ID, RevokerId: 9})), &revokeResp)
	if !revokeResp.GetStatus().GetSuccess() {
		t.Error("revoke: expected success")
	}

	var deleteResp platformv1.DeleteEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubDeleteCredential,
		&platformv1.DeleteEABCredentialRequest{CredentialId: cred.ID})), &deleteResp)
	if !deleteResp.GetStatus().GetSuccess() {
		t.Error("delete: expected success")
	}

	// Second delete: NotFound via the shared error translation.
	resp := handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubDeleteCredential,
		&platformv1.DeleteEABCredentialRequest{CredentialId: cred.ID}))
	if resp.Status != quicwire.StatusNotFound {
		t.Errorf("second delete: expected StatusNotFound, got 0x%02x", resp.Status)
	}
}

func TestEABQUIC_DeliveryRoundTrip(t *testing.T) {
	handler, svc, del := newEABQUICHandler(t, true)
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{ProfileID: 1, TenantID: "t"})

	var qrResp platformv1.GetEABCredentialQRCodeResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubGetCredentialQRCode,
		&platformv1.GetEABCredentialQRCodeRequest{CredentialId: cred.ID, Size: 128})), &qrResp)
	if string(qrResp.GetQrCode()) != string(del.qrPayload) {
		t.Error("qr payload mismatch")
	}
	if qrResp.GetContentType() != "image/png" {
		t.Errorf("content_type = %q", qrResp.GetContentType())
	}
	if del.lastSize != 128 {
		t.Errorf("size not threaded: %d", del.lastSize)
	}

	var urlResp platformv1.GetEABEnrollmentURLResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubGetEnrollmentURL,
		&platformv1.GetEABEnrollmentURLRequest{CredentialId: cred.ID})), &urlResp)
	if urlResp.GetUrl() != del.url {
		t.Errorf("url = %q, want %q", urlResp.GetUrl(), del.url)
	}
}

func TestEABQUIC_CleanupRoundTrip(t *testing.T) {
	handler, svc, _ := newEABQUICHandler(t, true)
	svc.cleanupCount = 3

	var cleanupResp platformv1.CleanupExpiredEABCredentialsResponse
	decodeEABOK(t, handler.HandleRequest(context.Background(),
		eabQUICRequest(t, quicwire.EABSubCleanupExpiredCredentials,
			&platformv1.CleanupExpiredEABCredentialsRequest{})), &cleanupResp)
	if cleanupResp.GetDeletedCount() != 3 {
		t.Errorf("deleted_count = %d, want 3", cleanupResp.GetDeletedCount())
	}
}

// TestEABQUIC_TimestampRoundTrip pins that pb Timestamp messages survive
// the msgpack field-name codec both ways.
func TestEABQUIC_TimestampRoundTrip(t *testing.T) {
	handler, svc, _ := newEABQUICHandler(t, true)
	ctx := context.Background()
	cred, _ := svc.Generate(ctx, eab.GenerateParams{
		ProfileID: 1,
		TenantID:  "t",
		ExpiresIn: time.Hour,
	})

	var getResp platformv1.GetEABCredentialResponse
	decodeEABOK(t, handler.HandleRequest(ctx, eabQUICRequest(t, quicwire.EABSubGetCredential,
		&platformv1.GetEABCredentialRequest{CredentialId: cred.ID})), &getResp)
	if got := getResp.GetCredential().GetCreatedAt().AsTime().Unix(); got != cred.CreatedAt.Unix() {
		t.Errorf("created_at = %d, want %d", got, cred.CreatedAt.Unix())
	}
	if got := getResp.GetCredential().GetExpiresAt().AsTime().Unix(); got != cred.ExpiresAt.Unix() {
		t.Errorf("expires_at = %d, want %d", got, cred.ExpiresAt.Unix())
	}
}
