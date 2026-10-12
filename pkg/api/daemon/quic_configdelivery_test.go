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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Test Helpers
// =============================================================================

// newProvisioningQUICHandler builds a QUIC handler backed by the given
// config delivery service (nil allowed to exercise the unavailable guard).
func newProvisioningQUICHandler(svc ConfigDeliveryQUICService) *QUICServiceHandler {
	if svc == nil {
		return newTestQUICServiceHandler(nil)
	}
	return newTestQUICServiceHandler(nil, WithQUICConfigDeliveryService(svc))
}

// provisioningQUICRequest builds an OpProvisioningCategory request with
// the given sub-opcode and optional body, encoding the body exactly as
// the SDK QUIC transport does (the platformv1 proto struct directly).
func provisioningQUICRequest(t *testing.T, sub byte, body interface{}) *quicwire.Request {
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

// decodeProvisioningOK asserts StatusOK and decodes the response payload.
func decodeProvisioningOK(t *testing.T, resp *quicwire.Response, out interface{}) {
	t.Helper()
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("expected StatusOK, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
	if err := quicwire.DecodePayload(resp.Payload, out); err != nil {
		t.Fatalf("decode response into %T: %v", out, err)
	}
}

// newProvisioningBackedHandler wires a real configdelivery.Service through
// the shared ConfigDeliveryGRPCService into a QUIC handler.
func newProvisioningBackedHandler(t *testing.T, resolver configdelivery.ProfileResolver, signer configdelivery.DBKeySigner) (*QUICServiceHandler, *configdelivery.Service) {
	t.Helper()
	backing := newCDTestService(t, resolver, signer)
	return newProvisioningQUICHandler(newCDGRPCService(t, backing)), backing
}

// =============================================================================
// Wire Compat: flat requests (pb encoding decodes into daemon wire structs)
// =============================================================================

func TestQUICWireCompatProvisioningFetchConfigRequest(t *testing.T) {
	var out ConfigDeliveryFetchConfigRequest
	encodeAs(t, &platformv1.FetchConfigRequest{
		EkSerial:   "ek-1",
		MacAddress: "aa:bb:cc:dd:ee:ff",
		EkCert:     "ZGVy",
		EabKeyId:   "key-1",
		EabHmac:    "hmac-1",
		Nonce:      "nonce-1",
	}, &out)

	if out.EkSerial != "ek-1" || out.MacAddress != "aa:bb:cc:dd:ee:ff" || out.EkCert != "ZGVy" {
		t.Errorf("identity fields = %q/%q/%q, want ek-1/aa:bb:cc:dd:ee:ff/ZGVy",
			out.EkSerial, out.MacAddress, out.EkCert)
	}
	if out.EabKeyId != "key-1" || out.EabHmac != "hmac-1" || out.Nonce != "nonce-1" {
		t.Errorf("auth fields = %q/%q/%q, want key-1/hmac-1/nonce-1",
			out.EabKeyId, out.EabHmac, out.Nonce)
	}
}

func TestQUICWireCompatProvisioningSignDigestRequest(t *testing.T) {
	var out ConfigDeliverySignDigestRequest
	encodeAs(t, &platformv1.SignDigestRequest{
		EkSerial:   "ek-2",
		MacAddress: "11:22:33:44:55:66",
		EkCert:     "Y2VydA",
		EabKeyId:   "key-2",
		EabHmac:    "hmac-2",
		Nonce:      "nonce-2",
		Digest:     []byte{1, 2, 3},
		KeyRef:     "db",
	}, &out)

	if out.EkSerial != "ek-2" || out.MacAddress != "11:22:33:44:55:66" || out.EkCert != "Y2VydA" {
		t.Errorf("identity fields = %q/%q/%q, want ek-2/11:22:33:44:55:66/Y2VydA",
			out.EkSerial, out.MacAddress, out.EkCert)
	}
	if out.EabKeyId != "key-2" || out.EabHmac != "hmac-2" || out.Nonce != "nonce-2" {
		t.Errorf("auth fields = %q/%q/%q, want key-2/hmac-2/nonce-2",
			out.EabKeyId, out.EabHmac, out.Nonce)
	}
	if !bytes.Equal(out.Digest, []byte{1, 2, 3}) || out.KeyRef != "db" {
		t.Errorf("Digest/KeyRef = %v/%q, want [1 2 3]/db", out.Digest, out.KeyRef)
	}
}

func TestQUICWireCompatProvisioningSessionRequests(t *testing.T) {
	var poll ConfigDeliveryPollSessionRequest
	encodeAs(t, &platformv1.PollSessionRequest{SessionId: "s-1"}, &poll)
	if poll.SessionId != "s-1" {
		t.Errorf("PollSession SessionId = %q, want s-1", poll.SessionId)
	}

	var fulfill ConfigDeliveryFulfillSessionRequest
	encodeAs(t, &platformv1.FulfillSessionRequest{SessionId: "s-2", ProfileId: 42}, &fulfill)
	if fulfill.SessionId != "s-2" || fulfill.ProfileId != 42 {
		t.Errorf("FulfillSession = %q/%d, want s-2/42", fulfill.SessionId, fulfill.ProfileId)
	}

	var get ConfigDeliveryGetSessionRequest
	encodeAs(t, &platformv1.GetSessionRequest{SessionId: "s-3"}, &get)
	if get.SessionId != "s-3" {
		t.Errorf("GetSession SessionId = %q, want s-3", get.SessionId)
	}
}

// =============================================================================
// Wire Compat: flat responses (daemon wire structs decode into pb structs)
// =============================================================================

func TestQUICWireCompatProvisioningGetNonceResponse(t *testing.T) {
	var out platformv1.GetNonceResponse
	encodeAs(t, &ConfigDeliveryGetNonceResponse{Nonce: "n-1"}, &out)
	if out.GetNonce() != "n-1" {
		t.Errorf("Nonce = %q, want n-1", out.GetNonce())
	}
}

func TestQUICWireCompatProvisioningSignDigestResponse(t *testing.T) {
	var out platformv1.SignDigestResponse
	encodeAs(t, &ConfigDeliverySignDigestResponse{
		Signature: []byte("sig"),
		CertPem:   []byte("pem"),
	}, &out)
	if string(out.GetSignature()) != "sig" || string(out.GetCertPem()) != "pem" {
		t.Errorf("Signature/CertPem = %q/%q, want sig/pem", out.GetSignature(), out.GetCertPem())
	}
}

func TestQUICWireCompatProvisioningFulfillSessionResponse(t *testing.T) {
	var out platformv1.FulfillSessionResponse
	encodeAs(t, &ConfigDeliveryFulfillSessionResponse{Status: fulfillSessionStatus}, &out)
	if out.GetStatus() != fulfillSessionStatus {
		t.Errorf("Status = %q, want %q", out.GetStatus(), fulfillSessionStatus)
	}
}

// TestQUICWireCompatProvisioningSessionResponses proves the nested
// platformv1.ProvisioningSession (including DeviceProfile and Timestamp
// messages) round-trips through the codec by Go field name.
func TestQUICWireCompatProvisioningSessionResponses(t *testing.T) {
	session := &platformv1.ProvisioningSession{
		Id:         "s-1",
		EkSerial:   "ek-1",
		MacAddress: "aa:bb:cc:dd:ee:ff",
		TenantId:   "tenant-1",
		ProfileId:  42,
		Profile: &platformv1.DeviceProfile{
			Id:       42,
			Name:     "compute-01",
			Model:    "x10",
			Role:     platformv1.DeviceRole_DEVICE_ROLE_SERVER,
			Config:   []byte(`{"hostname":"node1"}`),
			EkSerial: "ek-1",
			Zone:     "z1",
		},
		Fulfilled: true,
		CreatedAt: timestamppb.New(timestamppb.Now().AsTime()),
		ExpiresAt: &timestamppb.Timestamp{Seconds: 1900000000, Nanos: 42},
	}

	var list platformv1.ListSessionsResponse
	encodeAs(t, &ConfigDeliveryListSessionsResponse{
		Sessions: []*platformv1.ProvisioningSession{session},
	}, &list)
	if len(list.GetSessions()) != 1 {
		t.Fatalf("Sessions = %d, want 1", len(list.GetSessions()))
	}
	got := list.GetSessions()[0]
	if got.GetId() != "s-1" || got.GetEkSerial() != "ek-1" || got.GetTenantId() != "tenant-1" {
		t.Errorf("session = %q/%q/%q, want s-1/ek-1/tenant-1",
			got.GetId(), got.GetEkSerial(), got.GetTenantId())
	}
	if got.GetProfileId() != 42 || !got.GetFulfilled() {
		t.Errorf("ProfileId/Fulfilled = %d/%v, want 42/true", got.GetProfileId(), got.GetFulfilled())
	}
	if got.GetProfile().GetName() != "compute-01" ||
		got.GetProfile().GetRole() != platformv1.DeviceRole_DEVICE_ROLE_SERVER {
		t.Errorf("Profile = %q/%v, want compute-01/COMPUTE",
			got.GetProfile().GetName(), got.GetProfile().GetRole())
	}
	if string(got.GetProfile().GetConfig()) != `{"hostname":"node1"}` {
		t.Errorf("Profile.Config = %q, want inline JSON", got.GetProfile().GetConfig())
	}
	if got.GetExpiresAt().GetSeconds() != 1900000000 || got.GetExpiresAt().GetNanos() != 42 {
		t.Errorf("ExpiresAt = %v, want 1900000000/42", got.GetExpiresAt())
	}

	var single platformv1.GetSessionResponse
	encodeAs(t, &ConfigDeliveryGetSessionResponse{Session: session}, &single)
	if single.GetSession().GetId() != "s-1" || single.GetSession().GetProfile().GetId() != 42 {
		t.Errorf("GetSession = %q/%d, want s-1/42",
			single.GetSession().GetId(), single.GetSession().GetProfile().GetId())
	}
}

// =============================================================================
// Oneof Flattening (pb oneof <-> flat wire, both directions)
// =============================================================================

func TestFlattenFetchConfigResponse_Delivered(t *testing.T) {
	flat := flattenFetchConfigResponse(&platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Delivered{
			Delivered: &platformv1.DeliveredConfig{ConfigJson: []byte(`{"a":1}`), Status: "ok"},
		},
	})
	if flat.Result != ConfigDeliveryResultDelivered {
		t.Fatalf("Result = %q, want delivered", flat.Result)
	}
	if string(flat.ConfigJson) != `{"a":1}` || flat.Status != "ok" {
		t.Errorf("ConfigJson/Status = %q/%q, want {\"a\":1}/ok", flat.ConfigJson, flat.Status)
	}

	pb := flat.ToProto()
	if pb.GetDelivered() == nil || pb.GetPending() != nil {
		t.Fatalf("ToProto arm mismatch: %v", pb)
	}
	if string(pb.GetDelivered().GetConfigJson()) != `{"a":1}` || pb.GetDelivered().GetStatus() != "ok" {
		t.Errorf("ToProto delivered = %q/%q, want {\"a\":1}/ok",
			pb.GetDelivered().GetConfigJson(), pb.GetDelivered().GetStatus())
	}
}

func TestFlattenFetchConfigResponse_Pending(t *testing.T) {
	flat := flattenFetchConfigResponse(&platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Pending{
			Pending: &platformv1.PendingSession{
				SessionId:           "s-1",
				ProvisionUrl:        "https://cp/provision/s-1",
				PollIntervalSeconds: 5,
			},
		},
	})
	if flat.Result != ConfigDeliveryResultPending {
		t.Fatalf("Result = %q, want pending", flat.Result)
	}
	if flat.SessionId != "s-1" || flat.ProvisionUrl != "https://cp/provision/s-1" || flat.PollIntervalSeconds != 5 {
		t.Errorf("pending fields = %q/%q/%d, want s-1/url/5",
			flat.SessionId, flat.ProvisionUrl, flat.PollIntervalSeconds)
	}

	pb := flat.ToProto()
	if pb.GetPending() == nil || pb.GetDelivered() != nil {
		t.Fatalf("ToProto arm mismatch: %v", pb)
	}
	if pb.GetPending().GetSessionId() != "s-1" || pb.GetPending().GetPollIntervalSeconds() != 5 {
		t.Errorf("ToProto pending = %q/%d, want s-1/5",
			pb.GetPending().GetSessionId(), pb.GetPending().GetPollIntervalSeconds())
	}
}

func TestFlattenFetchConfigResponse_Nil(t *testing.T) {
	if flattenFetchConfigResponse(nil) != nil {
		t.Error("flattenFetchConfigResponse(nil) != nil")
	}
	var flat *ConfigDeliveryFetchConfigResponse
	if flat.ToProto() != nil {
		t.Error("nil receiver ToProto() != nil")
	}
}

func TestFlattenPollSessionResponse_Delivered(t *testing.T) {
	flat := flattenPollSessionResponse(&platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_Delivered{
			Delivered: &platformv1.DeliveredConfig{ConfigJson: []byte(`{"b":2}`), Status: "ok"},
		},
	})
	if flat.Result != ConfigDeliveryResultDelivered {
		t.Fatalf("Result = %q, want delivered", flat.Result)
	}
	if string(flat.ConfigJson) != `{"b":2}` || flat.Status != "ok" {
		t.Errorf("ConfigJson/Status = %q/%q, want {\"b\":2}/ok", flat.ConfigJson, flat.Status)
	}

	pb := flat.ToProto()
	if pb.GetDelivered() == nil {
		t.Fatalf("ToProto arm mismatch: %v", pb)
	}
	if string(pb.GetDelivered().GetConfigJson()) != `{"b":2}` {
		t.Errorf("ToProto delivered = %q, want {\"b\":2}", pb.GetDelivered().GetConfigJson())
	}
}

func TestFlattenPollSessionResponse_Pending(t *testing.T) {
	flat := flattenPollSessionResponse(&platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_PendingStatus{
			PendingStatus: pollSessionPendingStatus,
		},
	})
	if flat.Result != ConfigDeliveryResultPending {
		t.Fatalf("Result = %q, want pending", flat.Result)
	}
	if flat.PendingStatus != pollSessionPendingStatus {
		t.Errorf("PendingStatus = %q, want %q", flat.PendingStatus, pollSessionPendingStatus)
	}

	pb := flat.ToProto()
	if pb.GetDelivered() != nil {
		t.Fatalf("ToProto arm mismatch: %v", pb)
	}
	if pb.GetPendingStatus() != pollSessionPendingStatus {
		t.Errorf("ToProto pending_status = %q, want %q", pb.GetPendingStatus(), pollSessionPendingStatus)
	}
}

func TestFlattenPollSessionResponse_Nil(t *testing.T) {
	if flattenPollSessionResponse(nil) != nil {
		t.Error("flattenPollSessionResponse(nil) != nil")
	}
	var flat *ConfigDeliveryPollSessionResponse
	if flat.ToProto() != nil {
		t.Error("nil receiver ToProto() != nil")
	}
}

// TestQUICWireCompatProvisioningFlatResponsesRoundTrip guards the wire
// encoding of the flattened oneof responses: server flat struct ->
// codec -> client flat struct -> ToProto.
func TestQUICWireCompatProvisioningFlatResponsesRoundTrip(t *testing.T) {
	var fetch ConfigDeliveryFetchConfigResponse
	encodeAs(t, &ConfigDeliveryFetchConfigResponse{
		Result:              ConfigDeliveryResultPending,
		SessionId:           "s-9",
		ProvisionUrl:        "https://cp/provision/s-9",
		PollIntervalSeconds: 7,
	}, &fetch)
	if pb := fetch.ToProto(); pb.GetPending().GetSessionId() != "s-9" ||
		pb.GetPending().GetPollIntervalSeconds() != 7 {
		t.Errorf("fetch round-trip = %v, want pending s-9/7", pb)
	}

	var poll ConfigDeliveryPollSessionResponse
	encodeAs(t, &ConfigDeliveryPollSessionResponse{
		Result:     ConfigDeliveryResultDelivered,
		ConfigJson: []byte(`{"c":3}`),
		Status:     "ok",
	}, &poll)
	if pb := poll.ToProto(); string(pb.GetDelivered().GetConfigJson()) != `{"c":3}` ||
		pb.GetDelivered().GetStatus() != "ok" {
		t.Errorf("poll round-trip = %v, want delivered {\"c\":3}/ok", pb)
	}
}

// =============================================================================
// Category Dispatch
// =============================================================================

func TestProvisioningCategory_NilService(t *testing.T) {
	handler := newProvisioningQUICHandler(nil)
	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubGetNonce, nil))
	if resp.Status != quicwire.StatusUnavailable {
		t.Fatalf("expected StatusUnavailable, got 0x%02x", resp.Status)
	}
	if !strings.Contains(string(resp.Payload), ErrConfigDeliveryServiceNotAvailable{}.Error()) {
		t.Fatalf("expected typed unavailable message, got %q", resp.Payload)
	}
}

func TestProvisioningCategory_EmptyPayload(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	resp := handler.HandleRequest(context.Background(),
		&quicwire.Request{Opcode: quicwire.OpProvisioningCategory})
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Fatalf("expected StatusInvalidRequest, got 0x%02x", resp.Status)
	}
}

func TestProvisioningCategory_UnknownSubOpcode(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	// The authorization guard refuses an unclassified sub-opcode before
	// dispatch; the category handler still rejects it on its own.
	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, 0xEE, nil))
	if resp.Status != quicwire.StatusPermissionDenied {
		t.Fatalf("expected StatusPermissionDenied, got 0x%02x", resp.Status)
	}
	resp = handler.handleProvisioningCategory(context.Background(),
		provisioningQUICRequest(t, 0xEE, nil))
	if resp.Status != quicwire.StatusNotImplemented {
		t.Fatalf("handler: expected StatusNotImplemented, got 0x%02x", resp.Status)
	}
}

// =============================================================================
// Sub-operation Handlers
// =============================================================================

func TestProvisioningQUIC_GetNonce(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubGetNonce, nil))

	var out ConfigDeliveryGetNonceResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
}

func TestProvisioningQUIC_FetchConfig_Delivered(t *testing.T) {
	wantConfig := map[string]any{"hostname": "node1", "role": "compute"}
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 42, Config: wantConfig}, nil
		},
	}
	handler, backing := newProvisioningBackedHandler(t, resolver, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFetchConfig, &platformv1.FetchConfigRequest{
			EkSerial: "ek-123",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    cdIssueNonce(t, backing),
		}))

	var out ConfigDeliveryFetchConfigResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Result != ConfigDeliveryResultDelivered {
		t.Fatalf("Result = %q, want delivered", out.Result)
	}
	if out.Status != "ok" {
		t.Fatalf("Status = %q, want ok", out.Status)
	}
	var got map[string]any
	if err := json.Unmarshal(out.ConfigJson, &got); err != nil {
		t.Fatalf("config_json did not decode: %v", err)
	}
	if got["hostname"] != "node1" || got["role"] != "compute" {
		t.Fatalf("unexpected config payload: %v", got)
	}
}

func TestProvisioningQUIC_FetchConfig_Pending(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFetchConfig, &platformv1.FetchConfigRequest{
			EkSerial: "ek-unmatched",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    cdIssueNonce(t, backing),
		}))

	var out ConfigDeliveryFetchConfigResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Result != ConfigDeliveryResultPending {
		t.Fatalf("Result = %q, want pending", out.Result)
	}
	if out.SessionId == "" {
		t.Fatal("expected non-empty session_id")
	}
	if !strings.Contains(out.ProvisionUrl, out.SessionId) {
		t.Fatalf("expected provision_url to reference the session, got %q", out.ProvisionUrl)
	}
	if out.PollIntervalSeconds <= 0 {
		t.Fatalf("expected positive poll interval, got %d", out.PollIntervalSeconds)
	}
}

func TestProvisioningQUIC_FetchConfig_InvalidNonce(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFetchConfig, &platformv1.FetchConfigRequest{
			EkSerial: "ek-123",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    "never-issued",
		}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("expected StatusInvalidArgument, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_FetchConfig_DecodeError(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFetchConfig, []string{"not", "a", "struct"}))
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Fatalf("expected StatusInvalidRequest, got 0x%02x", resp.Status)
	}
}

func TestProvisioningQUIC_SignDigest_Success(t *testing.T) {
	profile := cdRemoteSignProfile()
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return profile, nil
		},
	}
	signer := &cdFakeDBKeySigner{signature: []byte("sig-bytes"), certPEM: []byte("db-cert-pem")}
	handler, backing := newProvisioningBackedHandler(t, resolver, signer)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubSignDigest, &platformv1.SignDigestRequest{
			EkSerial: "ek-123",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    cdIssueNonce(t, backing),
			Digest:   []byte("uki-digest"),
		}))

	var out ConfigDeliverySignDigestResponse
	decodeProvisioningOK(t, resp, &out)
	if string(out.Signature) != "sig-bytes" {
		t.Fatalf("Signature = %q, want sig-bytes", out.Signature)
	}
	if string(out.CertPem) != "db-cert-pem" {
		t.Fatalf("CertPem = %q, want db-cert-pem", out.CertPem)
	}
}

func TestProvisioningQUIC_SignDigest_SignerUnavailable(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubSignDigest, &platformv1.SignDigestRequest{
			EkSerial: "ek-123",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    cdIssueNonce(t, backing),
			Digest:   []byte("digest"),
		}))
	if resp.Status != quicwire.StatusUnavailable {
		t.Fatalf("expected StatusUnavailable, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_SignDigest_NotConfigured(t *testing.T) {
	resolver := &cdMockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 9, Config: map[string]any{"hostname": "no-sb"}}, nil
		},
	}
	signer := &cdFakeDBKeySigner{signature: []byte("sig")}
	handler, backing := newProvisioningBackedHandler(t, resolver, signer)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubSignDigest, &platformv1.SignDigestRequest{
			EkSerial: "ek-123",
			EabKeyId: "key-1",
			EabHmac:  cdValidEABHMAC(),
			Nonce:    cdIssueNonce(t, backing),
			Digest:   []byte("digest"),
		}))
	// FailedPrecondition (REST 409) maps to StatusInvalidRequest on QUIC.
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Fatalf("expected StatusInvalidRequest, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_PollSession_Pending(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubPollSession,
			&platformv1.PollSessionRequest{SessionId: session.ID}))

	var out ConfigDeliveryPollSessionResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Result != ConfigDeliveryResultPending {
		t.Fatalf("Result = %q, want pending", out.Result)
	}
	if out.PendingStatus != pollSessionPendingStatus {
		t.Fatalf("PendingStatus = %q, want %q", out.PendingStatus, pollSessionPendingStatus)
	}
}

func TestProvisioningQUIC_PollSession_Delivered(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
	if err := backing.FulfillSession(context.Background(), session.ID, 42); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubPollSession,
			&platformv1.PollSessionRequest{SessionId: session.ID}))

	var out ConfigDeliveryPollSessionResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Result != ConfigDeliveryResultDelivered {
		t.Fatalf("Result = %q, want delivered", out.Result)
	}
	var got map[string]any
	if err := json.Unmarshal(out.ConfigJson, &got); err != nil {
		t.Fatalf("config_json did not decode: %v", err)
	}
	if got["hostname"] != "fulfilled-node" {
		t.Fatalf("unexpected config payload: %v", got)
	}
}

func TestProvisioningQUIC_PollSession_NotFound(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubPollSession,
			&platformv1.PollSessionRequest{SessionId: "missing"}))
	if resp.Status != quicwire.StatusNotFound {
		t.Fatalf("expected StatusNotFound, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_PollSession_MissingSessionID(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubPollSession,
			&platformv1.PollSessionRequest{}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("expected StatusInvalidArgument, got 0x%02x", resp.Status)
	}
}

func TestProvisioningQUIC_FulfillSession_Success(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFulfillSession,
			&platformv1.FulfillSessionRequest{SessionId: session.ID, ProfileId: 42}))

	var out ConfigDeliveryFulfillSessionResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Status != fulfillSessionStatus {
		t.Fatalf("Status = %q, want %q", out.Status, fulfillSessionStatus)
	}
}

func TestProvisioningQUIC_FulfillSession_NotFound(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFulfillSession,
			&platformv1.FulfillSessionRequest{SessionId: "missing", ProfileId: 42}))
	if resp.Status != quicwire.StatusNotFound {
		t.Fatalf("expected StatusNotFound, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_FulfillSession_AlreadyFulfilled(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
	if err := backing.FulfillSession(context.Background(), session.ID, 42); err != nil {
		t.Fatalf("unexpected error fulfilling session: %v", err)
	}

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFulfillSession,
			&platformv1.FulfillSessionRequest{SessionId: session.ID, ProfileId: 43}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("expected StatusInvalidArgument, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_FulfillSession_MissingSessionID(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubFulfillSession,
			&platformv1.FulfillSessionRequest{ProfileId: 42}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("expected StatusInvalidArgument, got 0x%02x", resp.Status)
	}
}

func TestProvisioningQUIC_ListSessions(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	first := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	second := backing.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubListSessions, nil))

	var out ConfigDeliveryListSessionsResponse
	decodeProvisioningOK(t, resp, &out)
	if len(out.Sessions) != 2 {
		t.Fatalf("Sessions = %d, want 2", len(out.Sessions))
	}
	ids := map[string]bool{}
	for _, session := range out.Sessions {
		ids[session.GetId()] = true
	}
	if !ids[first.ID] || !ids[second.ID] {
		t.Fatalf("expected sessions %q and %q, got %v", first.ID, second.ID, ids)
	}
}

func TestProvisioningQUIC_GetSession_Success(t *testing.T) {
	handler, backing := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)
	session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubGetSession,
			&platformv1.GetSessionRequest{SessionId: session.ID}))

	var out ConfigDeliveryGetSessionResponse
	decodeProvisioningOK(t, resp, &out)
	if out.Session.GetId() != session.ID {
		t.Fatalf("Session.Id = %q, want %q", out.Session.GetId(), session.ID)
	}
	if out.Session.GetEkSerial() != "ek-1" || out.Session.GetMacAddress() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("session identity = %q/%q, want ek-1/aa:bb:cc:dd:ee:ff",
			out.Session.GetEkSerial(), out.Session.GetMacAddress())
	}
}

func TestProvisioningQUIC_GetSession_NotFound(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubGetSession,
			&platformv1.GetSessionRequest{SessionId: "missing"}))
	if resp.Status != quicwire.StatusNotFound {
		t.Fatalf("expected StatusNotFound, got 0x%02x (payload: %s)", resp.Status, resp.Payload)
	}
}

func TestProvisioningQUIC_GetSession_MissingSessionID(t *testing.T) {
	handler, _ := newProvisioningBackedHandler(t, &cdMockProfileResolver{}, nil)

	resp := handler.HandleRequest(context.Background(),
		provisioningQUICRequest(t, quicwire.ProvisioningSubGetSession,
			&platformv1.GetSessionRequest{}))
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Fatalf("expected StatusInvalidArgument, got 0x%02x", resp.Status)
	}
}

// =============================================================================
// Error Mapping
// =============================================================================

func TestConfigDeliveryErrorToQUICResponse_CodeMapping(t *testing.T) {
	handler := newProvisioningQUICHandler(nil)

	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"InvalidArgument", status.Error(codes.InvalidArgument, "bad"), quicwire.StatusInvalidArgument},
		{"Unauthenticated", status.Error(codes.Unauthenticated, "eab"), quicwire.StatusUnauthorized},
		{"PermissionDenied", status.Error(codes.PermissionDenied, "ek"), quicwire.StatusPermissionDenied},
		{"NotFound", status.Error(codes.NotFound, "session"), quicwire.StatusNotFound},
		{"FailedPrecondition", status.Error(codes.FailedPrecondition, "resign"), quicwire.StatusInvalidRequest},
		{"Unavailable", status.Error(codes.Unavailable, "signer"), quicwire.StatusUnavailable},
		{"Internal", status.Error(codes.Internal, "boom"), quicwire.StatusInternalError},
		{"UnknownCode", status.Error(codes.Aborted, "aborted"), quicwire.StatusInternalError},
		{"NonStatusError", configdelivery.ErrInvalidRequest{Reason: "raw"}, quicwire.StatusInternalError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.configDeliveryErrorToQUICResponse("TestOp", tc.err)
			if resp.Status != tc.want {
				t.Fatalf("status = 0x%02x, want 0x%02x", resp.Status, tc.want)
			}
			if !strings.Contains(string(resp.Payload), "TestOp") {
				t.Fatalf("expected op name in payload, got %q", resp.Payload)
			}
		})
	}
}
