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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// envelope wraps a payload in the standard platformd REST response envelope
// (sdk/go/wire/restwire.WebServiceResponse).
func envelope(payload string) string {
	return `{"code":200,"error":"","success":true,"payload":` + payload + `}`
}

func TestProvisioning_GetNonce_RouteAndDecode(t *testing.T) {
	var captured struct {
		method string
		path   string
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"nonce":"n-1"}`)))
	})

	conn := a.Connection()
	resp := &platformv1.GetNonceResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/GetNonce",
		&platformv1.GetNonceRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodGet {
		t.Errorf("method = %q, want GET", captured.method)
	}
	if captured.path != "/api/v1/provisioning/config/nonce" {
		t.Errorf("path = %q, want /api/v1/provisioning/config/nonce", captured.path)
	}
	if resp.GetNonce() != "n-1" {
		t.Errorf("nonce = %q, want n-1", resp.GetNonce())
	}
}

func TestProvisioning_FetchConfig_Delivered(t *testing.T) {
	var captured struct {
		method string
		path   string
		body   map[string]interface{}
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"config":{"hostname":"node-02"},"status":"ok"}`)))
	})

	conn := a.Connection()
	req := &platformv1.FetchConfigRequest{EabKeyId: "kid", EabHmac: "mac", Nonce: "n"}
	resp := &platformv1.FetchConfigResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig", req, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/provisioning/config" {
		t.Errorf("route = %s %s, want POST /api/v1/provisioning/config", captured.method, captured.path)
	}
	if captured.body["eab_key_id"] != "kid" || captured.body["nonce"] != "n" {
		t.Errorf("request body = %v", captured.body)
	}

	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered arm, got %+v", resp)
	}
	if delivered.GetStatus() != "ok" {
		t.Errorf("status = %q", delivered.GetStatus())
	}
	if string(delivered.GetConfigJson()) != `{"hostname":"node-02"}` {
		t.Errorf("config_json = %s", delivered.GetConfigJson())
	}
}

func TestProvisioning_FetchConfig_Pending(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"session_id":"sess-1","provision_url":"https://cp/p/sess-1","poll_interval_seconds":5}`)))
	})

	conn := a.Connection()
	resp := &platformv1.FetchConfigResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig",
		&platformv1.FetchConfigRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	pending := resp.GetPending()
	if pending == nil {
		t.Fatalf("expected pending arm, got %+v", resp)
	}
	if pending.GetSessionId() != "sess-1" || pending.GetPollIntervalSeconds() != 5 {
		t.Errorf("pending = %+v", pending)
	}
}

func TestProvisioning_SignDigest_RouteAndDecode(t *testing.T) {
	var captured struct {
		method string
		path   string
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// encoding/json marshals []byte as std base64: "sig" -> c2ln, "PEM" -> UEVN
		_, _ = w.Write([]byte(envelope(`{"signature":"c2ln","cert_pem":"UEVN"}`)))
	})

	conn := a.Connection()
	resp := &platformv1.SignDigestResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/SignDigest",
		&platformv1.SignDigestRequest{Digest: []byte{1, 2, 3}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/provisioning/sign" {
		t.Errorf("route = %s %s, want POST /api/v1/provisioning/sign", captured.method, captured.path)
	}
	if string(resp.GetSignature()) != "sig" {
		t.Errorf("signature = %q, want sig", resp.GetSignature())
	}
	if string(resp.GetCertPem()) != "PEM" {
		t.Errorf("cert_pem = %q, want PEM", resp.GetCertPem())
	}
}

func TestProvisioning_ListSessions_RouteAndDecode(t *testing.T) {
	var captured struct {
		method string
		path   string
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`[{"id":"sess-1","ek_serial":"EK1","profile_id":42,"fulfilled":false,"created_at":"2026-08-01T10:00:00Z","expires_at":"2026-08-01T10:15:00Z","profile":{"id":42,"name":"node-02","role":"gateway"}}]`)))
	})

	conn := a.Connection()
	resp := &platformv1.ListSessionsResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/ListSessions",
		&platformv1.ListSessionsRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodGet || captured.path != "/api/v1/provisioning/sessions" {
		t.Errorf("route = %s %s, want GET /api/v1/provisioning/sessions", captured.method, captured.path)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(resp.GetSessions()))
	}
	session := resp.GetSessions()[0]
	if session.GetId() != "sess-1" || session.GetProfileId() != 42 {
		t.Errorf("session = %+v", session)
	}
	if session.GetProfile().GetRole() != platformv1.DeviceRole_DEVICE_ROLE_GATEWAY {
		t.Errorf("profile role = %v, want DEVICE_ROLE_GATEWAY", session.GetProfile().GetRole())
	}
}

func TestProvisioning_GetSession_PathTemplated(t *testing.T) {
	var captured struct {
		method string
		path   string
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"id":"sess-1","fulfilled":true}`)))
	})

	conn := a.Connection()
	resp := &platformv1.GetSessionResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/GetSession",
		&platformv1.GetSessionRequest{SessionId: "sess-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodGet {
		t.Errorf("method = %q, want GET", captured.method)
	}
	if captured.path != "/api/v1/provisioning/sessions/sess-1" {
		t.Errorf("path = %q, want /api/v1/provisioning/sessions/sess-1", captured.path)
	}
	if resp.GetSession().GetId() != "sess-1" || !resp.GetSession().GetFulfilled() {
		t.Errorf("session = %+v", resp.GetSession())
	}
}

func TestProvisioning_PollSession_PathTemplated(t *testing.T) {
	var captured struct {
		path string
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"status":"pending"}`)))
	})

	conn := a.Connection()
	resp := &platformv1.PollSessionResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/PollSession",
		&platformv1.PollSessionRequest{SessionId: "sess-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.path != "/api/v1/provisioning/sessions/sess-1/poll" {
		t.Errorf("path = %q, want /api/v1/provisioning/sessions/sess-1/poll", captured.path)
	}
	if resp.GetPendingStatus() != "pending" {
		t.Errorf("pending_status = %q, want pending", resp.GetPendingStatus())
	}
}

func TestProvisioning_FulfillSession_PathAndBody(t *testing.T) {
	var captured struct {
		method string
		path   string
		body   map[string]interface{}
	}

	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope(`{"status":"fulfilled"}`)))
	})

	conn := a.Connection()
	resp := &platformv1.FulfillSessionResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FulfillSession",
		&platformv1.FulfillSessionRequest{SessionId: "sess-1", ProfileId: 42}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost {
		t.Errorf("method = %q, want POST", captured.method)
	}
	if captured.path != "/api/v1/provisioning/sessions/sess-1/fulfill" {
		t.Errorf("path = %q, want /api/v1/provisioning/sessions/sess-1/fulfill", captured.path)
	}
	// session_id rides in the URL; profile_id stays in the body.
	if _, has := captured.body["session_id"]; has {
		t.Errorf("body must not echo session_id: %v", captured.body)
	}
	if captured.body["profile_id"] != float64(42) {
		t.Errorf("body profile_id = %v, want 42", captured.body["profile_id"])
	}
	if resp.GetStatus() != "fulfilled" {
		t.Errorf("status = %q, want fulfilled", resp.GetStatus())
	}
}

func TestProvisioning_FulfillSession_EmptySessionIDRejected(t *testing.T) {
	var apiHits int
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			apiHits++
		}
		w.WriteHeader(http.StatusOK)
	})

	conn := a.Connection()
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FulfillSession",
		&platformv1.FulfillSessionRequest{ProfileId: 42}, &platformv1.FulfillSessionResponse{})
	if err == nil {
		t.Fatal("expected error for empty session_id path param")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
	if apiHits != 0 {
		t.Errorf("request must not reach the server, got %d API hits", apiHits)
	}
}

func TestProvisioning_DecodeFailureSurfacesInternal(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Sessions key with a non-array value breaks the wire decoder.
		_, _ = w.Write([]byte(envelope(`{"sessions":"garbage"}`)))
	})

	conn := a.Connection()
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/ListSessions",
		&platformv1.ListSessionsRequest{}, &platformv1.ListSessionsResponse{})
	if err == nil {
		t.Fatal("expected decode error")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v, want Internal", status.Code(err))
	}
}

func TestDecodeProvisioningDecoders_WrongReplyType(t *testing.T) {
	wrong := &platformv1.GetNonceResponse{}
	if err := decodeProvisioningFetchConfig(nil, wrong); err == nil {
		t.Error("decodeProvisioningFetchConfig must reject wrong reply type")
	}
	if err := decodeProvisioningPollSession(nil, wrong); err == nil {
		t.Error("decodeProvisioningPollSession must reject wrong reply type")
	}
	if err := decodeProvisioningListSessions(nil, wrong); err == nil {
		t.Error("decodeProvisioningListSessions must reject wrong reply type")
	}
	if err := decodeProvisioningGetSession(nil, wrong); err == nil {
		t.Error("decodeProvisioningGetSession must reject wrong reply type")
	}
}
