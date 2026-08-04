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

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// toolCall records the tool invocation the test server received.
type toolCall struct {
	Name      string
	Arguments map[string]interface{}
}

// provisioningTestServer runs a JSON-RPC MCP server that records tools/call
// requests and answers with the supplied per-tool results.
func provisioningTestServer(t *testing.T, results map[string]interface{}, calls *[]toolCall) *Adapter {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpapi.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(mcpapi.JSONRPCResponse{
				JSONRPC: "2.0", ID: req.ID,
				Result: map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo":      map[string]string{"name": "test", "version": "1.0"},
					"capabilities":    map[string]interface{}{},
				},
			})
		case "tools/call":
			params, _ := req.Params.(map[string]interface{})
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]interface{})
			*calls = append(*calls, toolCall{Name: name, Arguments: args})
			_ = json.NewEncoder(w).Encode(mcpapi.JSONRPCResponse{
				JSONRPC: "2.0", ID: req.ID, Result: results[name],
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	adapter, err := Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(server.URL)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	return adapter.(*Adapter)
}

func TestProvisioning_GetNonce_ToolMappingAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_get_nonce": map[string]interface{}{"nonce": "n-9"},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.GetNonceResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/GetNonce",
		&platformv1.GetNonceRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "provision_get_nonce" {
		t.Fatalf("calls = %+v, want single provision_get_nonce", calls)
	}
	if resp.GetNonce() != "n-9" {
		t.Errorf("nonce = %q, want n-9", resp.GetNonce())
	}
}

func TestProvisioning_FetchConfig_SnakeCaseArgsAndDelivered(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_fetch_config": map[string]interface{}{
			"config": map[string]interface{}{"hostname": "lab-node-2"},
			"status": "ok",
		},
	}, &calls)

	conn := a.Connection()
	req := &platformv1.FetchConfigRequest{
		EkSerial:   "EK1",
		MacAddress: "aa:bb",
		EabKeyId:   "kid",
		EabHmac:    "mac",
		Nonce:      "n",
	}
	resp := &platformv1.FetchConfigResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig", req, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["ek_serial"] != "EK1" || args["mac_address"] != "aa:bb" ||
		args["eab_key_id"] != "kid" || args["eab_hmac"] != "mac" || args["nonce"] != "n" {
		t.Errorf("tool arguments = %v, want snake_case identity fields", args)
	}

	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered arm, got %+v", resp)
	}
	var cfg map[string]any
	if err := json.Unmarshal(delivered.GetConfigJson(), &cfg); err != nil {
		t.Fatalf("config_json invalid: %v", err)
	}
	if cfg["hostname"] != "lab-node-2" {
		t.Errorf("config = %v", cfg)
	}
}

func TestProvisioning_FetchConfig_Pending(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_fetch_config": map[string]interface{}{
			"session_id":            "sess-3",
			"provision_url":         "https://cp/p/sess-3",
			"poll_interval_seconds": 5,
		},
	}, &calls)

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
	if pending.GetSessionId() != "sess-3" || pending.GetPollIntervalSeconds() != 5 {
		t.Errorf("pending = %+v", pending)
	}
}

func TestProvisioning_SignDigest_Base64ArgsAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		// sign_digest returns std-b64 signature and cert_pem: "sig", "PEM".
		"provision_sign_digest": map[string]interface{}{
			"signature": "c2ln",
			"cert_pem":  "UEVN",
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.SignDigestResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/SignDigest",
		&platformv1.SignDigestRequest{Digest: []byte("digest"), KeyRef: "db"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	// pb bytes marshal as std base64 through encoding/json: "digest" -> ZGlnZXN0
	if calls[0].Arguments["digest"] != "ZGlnZXN0" {
		t.Errorf("digest argument = %v, want ZGlnZXN0", calls[0].Arguments["digest"])
	}
	if calls[0].Arguments["key_ref"] != "db" {
		t.Errorf("key_ref = %v, want db", calls[0].Arguments["key_ref"])
	}
	if string(resp.GetSignature()) != "sig" || string(resp.GetCertPem()) != "PEM" {
		t.Errorf("decoded = sig:%q cert:%q", resp.GetSignature(), resp.GetCertPem())
	}
}

func TestProvisioning_PollSession_PendingAndDelivered(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		var calls []toolCall
		a := provisioningTestServer(t, map[string]interface{}{
			"provision_poll_session": map[string]interface{}{"status": "pending"},
		}, &calls)

		conn := a.Connection()
		resp := &platformv1.PollSessionResponse{}
		err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/PollSession",
			&platformv1.PollSessionRequest{SessionId: "sess-1"}, resp)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if calls[0].Arguments["session_id"] != "sess-1" {
			t.Errorf("session_id argument = %v", calls[0].Arguments["session_id"])
		}
		if resp.GetPendingStatus() != "pending" {
			t.Errorf("pending_status = %q", resp.GetPendingStatus())
		}
	})

	t.Run("delivered", func(t *testing.T) {
		var calls []toolCall
		a := provisioningTestServer(t, map[string]interface{}{
			"provision_poll_session": map[string]interface{}{
				"config": map[string]interface{}{"role": "compute"},
				"status": "ok",
			},
		}, &calls)

		conn := a.Connection()
		resp := &platformv1.PollSessionResponse{}
		err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/PollSession",
			&platformv1.PollSessionRequest{SessionId: "sess-1"}, resp)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetDelivered().GetStatus() != "ok" {
			t.Errorf("delivered = %+v", resp.GetDelivered())
		}
	})
}

func TestProvisioning_FulfillSession_ProfileIDDecimalString(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_fulfill_session": map[string]interface{}{"status": "fulfilled"},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.FulfillSessionResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FulfillSession",
		&platformv1.FulfillSessionRequest{SessionId: "sess-1", ProfileId: 18446744073709551615}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["session_id"] != "sess-1" {
		t.Errorf("session_id = %v", args["session_id"])
	}
	// The uint64-safe convention: profile_id crosses the wire as a decimal
	// string, never a JSON number.
	if args["profile_id"] != "18446744073709551615" {
		t.Errorf("profile_id = %v (%T), want decimal string", args["profile_id"], args["profile_id"])
	}
	if resp.GetStatus() != "fulfilled" {
		t.Errorf("status = %q", resp.GetStatus())
	}
}

func TestProvisioning_ListSessions_WrappedDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_list_sessions": map[string]interface{}{
			"sessions": []interface{}{
				map[string]interface{}{
					"id":         "sess-1",
					"ek_serial":  "EK1",
					"profile_id": 42,
					"fulfilled":  true,
					"created_at": "2026-08-01T10:00:00Z",
					"expires_at": "2026-08-01T10:15:00Z",
					"profile": map[string]interface{}{
						"id":   42,
						"name": "lab-node-2",
						"role": "server",
					},
				},
			},
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.ListSessionsResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/ListSessions",
		&platformv1.ListSessionsRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(resp.GetSessions()))
	}
	session := resp.GetSessions()[0]
	if session.GetId() != "sess-1" || session.GetProfileId() != 42 || !session.GetFulfilled() {
		t.Errorf("session = %+v", session)
	}
	if session.GetProfile().GetRole() != platformv1.DeviceRole_DEVICE_ROLE_SERVER {
		t.Errorf("profile role = %v", session.GetProfile().GetRole())
	}
	if session.GetCreatedAt() == nil {
		t.Error("created_at timestamp not decoded")
	}
}

func TestProvisioning_GetSession_WrappedDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_get_session": map[string]interface{}{
			"session": map[string]interface{}{
				"id":        "sess-1",
				"fulfilled": false,
			},
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.GetSessionResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/GetSession",
		&platformv1.GetSessionRequest{SessionId: "sess-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if calls[0].Name != "provision_get_session" {
		t.Errorf("tool = %q", calls[0].Name)
	}
	if resp.GetSession().GetId() != "sess-1" {
		t.Errorf("session = %+v", resp.GetSession())
	}
}

func TestProvisioning_ListSessions_DecodeFailureSurfacesInternal(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"provision_list_sessions": map[string]interface{}{"sessions": "garbage"},
	}, &calls)

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

func TestBuildProvisionFulfillSessionArgs_WrongType(t *testing.T) {
	_, err := buildProvisionFulfillSessionArgs(&platformv1.GetNonceRequest{})
	if err == nil {
		t.Fatal("expected error for wrong request type")
	}
	if _, ok := err.(ErrUnexpectedArgsType); !ok {
		t.Errorf("expected ErrUnexpectedArgsType, got %T", err)
	}
}

func TestProvisionReplyDecoders_WrongReplyType(t *testing.T) {
	wrong := &platformv1.GetNonceResponse{}
	if err := decodeProvisionFetchConfigResult(map[string]interface{}{}, wrong); err == nil {
		t.Error("decodeProvisionFetchConfigResult must reject wrong reply type")
	}
	if err := decodeProvisionPollSessionResult(map[string]interface{}{}, wrong); err == nil {
		t.Error("decodeProvisionPollSessionResult must reject wrong reply type")
	}
	if err := decodeProvisionListSessionsResult(map[string]interface{}{}, wrong); err == nil {
		t.Error("decodeProvisionListSessionsResult must reject wrong reply type")
	}
	if err := decodeProvisionGetSessionResult(map[string]interface{}{}, wrong); err == nil {
		t.Error("decodeProvisionGetSessionResult must reject wrong reply type")
	}
}
