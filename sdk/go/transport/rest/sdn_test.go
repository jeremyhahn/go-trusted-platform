// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sentRequest is what the test server saw of one SDK request.
type sentRequest struct {
	method string
	path   string
	body   map[string]interface{}
}

// sdnOverREST answers every non-health request with answer and records it.
func sdnOverREST(t *testing.T, answer string) (platformv1.SDNServiceClient, *sentRequest) {
	t.Helper()
	sent := &sentRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		sent.method, sent.path = r.Method, r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(raw, &sent.body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	})
	return platformv1.NewSDNServiceClient(a.Connection()), sent
}

func TestSDNSetPortState_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t,
		`{"bridge_id":"br-int","port_id":"eth0","port_number":7,"admin_state":"down","oper_state":"down"}`)

	resp, err := client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId:    "br-int",
		PortId:      "eth0",
		AdminState:  "down",
		IngressRate: 10_000,
	})
	if err != nil {
		t.Fatalf("SetPortState over REST: %v", err)
	}

	if sent.method != http.MethodPut || sent.path != "/api/v1/sdn/bridges/br-int/ports/eth0/state" {
		t.Errorf("sent %s %s, want PUT /api/v1/sdn/bridges/br-int/ports/eth0/state", sent.method, sent.path)
	}
	if sent.body["admin_state"] != "down" || sent.body["ingress_rate"] != float64(10_000) {
		t.Errorf("body = %v, want admin_state down and ingress_rate 10000", sent.body)
	}
	if _, ok := sent.body["bridge_id"]; ok {
		t.Errorf("body = %v: the bridge travels in the path, not the body", sent.body)
	}

	port := resp.GetPort()
	if port.GetBridgeId() != "br-int" || port.GetConfig().GetName() != "eth0" ||
		port.GetStatus() != platformv1.PortStatus_PORT_STATUS_DOWN {
		t.Errorf("port = %v, want eth0 on br-int, status DOWN", port)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
}

func TestSDNSetPortState_SDKOverRESTRefusesAnEmptyPort(t *testing.T) {
	client, sent := sdnOverREST(t, `{}`)

	_, err := client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br-int", AdminState: "up",
	})
	if err == nil {
		t.Fatal("SetPortState without a port_id succeeded, want InvalidArgument")
	}
	if sent.path != "" {
		t.Errorf("a request without a port reached the server: %s %s", sent.method, sent.path)
	}
}

func TestDecodeSDNSetPortState(t *testing.T) {
	t.Run("maps an unknown admin state to unspecified", func(t *testing.T) {
		reply := &platformv1.SetPortStateResponse{}
		if err := decodeSDNSetPortState([]byte(`{"port_id":"eth0","admin_state":"testing"}`), reply); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if reply.GetPort().GetStatus() != platformv1.PortStatus_PORT_STATUS_UNSPECIFIED {
			t.Errorf("status = %v, want UNSPECIFIED", reply.GetPort().GetStatus())
		}
	})

	t.Run("refuses a reply of another type", func(t *testing.T) {
		err := decodeSDNSetPortState([]byte(`{}`), &platformv1.GetPortResponse{})
		var typed ErrUnexpectedReplyType
		if !errors.As(err, &typed) {
			t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("refuses a body that is not JSON", func(t *testing.T) {
		err := decodeSDNSetPortState([]byte(`not json`), &platformv1.SetPortStateResponse{})
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
		}
	})
}
