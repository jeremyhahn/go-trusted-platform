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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// enveloped wraps payload in the webservice response envelope.
func enveloped(payload string) string {
	return `{"code":200,"success":true,"payload":` + payload + `}`
}

// assertNoIDsInBody fails when any of the path-borne fields travelled in the
// body too.
func assertNoIDsInBody(t *testing.T, sent *sentRequest, fields ...string) {
	t.Helper()
	for _, field := range fields {
		if _, ok := sent.body[field]; ok {
			t.Errorf("body = %v: %s travels in the path, not the body", sent.body, field)
		}
	}
}

func TestSDNDeleteBridge_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t, enveloped(`{"success":true,"message":"bridge deleted"}`))

	resp, err := client.DeleteBridge(context.Background(), &platformv1.DeleteBridgeRequest{Id: "br-int", Force: true})
	if err != nil {
		t.Fatalf("DeleteBridge over REST: %v", err)
	}

	if sent.method != http.MethodDelete || sent.path != "/api/v1/sdn/bridges/br-int" {
		t.Errorf("sent %s %s, want DELETE /api/v1/sdn/bridges/br-int", sent.method, sent.path)
	}
	assertNoIDsInBody(t, sent, "id")
	if sent.body["force"] != true {
		t.Errorf("body = %v, want force true", sent.body)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "bridge deleted" {
		t.Errorf("status = %v, want success with the server's message", resp.GetStatus())
	}
}

func TestSDNDeletePort_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t, enveloped(`{"success":true,"message":"port deleted"}`))

	resp, err := client.DeletePort(context.Background(), &platformv1.DeletePortRequest{BridgeId: "br-int", PortId: "eth0"})
	if err != nil {
		t.Fatalf("DeletePort over REST: %v", err)
	}

	if sent.method != http.MethodDelete || sent.path != "/api/v1/sdn/bridges/br-int/ports/eth0" {
		t.Errorf("sent %s %s, want DELETE /api/v1/sdn/bridges/br-int/ports/eth0", sent.method, sent.path)
	}
	assertNoIDsInBody(t, sent, "bridge_id", "port_id")
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "port deleted" {
		t.Errorf("status = %v, want success with the server's message", resp.GetStatus())
	}
}

func TestSDNAuthenticatePort_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t, enveloped(`{"bridge_id":"br-int","port_id":"eth0","authenticated":true,`+
		`"certificate_cn":"device-01","authenticated_at":"2026-10-14T08:00:00Z",`+
		`"expires_at":"2027-10-14T08:00:00Z","authorized_vlans":[10,20]}`))
	cert := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

	resp, err := client.AuthenticatePort(context.Background(), &platformv1.AuthenticatePortRequest{
		BridgeId:    "br-int",
		PortId:      "eth0",
		Certificate: cert,
		Format:      "PEM",
	})
	if err != nil {
		t.Fatalf("AuthenticatePort over REST: %v", err)
	}

	if sent.method != http.MethodPost || sent.path != "/api/v1/sdn/bridges/br-int/ports/eth0/auth" {
		t.Errorf("sent %s %s, want POST /api/v1/sdn/bridges/br-int/ports/eth0/auth", sent.method, sent.path)
	}
	assertNoIDsInBody(t, sent, "bridge_id", "port_id")
	if sent.body["certificate"] != base64.StdEncoding.EncodeToString(cert) || sent.body["format"] != "PEM" {
		t.Errorf("body = %v, want the base64 certificate and format PEM", sent.body)
	}

	auth := resp.GetAuth()
	if !auth.GetAuthenticated() || auth.GetCertificateCn() != "device-01" {
		t.Errorf("auth = %v, want device-01 authenticated", auth)
	}
	wantAt := time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	if !auth.GetAuthenticatedAt().AsTime().Equal(wantAt) || !auth.GetExpiresAt().AsTime().Equal(wantAt.AddDate(1, 0, 0)) {
		t.Errorf("auth times = %v / %v, want %v and a year later", auth.GetAuthenticatedAt(), auth.GetExpiresAt(), wantAt)
	}
	if len(auth.GetAuthorizedVlans()) != 2 || auth.GetAuthorizedVlans()[1] != 20 {
		t.Errorf("authorized VLANs = %v, want [10 20]", auth.GetAuthorizedVlans())
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
}

func TestSDNRevokePortAuth_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t, enveloped(`{"success":true,"message":"revoked"}`))

	resp, err := client.RevokePortAuth(context.Background(), &platformv1.RevokePortAuthRequest{BridgeId: "br-int", PortId: "eth0"})
	if err != nil {
		t.Fatalf("RevokePortAuth over REST: %v", err)
	}

	if sent.method != http.MethodDelete || sent.path != "/api/v1/sdn/bridges/br-int/ports/eth0/auth" {
		t.Errorf("sent %s %s, want DELETE /api/v1/sdn/bridges/br-int/ports/eth0/auth", sent.method, sent.path)
	}
	assertNoIDsInBody(t, sent, "bridge_id", "port_id")
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "revoked" {
		t.Errorf("status = %v, want success with the server's message", resp.GetStatus())
	}
}

func TestSDNAddPort_SDKOverREST(t *testing.T) {
	client, sent := sdnOverREST(t, enveloped(`{"id":"uuid-1","bridge_id":"br-int","name":"tap0","type":"tap",`+
		`"vlan":10,"status":"up","created_at":"2026-10-14T08:00:00Z","labels":{"tier":"edge"}}`))

	resp, err := client.AddPort(context.Background(), &platformv1.AddPortRequest{
		BridgeId: "br-int",
		Config: &platformv1.PortConfig{
			Name:       "tap0",
			Type:       platformv1.PortType_PORT_TYPE_TAP,
			Vlan:       10,
			TrunkVlans: []uint32{20, 30},
			Labels:     map[string]string{"tier": "edge"},
		},
	})
	if err != nil {
		t.Fatalf("AddPort over REST: %v", err)
	}

	if sent.method != http.MethodPost || sent.path != "/api/v1/sdn/bridges/br-int/ports" {
		t.Errorf("sent %s %s, want POST /api/v1/sdn/bridges/br-int/ports", sent.method, sent.path)
	}
	assertNoIDsInBody(t, sent, "bridge_id", "config")
	if sent.body["name"] != "tap0" || sent.body["type"] != "tap" || sent.body["vlan"] != float64(10) {
		t.Errorf("body = %v, want the flat port document for tap0", sent.body)
	}
	if trunks, ok := sent.body["trunk_vlans"].([]interface{}); !ok || len(trunks) != 2 {
		t.Errorf("body trunk_vlans = %v, want [20 30]", sent.body["trunk_vlans"])
	}

	port := resp.GetPort()
	if port.GetId() != "uuid-1" || port.GetBridgeId() != "br-int" || port.GetConfig().GetName() != "tap0" {
		t.Errorf("port = %v, want tap0 (uuid-1) on br-int", port)
	}
	if port.GetConfig().GetType() != platformv1.PortType_PORT_TYPE_TAP || port.GetStatus() != platformv1.PortStatus_PORT_STATUS_UP {
		t.Errorf("port type/status = %v/%v, want TAP/UP", port.GetConfig().GetType(), port.GetStatus())
	}
	if port.GetConfig().GetLabels()["tier"] != "edge" || port.GetCreatedAt() == nil || port.GetUpdatedAt() != nil {
		t.Errorf("port = %v, want label tier=edge, a creation time and no update time", port)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
}

func TestSDNAddPort_SDKOverRESTRefusesAnUnknownPortType(t *testing.T) {
	client, sent := sdnOverREST(t, `{}`)

	_, err := client.AddPort(context.Background(), &platformv1.AddPortRequest{
		BridgeId: "br-int",
		Config:   &platformv1.PortConfig{Name: "tap0", Type: platformv1.PortType(99)},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AddPort with port type 99 = %v, want InvalidArgument", err)
	}
	if sent.path != "" {
		t.Errorf("a request with an unknown port type reached the server: %s %s", sent.method, sent.path)
	}
}

func TestSDNPortRoutes_SDKOverRESTRefuseAnEmptyID(t *testing.T) {
	tests := []struct {
		name string
		call func(platformv1.SDNServiceClient) error
	}{
		{name: "DeleteBridge", call: func(c platformv1.SDNServiceClient) error {
			_, err := c.DeleteBridge(context.Background(), &platformv1.DeleteBridgeRequest{})
			return err
		}},
		{name: "DeletePort", call: func(c platformv1.SDNServiceClient) error {
			_, err := c.DeletePort(context.Background(), &platformv1.DeletePortRequest{BridgeId: "br-int"})
			return err
		}},
		{name: "AuthenticatePort", call: func(c platformv1.SDNServiceClient) error {
			_, err := c.AuthenticatePort(context.Background(), &platformv1.AuthenticatePortRequest{PortId: "eth0"})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, sent := sdnOverREST(t, `{}`)
			if err := tt.call(client); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("%s without an ID = %v, want InvalidArgument", tt.name, err)
			}
			if sent.path != "" {
				t.Errorf("a request without an ID reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}

func TestSDNStatusDecoder(t *testing.T) {
	decode := restResponseDecoders[platformv1.SDNService_DeletePort_FullMethodName]

	t.Run("refuses a reply of another type", func(t *testing.T) {
		err := decode([]byte(`{"success":true}`), &platformv1.DeleteBridgeResponse{})
		var typed ErrUnexpectedReplyType
		if !errors.As(err, &typed) {
			t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("refuses a body that is not JSON", func(t *testing.T) {
		err := decode([]byte(`not json`), &platformv1.DeletePortResponse{})
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
		}
	})

	t.Run("carries a refusal through", func(t *testing.T) {
		reply := &platformv1.DeletePortResponse{}
		if err := decode([]byte(`{"success":false,"message":"busy"}`), reply); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "busy" {
			t.Errorf("status = %v, want unsuccessful with message busy", reply.GetStatus())
		}
	})
}

func TestDecodeSDNPortDocuments(t *testing.T) {
	t.Run("AddPort maps unknown names to unspecified", func(t *testing.T) {
		resp, err := decodeSDNAddPort([]byte(`{"name":"p0","type":"loopback","status":"unknown"}`))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.GetPort().GetConfig().GetType() != platformv1.PortType_PORT_TYPE_UNSPECIFIED ||
			resp.GetPort().GetStatus() != platformv1.PortStatus_PORT_STATUS_UNSPECIFIED {
			t.Errorf("port = %v, want type and status UNSPECIFIED", resp.GetPort())
		}
	})

	t.Run("AddPort refuses a body that is not JSON", func(t *testing.T) {
		_, err := decodeSDNAddPort([]byte(`not json`))
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
		}
	})

	t.Run("AuthenticatePort refuses a body that is not JSON", func(t *testing.T) {
		_, err := decodeSDNAuthenticatePort([]byte(`not json`))
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
		}
	})
}

func TestSDNPortTypeName(t *testing.T) {
	tests := []struct {
		in   platformv1.PortType
		want string
	}{
		{in: platformv1.PortType_PORT_TYPE_UNSPECIFIED, want: ""},
		{in: platformv1.PortType_PORT_TYPE_INTERNAL, want: "internal"},
		{in: platformv1.PortType_PORT_TYPE_VXLAN, want: "vxlan"},
	}
	for _, tt := range tests {
		got, err := sdnPortTypeName(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("sdnPortTypeName(%v) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}

	_, err := sdnPortTypeName(platformv1.PortType(99))
	var typed ErrUnknownPortType
	if !errors.As(err, &typed) || typed.Type != 99 {
		t.Errorf("sdnPortTypeName(99) = %v, want ErrUnknownPortType{99}", err)
	}
}
