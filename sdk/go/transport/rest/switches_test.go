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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recordOverREST answers every non-health request with the enveloped payload
// and records it. The path is recorded escaped, so a test can see a port name
// travel as one segment.
func recordOverREST(t *testing.T, payload string) (*Adapter, *sentRequest) {
	t.Helper()
	sent := &sentRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		sent.method, sent.path, sent.query = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(raw) > 0 && json.Unmarshal(raw, &sent.body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":` + payload + `}`))
	})
	return a, sent
}

// switchesOverREST is recordOverREST with a SwitchService client.
func switchesOverREST(t *testing.T, payload string) (platformv1.SwitchServiceClient, *sentRequest) {
	t.Helper()
	a, sent := recordOverREST(t, payload)
	return platformv1.NewSwitchServiceClient(a.Connection()), sent
}

// assertNamesOnlyInPath fails when the switch or port travelled in the body.
func assertNamesOnlyInPath(t *testing.T, sent *sentRequest) {
	t.Helper()
	for _, field := range []string{"switch_name", "port_name"} {
		if _, ok := sent.body[field]; ok {
			t.Errorf("body = %v: %s travels in the path, not the body", sent.body, field)
		}
	}
}

func TestSwitchListPorts_SDKOverREST(t *testing.T) {
	client, sent := switchesOverREST(t,
		`[{"port":"Eth1/3","mode":"trunk","access_vlan":1,"trunk_vlans":[100,200],"native_vlan":10,"enabled":true,"link_up":true,"description":"uplink"}]`)

	resp, err := client.ListPorts(context.Background(), &platformv1.ListSwitchPortsRequest{SwitchName: "tor-1"})
	if err != nil {
		t.Fatalf("ListPorts over REST: %v", err)
	}

	if sent.method != http.MethodGet || sent.path != "/api/v1/switches/tor-1/ports" {
		t.Errorf("sent %s %s, want GET /api/v1/switches/tor-1/ports", sent.method, sent.path)
	}
	assertNamesOnlyInPath(t, sent)

	if len(resp.GetPorts()) != 1 {
		t.Fatalf("ports = %v, want one", resp.GetPorts())
	}
	port := resp.GetPorts()[0]
	if port.GetPort() != "Eth1/3" || port.GetMode() != "trunk" || port.GetNativeVlan() != 10 ||
		len(port.GetTrunkVlans()) != 2 || port.GetTrunkVlans()[1] != 200 ||
		!port.GetEnabled() || !port.GetLinkUp() || port.GetDescription() != "uplink" {
		t.Errorf("port = %v, want Eth1/3 trunk 100,200 native 10, enabled and up", port)
	}
}

func TestSwitchGetPortStatus_SDKOverREST(t *testing.T) {
	client, sent := switchesOverREST(t,
		`{"port":"Eth1/3","mode":"access","access_vlan":100,"enabled":true,"link_up":false}`)

	resp, err := client.GetPortStatus(context.Background(), &platformv1.GetSwitchPortStatusRequest{
		SwitchName: "tor-1", PortName: "Eth1/3",
	})
	if err != nil {
		t.Fatalf("GetPortStatus over REST: %v", err)
	}

	if sent.method != http.MethodGet || sent.path != "/api/v1/switches/tor-1/ports/Eth1%2F3" {
		t.Errorf("sent %s %s, want GET /api/v1/switches/tor-1/ports/Eth1%%2F3", sent.method, sent.path)
	}
	assertNamesOnlyInPath(t, sent)

	port := resp.GetPort()
	if port.GetPort() != "Eth1/3" || port.GetAccessVlan() != 100 || !port.GetEnabled() || port.GetLinkUp() {
		t.Errorf("port = %v, want Eth1/3 access 100, enabled, link down", port)
	}
}

func TestSwitchSetPortVLAN_SDKOverREST(t *testing.T) {
	client, sent := switchesOverREST(t,
		`{"switch":"tor-1","port":"Eth1/3","vlan_id":200,"status":"ok"}`)

	resp, err := client.SetPortVLAN(context.Background(), &platformv1.SetSwitchPortVLANRequest{
		SwitchName: "tor-1", PortName: "Eth1/3", VlanId: 200,
	})
	if err != nil {
		t.Fatalf("SetPortVLAN over REST: %v", err)
	}

	if sent.method != http.MethodPost || sent.path != "/api/v1/switches/tor-1/ports/Eth1%2F3/vlan" {
		t.Errorf("sent %s %s, want POST /api/v1/switches/tor-1/ports/Eth1%%2F3/vlan", sent.method, sent.path)
	}
	if sent.body["vlan_id"] != float64(200) {
		t.Errorf("body = %v, want vlan_id 200", sent.body)
	}
	assertNamesOnlyInPath(t, sent)

	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != switchVLANUpdatedMessage {
		t.Errorf("status = %v, want success %q", resp.GetStatus(), switchVLANUpdatedMessage)
	}
}

func TestSwitchEnableDisablePort_SDKOverREST(t *testing.T) {
	cases := []struct {
		name     string
		action   string
		call     func(platformv1.SwitchServiceClient) (*platformv1.Status, error)
		wantPath string
		wantMsg  string
	}{
		{
			name:   "enable",
			action: "enable",
			call: func(c platformv1.SwitchServiceClient) (*platformv1.Status, error) {
				resp, err := c.EnablePort(context.Background(), &platformv1.EnableSwitchPortRequest{
					SwitchName: "tor-1", PortName: "Eth1/3",
				})
				return resp.GetStatus(), err
			},
			wantPath: "/api/v1/switches/tor-1/ports/Eth1%2F3/enable",
			wantMsg:  switchPortEnabledMessage,
		},
		{
			name:   "disable",
			action: "disable",
			call: func(c platformv1.SwitchServiceClient) (*platformv1.Status, error) {
				resp, err := c.DisablePort(context.Background(), &platformv1.DisableSwitchPortRequest{
					SwitchName: "tor-1", PortName: "Eth1/3",
				})
				return resp.GetStatus(), err
			},
			wantPath: "/api/v1/switches/tor-1/ports/Eth1%2F3/disable",
			wantMsg:  switchPortDisabledMessage,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := switchesOverREST(t,
				`{"switch":"tor-1","port":"Eth1/3","action":"`+tc.action+`","status":"ok"}`)

			got, err := tc.call(client)
			if err != nil {
				t.Fatalf("%s over REST: %v", tc.name, err)
			}
			if sent.method != http.MethodPost || sent.path != tc.wantPath {
				t.Errorf("sent %s %s, want POST %s", sent.method, sent.path, tc.wantPath)
			}
			assertNamesOnlyInPath(t, sent)
			if !got.GetSuccess() || got.GetMessage() != tc.wantMsg {
				t.Errorf("status = %v, want success %q", got, tc.wantMsg)
			}
		})
	}
}

func TestSwitchPortRoutes_RefuseAMissingName(t *testing.T) {
	cases := []struct {
		name string
		call func(platformv1.SwitchServiceClient) error
	}{
		{"ListPorts without a switch", func(c platformv1.SwitchServiceClient) error {
			_, err := c.ListPorts(context.Background(), &platformv1.ListSwitchPortsRequest{})
			return err
		}},
		{"GetPortStatus without a port", func(c platformv1.SwitchServiceClient) error {
			_, err := c.GetPortStatus(context.Background(), &platformv1.GetSwitchPortStatusRequest{SwitchName: "tor-1"})
			return err
		}},
		{"SetPortVLAN without a switch", func(c platformv1.SwitchServiceClient) error {
			_, err := c.SetPortVLAN(context.Background(), &platformv1.SetSwitchPortVLANRequest{PortName: "Eth1/3", VlanId: 200})
			return err
		}},
		{"EnablePort without a port", func(c platformv1.SwitchServiceClient) error {
			_, err := c.EnablePort(context.Background(), &platformv1.EnableSwitchPortRequest{SwitchName: "tor-1"})
			return err
		}},
		{"DisablePort without a port", func(c platformv1.SwitchServiceClient) error {
			_, err := c.DisablePort(context.Background(), &platformv1.DisableSwitchPortRequest{SwitchName: "tor-1"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := switchesOverREST(t, `{}`)
			err := tc.call(client)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if sent.path != "" {
				t.Errorf("a request without its names reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}

func TestSwitchPortRoutes_SurfaceTheServerRefusal(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":404,"success":false,"error":"switch not found"}`))
	})
	client := platformv1.NewSwitchServiceClient(a.Connection())

	_, err := client.GetPortStatus(context.Background(), &platformv1.GetSwitchPortStatusRequest{
		SwitchName: "no-such-switch", PortName: "Eth1/3",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestDecodeSwitchReads(t *testing.T) {
	t.Run("ListPorts refuses a reply of another type", func(t *testing.T) {
		err := decodeSwitchListPorts([]byte(`[]`), &platformv1.GetSwitchPortStatusResponse{})
		var typed ErrUnexpectedReplyType
		if !errors.As(err, &typed) {
			t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("ListPorts refuses an object where a list belongs", func(t *testing.T) {
		err := decodeSwitchListPorts([]byte(`{"port":"Eth1/3"}`), &platformv1.ListSwitchPortsResponse{})
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of an object = %v, want ErrUnmarshalFailed", err)
		}
	})

	t.Run("ListPorts answers an empty list with no ports", func(t *testing.T) {
		reply := &platformv1.ListSwitchPortsResponse{}
		if err := decodeSwitchListPorts([]byte(`[]`), reply); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(reply.GetPorts()) != 0 {
			t.Errorf("ports = %v, want none", reply.GetPorts())
		}
	})

	t.Run("GetPortStatus refuses a reply of another type", func(t *testing.T) {
		err := decodeSwitchGetPortStatus([]byte(`{}`), &platformv1.ListSwitchPortsResponse{})
		var typed ErrUnexpectedReplyType
		if !errors.As(err, &typed) {
			t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("GetPortStatus refuses a body that is not JSON", func(t *testing.T) {
		err := decodeSwitchGetPortStatus([]byte(`not json`), &platformv1.GetSwitchPortStatusResponse{})
		var typed ErrUnmarshalFailed
		if !errors.As(err, &typed) {
			t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
		}
	})
}

func TestDecodeSwitchAcks(t *testing.T) {
	decoders := []struct {
		name   string
		decode restResponseDecoder
		reply  func() interface{}
	}{
		{"SetPortVLAN", decodeSwitchSetPortVLAN, func() interface{} { return &platformv1.SetSwitchPortVLANResponse{} }},
		{"EnablePort", decodeSwitchEnablePort, func() interface{} { return &platformv1.EnableSwitchPortResponse{} }},
		{"DisablePort", decodeSwitchDisablePort, func() interface{} { return &platformv1.DisableSwitchPortResponse{} }},
	}
	for _, d := range decoders {
		t.Run(d.name+" refuses a reply of another type", func(t *testing.T) {
			err := d.decode([]byte(`{"status":"ok"}`), &platformv1.ListSwitchPortsResponse{})
			var typed ErrUnexpectedReplyType
			if !errors.As(err, &typed) {
				t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
			}
		})

		t.Run(d.name+" refuses a body that is not JSON", func(t *testing.T) {
			err := d.decode([]byte(`not json`), d.reply())
			var typed ErrUnmarshalFailed
			if !errors.As(err, &typed) {
				t.Fatalf("decode of a non-JSON body = %v, want ErrUnmarshalFailed", err)
			}
		})

		t.Run(d.name+" refuses an answer that is not ok", func(t *testing.T) {
			err := d.decode([]byte(`{"status":"pending"}`), d.reply())
			var typed ErrSwitchActionNotAcknowledged
			if !errors.As(err, &typed) || typed.Status != "pending" {
				t.Fatalf("decode of a pending answer = %v, want ErrSwitchActionNotAcknowledged{pending}", err)
			}
		})
	}
}
