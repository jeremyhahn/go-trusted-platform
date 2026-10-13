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

package gateway

import (
	"context"
	"errors"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
)

func TestModesFromNames(t *testing.T) {
	cases := map[string]struct {
		names []string
		want  uint32
	}{
		"one mode":         {[]string{"edge"}, 2},
		"all three":        {[]string{"transit", "overlay", "edge"}, 7},
		"a repeated name":  {[]string{"edge", "edge"}, 2},
		"no names is zero": {nil, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ModesFromNames(tc.names)
			if err != nil {
				t.Fatalf("ModesFromNames(%v): %v", tc.names, err)
			}
			if got != tc.want {
				t.Errorf("ModesFromNames(%v) = %d, want %d", tc.names, got, tc.want)
			}
		})
	}
}

func TestModesFromNames_UnknownName(t *testing.T) {
	for _, bad := range []string{"router", "Edge", ""} {
		_, err := ModesFromNames([]string{"overlay", bad})
		var unknown *ErrUnknownGatewayMode
		if !errors.As(err, &unknown) || unknown.Mode != bad {
			t.Errorf("ModesFromNames(%q): got %v, want ErrUnknownGatewayMode", bad, err)
		}
	}
}

func TestModeNames(t *testing.T) {
	if got, want := ModeNames(7), []string{"overlay", "edge", "transit"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ModeNames(7) = %v, want %v", got, want)
	}
	if got, want := ModeNames(4), []string{"transit"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ModeNames(4) = %v, want %v", got, want)
	}
}

func TestModeNames_UndefinedBitsIgnored(t *testing.T) {
	if got := ModeNames(8 | 16); len(got) != 0 {
		t.Errorf("ModeNames(24) = %v, want none", got)
	}
	if got, want := ModeNames(8|2), []string{"edge"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ModeNames(10) = %v, want %v", got, want)
	}
}

// fakeModeGatewayClient records the SetGatewayMode request it receives.
type fakeModeGatewayClient struct {
	platformv1.GatewayServiceClient

	lastReq *platformv1.SetGatewayModeRequest
}

func (f *fakeModeGatewayClient) SetGatewayMode(_ context.Context, req *platformv1.SetGatewayModeRequest, _ ...grpc.CallOption) (*platformv1.SetGatewayModeResponse, error) {
	f.lastReq = req
	return &platformv1.SetGatewayModeResponse{GatewayStatus: &platformv1.GatewayStatus{Modes: req.GetModes()}}, nil
}

func TestClient_SetModeFromStrings(t *testing.T) {
	fake := &fakeModeGatewayClient{}

	status, err := NewClientFromGRPC(fake).SetModeFromStrings(context.Background(), []string{"overlay", "transit"})

	if err != nil {
		t.Fatalf("SetModeFromStrings: %v", err)
	}
	if fake.lastReq.GetModes() != 5 || status.GetModes() != 5 {
		t.Errorf("sent %d, status %d; want 5", fake.lastReq.GetModes(), status.GetModes())
	}
}

func TestClient_SetModeFromStrings_UnknownName(t *testing.T) {
	fake := &fakeModeGatewayClient{}

	_, err := NewClientFromGRPC(fake).SetModeFromStrings(context.Background(), []string{"l3"})

	var failed *ErrSetModeFailed
	var unknown *ErrUnknownGatewayMode
	if !errors.As(err, &failed) || !errors.As(err, &unknown) {
		t.Fatalf("got %v, want ErrSetModeFailed wrapping ErrUnknownGatewayMode", err)
	}
	if fake.lastReq != nil {
		t.Error("an unknown name must be refused before the RPC")
	}
}
