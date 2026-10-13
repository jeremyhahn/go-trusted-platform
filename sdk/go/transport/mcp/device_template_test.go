// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDeviceTemplateMCP_CreateTemplate(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_template_create": map[string]interface{}{
			"id":          "18446744073709551615",
			"tenant_id":   "tenant-1",
			"name":        "edge",
			"role":        "load-balancer",
			"config":      "hostname: edge-01\n",
			"match_rules": map[string]interface{}{"mac_prefix": "00:25:90"},
			"created_at":  "2026-10-12T09:00:00Z",
			"updated_at":  "2026-10-12T09:00:00Z",
		},
	}, &calls)

	resp := &platformv1.DeviceTemplateCreateResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateTemplate_FullMethodName,
		&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{
			TenantId:   "tenant-1",
			Name:       "edge",
			Role:       platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
			Config:     []byte("hostname: edge-01\n"),
			MatchRules: &platformv1.ProfileMatchRules{MacPrefix: "00:25:90"},
		}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if calls[0].Name != "device_template_create" {
		t.Fatalf("tool = %q, want device_template_create", calls[0].Name)
	}
	args := calls[0].Arguments
	if args["name"] != "edge" || args["tenant_id"] != "tenant-1" {
		t.Errorf("args = %v", args)
	}
	if args["role"] != "load-balancer" {
		t.Errorf("role = %v, want the domain role string", args["role"])
	}
	if args["config"] != "hostname: edge-01\n" {
		t.Errorf("config = %v, want YAML text", args["config"])
	}
	if rules, _ := args["match_rules"].(map[string]interface{}); rules["mac_prefix"] != "00:25:90" {
		t.Errorf("match_rules = %v", args["match_rules"])
	}
	if _, sent := args["description"]; sent {
		t.Error("an unset field must not be sent")
	}

	got := resp.GetTemplate()
	if got.GetId() != 18446744073709551615 {
		t.Errorf("id = %d, want the full uint64", got.GetId())
	}
	if got.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER {
		t.Errorf("role = %v", got.GetRole())
	}
	if string(got.GetConfig()) != "hostname: edge-01\n" {
		t.Errorf("config = %q", got.GetConfig())
	}
	if got.GetMatchRules().GetMacPrefix() != "00:25:90" || got.GetCreatedAt() == nil {
		t.Errorf("template = %v", got)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("status must report success")
	}
}

func TestDeviceTemplateMCP_CreateTemplate_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("BMCRefused", func(t *testing.T) {
		var calls []toolCall
		a := provisioningTestServer(t, map[string]interface{}{}, &calls)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_CreateTemplate_FullMethodName,
			&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{
				Name: "edge",
				Bmc:  &platformv1.BMCConfig{},
			}}, &platformv1.DeviceTemplateCreateResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		if len(calls) != 0 {
			t.Error("a refused request must not reach the server")
		}
	})

	t.Run("WrongArgsType", func(t *testing.T) {
		if _, err := buildDeviceTemplateCreateArgs(&platformv1.GetDeviceRequest{}); err == nil {
			t.Fatal("expected ErrUnexpectedArgsType")
		}
	})

	t.Run("WrongReplyType", func(t *testing.T) {
		err := decodeDeviceTemplateCreateResult(map[string]interface{}{}, &platformv1.CreateProfileResponse{})
		if _, ok := err.(ErrUnexpectedReplyType); !ok {
			t.Fatalf("err = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("ResultNotAnObject", func(t *testing.T) {
		if err := decodeDeviceTemplateCreateResult([]interface{}{"x"}, &platformv1.DeviceTemplateCreateResponse{}); err == nil {
			t.Fatal("expected a decode error")
		}
	})
}

func TestDeviceTemplateMCP_CreateProfileFromTemplate(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"profile_create_from_template": map[string]interface{}{
			"id":        "9007199254740993",
			"name":      "gw-01",
			"role":      "gateway",
			"ek_serial": "EK-1",
			"config":    map[string]interface{}{"hostname": "gw-01"},
		},
	}, &calls)

	resp := &platformv1.CreateProfileResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
		&platformv1.CreateProfileFromTemplateRequest{
			TemplateId: 18446744073709551615,
			Overrides: &platformv1.DeviceProfile{
				Name:       "gw-01",
				EkSerial:   "EK-1",
				MacAddress: "00:25:90:aa:bb:01",
				EventLog:   []byte{0x01, 0x02},
			},
		}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["template_id"] != "18446744073709551615" {
		t.Errorf("template_id = %v (%T), want decimal string", args["template_id"], args["template_id"])
	}
	overrides, _ := args["overrides"].(map[string]interface{})
	if overrides["name"] != "gw-01" || overrides["ek_serial"] != "EK-1" || overrides["mac_address"] != "00:25:90:aa:bb:01" {
		t.Errorf("overrides = %v", overrides)
	}
	if overrides["event_log"] != "AQI=" {
		t.Errorf("event_log = %v, want base64", overrides["event_log"])
	}
	if _, sent := overrides["role"]; sent {
		t.Error("an unset role must not be sent, so the template's role is kept")
	}

	got := resp.GetProfile()
	if got.GetId() != 9007199254740993 {
		t.Errorf("id = %d, want the exact uint64", got.GetId())
	}
	if got.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_GATEWAY || got.GetEkSerial() != "EK-1" {
		t.Errorf("profile = %v", got)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("status must report success")
	}
}

func TestDeviceTemplateMCP_CreateProfileFromTemplate_Errors(t *testing.T) {
	ctx := context.Background()

	refused := map[string]*platformv1.DeviceProfile{
		"TenantID":        {TenantId: "tenant-2"},
		"Networks":        {Networks: map[string]*platformv1.NetworkPhaseConfig{"admitted": {}}},
		"PlatformdConfig": {PlatformdConfig: &platformv1.PlatformdConfigRef{}},
	}
	for name, overrides := range refused {
		t.Run(name, func(t *testing.T) {
			var calls []toolCall
			a := provisioningTestServer(t, map[string]interface{}{}, &calls)
			err := a.Connection().Invoke(ctx, platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
				&platformv1.CreateProfileFromTemplateRequest{TemplateId: 1, Overrides: overrides},
				&platformv1.CreateProfileResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if len(calls) != 0 {
				t.Error("a refused request must not reach the server")
			}
		})
	}

	t.Run("WrongArgsType", func(t *testing.T) {
		if _, err := buildProfileFromTemplateArgs(&platformv1.GetDeviceRequest{}); err == nil {
			t.Fatal("expected ErrUnexpectedArgsType")
		}
	})

	t.Run("WrongReplyType", func(t *testing.T) {
		err := decodeProfileFromTemplateResult(map[string]interface{}{}, &platformv1.DeviceTemplateCreateResponse{})
		if _, ok := err.(ErrUnexpectedReplyType); !ok {
			t.Fatalf("err = %v, want ErrUnexpectedReplyType", err)
		}
	})
}
