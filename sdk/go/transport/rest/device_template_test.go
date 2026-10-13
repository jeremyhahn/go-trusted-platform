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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// templateRequest records what a device template handler stub received.
type templateRequest struct {
	method string
	path   string
	body   map[string]interface{}
}

// templateServer answers every API request with payload in the standard
// envelope and records the request it was sent.
func templateServer(t *testing.T, payload string) (*Adapter, *templateRequest) {
	t.Helper()
	captured := &templateRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"code":201,"success":true,"payload":` + payload + `}`))
	})
	return a, captured
}

func TestDeviceCreateTemplate_REST(t *testing.T) {
	a, captured := templateServer(t, `{
		"id": "18446744073709551615",
		"name": "edge",
		"role": "load-balancer",
		"config": "aG9zdG5hbWU6IGVkZ2UtMDEK",
		"created_at": "2026-10-12T09:00:00Z",
		"updated_at": "2026-10-12T09:00:00Z"
	}`)

	resp := &platformv1.DeviceTemplateCreateResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateTemplate_FullMethodName,
		&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{
			Name:       "edge",
			Role:       platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
			Config:     []byte("hostname: edge-01\n"),
			MatchRules: &platformv1.ProfileMatchRules{MacPrefix: "00:25:90"},
		}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/device/templates" {
		t.Errorf("request = %s %s, want POST /api/v1/device/templates", captured.method, captured.path)
	}
	if captured.body["role"] != "load-balancer" {
		t.Errorf("role = %v, want the domain role string", captured.body["role"])
	}
	if captured.body["config"] != "aG9zdG5hbWU6IGVkZ2UtMDEK" {
		t.Errorf("config = %v, want the bytes as base64", captured.body["config"])
	}
	if rules, _ := captured.body["match_rules"].(map[string]interface{}); rules["mac_prefix"] != "00:25:90" {
		t.Errorf("match_rules = %v, want snake_case fields", captured.body["match_rules"])
	}

	template := resp.GetTemplate()
	if template.GetId() != 18446744073709551615 || template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER {
		t.Errorf("template = %v, id or role not decoded", template)
	}
	if string(template.GetConfig()) != "hostname: edge-01\n" {
		t.Errorf("config = %q, want the base64 decoded once", template.GetConfig())
	}
	if !resp.GetStatus().GetSuccess() {
		t.Error("status not set on the reply")
	}
}

func TestDeviceCreateProfileFromTemplate_REST(t *testing.T) {
	a, captured := templateServer(t, `{"id": "77", "name": "gw-01", "role": "gateway", "ek_serial": "EK-1"}`)

	resp := &platformv1.CreateProfileResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
		&platformv1.CreateProfileFromTemplateRequest{
			TemplateId: 9000,
			Overrides:  &platformv1.DeviceProfile{Name: "gw-01", EkSerial: "EK-1"},
		}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if captured.method != http.MethodPost || captured.path != "/api/v1/device/templates/9000/create-profile" {
		t.Errorf("request = %s %s, want POST /api/v1/device/templates/9000/create-profile", captured.method, captured.path)
	}
	if _, has := captured.body["template_id"]; has {
		t.Errorf("body = %v, template_id must travel in the path only", captured.body)
	}
	overrides, _ := captured.body["overrides"].(map[string]interface{})
	if overrides["name"] != "gw-01" || overrides["ek_serial"] != "EK-1" {
		t.Errorf("overrides = %v, fields not mapped", overrides)
	}

	profile := resp.GetProfile()
	if profile.GetId() != 77 || profile.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_GATEWAY {
		t.Errorf("profile = %v, id or role not decoded", profile)
	}
}

func TestDeviceTemplate_REST_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("BMCRefusedBeforeTheWire", func(t *testing.T) {
		a, captured := templateServer(t, `{}`)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_CreateTemplate_FullMethodName,
			&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{
				Name: "edge",
				Bmc:  &platformv1.BMCConfig{},
			}}, &platformv1.DeviceTemplateCreateResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		if captured.path != "" {
			t.Errorf("request reached %s, want it refused locally", captured.path)
		}
	})

	t.Run("ZeroTemplateIDRefused", func(t *testing.T) {
		a, _ := templateServer(t, `{}`)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
			&platformv1.CreateProfileFromTemplateRequest{}, &platformv1.CreateProfileResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
	})

	t.Run("UndecodablePayload", func(t *testing.T) {
		a, _ := templateServer(t, `{"name": 42}`)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_CreateTemplate_FullMethodName,
			&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{Name: "edge"}},
			&platformv1.DeviceTemplateCreateResponse{})
		if status.Code(err) != codes.Internal {
			t.Fatalf("err = %v, want Internal", err)
		}
	})

	t.Run("WrongMessageTypes", func(t *testing.T) {
		var requestErr ErrUnexpectedRequestType
		if _, err := encodeCreateTemplate(&platformv1.CreateProfileFromTemplateRequest{}); !errors.As(err, &requestErr) {
			t.Errorf("encodeCreateTemplate err = %v, want ErrUnexpectedRequestType", err)
		}
		var replyErr ErrUnexpectedReplyType
		if err := decodeCreateTemplate([]byte(`{}`), &platformv1.CreateProfileResponse{}); !errors.As(err, &replyErr) {
			t.Errorf("decodeCreateTemplate err = %v, want ErrUnexpectedReplyType", err)
		}
	})
}
