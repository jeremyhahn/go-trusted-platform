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
	"io"
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
	query  string
	body   map[string]interface{}
}

// templateServer answers every API request with payload in the standard
// envelope and records the request it was sent.
func templateServer(t *testing.T, payload string) (*Adapter, *templateRequest) {
	t.Helper()
	captured := &templateRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health/live" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.RawQuery
		// A read or delete sends no body.
		if err := json.NewDecoder(r.Body).Decode(&captured.body); err != nil && !errors.Is(err, io.EOF) {
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

// TestDeviceTemplateCRUD_REST drives GetTemplate, ListTemplates,
// UpdateTemplate and DeleteTemplate against the handlers' wire shapes: the
// id in the path, the list paged by query and its "total" read as the pb
// total_items, the domain role decoded.
func TestDeviceTemplateCRUD_REST(t *testing.T) {
	ctx := context.Background()
	const edge = `{"id": "5", "name": "edge", "role": "load-balancer", "config": "aG9zdG5hbWU6IGVkZ2UtMDEK"}`

	t.Run("Get", func(t *testing.T) {
		a, captured := templateServer(t, edge)
		resp := &platformv1.DeviceTemplateGetResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.DeviceService_GetTemplate_FullMethodName,
			&platformv1.DeviceTemplateGetRequest{Id: 5}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodGet || captured.path != "/api/v1/device/templates/5" {
			t.Errorf("request = %s %s, want GET /api/v1/device/templates/5", captured.method, captured.path)
		}
		if resp.GetTemplate().GetId() != 5 || resp.GetTemplate().GetRole() != platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER {
			t.Errorf("template = %v, id or role not decoded", resp.GetTemplate())
		}
	})

	t.Run("List", func(t *testing.T) {
		a, captured := templateServer(t, `{"templates": [`+edge+`],
			"pagination": {"page": 2, "page_size": 10, "total": 11, "total_pages": 2, "has_more": false}}`)
		resp := &platformv1.DeviceTemplateListResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.DeviceService_ListTemplates_FullMethodName,
			&platformv1.DeviceTemplateListRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10}}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodGet || captured.path != "/api/v1/device/templates" {
			t.Errorf("request = %s %s, want GET /api/v1/device/templates", captured.method, captured.path)
		}
		if captured.query != "page=2&page_size=10" {
			t.Errorf("query = %q, want page=2&page_size=10", captured.query)
		}
		if len(resp.GetTemplates()) != 1 || string(resp.GetTemplates()[0].GetConfig()) != "hostname: edge-01\n" {
			t.Errorf("templates = %v, want the one template decoded", resp.GetTemplates())
		}
		if page := resp.GetPagination(); page.GetTotalItems() != 11 || page.GetTotalPages() != 2 || page.GetPage() != 2 {
			t.Errorf("pagination = %v, want page 2 of 2 with 11 items", page)
		}
	})

	t.Run("Update", func(t *testing.T) {
		a, captured := templateServer(t, edge)
		resp := &platformv1.DeviceTemplateUpdateResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.DeviceService_UpdateTemplate_FullMethodName,
			&platformv1.DeviceTemplateUpdateRequest{Template: &platformv1.DeviceTemplate{
				Id:     5,
				Name:   "edge",
				Role:   platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
				Config: []byte("hostname: edge-01\n"),
			}}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodPut || captured.path != "/api/v1/device/templates/5" {
			t.Errorf("request = %s %s, want PUT /api/v1/device/templates/5", captured.method, captured.path)
		}
		if captured.body["role"] != "load-balancer" || captured.body["config"] != "aG9zdG5hbWU6IGVkZ2UtMDEK" {
			t.Errorf("body = %v, want the domain TemplateRequest", captured.body)
		}
		if resp.GetTemplate().GetName() != "edge" || !resp.GetStatus().GetSuccess() {
			t.Errorf("reply = %v, want the stored template and a success status", resp)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		a, captured := templateServer(t, `{}`)
		if err := a.Connection().Invoke(ctx, platformv1.DeviceService_DeleteTemplate_FullMethodName,
			&platformv1.DeviceTemplateDeleteRequest{Id: 5}, &platformv1.DeviceTemplateDeleteResponse{}); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if captured.method != http.MethodDelete || captured.path != "/api/v1/device/templates/5" {
			t.Errorf("request = %s %s, want DELETE /api/v1/device/templates/5", captured.method, captured.path)
		}
	})
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
		decodeCreate := templateReplyDecoder(platformv1.DeviceService_CreateTemplate_FullMethodName)
		if err := decodeCreate([]byte(`{}`), &platformv1.CreateProfileResponse{}); !errors.As(err, &replyErr) {
			t.Errorf("CreateTemplate reply decoder err = %v, want ErrUnexpectedReplyType", err)
		}
		if _, err := encodeUpdateTemplate(&platformv1.DeviceTemplateCreateRequest{}); !errors.As(err, &requestErr) {
			t.Errorf("encodeUpdateTemplate err = %v, want ErrUnexpectedRequestType", err)
		}
		if err := decodeTemplateList([]byte(`{}`), &platformv1.DeviceTemplateGetResponse{}); !errors.As(err, &replyErr) {
			t.Errorf("decodeTemplateList err = %v, want ErrUnexpectedReplyType", err)
		}
	})

	t.Run("UpdateWithoutIDRefusedBeforeTheWire", func(t *testing.T) {
		a, captured := templateServer(t, `{}`)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_UpdateTemplate_FullMethodName,
			&platformv1.DeviceTemplateUpdateRequest{Template: &platformv1.DeviceTemplate{Name: "edge"}},
			&platformv1.DeviceTemplateUpdateResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		if captured.path != "" {
			t.Errorf("request reached %s, want it refused locally", captured.path)
		}
	})

	t.Run("UndecodableListEntry", func(t *testing.T) {
		a, _ := templateServer(t, `{"templates": [{"name": 42}], "pagination": {}}`)
		err := a.Connection().Invoke(ctx, platformv1.DeviceService_ListTemplates_FullMethodName,
			&platformv1.DeviceTemplateListRequest{}, &platformv1.DeviceTemplateListResponse{})
		if status.Code(err) != codes.Internal {
			t.Fatalf("err = %v, want Internal", err)
		}
	})
}
