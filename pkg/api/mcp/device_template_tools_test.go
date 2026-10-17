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
	"errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// deviceTemplateToolNames are the device template tools routed through the
// device profile dispatcher.
var deviceTemplateToolNames = map[string]string{
	"device_template_create":       "device:write",
	"device_template_get":          "device:read",
	"device_template_list":         "device:read",
	"device_template_update":       "device:write",
	"device_template_delete":       "device:delete",
	"profile_create_from_template": "device:write",
}

// errStubTemplateNotFound is what the stub answers for an unknown template.
type errStubTemplateNotFound struct{}

func (errStubTemplateNotFound) Error() string { return "template not found" }

// deviceTemplateStubProvider records what the template tools hand the
// backend, so the tests assert the argument mapping rather than a copy of
// the template service.
type deviceTemplateStubProvider struct {
	templates     map[uint64]*entities.DeviceTemplate
	lastOverrides *entities.DeviceProfile
}

func (s *deviceTemplateStubProvider) DeviceTemplateCreate(ctx context.Context, template *entities.DeviceTemplate) (*entities.DeviceTemplate, error) {
	if template.ID == 0 {
		template.ID = uint64(len(s.templates) + 9000)
	}
	s.templates[template.ID] = template
	return template, nil
}

func (s *deviceTemplateStubProvider) DeviceTemplateGet(ctx context.Context, id uint64) (*entities.DeviceTemplate, error) {
	template, ok := s.templates[id]
	if !ok {
		return nil, errStubTemplateNotFound{}
	}
	return template, nil
}

func (s *deviceTemplateStubProvider) DeviceTemplateList(ctx context.Context, page, pageSize int) ([]*entities.DeviceTemplate, int, error) {
	ids := make([]uint64, 0, len(s.templates))
	for id := range s.templates {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	templates := make([]*entities.DeviceTemplate, 0, len(ids))
	for _, id := range ids {
		templates = append(templates, s.templates[id])
	}
	return templates, len(templates), nil
}

func (s *deviceTemplateStubProvider) DeviceTemplateUpdate(ctx context.Context, template *entities.DeviceTemplate) (*entities.DeviceTemplate, error) {
	if _, ok := s.templates[template.ID]; !ok {
		return nil, errStubTemplateNotFound{}
	}
	s.templates[template.ID] = template
	return template, nil
}

func (s *deviceTemplateStubProvider) DeviceTemplateDelete(ctx context.Context, id uint64) error {
	if _, ok := s.templates[id]; !ok {
		return errStubTemplateNotFound{}
	}
	delete(s.templates, id)
	return nil
}

func (s *deviceTemplateStubProvider) DeviceProfileFromTemplate(ctx context.Context, templateID uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	template, ok := s.templates[templateID]
	if !ok {
		return nil, errStubTemplateNotFound{}
	}
	s.lastOverrides = overrides
	return &entities.DeviceProfile{
		ID:       77,
		TenantID: template.TenantID,
		Name:     overrides.Name,
		Role:     template.Role,
		EKSerial: overrides.EKSerial,
		EKCert:   overrides.EKCert,
	}, nil
}

type deviceTemplateCombinedProvider struct {
	*mockServiceProvider
	*deviceTemplateStubProvider
}

func newDeviceTemplateRegistry() (*ToolRegistry, *deviceTemplateStubProvider) {
	stub := &deviceTemplateStubProvider{templates: make(map[uint64]*entities.DeviceTemplate)}
	svc := &deviceTemplateCombinedProvider{
		mockServiceProvider:        newMockServiceProvider(),
		deviceTemplateStubProvider: stub,
	}
	return NewToolRegistry(svc, newTestLogger()), stub
}

// TestDeviceTemplateToolRegistration verifies each template tool is
// registered, routed, authorized, and refuses to run without a backend.
func TestDeviceTemplateToolRegistration(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
	}
	authz := NewAuthorizationChecker(nil, nil)

	for name, wantPerm := range deviceTemplateToolNames {
		if !registered[name] {
			t.Errorf("tool %q is not registered", name)
		}
		if _, ok := deviceProfileToolDispatch[name]; !ok {
			t.Errorf("tool %q has no executor in deviceProfileToolDispatch", name)
		}
		if perm := authz.toolPermissions[name]; perm != wantPerm {
			t.Errorf("tool %q permission = %q, want %s", name, perm, wantPerm)
		}
		args := map[string]interface{}{"template_id": 1, "id": 1, "name": "x"}
		if _, err := registry.ExecuteTool(ctx, name, args); !errors.Is(err, ErrDeviceTemplateNotConfigured) {
			t.Errorf("ExecuteTool(%q) without provider: err = %v, want ErrDeviceTemplateNotConfigured", name, err)
		}
	}
}

func TestDeviceTemplateCreate(t *testing.T) {
	registry, stub := newDeviceTemplateRegistry()

	result, err := registry.ExecuteTool(context.Background(), "device_template_create", map[string]interface{}{
		"tenant_id":   "tenant-1",
		"name":        "edge",
		"description": "edge servers",
		"role":        "edge",
		"config":      "hostname: edge-01\n",
		"match_rules": map[string]interface{}{"mac_prefix": "00:25:90"},
	})
	if err != nil {
		t.Fatalf("device_template_create: %v", err)
	}

	obj := result.(map[string]interface{})
	if obj["id"] != "9000" {
		t.Errorf("id = %v, want string \"9000\"", obj["id"])
	}
	if obj["config"] != "hostname: edge-01\n" {
		t.Errorf("config = %v, want the YAML text back", obj["config"])
	}

	stored := stub.templates[9000]
	if stored == nil {
		t.Fatal("template was not handed to the backend")
	}
	if stored.Name != "edge" || stored.TenantID != "tenant-1" || stored.Description != "edge servers" {
		t.Errorf("stored template = %+v", stored)
	}
	if stored.Role != entities.DeviceRoleEdge {
		t.Errorf("role = %q, want edge", stored.Role)
	}
	if string(stored.Config) != "hostname: edge-01\n" {
		t.Errorf("config = %q", stored.Config)
	}
	if stored.MatchRules == nil || stored.MatchRules.MACPrefix != "00:25:90" {
		t.Errorf("match rules = %+v", stored.MatchRules)
	}
}

func TestDeviceTemplateCreate_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("MissingName", func(t *testing.T) {
		registry, stub := newDeviceTemplateRegistry()
		_, err := registry.ExecuteTool(ctx, "device_template_create", map[string]interface{}{"role": "edge"})
		if !errors.Is(err, ErrTemplateNameRequired) {
			t.Errorf("err = %v, want ErrTemplateNameRequired", err)
		}
		if len(stub.templates) != 0 {
			t.Error("a rejected template must not reach the backend")
		}
	})

	t.Run("MalformedArguments", func(t *testing.T) {
		registry, _ := newDeviceTemplateRegistry()
		_, err := registry.ExecuteTool(ctx, "device_template_create", map[string]interface{}{"name": 42})
		var invalid ErrDeviceProfileInvalidArgs
		if !errors.As(err, &invalid) {
			t.Errorf("err = %v, want ErrDeviceProfileInvalidArgs", err)
		}
	})
}

// TestDeviceTemplateGetListUpdateDelete drives a stored template through
// the four template tools and checks each returns what the backend holds.
func TestDeviceTemplateGetListUpdateDelete(t *testing.T) {
	ctx := context.Background()
	registry, stub := newDeviceTemplateRegistry()
	stub.templates[41] = &entities.DeviceTemplate{ID: 41, Name: "edge", Role: entities.DeviceRoleEdge}
	stub.templates[42] = &entities.DeviceTemplate{ID: 42, Name: "core", Config: []byte("hostname: core\n")}

	got, err := registry.ExecuteTool(ctx, "device_template_get", map[string]interface{}{"id": 42})
	if err != nil {
		t.Fatalf("device_template_get: %v", err)
	}
	obj := got.(map[string]interface{})
	if obj["id"] != "42" || obj["name"] != "core" || obj["config"] != "hostname: core\n" {
		t.Errorf("device_template_get = %v", obj)
	}

	listed, err := registry.ExecuteTool(ctx, "device_template_list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("device_template_list: %v", err)
	}
	page := listed.(map[string]interface{})
	templates := page["templates"].([]interface{})
	if len(templates) != 2 || page["total"] != 2 || page["page"] != 1 || page["page_size"] != 50 {
		t.Errorf("device_template_list = %v, want 2 templates on page 1 of size 50", page)
	}

	updated, err := registry.ExecuteTool(ctx, "device_template_update", map[string]interface{}{
		"id":          41,
		"name":        "edge-v2",
		"description": "second revision",
	})
	if err != nil {
		t.Fatalf("device_template_update: %v", err)
	}
	if updated.(map[string]interface{})["name"] != "edge-v2" {
		t.Errorf("device_template_update = %v", updated)
	}
	stored := stub.templates[41]
	if stored.Name != "edge-v2" || stored.Description != "second revision" {
		t.Errorf("stored template = %+v", stored)
	}
	if stored.Role != "" {
		t.Errorf("role = %q: an update replaces the template, so an omitted role is cleared", stored.Role)
	}

	deleted, err := registry.ExecuteTool(ctx, "device_template_delete", map[string]interface{}{"id": 41})
	if err != nil {
		t.Fatalf("device_template_delete: %v", err)
	}
	if deleted.(map[string]interface{})["id"] != "41" {
		t.Errorf("device_template_delete = %v", deleted)
	}
	if _, ok := stub.templates[41]; ok {
		t.Error("the deleted template is still stored")
	}
}

func TestDeviceTemplateGetListUpdateDelete_Errors(t *testing.T) {
	ctx := context.Background()

	for _, name := range []string{"device_template_get", "device_template_update", "device_template_delete"} {
		t.Run(name+"/MissingID", func(t *testing.T) {
			registry, _ := newDeviceTemplateRegistry()
			_, err := registry.ExecuteTool(ctx, name, map[string]interface{}{"name": "x"})
			if !errors.Is(err, ErrTemplateIDRequired) {
				t.Errorf("err = %v, want ErrTemplateIDRequired", err)
			}
		})
		t.Run(name+"/NotFound", func(t *testing.T) {
			registry, _ := newDeviceTemplateRegistry()
			_, err := registry.ExecuteTool(ctx, name, map[string]interface{}{"id": 4242, "name": "x"})
			var notFound errStubTemplateNotFound
			if !errors.As(err, &notFound) {
				t.Errorf("err = %v, want the backend's not-found error", err)
			}
		})
	}

	t.Run("device_template_update/MissingName", func(t *testing.T) {
		registry, stub := newDeviceTemplateRegistry()
		stub.templates[7] = &entities.DeviceTemplate{ID: 7, Name: "keep"}
		_, err := registry.ExecuteTool(ctx, "device_template_update", map[string]interface{}{"id": 7})
		if !errors.Is(err, ErrTemplateNameRequired) {
			t.Errorf("err = %v, want ErrTemplateNameRequired", err)
		}
		if stub.templates[7].Name != "keep" {
			t.Error("a rejected update must not reach the backend")
		}
	})

	t.Run("device_template_update/MalformedArguments", func(t *testing.T) {
		registry, _ := newDeviceTemplateRegistry()
		_, err := registry.ExecuteTool(ctx, "device_template_update", map[string]interface{}{"id": 7, "name": 42})
		var invalid ErrDeviceProfileInvalidArgs
		if !errors.As(err, &invalid) {
			t.Errorf("err = %v, want ErrDeviceProfileInvalidArgs", err)
		}
	})
}

func TestDeviceProfileFromTemplate(t *testing.T) {
	registry, stub := newDeviceTemplateRegistry()
	stub.templates[5] = &entities.DeviceTemplate{ID: 5, TenantID: "tenant-1", Name: "gw", Role: entities.DeviceRoleGateway}
	certPEM := newMCPTestEKCertPEM(t)

	result, err := registry.ExecuteTool(context.Background(), "profile_create_from_template", map[string]interface{}{
		"template_id": "5",
		"overrides": map[string]interface{}{
			"name":        "gw-01",
			"ek_serial":   "EK-MCP",
			"ek_cert":     certPEM,
			"mac_address": "00:25:90:aa:bb:01",
		},
	})
	if err != nil {
		t.Fatalf("profile_create_from_template: %v", err)
	}

	obj := result.(map[string]interface{})
	if obj["id"] != "77" {
		t.Errorf("id = %v, want string \"77\"", obj["id"])
	}
	if obj["role"] != string(entities.DeviceRoleGateway) {
		t.Errorf("role = %v, want the template's", obj["role"])
	}

	got := stub.lastOverrides
	if got.Name != "gw-01" || got.EKSerial != "EK-MCP" || got.EKCert != certPEM || got.MACAddress != "00:25:90:aa:bb:01" {
		t.Errorf("overrides handed to the backend = %+v", got)
	}
}

func TestDeviceProfileFromTemplate_Errors(t *testing.T) {
	ctx := context.Background()
	registry, stub := newDeviceTemplateRegistry()
	stub.templates[5] = &entities.DeviceTemplate{ID: 5, Name: "gw"}

	t.Run("MissingTemplateID", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{})
		if !errors.Is(err, ErrTemplateIDRequired) {
			t.Errorf("err = %v, want ErrTemplateIDRequired", err)
		}
	})

	t.Run("InvalidEKCertOverride", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{
			"template_id": 5,
			"overrides":   map[string]interface{}{"ek_cert": "not a pem certificate"},
		})
		var notPEM entities.ErrEKCertNotPEM
		if !errors.As(err, &notPEM) {
			t.Errorf("err = %v, want entities.ErrEKCertNotPEM", err)
		}
		if stub.lastOverrides != nil {
			t.Error("an invalid override must not reach the backend")
		}
	})

	t.Run("MalformedOverrides", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{
			"template_id": 5,
			"overrides":   "not an object",
		})
		var invalid ErrDeviceProfileInvalidArgs
		if !errors.As(err, &invalid) {
			t.Errorf("err = %v, want ErrDeviceProfileInvalidArgs", err)
		}
	})

	t.Run("UnknownTemplate", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{"template_id": 4242})
		if !errors.As(err, &errStubTemplateNotFound{}) {
			t.Errorf("err = %v, want the backend's not-found error", err)
		}
	})
}
