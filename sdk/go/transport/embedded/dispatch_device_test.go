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

package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// testDeviceTemplateServer answers the template methods, so the dispatch
// tests prove the request reaches the server and the reply comes back.
type testDeviceTemplateServer struct {
	platformv1.UnimplementedDeviceServiceServer
}

func (s *testDeviceTemplateServer) CreateTemplate(_ context.Context, req *platformv1.DeviceTemplateCreateRequest) (*platformv1.DeviceTemplateCreateResponse, error) {
	template := req.GetTemplate()
	template.Id = 9000
	return &platformv1.DeviceTemplateCreateResponse{Template: template}, nil
}

func (s *testDeviceTemplateServer) CreateProfileFromTemplate(_ context.Context, req *platformv1.CreateProfileFromTemplateRequest) (*platformv1.CreateProfileResponse, error) {
	if req.GetTemplateId() != 9000 {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &platformv1.CreateProfileResponse{Profile: &platformv1.DeviceProfile{Id: 77, Name: req.GetOverrides().GetName()}}, nil
}

func (s *testDeviceTemplateServer) GetTemplate(_ context.Context, req *platformv1.DeviceTemplateGetRequest) (*platformv1.DeviceTemplateGetResponse, error) {
	if req.GetId() != 9000 {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &platformv1.DeviceTemplateGetResponse{Template: &platformv1.DeviceTemplate{Id: 9000, Name: "edge"}}, nil
}

func (s *testDeviceTemplateServer) ListTemplates(_ context.Context, req *platformv1.DeviceTemplateListRequest) (*platformv1.DeviceTemplateListResponse, error) {
	return &platformv1.DeviceTemplateListResponse{
		Templates:  []*platformv1.DeviceTemplate{{Id: 9000, Name: "edge"}},
		Pagination: &platformv1.PaginationResponse{Page: req.GetPagination().GetPage(), TotalItems: 1, TotalPages: 1},
	}, nil
}

func (s *testDeviceTemplateServer) UpdateTemplate(_ context.Context, req *platformv1.DeviceTemplateUpdateRequest) (*platformv1.DeviceTemplateUpdateResponse, error) {
	return &platformv1.DeviceTemplateUpdateResponse{Template: req.GetTemplate()}, nil
}

func (s *testDeviceTemplateServer) DeleteTemplate(_ context.Context, req *platformv1.DeviceTemplateDeleteRequest) (*platformv1.DeviceTemplateDeleteResponse, error) {
	if req.GetId() != 9000 {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &platformv1.DeviceTemplateDeleteResponse{}, nil
}

func TestDispatch_DeviceCreateTemplate(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{Device: &testDeviceTemplateServer{}})

	handler, ok := m[platformv1.DeviceService_CreateTemplate_FullMethodName]
	if !ok {
		t.Fatal("expected CreateTemplate handler to be registered")
	}
	resp, err := handler(context.Background(), &platformv1.DeviceTemplateCreateRequest{
		Template: &platformv1.DeviceTemplate{Name: "edge"},
	})
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}
	created, ok := resp.(*platformv1.DeviceTemplateCreateResponse)
	if !ok {
		t.Fatalf("expected *DeviceTemplateCreateResponse, got %T", resp)
	}
	if created.GetTemplate().GetId() != 9000 || created.GetTemplate().GetName() != "edge" {
		t.Errorf("template = %v", created.GetTemplate())
	}
}

func TestDispatch_DeviceCreateProfileFromTemplate(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{Device: &testDeviceTemplateServer{}})

	handler, ok := m[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName]
	if !ok {
		t.Fatal("expected CreateProfileFromTemplate handler to be registered")
	}
	resp, err := handler(context.Background(), &platformv1.CreateProfileFromTemplateRequest{
		TemplateId: 9000,
		Overrides:  &platformv1.DeviceProfile{Name: "edge-01"},
	})
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}
	created, ok := resp.(*platformv1.CreateProfileResponse)
	if !ok {
		t.Fatalf("expected *CreateProfileResponse, got %T", resp)
	}
	if created.GetProfile().GetName() != "edge-01" {
		t.Errorf("profile = %v", created.GetProfile())
	}
}

// TestDispatch_DeviceTemplateCRUD proves Get, List, Update and Delete reach
// the server with the caller's request and hand its reply back unchanged.
func TestDispatch_DeviceTemplateCRUD(t *testing.T) {
	ctx := context.Background()
	m := buildHandlerMap(&ServiceRegistry{Device: &testDeviceTemplateServer{}})

	get, err := m[platformv1.DeviceService_GetTemplate_FullMethodName](ctx, &platformv1.DeviceTemplateGetRequest{Id: 9000})
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got := get.(*platformv1.DeviceTemplateGetResponse).GetTemplate(); got.GetName() != "edge" {
		t.Errorf("GetTemplate template = %v", got)
	}

	list, err := m[platformv1.DeviceService_ListTemplates_FullMethodName](ctx,
		&platformv1.DeviceTemplateListRequest{Pagination: &platformv1.PaginationRequest{Page: 3}})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	listed := list.(*platformv1.DeviceTemplateListResponse)
	if len(listed.GetTemplates()) != 1 || listed.GetPagination().GetPage() != 3 {
		t.Errorf("ListTemplates reply = %v, want one template on the requested page", listed)
	}

	update, err := m[platformv1.DeviceService_UpdateTemplate_FullMethodName](ctx,
		&platformv1.DeviceTemplateUpdateRequest{Template: &platformv1.DeviceTemplate{Id: 9000, Name: "core"}})
	if err != nil {
		t.Fatalf("UpdateTemplate: %v", err)
	}
	if got := update.(*platformv1.DeviceTemplateUpdateResponse).GetTemplate(); got.GetName() != "core" {
		t.Errorf("UpdateTemplate template = %v", got)
	}

	if _, err := m[platformv1.DeviceService_DeleteTemplate_FullMethodName](ctx, &platformv1.DeviceTemplateDeleteRequest{Id: 9000}); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
}

func TestDispatch_DeviceTemplate_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("UnknownTemplate", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{Device: &testDeviceTemplateServer{}})
		handler := m[platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName]
		_, err := handler(ctx, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 1})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want the server's NotFound", err)
		}
	})

	t.Run("GetUnknownTemplate", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{Device: &testDeviceTemplateServer{}})
		handler := m[platformv1.DeviceService_GetTemplate_FullMethodName]
		_, err := handler(ctx, &platformv1.DeviceTemplateGetRequest{Id: 1})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want the server's NotFound", err)
		}
	})

	t.Run("NoDeviceService", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{})
		for _, method := range []string{
			platformv1.DeviceService_CreateTemplate_FullMethodName,
			platformv1.DeviceService_GetTemplate_FullMethodName,
			platformv1.DeviceService_ListTemplates_FullMethodName,
			platformv1.DeviceService_UpdateTemplate_FullMethodName,
			platformv1.DeviceService_DeleteTemplate_FullMethodName,
			platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
		} {
			if _, ok := m[method]; ok {
				t.Errorf("%s registered without a device service", method)
			}
		}
	})
}
