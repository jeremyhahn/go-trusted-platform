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

package device

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// fakeTemplateCRUDClient records the get, list, update and delete template
// requests the client sends and answers each with err when it is set.
type fakeTemplateCRUDClient struct {
	platformv1.DeviceServiceClient

	err       error
	getReq    *platformv1.DeviceTemplateGetRequest
	listReq   *platformv1.DeviceTemplateListRequest
	updateReq *platformv1.DeviceTemplateUpdateRequest
	deleteReq *platformv1.DeviceTemplateDeleteRequest
}

func (f *fakeTemplateCRUDClient) GetTemplate(_ context.Context, req *platformv1.DeviceTemplateGetRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateGetResponse, error) {
	f.getReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeviceTemplateGetResponse{Template: &platformv1.DeviceTemplate{Id: req.GetId(), Name: "edge"}}, nil
}

func (f *fakeTemplateCRUDClient) ListTemplates(_ context.Context, req *platformv1.DeviceTemplateListRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateListResponse, error) {
	f.listReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeviceTemplateListResponse{
		Templates:  []*platformv1.DeviceTemplate{{Id: 1}, {Id: 2}},
		Pagination: &platformv1.PaginationResponse{Page: 2, PageSize: 2, TotalPages: 3, TotalItems: 6},
	}, nil
}

func (f *fakeTemplateCRUDClient) UpdateTemplate(_ context.Context, req *platformv1.DeviceTemplateUpdateRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateUpdateResponse, error) {
	f.updateReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeviceTemplateUpdateResponse{Template: req.GetTemplate()}, nil
}

func (f *fakeTemplateCRUDClient) DeleteTemplate(_ context.Context, req *platformv1.DeviceTemplateDeleteRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateDeleteResponse, error) {
	f.deleteReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeviceTemplateDeleteResponse{}, nil
}

func TestClient_TemplateCRUD(t *testing.T) {
	ctx := context.Background()
	fake := &fakeTemplateCRUDClient{}
	client := NewClientFromGRPC(fake)

	got, err := client.GetTemplate(ctx, 9000)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.GetId() != 9000 || fake.getReq.GetId() != 9000 {
		t.Errorf("GetTemplate = %+v, request = %+v", got, fake.getReq)
	}

	templates, page, err := client.ListTemplates(ctx, &common.Pagination{Page: 2, PageSize: 2, SortBy: "name", Asc: true})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(templates) != 2 {
		t.Errorf("ListTemplates returned %d templates, want 2", len(templates))
	}
	sent := fake.listReq.GetPagination()
	if sent.GetPage() != 2 || sent.GetPageSize() != 2 || sent.GetSortBy() != "name" || !sent.GetAscending() {
		t.Errorf("list pagination = %+v, fields not mapped", sent)
	}
	if page == nil || page.TotalPages != 3 || page.TotalItems != 6 {
		t.Errorf("page = %+v, want 3 pages of 6 items", page)
	}

	updated, err := client.UpdateTemplate(ctx, &platformv1.DeviceTemplate{Id: 9000, Name: "edge-v2"})
	if err != nil {
		t.Fatalf("UpdateTemplate: %v", err)
	}
	if updated.GetName() != "edge-v2" || fake.updateReq.GetTemplate().GetId() != 9000 {
		t.Errorf("UpdateTemplate = %+v, request = %+v", updated, fake.updateReq)
	}

	if err := client.DeleteTemplate(ctx, 9000); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	if fake.deleteReq.GetId() != 9000 {
		t.Errorf("delete request = %+v", fake.deleteReq)
	}
}

func TestClient_ListTemplates_NoOptions(t *testing.T) {
	fake := &fakeTemplateCRUDClient{}
	if _, _, err := NewClientFromGRPC(fake).ListTemplates(context.Background(), nil); err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if fake.listReq.GetPagination() != nil {
		t.Errorf("pagination = %+v, want none so the server applies its default", fake.listReq.GetPagination())
	}
}

// TestClient_TemplateCRUD_Errors checks each verb wraps the server's error
// in its typed error and keeps the gRPC code, so a caller can tell a
// missing template from a bad request.
func TestClient_TemplateCRUD_Errors(t *testing.T) {
	ctx := context.Background()
	for _, code := range []codes.Code{codes.NotFound, codes.InvalidArgument} {
		cause := status.Error(code, "refused")
		client := NewClientFromGRPC(&fakeTemplateCRUDClient{err: cause})

		_, err := client.GetTemplate(ctx, 4242)
		var getErr *ErrGetTemplateFailed
		if !errors.As(err, &getErr) || getErr.ID != 4242 {
			t.Errorf("GetTemplate err = %v, want ErrGetTemplateFailed for 4242", err)
		}
		if status.Code(err) != code {
			t.Errorf("GetTemplate code = %v, want %v", status.Code(err), code)
		}

		_, _, err = client.ListTemplates(ctx, nil)
		var listErr *ErrListTemplatesFailed
		if !errors.As(err, &listErr) || status.Code(err) != code {
			t.Errorf("ListTemplates err = %v, want ErrListTemplatesFailed with %v", err, code)
		}

		_, err = client.UpdateTemplate(ctx, &platformv1.DeviceTemplate{Id: 4242})
		var updateErr *ErrUpdateTemplateFailed
		if !errors.As(err, &updateErr) || updateErr.ID != 4242 || status.Code(err) != code {
			t.Errorf("UpdateTemplate err = %v, want ErrUpdateTemplateFailed for 4242 with %v", err, code)
		}

		err = client.DeleteTemplate(ctx, 4242)
		var deleteErr *ErrDeleteTemplateFailed
		if !errors.As(err, &deleteErr) || deleteErr.ID != 4242 || status.Code(err) != code {
			t.Errorf("DeleteTemplate err = %v, want ErrDeleteTemplateFailed for 4242 with %v", err, code)
		}
	}
}
