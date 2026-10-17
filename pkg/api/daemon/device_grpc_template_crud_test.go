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

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// storeTestTemplate saves a device template straight through the template
// service, so the RPC under test is the only one each test drives.
func storeTestTemplate(t *testing.T, svcs realTemplateServices, name string) *entities.DeviceTemplate {
	t.Helper()
	template := &entities.DeviceTemplate{
		ID:       device.NewID(),
		TenantID: "tenant-1",
		Name:     name,
		Role:     entities.DeviceRoleEdge,
		Config:   []byte(testTemplateConfigYAML),
	}
	require.NoError(t, svcs.templates.Save(context.Background(), template))
	stored, err := svcs.templates.Get(context.Background(), template.ID)
	require.NoError(t, err)
	return stored
}

func TestDeviceGRPCTemplateCRUD_Transports(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	for name, client := range deviceTemplateTransports(t, svc) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			stored := storeTestTemplate(t, svcs, "edge-"+name)

			got, err := client.GetTemplate(ctx, &platformv1.DeviceTemplateGetRequest{Id: stored.ID})
			require.NoError(t, err)
			assert.Equal(t, stored.ID, got.GetTemplate().GetId())
			assert.Equal(t, "edge-"+name, got.GetTemplate().GetName())
			assert.Equal(t, testTemplateConfigYAML, string(got.GetTemplate().GetConfig()))

			listed, err := client.ListTemplates(ctx, &platformv1.DeviceTemplateListRequest{
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 100},
			})
			require.NoError(t, err)
			var ids []uint64
			for _, tmpl := range listed.GetTemplates() {
				ids = append(ids, tmpl.GetId())
			}
			assert.Contains(t, ids, stored.ID)
			assert.Equal(t, uint64(len(ids)), listed.GetPagination().GetTotalItems())

			updated, err := client.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{
				Template: &platformv1.DeviceTemplate{
					Id:          stored.ID,
					TenantId:    "tenant-1",
					Name:        "edge-v2-" + name,
					Description: "second revision",
					Role:        platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
				},
			})
			require.NoError(t, err)
			require.True(t, updated.GetStatus().GetSuccess())
			reread, err := svcs.templates.Get(ctx, stored.ID)
			require.NoError(t, err)
			assert.Equal(t, "edge-v2-"+name, reread.Name)
			assert.Equal(t, "second revision", reread.Description)
			assert.Equal(t, entities.DeviceRoleGateway, reread.Role)
			assert.Empty(t, reread.Config, "an update replaces the template, so the omitted config is cleared")
			assert.True(t, stored.CreatedAt.Equal(reread.CreatedAt), "an update keeps the creation time")

			deleted, err := client.DeleteTemplate(ctx, &platformv1.DeviceTemplateDeleteRequest{Id: stored.ID})
			require.NoError(t, err)
			require.True(t, deleted.GetStatus().GetSuccess())
			_, err = svcs.templates.Get(ctx, stored.ID)
			require.Error(t, err, "the deleted template is still stored")
		})
	}
}

func TestDeviceGRPCTemplateCRUD_Errors(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	bare := NewDeviceGRPCService(newMockDeviceService(), svcs.profiles, nil)
	ctx := context.Background()
	const absent = uint64(4242)

	tests := []struct {
		name string
		call func(*DeviceGRPCService) error
		code codes.Code
	}{
		{"get without id", func(s *DeviceGRPCService) error {
			_, err := s.GetTemplate(ctx, &platformv1.DeviceTemplateGetRequest{})
			return err
		}, codes.InvalidArgument},
		{"get unknown id", func(s *DeviceGRPCService) error {
			_, err := s.GetTemplate(ctx, &platformv1.DeviceTemplateGetRequest{Id: absent})
			return err
		}, codes.NotFound},
		{"update without template", func(s *DeviceGRPCService) error {
			_, err := s.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{})
			return err
		}, codes.InvalidArgument},
		{"update without id", func(s *DeviceGRPCService) error {
			_, err := s.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{
				Template: &platformv1.DeviceTemplate{Name: "edge"},
			})
			return err
		}, codes.InvalidArgument},
		{"update unknown id", func(s *DeviceGRPCService) error {
			_, err := s.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{
				Template: &platformv1.DeviceTemplate{Id: absent, Name: "edge"},
			})
			return err
		}, codes.NotFound},
		{"delete without id", func(s *DeviceGRPCService) error {
			_, err := s.DeleteTemplate(ctx, &platformv1.DeviceTemplateDeleteRequest{})
			return err
		}, codes.InvalidArgument},
		{"delete unknown id", func(s *DeviceGRPCService) error {
			_, err := s.DeleteTemplate(ctx, &platformv1.DeviceTemplateDeleteRequest{Id: absent})
			return err
		}, codes.NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(svc)
			assert.Equal(t, tt.code, status.Code(err), "error: %v", err)
		})
	}

	// A daemon without the template service answers every template RPC
	// Unavailable, before it looks at the request.
	unavailable := []func(*DeviceGRPCService) error{
		func(s *DeviceGRPCService) error {
			_, err := s.GetTemplate(ctx, &platformv1.DeviceTemplateGetRequest{Id: 1})
			return err
		},
		func(s *DeviceGRPCService) error {
			_, err := s.ListTemplates(ctx, &platformv1.DeviceTemplateListRequest{})
			return err
		},
		func(s *DeviceGRPCService) error {
			_, err := s.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{
				Template: &platformv1.DeviceTemplate{Id: 1, Name: "edge"},
			})
			return err
		},
		func(s *DeviceGRPCService) error {
			_, err := s.DeleteTemplate(ctx, &platformv1.DeviceTemplateDeleteRequest{Id: 1})
			return err
		},
	}
	for i, call := range unavailable {
		assert.Equal(t, codes.Unavailable, status.Code(call(bare)), "call %d", i)
	}
}
