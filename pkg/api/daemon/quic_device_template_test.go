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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newQUICDeviceTemplateHandler builds a QUIC handler over the real profile
// and template services.
func newQUICDeviceTemplateHandler(t *testing.T) (*QUICServiceHandler, realTemplateServices) {
	t.Helper()
	svcs := newRealTemplateServices(t)
	handler := newTestQUICServiceHandler(logging.DefaultLogger(),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(svcs.profiles),
		WithQUICDeviceTemplateService(svcs.templates))
	return handler, svcs
}

func TestQUICDeviceTemplateCreate(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubTemplateCreate,
		&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{
			Name:   "edge",
			Role:   platformv1.DeviceRole_DEVICE_ROLE_EDGE,
			Config: []byte(testTemplateConfigYAML),
		}})
	var resp platformv1.DeviceTemplateCreateResponse
	decodeQUICResponse(t, handler.HandleRequest(ctx, req), &resp)
	require.NotZero(t, resp.GetTemplate().GetId(), "the server assigns an id")

	stored, err := svcs.templates.Get(ctx, resp.GetTemplate().GetId())
	require.NoError(t, err)
	assert.Equal(t, "edge", stored.Name)
	assert.Equal(t, entities.DeviceRoleEdge, stored.Role)
	assert.Equal(t, testTemplateConfigYAML, string(stored.Config))
}

func TestQUICDeviceTemplateCreate_Errors(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()

	t.Run("UnnamedTemplate", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubTemplateCreate,
			&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{}})
		assert.Equal(t, quicwire.StatusInvalidArgument, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("MalformedPayload", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{quicwire.DeviceSubTemplateCreate, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICDeviceService(newMockDeviceService()))
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubTemplateCreate,
			&platformv1.DeviceTemplateCreateRequest{Template: &platformv1.DeviceTemplate{Name: "edge"}})
		assert.Equal(t, quicwire.StatusUnavailable, bare.HandleRequest(ctx, req).Status)
	})

	count, err := svcs.templates.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count, "a rejected template must not be stored")
}

func TestQUICDeviceProfileFromTemplate(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()
	template := &entities.DeviceTemplate{
		ID:     7001,
		Name:   "gateway",
		Role:   entities.DeviceRoleGateway,
		Config: []byte(testTemplateConfigYAML),
	}
	require.NoError(t, svcs.templates.Save(ctx, template))

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate,
		&platformv1.CreateProfileFromTemplateRequest{
			TemplateId: template.ID,
			Overrides:  &platformv1.DeviceProfile{Name: "gw-01", EkSerial: "EK-QUIC"},
		})
	var resp platformv1.CreateProfileResponse
	decodeQUICResponse(t, handler.HandleRequest(ctx, req), &resp)
	require.NotZero(t, resp.GetProfile().GetId(), "the server assigns an id")

	stored, err := svcs.profiles.Get(ctx, resp.GetProfile().GetId())
	require.NoError(t, err)
	assert.Equal(t, "gw-01", stored.Name)
	assert.Equal(t, "EK-QUIC", stored.EKSerial)
	assert.Equal(t, entities.DeviceRoleGateway, stored.Role, "role comes from the template")
}

func TestQUICDeviceProfileFromTemplate_Errors(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()

	t.Run("MissingTemplateID", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate,
			&platformv1.CreateProfileFromTemplateRequest{})
		assert.Equal(t, quicwire.StatusInvalidArgument, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("UnknownTemplate", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate,
			&platformv1.CreateProfileFromTemplateRequest{TemplateId: 4242})
		assert.Equal(t, quicwire.StatusNotFound, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("MalformedPayload", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{quicwire.DeviceSubProfileFromTemplate, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("NoTemplateService", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger(),
			WithQUICDeviceService(newMockDeviceService()),
			WithQUICDeviceProfileService(svcs.profiles))
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate,
			&platformv1.CreateProfileFromTemplateRequest{TemplateId: 1})
		assert.Equal(t, quicwire.StatusUnavailable, bare.HandleRequest(ctx, req).Status)
	})

	t.Run("NoProfileService", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger(),
			WithQUICDeviceService(newMockDeviceService()),
			WithQUICDeviceTemplateService(svcs.templates))
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubProfileFromTemplate,
			&platformv1.CreateProfileFromTemplateRequest{TemplateId: 1})
		assert.Equal(t, quicwire.StatusUnavailable, bare.HandleRequest(ctx, req).Status)
	})
}
