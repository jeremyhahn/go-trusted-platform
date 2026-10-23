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

func TestQUICDeviceFindMatchingProfile(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:         8101,
		Name:       "rack-a",
		Model:      "R640",
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "SN100"},
	}
	require.NoError(t, svcs.profiles.Save(ctx, profile))

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindMatchingProfile,
		&platformv1.FindMatchingProfileRequest{Serial: "SN100-XYZ"})
	var resp platformv1.FindMatchingProfileResponse
	decodeQUICResponse(t, handler.HandleRequest(ctx, req), &resp)
	assert.Equal(t, profile.ID, resp.GetProfile().GetId())
	assert.Equal(t, "rack-a", resp.GetProfile().GetName())
}

func TestQUICDeviceFindMatchingProfile_Errors(t *testing.T) {
	handler, _ := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()

	t.Run("NoMatch", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindMatchingProfile,
			&platformv1.FindMatchingProfileRequest{Serial: "SN999"})
		assert.Equal(t, quicwire.StatusNotFound, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("MalformedPayload", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{quicwire.DeviceSubFindMatchingProfile, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("NoProfileService", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICDeviceService(newMockDeviceService()))
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindMatchingProfile,
			&platformv1.FindMatchingProfileRequest{Serial: "SN100"})
		assert.Equal(t, quicwire.StatusUnavailable, bare.HandleRequest(ctx, req).Status)
	})
}

func TestQUICDeviceFindConfigForDevice(t *testing.T) {
	handler, svcs := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()
	byEK := &entities.DeviceProfile{ID: 8201, Name: "by-ek", EKSerial: "EK-8201"}
	byMAC := &entities.DeviceProfile{ID: 8202, Name: "by-mac", MACAddress: "52:54:00:aa:bb:02"}
	require.NoError(t, svcs.profiles.Save(ctx, byEK))
	require.NoError(t, svcs.profiles.Save(ctx, byMAC))

	cases := []struct {
		name string
		req  *platformv1.FindConfigForDeviceRequest
		want uint64
	}{
		{"EKSerial", &platformv1.FindConfigForDeviceRequest{EkSerial: "EK-8201"}, byEK.ID},
		{"MACAddress", &platformv1.FindConfigForDeviceRequest{MacAddress: "52:54:00:aa:bb:02"}, byMAC.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindConfigForDevice, tc.req)
			var resp platformv1.FindConfigForDeviceResponse
			decodeQUICResponse(t, handler.HandleRequest(ctx, req), &resp)
			assert.Equal(t, tc.want, resp.GetProfile().GetId())
		})
	}
}

func TestQUICDeviceFindConfigForDevice_Errors(t *testing.T) {
	handler, _ := newQUICDeviceTemplateHandler(t)
	ctx := context.Background()

	t.Run("NoIdentity", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindConfigForDevice,
			&platformv1.FindConfigForDeviceRequest{})
		assert.Equal(t, quicwire.StatusInvalidArgument, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("UnknownIdentity", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindConfigForDevice,
			&platformv1.FindConfigForDeviceRequest{EkSerial: "EK-NONE"})
		assert.Equal(t, quicwire.StatusNotFound, handler.HandleRequest(ctx, req).Status)
	})

	t.Run("MalformedPayload", func(t *testing.T) {
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{quicwire.DeviceSubFindConfigForDevice, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("NoProfileService", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICDeviceService(newMockDeviceService()))
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubFindConfigForDevice,
			&platformv1.FindConfigForDeviceRequest{EkSerial: "EK-8201"})
		assert.Equal(t, quicwire.StatusUnavailable, bare.HandleRequest(ctx, req).Status)
	})
}
