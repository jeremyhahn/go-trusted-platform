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
