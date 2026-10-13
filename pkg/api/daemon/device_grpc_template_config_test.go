// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceGRPCService_CreateProfileFromTemplate stores a profile derived
// from a saved template with the request's overrides applied. gRPC, Unix and
// the embedded transport all reach this method.
func TestDeviceGRPCService_CreateProfileFromTemplate(t *testing.T) {
	ctx := context.Background()
	svcs := newRealTemplateServices(t)
	templates, profiles := svcs.templates, svcs.profiles
	require.NoError(t, templates.Save(ctx, &entities.DeviceTemplate{
		ID: 2501, Name: "edge", Role: entities.DeviceRoleWorker,
		MatchRules: &entities.ProfileMatchRules{MACPrefix: "52:54:00"},
	}))
	svc := NewDeviceGRPCService(newMockDeviceService(), profiles, nil, WithDeviceTemplateService(templates))

	resp, err := svc.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{
		TemplateId: 2501,
		Overrides:  &platformv1.DeviceProfile{Name: "edge-01"},
	})
	require.NoError(t, err)
	require.NotZero(t, resp.GetProfile().GetId(), "the derived profile is given an ID")
	assert.True(t, resp.GetStatus().GetSuccess())

	stored, err := profiles.Get(ctx, resp.GetProfile().GetId())
	require.NoError(t, err, "the derived profile is saved")
	assert.Equal(t, "edge-01", stored.Name, "the override wins")
	assert.Equal(t, entities.DeviceRoleWorker, stored.Role, "unset fields come from the template")
	require.NotNil(t, stored.MatchRules, "the template's match rules are copied")
	assert.Equal(t, "52:54:00", stored.MatchRules.MACPrefix)
}

// TestDeviceGRPCService_CreateProfileFromTemplate_Errors maps each failure to
// a distinct status and stores nothing.
func TestDeviceGRPCService_CreateProfileFromTemplate_Errors(t *testing.T) {
	ctx := context.Background()
	svcs := newRealTemplateServices(t)
	templates, profiles := svcs.templates, svcs.profiles
	svc := NewDeviceGRPCService(newMockDeviceService(), profiles, nil, WithDeviceTemplateService(templates))

	_, err := svc.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no template ID: %v", err)

	_, err = svc.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 404})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown template: %v", err)

	_, err = svc.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{
		TemplateId: 2501,
		Overrides:  &platformv1.DeviceProfile{Config: []byte("{not json")},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "malformed overrides: %v", err)

	// A daemon wired without a template service is a deployment fault, not
	// a missing template: Unavailable, as on every template RPC.
	unwired := NewDeviceGRPCService(newMockDeviceService(), profiles, nil)
	_, err = unwired.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 2501})
	assert.Equal(t, codes.Unavailable, status.Code(err), "no template service: %v", err)

	count, err := profiles.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count, "a failed create stores no profile")
}

// TestDeviceGRPCService_FindConfigForDevice resolves the profile bound to a
// machine by either its EK serial or its MAC address.
func TestDeviceGRPCService_FindConfigForDevice(t *testing.T) {
	ctx := context.Background()
	profiles := newRealProfileService(t)
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 2502, Name: "node-25", Role: entities.DeviceRoleWorker}))
	require.NoError(t, profiles.AssignToDevice(ctx, 2502, "EK-2502", "52:54:00:00:25:02"))
	svc := NewDeviceGRPCService(newMockDeviceService(), profiles, nil)

	for _, req := range []*platformv1.FindConfigForDeviceRequest{
		{EkSerial: "EK-2502"},
		{MacAddress: "52:54:00:00:25:02"},
	} {
		resp, err := svc.FindConfigForDevice(ctx, req)
		require.NoError(t, err, req.String())
		assert.Equal(t, uint64(2502), resp.GetProfile().GetId(), req.String())
		assert.Equal(t, "node-25", resp.GetProfile().GetName(), req.String())
	}
}

// TestDeviceGRPCService_FindConfigForDevice_Errors keeps the three failures
// apart: no identity is the caller's fault, an unknown identity gets no
// profile, and a profile service that cannot resolve configs is a wiring
// fault.
func TestDeviceGRPCService_FindConfigForDevice_Errors(t *testing.T) {
	ctx := context.Background()
	profiles := newRealProfileService(t)
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 2503, Name: "node-26", Role: entities.DeviceRoleWorker}))
	require.NoError(t, profiles.AssignToDevice(ctx, 2503, "EK-2503", ""))
	svc := NewDeviceGRPCService(newMockDeviceService(), profiles, nil)

	_, err := svc.FindConfigForDevice(ctx, &platformv1.FindConfigForDeviceRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no identity: %v", err)

	resp, err := svc.FindConfigForDevice(ctx, &platformv1.FindConfigForDeviceRequest{EkSerial: "EK-UNKNOWN"})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown identity: %v", err)
	assert.Nil(t, resp, "an unknown identity is handed no profile")

	unwired := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	_, err = unwired.FindConfigForDevice(ctx, &platformv1.FindConfigForDeviceRequest{EkSerial: "EK-2503"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "profile service without config lookup: %v", err)
}
