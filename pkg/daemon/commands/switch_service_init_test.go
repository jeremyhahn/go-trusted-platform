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

package commands

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// coreSwitchApp returns an App with one noop switch named core-1, which
// builds a service without opening any connection.
func coreSwitchApp() *app.App {
	return &app.App{
		SwitchConfigs: []switchmgmt.Config{{Name: "core-1", Vendor: switchmgmt.VendorNoop}},
	}
}

func TestNewSwitchService_NoSwitchesLeavesTheSurfaceDark(t *testing.T) {
	logger := logging.DefaultLogger()

	svc, err := newSwitchService(logger, nil)
	require.NoError(t, err)
	assert.Nil(t, svc, "a nil App builds no switch service")

	svc, err = newSwitchService(logger, &app.App{})
	require.NoError(t, err)
	assert.Nil(t, svc, "an App with no switches block builds no switch service")
}

func TestNewSwitchService_BuildsOneManagerPerConfiguredSwitch(t *testing.T) {
	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	require.NotNil(t, svc)
	t.Cleanup(func() { _ = svc.Close() })

	mgr, err := svc.Manager("core-1")
	require.NoError(t, err)
	assert.NotNil(t, mgr)

	_, err = svc.Manager("edge-9")
	require.Error(t, err)
	var notFound switchmgmt.ErrManagerNotFound
	assert.True(t, errors.As(err, &notFound), "an unconfigured switch is ErrManagerNotFound, got %v", err)
}

func TestNewSwitchService_RefusesAnUnsupportedVendor(t *testing.T) {
	a := &app.App{
		SwitchConfigs: []switchmgmt.Config{{Name: "core-1", Vendor: "unknown-vendor"}},
	}

	svc, err := newSwitchService(logging.DefaultLogger(), a)
	require.Error(t, err)
	assert.Nil(t, svc)
	var unsupported switchmgmt.ErrUnsupportedVendor
	assert.True(t, errors.As(err, &unsupported), "the cause stays reachable through the wrap, got %v", err)
}

func TestSwitchServiceProvider_NilServiceIsANilInterface(t *testing.T) {
	// assert.Nil also passes for a typed nil inside an interface; the REST
	// router tests the interface against nil, so compare it directly.
	require.True(t, switchServiceProvider(nil) == nil)

	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })
	require.True(t, switchServiceProvider(svc) != nil)
}

func TestWireSwitchService_TheServicerAnswersForAConfiguredSwitch(t *testing.T) {
	ctx := context.Background()
	grpcSvc := daemon.NewSwitchGRPCService(logging.DefaultLogger(), nil)

	_, err := grpcSvc.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "before wiring the servicer is dark")

	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })
	wireSwitchService(grpcSvc, svc)

	_, err = grpcSvc.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"})
	require.NoError(t, err)

	_, err = grpcSvc.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: "edge-9"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestWireSwitchService_ANilServiceKeepsTheServicerUnavailable(t *testing.T) {
	ctx := context.Background()
	grpcSvc := daemon.NewSwitchGRPCService(logging.DefaultLogger(), nil)

	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	require.NotPanics(t, func() { wireSwitchService(grpcSvc, nil) })
	require.NotPanics(t, func() { wireSwitchService(nil, svc) })

	_, err = grpcSvc.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
