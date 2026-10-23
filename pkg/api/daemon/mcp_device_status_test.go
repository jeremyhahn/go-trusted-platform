// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// The MCP device tools answer a missing device with NotFound, the class the
// gRPC device service reports for the same request. The production device
// service wraps the quicbaas DAO miss, which carries no datastore sentinel,
// so before the tools classified through deviceStatusError the MCP server
// reported it as Internal (TestDeviceErrorClassParity/MCP).
func TestMCPServiceProvider_DeviceTools_MissingDeviceIsNotFound(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: newRealDeviceService(t),
	})

	calls := map[string]func() error{
		"get": func() error {
			_, err := provider.DeviceGet(ctx, "999999999")
			return err
		},
		"find by serial": func() error {
			_, err := provider.DeviceFindBySerial(ctx, "SN-missing")
			return err
		},
		"delete": func() error {
			return provider.DeviceDelete(ctx, "999999999")
		},
		"update": func() error {
			return provider.DeviceUpdate(ctx, "999999999", map[string]interface{}{"model": "m"})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.NotFound, status.Code(err), "error = %v", err)
		})
	}
}

// A stored device is still returned unchanged, and an unparseable id is still
// refused before the service is asked.
func TestMCPServiceProvider_DeviceGet_ExistingAndInvalid(t *testing.T) {
	ctx := context.Background()
	svc := newRealDeviceService(t)
	require.NoError(t, svc.Create(ctx, &entities.Device{ID: 4242, Serial: "SN-4242"}))
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceService: svc})

	got, err := provider.DeviceGet(ctx, "4242")
	require.NoError(t, err)
	dev, ok := got.(*entities.Device)
	require.True(t, ok, "DeviceGet returned %T", got)
	assert.Equal(t, "SN-4242", dev.Serial)

	_, err = provider.DeviceGet(ctx, "not-a-number")
	require.Error(t, err)
	assert.NotEqual(t, codes.NotFound, status.Code(err))
}
