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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

// bootOverMCP is one MCP provider's pair of boot tools.
type bootOverMCP interface {
	DeviceBootCertificate(ctx context.Context, identity string, signature []byte) (interface{}, error)
	DeviceBootDelivery(ctx context.Context, evidence []byte) (interface{}, error)
}

// MCP carries no TLS connection, so both providers refuse both boot tools
// with the typed channel refusal, whatever the request holds.
func TestMCPProviders_DeviceBootIsRefusedWithoutAChannel(t *testing.T) {
	providers := map[string]bootOverMCP{
		"MCPServiceProvider": NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService: newMockDeviceService(),
			Logger:        slog.Default(),
		}),
		"PlatformServiceProvider": NewPlatformServiceProvider(&PlatformServiceProviderConfig{
			DeviceService: newMockDeviceService(),
			Logger:        slog.Default(),
		}),
	}
	for name, p := range providers {
		t.Run(name, func(t *testing.T) {
			out, err := p.DeviceBootCertificate(context.Background(), "node-1.example", []byte("sig"))
			assert.Nil(t, out)
			assertRefusedOverMCP(t, err)

			out, err = p.DeviceBootDelivery(context.Background(), []byte("evidence"))
			assert.Nil(t, out)
			assertRefusedOverMCP(t, err)
		})
	}
}

func assertRefusedOverMCP(t *testing.T, err error) {
	t.Helper()
	var refused restdevice.ErrBootChannelRequired
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "MCP", refused.Transport)
	var unbound *provisioning.ErrBootChannelUnbound
	assert.ErrorAs(t, err, &unbound, "the refusal carries why the channel is unbound")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "MCP classifies the refusal as gRPC answers it")
}
