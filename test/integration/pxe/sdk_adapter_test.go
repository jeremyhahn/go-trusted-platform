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

//go:build integration

package pxe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// TestSDKAdaptersRegisterTheirTransport proves every protocol the suite's SDK
// adapters dial has a registered connector in this package. A transport the
// package never blank-imports fails Connect with ErrProtocolNotImplemented
// before it dials anything, which is how the gRPC leg failed (#949). Whether
// the dial itself succeeds depends on the daemon and is the suite's concern,
// not this test's.
func TestSDKAdaptersRegisterTheirTransport(t *testing.T) {
	for _, proto := range []platform.Protocol{
		platform.ProtocolREST,
		platform.ProtocolGRPC,
		platform.ProtocolQUIC,
		platform.ProtocolMCP,
		platform.ProtocolUnix,
	} {
		t.Run(proto.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			client, err := platform.Connect(ctx, platform.NewOptions(platform.WithOnlyProtocol(proto)))
			if err == nil {
				assert.NoError(t, client.Close())
				return
			}

			var notImplemented platform.ErrProtocolNotImplemented
			assert.False(t, errors.As(err, &notImplemented),
				"%s has no registered SDK transport: %v", proto, err)
		})
	}
}

// TestSDKAdapterSetupReportsAnUnregisteredProtocol is the negative case: a
// protocol nothing registers surfaces as ErrProtocolNotImplemented through
// ErrConnectionFailed, which is what the test above relies on. The suite
// never imports the embedded transport, so ProtocolEmbedded is unregistered.
func TestSDKAdapterSetupReportsAnUnregisteredProtocol(t *testing.T) {
	adapter := &SDKAdapter{
		name:     "embedded",
		endpoint: "in-process",
		options: func() *platform.Options {
			return platform.NewOptions(platform.WithOnlyProtocol(platform.ProtocolEmbedded))
		},
	}

	err := adapter.Setup(context.Background())

	var notImplemented platform.ErrProtocolNotImplemented
	assert.True(t, errors.As(err, &notImplemented), "want ErrProtocolNotImplemented, got %v", err)
}
