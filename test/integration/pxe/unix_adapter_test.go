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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func TestNewUnixAdapter_SpeaksGRPCOnTheSocket(t *testing.T) {
	t.Setenv(EnvPlatformdSocket, "/run/test-platformd.sock")

	adapter := NewUnixAdapter()
	opts := adapter.options()

	assert.Equal(t, "Unix", adapter.Name())
	assert.Equal(t, "/run/test-platformd.sock", opts.UnixSocket)
	assert.Equal(t, platform.ProtocolUnix, opts.OnlyProtocol, "the socket serves gRPC, not HTTP")
}

func TestNewUnixAdapter_MissingSocketFails(t *testing.T) {
	t.Setenv(EnvPlatformdSocket, filepath.Join(t.TempDir(), "absent.sock"))

	adapter := NewUnixAdapter()
	err := adapter.Setup(context.Background())
	if err == nil {
		// The gRPC transport dials lazily; the first call reaches the socket.
		_, err = adapter.GetStatus(context.Background())
	}
	t.Cleanup(func() { assert.NoError(t, adapter.Teardown()) })

	require.Error(t, err)
	var connErr ErrConnectionFailed
	var reqErr ErrRequestFailed
	assert.True(t, errors.As(err, &connErr) || errors.As(err, &reqErr), "got %T: %v", err, err)
}
