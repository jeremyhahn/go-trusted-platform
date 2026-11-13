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

package qemu

import (
	"context"
	"testing"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMonitor(t *testing.T) {
	t.Run("creates monitor with valid parameters", func(t *testing.T) {
		socketPath := "/tmp/qmp.sock"
		timeout := 5 * time.Second

		mon := NewMonitor(socketPath, timeout, nil)

		require.NotNil(t, mon)
		assert.Equal(t, socketPath, mon.GetSocketPath())
		assert.Equal(t, timeout, mon.timeout)
		assert.NotNil(t, mon.logger)
		assert.False(t, mon.IsConnected())
	})

	t.Run("creates monitor with nil logger uses default", func(t *testing.T) {
		mon := NewMonitor("/tmp/test.sock", time.Second, nil)

		require.NotNil(t, mon)
		assert.NotNil(t, mon.logger)
	})
}

func TestMonitorConnectErrors(t *testing.T) {
	t.Run("connect fails with non-existent socket", func(t *testing.T) {
		mon := NewMonitor("/nonexistent/path/to/qmp.sock", time.Second, nil)
		ctx := context.Background()

		err := mon.Connect(ctx)

		require.Error(t, err)
		var socketErr ErrMonitorSocketNotFound
		assert.ErrorAs(t, err, &socketErr)
		assert.Equal(t, "/nonexistent/path/to/qmp.sock", socketErr.SocketPath)
	})

	t.Run("operations fail when not connected", func(t *testing.T) {
		mon := NewMonitor("/tmp/test.sock", time.Second, nil)
		ctx := context.Background()

		// Status
		_, err := mon.Status(ctx)
		require.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)

		// SystemPowerdown
		err = mon.SystemPowerdown(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// SystemReset
		err = mon.SystemReset(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// Pause
		err = mon.Pause(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// Resume
		err = mon.Resume(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// BlockDevices
		_, err = mon.BlockDevices(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// Version
		_, err = mon.Version()
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// Capabilities
		_, err = mon.Capabilities()
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// QueryCommands
		_, err = mon.QueryCommands(ctx)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// Run
		_, err = mon.Run(ctx, "test-cmd", nil)
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)

		// SubscribeEvents
		err = mon.SubscribeEvents(ctx, func(event qmp.Event) {})
		require.Error(t, err)
		assert.ErrorAs(t, err, &notConnected)
	})
}

func TestMonitorClose(t *testing.T) {
	t.Run("close on unconnected monitor returns nil", func(t *testing.T) {
		mon := NewMonitor("/tmp/test.sock", time.Second, nil)

		err := mon.Close()

		assert.NoError(t, err)
	})
}

func TestMonitorUnsubscribeEvents(t *testing.T) {
	t.Run("unsubscribe on unsubscribed monitor is safe", func(t *testing.T) {
		mon := NewMonitor("/tmp/test.sock", time.Second, nil)

		// Should not panic
		mon.UnsubscribeEvents()
		assert.Nil(t, mon.eventHandler)
	})
}

func TestMonitorIsConnected(t *testing.T) {
	t.Run("returns false for new monitor", func(t *testing.T) {
		mon := NewMonitor("/tmp/test.sock", time.Second, nil)

		assert.False(t, mon.IsConnected())
	})
}

func TestParseVMStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected VMStatus
	}{
		{"running", "running", VMStatus("running")},
		{"paused", "paused", VMStatus("paused")},
		{"shutdown", "shutdown", VMStatus("shutdown")},
		{"prelaunch", "prelaunch", VMStatus("prelaunch")},
		{"io-error", "io-error", VMStatus("io-error")},
		{"internal-error", "internal-error", VMStatus("internal-error")},
		{"suspended", "suspended", VMStatus("suspended")},
		{"guest-panicked", "guest-panicked", VMStatus("guest-panicked")},
		{"unknown status", "some-random-status", VMStatus("unknown")},
		{"empty string", "", VMStatus("unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVMStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMonitorErrors(t *testing.T) {
	t.Run("ErrMonitorConnectionFailed error message", func(t *testing.T) {
		err := ErrMonitorConnectionFailed{
			SocketPath: "/tmp/test.sock",
			Cause:      assert.AnError,
		}
		assert.Contains(t, err.Error(), "/tmp/test.sock")
		assert.Contains(t, err.Error(), "failed to connect")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("ErrMonitorConnectionFailed without cause", func(t *testing.T) {
		err := ErrMonitorConnectionFailed{
			SocketPath: "/tmp/test.sock",
		}
		assert.Contains(t, err.Error(), "/tmp/test.sock")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrMonitorNotConnected error message", func(t *testing.T) {
		err := ErrMonitorNotConnected{}
		assert.Contains(t, err.Error(), "not connected")
	})

	t.Run("ErrMonitorAlreadyConnected error message", func(t *testing.T) {
		err := ErrMonitorAlreadyConnected{}
		assert.Contains(t, err.Error(), "already connected")
	})

	t.Run("ErrMonitorHandshakeFailed error message", func(t *testing.T) {
		err := ErrMonitorHandshakeFailed{Cause: assert.AnError}
		assert.Contains(t, err.Error(), "handshake failed")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("ErrMonitorHandshakeFailed without cause", func(t *testing.T) {
		err := ErrMonitorHandshakeFailed{}
		assert.Contains(t, err.Error(), "handshake failed")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrMonitorCommandFailed error message", func(t *testing.T) {
		err := ErrMonitorCommandFailed{
			Command: "query-status",
			Cause:   assert.AnError,
		}
		assert.Contains(t, err.Error(), "query-status")
		assert.Contains(t, err.Error(), "failed")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("ErrMonitorCommandFailed without cause", func(t *testing.T) {
		err := ErrMonitorCommandFailed{
			Command: "test-cmd",
		}
		assert.Contains(t, err.Error(), "test-cmd")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrMonitorTimeout error message", func(t *testing.T) {
		err := ErrMonitorTimeout{Operation: "connect"}
		assert.Contains(t, err.Error(), "connect")
		assert.Contains(t, err.Error(), "timed out")
	})

	t.Run("ErrMonitorSocketNotFound error message", func(t *testing.T) {
		err := ErrMonitorSocketNotFound{SocketPath: "/tmp/missing.sock"}
		assert.Contains(t, err.Error(), "/tmp/missing.sock")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ErrMonitorInvalidResponse error message", func(t *testing.T) {
		err := ErrMonitorInvalidResponse{
			Command: "query-block",
			Cause:   assert.AnError,
		}
		assert.Contains(t, err.Error(), "query-block")
		assert.Contains(t, err.Error(), "invalid")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("ErrMonitorInvalidResponse without cause", func(t *testing.T) {
		err := ErrMonitorInvalidResponse{
			Command: "test-cmd",
		}
		assert.Contains(t, err.Error(), "test-cmd")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrMonitorEventsNotSupported error message", func(t *testing.T) {
		err := ErrMonitorEventsNotSupported{}
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("ErrMonitorDisconnected error message", func(t *testing.T) {
		err := ErrMonitorDisconnected{}
		assert.Contains(t, err.Error(), "closed")
	})
}

func TestGetSocketPath(t *testing.T) {
	t.Run("returns configured socket path", func(t *testing.T) {
		socketPath := "/var/run/qemu/vm1.sock"
		mon := NewMonitor(socketPath, time.Second, nil)

		assert.Equal(t, socketPath, mon.GetSocketPath())
	})
}
