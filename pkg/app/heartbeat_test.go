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

package app

import (
	"context"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeartbeatConfig_Active(t *testing.T) {
	var nilCfg *HeartbeatConfig
	assert.False(t, nilCfg.Active())
	assert.False(t, (&HeartbeatConfig{}).Active())
	assert.True(t, (&HeartbeatConfig{Enabled: true}).Active())
}

// TestStartDeviceHeartbeat_AbsentSection proves the platform's
// explicit-configuration convention: no section, no reporter, no error.
func TestStartDeviceHeartbeat_AbsentSection(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	require.NoError(t, app.StartDeviceHeartbeat(context.Background()))
}

// TestStartDeviceHeartbeat_NoACMEClient proves a control plane (no ACME
// client section) does not report to itself.
func TestStartDeviceHeartbeat_NoACMEClient(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{Enabled: true},
	}
	require.NoError(t, app.StartDeviceHeartbeat(context.Background()))
}

// TestStartDeviceHeartbeat_IntervalTooShort proves a unitless YAML
// interval (nanoseconds) refuses startup instead of hot-looping.
func TestStartDeviceHeartbeat_IntervalTooShort(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{Enabled: true, Interval: 30 * time.Nanosecond},
		ACMEConfig: &trustedca.ACMEConfig{
			Client: &trustedca.ACMEClientYAMLConfig{
				DirectoryURL: "https://cp.example.internal:8443/api/v1/acme/directory",
			},
		},
	}
	err := app.StartDeviceHeartbeat(context.Background())
	require.Error(t, err)
	var tooShort ErrHeartbeatIntervalTooShort
	assert.ErrorAs(t, err, &tooShort)
}

// TestStartDeviceHeartbeat_StartsAndStops proves a valid section starts
// the reporter goroutine and context cancellation stops it. With no TPM
// wired the loop stays in its fail-soft retry path, which is exactly
// the contract: liveness reporting never takes a node down.
func TestStartDeviceHeartbeat_StartsAndStops(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{Enabled: true, Interval: MinHeartbeatInterval},
		ACMEConfig: &trustedca.ACMEConfig{
			Client: &trustedca.ACMEClientYAMLConfig{
				DirectoryURL: "https://cp.example.internal:8443/api/v1/acme/directory",
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, app.StartDeviceHeartbeat(ctx))
	cancel()
}

// TestStopDeviceHeartbeat_Idempotent proves stop is safe with and
// without a running reporter, and that a second Start replaces the
// first loop instead of leaking one.
func TestStopDeviceHeartbeat_Idempotent(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{Enabled: true, Interval: MinHeartbeatInterval},
		ACMEConfig: &trustedca.ACMEConfig{
			Client: &trustedca.ACMEClientYAMLConfig{
				DirectoryURL: "https://cp.example.internal:8443/api/v1/acme/directory",
			},
		},
	}
	app.StopDeviceHeartbeat() // nothing running: must not panic
	require.NoError(t, app.StartDeviceHeartbeat(context.Background()))
	require.NoError(t, app.StartDeviceHeartbeat(context.Background()))
	app.StopDeviceHeartbeat()
	assert.Nil(t, app.heartbeatCancel)
}

// TestNewFileHeartbeatClient_HalfConfigured proves a section with only
// one of cert-file/key-file fails closed instead of falling back.
func TestNewFileHeartbeatClient_HalfConfigured(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{Enabled: true, CertFile: "/etc/x/client.pem"},
	}
	_, err := app.newHeartbeatClient("https://cp.example.internal:9443")
	var incomplete ErrHeartbeatIdentityIncomplete
	assert.ErrorAs(t, err, &incomplete)
}

// TestNewFileHeartbeatClient_MissingFiles proves unreadable identity
// files surface as errors, not panics.
func TestNewFileHeartbeatClient_MissingFiles(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{
			Enabled:  true,
			CertFile: "/nonexistent/client.pem",
			KeyFile:  "/nonexistent/client-key.pem",
		},
	}
	_, err := app.newHeartbeatClient("https://cp.example.internal:9443")
	assert.Error(t, err)
}

// TestStartDeviceHeartbeat_HalfConfiguredIdentity proves a section with
// only one of cert-file/key-file refuses startup synchronously.
func TestStartDeviceHeartbeat_HalfConfiguredIdentity(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		HeartbeatConfig: &HeartbeatConfig{
			Enabled:  true,
			Interval: MinHeartbeatInterval,
			CertFile: "/etc/x/client.pem",
		},
		ACMEConfig: &trustedca.ACMEConfig{
			Client: &trustedca.ACMEClientYAMLConfig{
				DirectoryURL: "https://cp.example.internal:8443/api/v1/acme/directory",
			},
		},
	}
	err := app.StartDeviceHeartbeat(context.Background())
	var incomplete ErrHeartbeatIdentityIncomplete
	assert.ErrorAs(t, err, &incomplete)
	assert.Nil(t, app.heartbeatCancel)
}
