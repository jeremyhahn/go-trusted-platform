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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrMigrationFailed tests the ErrMigrationFailed error type.
func TestErrMigrationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrMigrationFailed{URI: "tcp:192.168.1.100:4444", Cause: cause}

		assert.Equal(t, "migration to tcp:192.168.1.100:4444 failed: connection refused", err.Error())
		assert.ErrorIs(t, err, cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrMigrationFailed{URI: "tcp:192.168.1.100:4444"}

		assert.Equal(t, "migration to tcp:192.168.1.100:4444 failed", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// TestErrMigrationCancelled tests the ErrMigrationCancelled error type.
func TestErrMigrationCancelled(t *testing.T) {
	t.Run("with URI", func(t *testing.T) {
		err := ErrMigrationCancelled{URI: "tcp:192.168.1.100:4444"}

		assert.Equal(t, "migration to tcp:192.168.1.100:4444 was cancelled", err.Error())
	})

	t.Run("without URI", func(t *testing.T) {
		err := ErrMigrationCancelled{}

		assert.Equal(t, "migration was cancelled", err.Error())
	})
}

// TestErrMigrationInProgress tests the ErrMigrationInProgress error type.
func TestErrMigrationInProgress(t *testing.T) {
	err := ErrMigrationInProgress{}

	assert.Equal(t, "migration is already in progress", err.Error())
}

// TestErrMigrationNotActive tests the ErrMigrationNotActive error type.
func TestErrMigrationNotActive(t *testing.T) {
	err := ErrMigrationNotActive{}

	assert.Equal(t, "no migration is currently active", err.Error())
}

// TestErrMigrationInvalidURI tests the ErrMigrationInvalidURI error type.
func TestErrMigrationInvalidURI(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("invalid port")
		err := ErrMigrationInvalidURI{URI: "tcp:host:abc", Cause: cause}

		assert.Equal(t, "invalid migration URI \"tcp:host:abc\": invalid port", err.Error())
		assert.ErrorIs(t, err, cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrMigrationInvalidURI{URI: "invalid"}

		assert.Equal(t, "invalid migration URI \"invalid\"", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// TestErrMigrationTimeout tests the ErrMigrationTimeout error type.
func TestErrMigrationTimeout(t *testing.T) {
	t.Run("with elapsed", func(t *testing.T) {
		err := ErrMigrationTimeout{URI: "tcp:192.168.1.100:4444", Elapsed: "30s"}

		assert.Equal(t, "migration to tcp:192.168.1.100:4444 timed out after 30s", err.Error())
	})

	t.Run("without elapsed", func(t *testing.T) {
		err := ErrMigrationTimeout{URI: "tcp:192.168.1.100:4444"}

		assert.Equal(t, "migration to tcp:192.168.1.100:4444 timed out", err.Error())
	})
}

// TestErrMigrationSetupFailed tests the ErrMigrationSetupFailed error type.
func TestErrMigrationSetupFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("capability not supported")
		err := ErrMigrationSetupFailed{Operation: "set-capabilities", Cause: cause}

		assert.Equal(t, "migration setup failed during set-capabilities: capability not supported", err.Error())
		assert.ErrorIs(t, err, cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrMigrationSetupFailed{Operation: "set-parameters"}

		assert.Equal(t, "migration setup failed during set-parameters", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// TestErrMigrationCapabilityNotSupported tests the ErrMigrationCapabilityNotSupported error type.
func TestErrMigrationCapabilityNotSupported(t *testing.T) {
	err := ErrMigrationCapabilityNotSupported{Capability: "xbzrle"}

	assert.Equal(t, "migration capability \"xbzrle\" is not supported", err.Error())
}

// TestErrMigrationParameterInvalid tests the ErrMigrationParameterInvalid error type.
func TestErrMigrationParameterInvalid(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("value out of range")
		err := ErrMigrationParameterInvalid{Parameter: "compress-level", Value: 15, Cause: cause}

		assert.Equal(t, "invalid migration parameter compress-level=15: value out of range", err.Error())
		assert.ErrorIs(t, err, cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrMigrationParameterInvalid{Parameter: "bandwidth", Value: -1}

		assert.Equal(t, "invalid migration parameter bandwidth=-1", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// TestMigrationStatusType tests the MigrationStatusType constants.
func TestMigrationStatusType(t *testing.T) {
	tests := []struct {
		name     string
		status   MigrationStatusType
		expected string
	}{
		{"none", MigrationStatusNone, "none"},
		{"setup", MigrationStatusSetup, "setup"},
		{"active", MigrationStatusActive, "active"},
		{"postcopy-active", MigrationStatusPostcopyActive, "postcopy-active"},
		{"postcopy-paused", MigrationStatusPostcopyPaused, "postcopy-paused"},
		{"postcopy-recover", MigrationStatusPostcopyRecover, "postcopy-recover"},
		{"completed", MigrationStatusCompleted, "completed"},
		{"failed", MigrationStatusFailed, "failed"},
		{"cancelling", MigrationStatusCancelling, "cancelling"},
		{"cancelled", MigrationStatusCancelled, "cancelled"},
		{"pre-switchover", MigrationStatusPreSwitchover, "pre-switchover"},
		{"device", MigrationStatusDevice, "device"},
		{"wait-unplug", MigrationStatusWaitUnplug, "wait-unplug"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.status))
		})
	}
}

// TestParseMigrationStatus tests the parseMigrationStatus function.
func TestParseMigrationStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected MigrationStatusType
	}{
		{"none", MigrationStatusNone},
		{"setup", MigrationStatusSetup},
		{"active", MigrationStatusActive},
		{"postcopy-active", MigrationStatusPostcopyActive},
		{"postcopy-paused", MigrationStatusPostcopyPaused},
		{"postcopy-recover", MigrationStatusPostcopyRecover},
		{"completed", MigrationStatusCompleted},
		{"failed", MigrationStatusFailed},
		{"cancelling", MigrationStatusCancelling},
		{"cancelled", MigrationStatusCancelled},
		{"pre-switchover", MigrationStatusPreSwitchover},
		{"device", MigrationStatusDevice},
		{"wait-unplug", MigrationStatusWaitUnplug},
		{"unknown", MigrationStatusNone},
		{"", MigrationStatusNone},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseMigrationStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNewMigrationManager tests the NewMigrationManager constructor.
func TestNewMigrationManager(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := logging.DefaultLogger()
		monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
		manager := NewMigrationManager(monitor, logger)

		require.NotNil(t, manager)
		assert.Equal(t, monitor, manager.GetMonitor())
	})

	t.Run("with nil logger", func(t *testing.T) {
		monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, nil)
		manager := NewMigrationManager(monitor, nil)

		require.NotNil(t, manager)
		assert.Equal(t, monitor, manager.GetMonitor())
	})
}

// TestMigrationManagerValidateURI tests URI validation.
func TestMigrationManagerValidateURI(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
	manager := NewMigrationManager(monitor, logger)

	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{"tcp valid", "tcp:192.168.1.100:4444", false},
		{"tcp ipv6", "tcp:[::1]:4444", false},
		{"unix valid", "unix:/var/run/migration.sock", false},
		{"exec valid", "exec:nc -l 4444", false},
		{"fd valid", "fd:migration-fd", false},
		{"rdma valid", "rdma:192.168.1.100:4444", false},
		{"empty", "", true},
		{"no protocol", "192.168.1.100:4444", true},
		{"invalid protocol", "http://host:4444", true},
		{"incomplete tcp", "tcp", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.validateURI(tt.uri)
			if tt.expectError {
				assert.Error(t, err)
				var uriErr ErrMigrationInvalidURI
				assert.ErrorAs(t, err, &uriErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMigrationManagerNotConnected tests operations when monitor is not connected.
func TestMigrationManagerNotConnected(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/nonexistent.sock", 5*time.Second, logger)
	manager := NewMigrationManager(monitor, logger)

	t.Run("migrate", func(t *testing.T) {
		err := manager.Migrate(context.TODO(), "tcp:192.168.1.100:4444")
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("migrate incoming", func(t *testing.T) {
		err := manager.MigrateIncoming(context.TODO(), "tcp:0:4444")
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("status", func(t *testing.T) {
		_, err := manager.Status(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("cancel", func(t *testing.T) {
		err := manager.Cancel(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("set parameters", func(t *testing.T) {
		params := &MigrationParams{MaxBandwidth: 1024 * 1024}
		err := manager.SetParameters(context.TODO(), params)
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("get parameters", func(t *testing.T) {
		_, err := manager.GetParameters(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("set capabilities", func(t *testing.T) {
		err := manager.SetCapabilities(context.TODO(), []string{"xbzrle"})
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("get capabilities", func(t *testing.T) {
		_, err := manager.GetCapabilities(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("continue migration", func(t *testing.T) {
		err := manager.ContinueMigration(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})

	t.Run("start postcopy", func(t *testing.T) {
		err := manager.StartPostcopy(context.TODO())
		assert.Error(t, err)
		var notConnected ErrMonitorNotConnected
		assert.ErrorAs(t, err, &notConnected)
	})
}

// TestMigrationManagerInvalidURI tests migration with invalid URI.
func TestMigrationManagerInvalidURI(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
	manager := NewMigrationManager(monitor, logger)

	t.Run("migrate with invalid URI", func(t *testing.T) {
		err := manager.Migrate(context.TODO(), "invalid-uri")
		assert.Error(t, err)
		var uriErr ErrMigrationInvalidURI
		assert.ErrorAs(t, err, &uriErr)
	})

	t.Run("migrate incoming with invalid URI", func(t *testing.T) {
		err := manager.MigrateIncoming(context.TODO(), "")
		assert.Error(t, err)
		var uriErr ErrMigrationInvalidURI
		assert.ErrorAs(t, err, &uriErr)
	})
}

// TestMigrationManagerSetParametersNil tests SetParameters with nil params.
func TestMigrationManagerSetParametersNil(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
	manager := NewMigrationManager(monitor, logger)

	err := manager.SetParameters(context.TODO(), nil)
	assert.Error(t, err)
	var paramErr ErrMigrationParameterInvalid
	assert.ErrorAs(t, err, &paramErr)
}

// TestMigrationManagerSetCapabilitiesEmpty tests SetCapabilities with empty slice.
func TestMigrationManagerSetCapabilitiesEmpty(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
	manager := NewMigrationManager(monitor, logger)

	// Empty capabilities should return nil without connecting
	err := manager.SetCapabilities(context.TODO(), []string{})
	assert.NoError(t, err)
}

// TestMigrationParamsValidation tests parameter validation.
func TestMigrationParamsValidation(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/qemu.sock", 5*time.Second, logger)
	// Force connected state for validation testing
	monitor.connected.Store(true)
	manager := NewMigrationManager(monitor, logger)

	t.Run("invalid compress level", func(t *testing.T) {
		params := &MigrationParams{CompressLevel: 15}
		err := manager.SetParameters(context.TODO(), params)
		assert.Error(t, err)
		var paramErr ErrMigrationParameterInvalid
		assert.ErrorAs(t, err, &paramErr)
	})

	// Reset connected state
	monitor.connected.Store(false)
}
