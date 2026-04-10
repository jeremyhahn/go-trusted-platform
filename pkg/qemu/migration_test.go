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

// TestRAMStats tests the RAMStats struct.
func TestRAMStats(t *testing.T) {
	stats := RAMStats{
		Transferred:      1024 * 1024 * 100,
		Remaining:        1024 * 1024 * 50,
		Total:            1024 * 1024 * 150,
		Duplicate:        1000,
		Skipped:          500,
		Normal:           2000,
		NormalBytes:      1024 * 1024 * 80,
		DirtyPagesRate:   100,
		DirtySync:        5,
		Mbps:             800.5,
		PageSize:         4096,
		PostcopyRequests: 10,
	}

	assert.Equal(t, int64(1024*1024*100), stats.Transferred)
	assert.Equal(t, int64(1024*1024*50), stats.Remaining)
	assert.Equal(t, int64(1024*1024*150), stats.Total)
	assert.Equal(t, int64(1000), stats.Duplicate)
	assert.Equal(t, int64(500), stats.Skipped)
	assert.Equal(t, int64(2000), stats.Normal)
	assert.Equal(t, int64(1024*1024*80), stats.NormalBytes)
	assert.Equal(t, int64(100), stats.DirtyPagesRate)
	assert.Equal(t, int64(5), stats.DirtySync)
	assert.Equal(t, 800.5, stats.Mbps)
	assert.Equal(t, int64(4096), stats.PageSize)
	assert.Equal(t, int64(10), stats.PostcopyRequests)
}

// TestDiskStats tests the DiskStats struct.
func TestDiskStats(t *testing.T) {
	stats := DiskStats{
		Transferred: 1024 * 1024 * 500,
		Remaining:   1024 * 1024 * 250,
		Total:       1024 * 1024 * 750,
	}

	assert.Equal(t, int64(1024*1024*500), stats.Transferred)
	assert.Equal(t, int64(1024*1024*250), stats.Remaining)
	assert.Equal(t, int64(1024*1024*750), stats.Total)
}

// TestMigrationStatus tests the MigrationStatus struct.
func TestMigrationStatus(t *testing.T) {
	ramStats := &RAMStats{
		Transferred: 1024 * 1024,
		Total:       1024 * 1024 * 2,
	}
	diskStats := &DiskStats{
		Transferred: 1024 * 1024 * 10,
		Total:       1024 * 1024 * 20,
	}

	status := MigrationStatus{
		Status:           MigrationStatusActive,
		TotalTime:        5000,
		SetupTime:        100,
		ExpectedDowntime: 50,
		Downtime:         0,
		RAM:              ramStats,
		Disk:             diskStats,
		Blocked:          false,
		BlockedReasons:   nil,
	}

	assert.Equal(t, MigrationStatusActive, status.Status)
	assert.Equal(t, int64(5000), status.TotalTime)
	assert.Equal(t, int64(100), status.SetupTime)
	assert.Equal(t, int64(50), status.ExpectedDowntime)
	assert.NotNil(t, status.RAM)
	assert.NotNil(t, status.Disk)
	assert.False(t, status.Blocked)
}

// TestMigrationStatusBlocked tests blocked migration status.
func TestMigrationStatusBlocked(t *testing.T) {
	status := MigrationStatus{
		Status:         MigrationStatusNone,
		Blocked:        true,
		BlockedReasons: []string{"dirty-rate-limit", "device-not-capable"},
	}

	assert.True(t, status.Blocked)
	assert.Len(t, status.BlockedReasons, 2)
	assert.Contains(t, status.BlockedReasons, "dirty-rate-limit")
	assert.Contains(t, status.BlockedReasons, "device-not-capable")
}

// TestMigrationCapability tests the MigrationCapability struct.
func TestMigrationCapability(t *testing.T) {
	cap := MigrationCapability{
		Capability: "xbzrle",
		State:      true,
	}

	assert.Equal(t, "xbzrle", cap.Capability)
	assert.True(t, cap.State)
}

// TestMigrationCapabilities tests the MigrationCapabilities struct.
func TestMigrationCapabilities(t *testing.T) {
	caps := MigrationCapabilities{
		XBZRLE:                true,
		AutoConverge:          true,
		Compress:              false,
		Postcopy:              true,
		Multifd:               true,
		DirtyBitmaps:          false,
		ZeroPageDetection:     true,
		PauseBeforeSwitchover: false,
	}

	assert.True(t, caps.XBZRLE)
	assert.True(t, caps.AutoConverge)
	assert.False(t, caps.Compress)
	assert.True(t, caps.Postcopy)
	assert.True(t, caps.Multifd)
	assert.False(t, caps.DirtyBitmaps)
	assert.True(t, caps.ZeroPageDetection)
	assert.False(t, caps.PauseBeforeSwitchover)
}

// TestMigrationParams tests the MigrationParams struct.
func TestMigrationParams(t *testing.T) {
	params := MigrationParams{
		MaxBandwidth:         1024 * 1024 * 100,
		DowntimeLimit:        100,
		CompressLevel:        5,
		CompressThreads:      4,
		DecompressThreads:    4,
		CPUThrottleInitial:   20,
		CPUThrottleIncrement: 10,
		CPUThrottleTailslow:  true,
		TLSCreds:             "tls0",
		TLSHostname:          "migration.example.com",
		TLSAuthz:             "authz0",
		MaxPostcopyBandwidth: 1024 * 1024 * 50,
		MultifdChannels:      4,
		MultifdCompression:   "zlib",
		MultifdZlibLevel:     6,
		MultifdZstdLevel:     3,
		XBZRLECacheSize:      1024 * 1024 * 64,
		BlockIncremental:     true,
		AnnounceInitial:      50,
		AnnounceMax:          550,
		AnnounceRounds:       5,
		AnnounceStep:         100,
	}

	assert.Equal(t, int64(1024*1024*100), params.MaxBandwidth)
	assert.Equal(t, int64(100), params.DowntimeLimit)
	assert.Equal(t, 5, params.CompressLevel)
	assert.Equal(t, 4, params.CompressThreads)
	assert.Equal(t, 4, params.DecompressThreads)
	assert.Equal(t, 20, params.CPUThrottleInitial)
	assert.Equal(t, 10, params.CPUThrottleIncrement)
	assert.True(t, params.CPUThrottleTailslow)
	assert.Equal(t, "tls0", params.TLSCreds)
	assert.Equal(t, "migration.example.com", params.TLSHostname)
	assert.Equal(t, "authz0", params.TLSAuthz)
	assert.Equal(t, int64(1024*1024*50), params.MaxPostcopyBandwidth)
	assert.Equal(t, 4, params.MultifdChannels)
	assert.Equal(t, "zlib", params.MultifdCompression)
	assert.Equal(t, 6, params.MultifdZlibLevel)
	assert.Equal(t, 3, params.MultifdZstdLevel)
	assert.Equal(t, int64(1024*1024*64), params.XBZRLECacheSize)
	assert.True(t, params.BlockIncremental)
	assert.Equal(t, 50, params.AnnounceInitial)
	assert.Equal(t, 550, params.AnnounceMax)
	assert.Equal(t, 5, params.AnnounceRounds)
	assert.Equal(t, 100, params.AnnounceStep)
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

// TestMigrationStatusWithError tests MigrationStatus with error description.
func TestMigrationStatusWithError(t *testing.T) {
	status := MigrationStatus{
		Status:           MigrationStatusFailed,
		ErrorDescription: "destination host unreachable",
	}

	assert.Equal(t, MigrationStatusFailed, status.Status)
	assert.Equal(t, "destination host unreachable", status.ErrorDescription)
}
