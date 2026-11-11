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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewSnapshotManager_WithValidMonitor(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/test.sock", time.Second, logger)

	sm, err := NewSnapshotManager(monitor, logger)
	require.NoError(t, err)
	require.NotNil(t, sm)
}

func TestNewSnapshotManager_WithNilLogger(t *testing.T) {
	monitor := NewMonitor("/tmp/test.sock", time.Second, nil)

	sm, err := NewSnapshotManager(monitor, nil)
	require.NoError(t, err)
	require.NotNil(t, sm)
}

func TestNewSnapshotManager_WithNilMonitor(t *testing.T) {
	sm, err := NewSnapshotManager(nil, nil)
	require.Error(t, err)
	require.Nil(t, sm)

	var notInitErr ErrSnapshotManagerNotInitialized
	require.True(t, errors.As(err, &notInitErr))
}

func TestIsValidSnapshotName_ValidNames(t *testing.T) {
	validNames := []string{
		"snapshot1",
		"_snapshot",
		"Snapshot_123",
		"snap-shot",
		"snap.shot",
		"SNAPSHOT",
		"a",
		"A1234567890",
		"snap_shot-v1.0",
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsValidSnapshotName(name), "expected %q to be valid", name)
		})
	}
}

func TestIsValidSnapshotName_InvalidNames(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{"", "empty name"},
		{"1snapshot", "starts with number"},
		{"-snapshot", "starts with hyphen"},
		{".snapshot", "starts with dot"},
		{"snap shot", "contains space"},
		{"snap@shot", "contains special char"},
		{"snap$shot", "contains dollar sign"},
		{"snap/shot", "contains slash"},
		{"snap\\shot", "contains backslash"},
		{"all", "reserved name"},
		{"none", "reserved name"},
		{"default", "reserved name"},
		{"ALL", "reserved name uppercase"},
		{"None", "reserved name mixed case"},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			assert.False(t, IsValidSnapshotName(tc.name), "expected %q to be invalid: %s", tc.name, tc.reason)
		})
	}
}

func TestIsValidSnapshotName_MaxLength(t *testing.T) {
	// 128 characters should be valid
	maxLen := "a" + string(make([]byte, 127))
	for i := 1; i < 128; i++ {
		maxLen = maxLen[:i] + "a"
	}
	maxLen = maxLen[:128]
	assert.Len(t, maxLen, 128)
	assert.True(t, IsValidSnapshotName(maxLen))

	// 129 characters should be invalid
	tooLong := maxLen + "a"
	assert.Len(t, tooLong, 129)
	assert.False(t, IsValidSnapshotName(tooLong))
}

// Error type tests

func TestErrSnapshotNotFound_Error(t *testing.T) {
	err := ErrSnapshotNotFound{Name: "my-snapshot"}
	assert.Equal(t, "snapshot not found: my-snapshot", err.Error())
}

func TestErrSnapshotCreateFailed_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("disk full")
		err := ErrSnapshotCreateFailed{Name: "snap1", Cause: cause}
		assert.Equal(t, `failed to create snapshot "snap1": disk full`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSnapshotCreateFailed{Name: "snap1"}
		assert.Equal(t, `failed to create snapshot "snap1"`, err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrSnapshotRestoreFailed_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("corrupted state")
		err := ErrSnapshotRestoreFailed{Name: "snap1", Cause: cause}
		assert.Equal(t, `failed to restore snapshot "snap1": corrupted state`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSnapshotRestoreFailed{Name: "snap1"}
		assert.Equal(t, `failed to restore snapshot "snap1"`, err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrSnapshotDeleteFailed_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("permission denied")
		err := ErrSnapshotDeleteFailed{Name: "snap1", Cause: cause}
		assert.Equal(t, `failed to delete snapshot "snap1": permission denied`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSnapshotDeleteFailed{Name: "snap1"}
		assert.Equal(t, `failed to delete snapshot "snap1"`, err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrSnapshotListFailed_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection lost")
		err := ErrSnapshotListFailed{Cause: cause}
		assert.Equal(t, "failed to list snapshots: connection lost", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSnapshotListFailed{}
		assert.Equal(t, "failed to list snapshots", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrSnapshotInvalidName_Error(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrSnapshotInvalidName{Name: "123bad", Reason: "starts with number"}
		assert.Equal(t, `invalid snapshot name "123bad": starts with number`, err.Error())
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrSnapshotInvalidName{Name: "bad!name"}
		assert.Equal(t, `invalid snapshot name "bad!name"`, err.Error())
	})
}

func TestErrSnapshotVMNotPaused_Error(t *testing.T) {
	t.Run("with operation", func(t *testing.T) {
		err := ErrSnapshotVMNotPaused{Operation: "restore"}
		assert.Equal(t, "VM must be paused for restore operation", err.Error())
	})

	t.Run("without operation", func(t *testing.T) {
		err := ErrSnapshotVMNotPaused{}
		assert.Equal(t, "VM must be paused for this operation", err.Error())
	})
}

func TestErrSnapshotManagerNotInitialized_Error(t *testing.T) {
	err := ErrSnapshotManagerNotInitialized{}
	assert.Equal(t, "snapshot manager is not initialized", err.Error())
}

func TestErrSnapshotAlreadyExists_Error(t *testing.T) {
	err := ErrSnapshotAlreadyExists{Name: "existing-snap"}
	assert.Equal(t, "snapshot already exists: existing-snap", err.Error())
}

func TestErrSnapshotParseError_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("invalid format")
		err := ErrSnapshotParseError{Line: "bad line here", Cause: cause}
		assert.Equal(t, `failed to parse snapshot info "bad line here": invalid format`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSnapshotParseError{Line: "bad line"}
		assert.Equal(t, `failed to parse snapshot info "bad line"`, err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// Helper function tests

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"0", 0},
		{"1", 1},
		{"100", 100},
		{"1K", 1024},
		{"1KB", 1024},
		{"1k", 1024},
		{"256M", 256 * 1024 * 1024},
		{"256MB", 256 * 1024 * 1024},
		{"1G", 1024 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"1.5M", uint64(1.5 * 1024 * 1024)},
		{"", 0},
		{"invalid", 0},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := parseSize(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseVMClock(t *testing.T) {
	tests := []struct {
		input       string
		expectedSec uint64
		expectedNs  uint64
	}{
		{"00:00:00", 0, 0},
		{"00:00:01", 1, 0},
		{"00:01:00", 60, 0},
		{"01:00:00", 3600, 0},
		{"00:05:30", 330, 0},
		{"00:00:00.123456789", 0, 123456789},
		{"00:05:30.123456789", 330, 123456789},
		{"00:00:00.1", 0, 100000000},
		{"00:00:00.12", 0, 120000000},
		{"00:00:00.123", 0, 123000000},
		{"01:30:45.500000000", 5445, 500000000},
		{"", 0, 0},
		{"invalid", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			sec, nsec := parseVMClock(tc.input)
			assert.Equal(t, tc.expectedSec, sec, "seconds mismatch")
			assert.Equal(t, tc.expectedNs, nsec, "nanoseconds mismatch")
		})
	}
}

func TestSnapshotManager_ValidateName(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/test.sock", time.Second, logger)
	sm, err := NewSnapshotManager(monitor, logger)
	require.NoError(t, err)

	t.Run("empty name", func(t *testing.T) {
		err := sm.validateName("")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
		assert.Contains(t, invalidErr.Reason, "empty")
	})

	t.Run("too long name", func(t *testing.T) {
		longName := string(make([]byte, 130))
		for i := range longName {
			longName = longName[:i] + "a" + longName[i+1:]
		}
		err := sm.validateName(longName)
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
		assert.Contains(t, invalidErr.Reason, "maximum length")
	})

	t.Run("invalid characters", func(t *testing.T) {
		err := sm.validateName("snap@shot")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})

	t.Run("reserved name", func(t *testing.T) {
		err := sm.validateName("all")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
		assert.Contains(t, invalidErr.Reason, "reserved")
	})

	t.Run("valid name", func(t *testing.T) {
		err := sm.validateName("valid_snapshot-name.v1")
		require.NoError(t, err)
	})
}

func TestSnapshotManager_OperationsRequireConnection(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/nonexistent.sock", time.Second, logger)
	sm, err := NewSnapshotManager(monitor, logger)
	require.NoError(t, err)

	ctx := t.Context()

	t.Run("Create requires connection", func(t *testing.T) {
		err := sm.Create(ctx, "test-snap")
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})

	t.Run("Restore requires connection", func(t *testing.T) {
		err := sm.Restore(ctx, "test-snap")
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})

	t.Run("Delete requires connection", func(t *testing.T) {
		err := sm.Delete(ctx, "test-snap")
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})

	t.Run("List requires connection", func(t *testing.T) {
		_, err := sm.List(ctx)
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})

	t.Run("Exists requires connection", func(t *testing.T) {
		_, err := sm.Exists(ctx, "test-snap")
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})

	t.Run("Get requires connection", func(t *testing.T) {
		_, err := sm.Get(ctx, "test-snap")
		require.Error(t, err)
		var notConnErr ErrMonitorNotConnected
		require.True(t, errors.As(err, &notConnErr))
	})
}

func TestSnapshotManager_ValidationBeforeConnection(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/nonexistent.sock", time.Second, logger)
	sm, err := NewSnapshotManager(monitor, logger)
	require.NoError(t, err)

	ctx := t.Context()

	t.Run("Create validates name first", func(t *testing.T) {
		err := sm.Create(ctx, "")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})

	t.Run("Restore validates name first", func(t *testing.T) {
		err := sm.Restore(ctx, "123invalid")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})

	t.Run("Delete validates name first", func(t *testing.T) {
		err := sm.Delete(ctx, "bad@name")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})

	t.Run("Exists validates name first", func(t *testing.T) {
		_, err := sm.Exists(ctx, "all")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})

	t.Run("Get validates name first", func(t *testing.T) {
		_, err := sm.Get(ctx, "none")
		require.Error(t, err)
		var invalidErr ErrSnapshotInvalidName
		require.True(t, errors.As(err, &invalidErr))
	})
}

func TestParseSnapshotLine(t *testing.T) {
	logger := logging.DefaultLogger()
	monitor := NewMonitor("/tmp/test.sock", time.Second, logger)
	sm, err := NewSnapshotManager(monitor, logger)
	require.NoError(t, err)

	t.Run("valid line", func(t *testing.T) {
		line := "1         snap1             256M 2024-01-15 10:30:00 00:05:30.123456789"
		snap, err := sm.parseSnapshotLine(line)
		require.NoError(t, err)
		assert.Equal(t, "1", snap.ID)
		assert.Equal(t, "snap1", snap.Name)
		assert.Equal(t, uint64(256*1024*1024), snap.VMStateSize)
		assert.Equal(t, uint64(330), snap.VMClockSec)
		assert.Equal(t, uint64(123456789), snap.VMClockNsec)
	})

	t.Run("minimum fields", func(t *testing.T) {
		line := "1 snap1 256M 2024-01-15 10:30:00"
		snap, err := sm.parseSnapshotLine(line)
		require.NoError(t, err)
		assert.Equal(t, "1", snap.ID)
		assert.Equal(t, "snap1", snap.Name)
	})

	t.Run("too few fields", func(t *testing.T) {
		line := "1 snap1 256M"
		_, err := sm.parseSnapshotLine(line)
		require.Error(t, err)
		var parseErr ErrSnapshotParseError
		require.True(t, errors.As(err, &parseErr))
	})
}

func TestHumanMonitorError(t *testing.T) {
	err := &humanMonitorError{message: "  Error: something went wrong  "}
	assert.Equal(t, "Error: something went wrong", err.Error())
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("underlying error")

	t.Run("ErrSnapshotCreateFailed unwrap", func(t *testing.T) {
		err := ErrSnapshotCreateFailed{Name: "test", Cause: cause}
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrSnapshotRestoreFailed unwrap", func(t *testing.T) {
		err := ErrSnapshotRestoreFailed{Name: "test", Cause: cause}
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrSnapshotDeleteFailed unwrap", func(t *testing.T) {
		err := ErrSnapshotDeleteFailed{Name: "test", Cause: cause}
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrSnapshotListFailed unwrap", func(t *testing.T) {
		err := ErrSnapshotListFailed{Cause: cause}
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrSnapshotParseError unwrap", func(t *testing.T) {
		err := ErrSnapshotParseError{Line: "test", Cause: cause}
		assert.Equal(t, cause, errors.Unwrap(err))
	})
}

func TestErrorsAs(t *testing.T) {
	t.Run("ErrSnapshotNotFound", func(t *testing.T) {
		var target ErrSnapshotNotFound
		err := ErrSnapshotNotFound{Name: "test"}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrSnapshotCreateFailed", func(t *testing.T) {
		var target ErrSnapshotCreateFailed
		err := ErrSnapshotCreateFailed{Name: "test", Cause: errors.New("cause")}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrSnapshotRestoreFailed", func(t *testing.T) {
		var target ErrSnapshotRestoreFailed
		err := ErrSnapshotRestoreFailed{Name: "test", Cause: errors.New("cause")}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrSnapshotDeleteFailed", func(t *testing.T) {
		var target ErrSnapshotDeleteFailed
		err := ErrSnapshotDeleteFailed{Name: "test", Cause: errors.New("cause")}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrSnapshotListFailed", func(t *testing.T) {
		var target ErrSnapshotListFailed
		err := ErrSnapshotListFailed{Cause: errors.New("cause")}
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrSnapshotInvalidName", func(t *testing.T) {
		var target ErrSnapshotInvalidName
		err := ErrSnapshotInvalidName{Name: "test", Reason: "reason"}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
		assert.Equal(t, "reason", target.Reason)
	})

	t.Run("ErrSnapshotVMNotPaused", func(t *testing.T) {
		var target ErrSnapshotVMNotPaused
		err := ErrSnapshotVMNotPaused{Operation: "restore"}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "restore", target.Operation)
	})

	t.Run("ErrSnapshotManagerNotInitialized", func(t *testing.T) {
		var target ErrSnapshotManagerNotInitialized
		err := ErrSnapshotManagerNotInitialized{}
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrSnapshotAlreadyExists", func(t *testing.T) {
		var target ErrSnapshotAlreadyExists
		err := ErrSnapshotAlreadyExists{Name: "test"}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Name)
	})

	t.Run("ErrSnapshotParseError", func(t *testing.T) {
		var target ErrSnapshotParseError
		err := ErrSnapshotParseError{Line: "test", Cause: errors.New("cause")}
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Line)
	})
}
