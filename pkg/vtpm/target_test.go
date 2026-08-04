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

package vtpm

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenUnixSocket creates a real Unix domain socket in dir and returns its
// path. The listener is closed via t.Cleanup while the socket file remains
// for stat-based checks.
func listenUnixSocket(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "swtpm.sock")
	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return path
}

// TestTPMTargetString asserts the target kinds render their canonical names.
func TestTPMTargetString(t *testing.T) {
	assert.Equal(t, "hardware", TPMTargetHardware.String())
	assert.Equal(t, "swtpm", TPMTargetSwtpm.String())
	assert.Equal(t, "simulator", TPMTargetSimulator.String())
	assert.Equal(t, "unknown", TPMTarget(99).String())
}

// TestResolveTPMTarget_NilConfig asserts a nil configuration fails with the
// typed error.
func TestResolveTPMTarget_NilConfig(t *testing.T) {
	_, err := ResolveTPMTarget(nil, logging.DefaultLogger())
	assert.ErrorIs(t, err, ErrNilTPMConfig{})
}

// TestResolveTPMTarget_Simulator asserts the explicit simulator flag wins,
// including when a device path is also configured (matching go-xkms
// semantics: UseSimulator takes precedence over Device).
func TestResolveTPMTarget_Simulator(t *testing.T) {
	cfg := &xkmssdk.TPMConfig{UseSimulator: true, Device: "/dev/tpmrm0"}
	resolved, err := ResolveTPMTarget(cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, TPMTargetSimulator, resolved.Target)
	assert.Empty(t, resolved.Device)
}

// TestResolveTPMTarget_ExplicitSwtpmSocket asserts a .sock device path
// resolves to the swtpm target when the socket exists.
func TestResolveTPMTarget_ExplicitSwtpmSocket(t *testing.T) {
	socket := listenUnixSocket(t, t.TempDir())
	cfg := &xkmssdk.TPMConfig{Device: socket}
	resolved, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Equal(t, TPMTargetSwtpm, resolved.Target)
	assert.Equal(t, socket, resolved.Device)
}

// TestResolveTPMTarget_MissingSwtpmSocket asserts a configured but absent
// swtpm socket fails closed instead of downgrading to another TPM.
func TestResolveTPMTarget_MissingSwtpmSocket(t *testing.T) {
	cfg := &xkmssdk.TPMConfig{Device: filepath.Join(t.TempDir(), "missing.sock")}
	_, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
	var swtpmErr ErrSwtpmSocketUnavailable
	require.ErrorAs(t, err, &swtpmErr)
	assert.Contains(t, swtpmErr.Socket, "missing.sock")
}

// TestResolveTPMTarget_SocketPathNotASocket asserts a .sock path that is a
// regular file is rejected with the typed error.
func TestResolveTPMTarget_SocketPathNotASocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.sock")
	require.NoError(t, os.WriteFile(path, []byte("not a socket"), 0644))
	cfg := &xkmssdk.TPMConfig{Device: path}
	_, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
	var swtpmErr ErrSwtpmSocketUnavailable
	require.ErrorAs(t, err, &swtpmErr)
	assert.ErrorIs(t, err, ErrNotUnixSocket{Path: path})
}

// TestResolveTPMTarget_MissingHardwareDevice asserts a configured but absent
// hardware device fails closed with ErrHardwareTPMUnavailable.
func TestResolveTPMTarget_MissingHardwareDevice(t *testing.T) {
	device := filepath.Join(t.TempDir(), "tpmrm0")
	cfg := &xkmssdk.TPMConfig{Device: device}
	_, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
	var hwErr ErrHardwareTPMUnavailable
	require.ErrorAs(t, err, &hwErr)
	assert.Equal(t, device, hwErr.Device)
}

// TestResolveTPMTarget_HardwarePathNotADevice asserts a device path that is a
// regular file is rejected with the typed error.
func TestResolveTPMTarget_HardwarePathNotADevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tpmrm0")
	require.NoError(t, os.WriteFile(path, []byte("not a device"), 0644))
	cfg := &xkmssdk.TPMConfig{Device: path}
	_, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
	var hwErr ErrHardwareTPMUnavailable
	require.ErrorAs(t, err, &hwErr)
	assert.ErrorIs(t, err, ErrNotCharDevice{Path: path})
}

// TestResolveTPMTarget_Auto asserts the auto sentinel performs runtime
// detection: on hosts with a TPM (hardware or swtpm) it resolves to a
// concrete target with a non-empty path; on TPM-less hosts it fails with the
// typed detection error. Both outcomes are asserted so the test is honest on
// any host without modifying it.
func TestResolveTPMTarget_Auto(t *testing.T) {
	for _, device := range []string{TPMDeviceAuto, "", "AUTO"} {
		cfg := &xkmssdk.TPMConfig{Device: device}
		resolved, err := ResolveTPMTarget(cfg, logging.DefaultLogger())
		if err != nil {
			var noTPM ErrNoTPMDetected
			require.ErrorAs(t, err, &noTPM, "auto detection must fail with the typed error")
			continue
		}
		require.NotNil(t, resolved)
		assert.NotEmpty(t, resolved.Device)
		assert.Contains(t, []TPMTarget{TPMTargetHardware, TPMTargetSwtpm}, resolved.Target)
	}
}

// TestGetTPMForTarget_NilTarget asserts the provider dispatch rejects a nil
// resolved target.
func TestGetTPMForTarget_NilTarget(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	_, err := provider.GetTPMForTarget(nil)
	assert.ErrorIs(t, err, ErrNilResolvedTarget{})
}

// TestGetTPMForTarget_UnknownTarget asserts an unrecognized target kind is
// rejected with the typed error.
func TestGetTPMForTarget_UnknownTarget(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	_, err := provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTarget(99)})
	assert.ErrorIs(t, err, ErrUnknownTPMTarget{Target: TPMTarget(99)})
}

// TestGetTPMForTarget_HardwareMissingDevice asserts hardware dispatch fails
// closed when the device is absent.
func TestGetTPMForTarget_HardwareMissingDevice(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	device := filepath.Join(t.TempDir(), "tpmrm0")
	_, err := provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTargetHardware, Device: device})
	var hwErr ErrHardwareTPMUnavailable
	require.ErrorAs(t, err, &hwErr)
	assert.Equal(t, device, hwErr.Device)
}

// TestGetHardwareTPM_NotADevice asserts a regular file at the device path is
// rejected before any open is attempted.
func TestGetHardwareTPM_NotADevice(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	path := filepath.Join(t.TempDir(), "tpm0")
	require.NoError(t, os.WriteFile(path, []byte("file"), 0644))
	_, err := provider.GetHardwareTPM(path)
	var hwErr ErrHardwareTPMUnavailable
	require.ErrorAs(t, err, &hwErr)
	assert.ErrorIs(t, err, ErrNotCharDevice{Path: path})
}

// TestGetSimulatorTPM asserts simulator dispatch either yields a working
// in-process TPM (go-xkms built with tpm_simulator) or the typed open error
// (simulator support not compiled in) — never a silent substitute.
func TestGetSimulatorTPM(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	tpm, err := provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTargetSimulator})
	if err != nil {
		var openErr ErrTPMDeviceOpenFailed
		require.ErrorAs(t, err, &openErr)
		assert.Equal(t, simulatorCacheKey, openErr.Device)
		return
	}
	require.NotNil(t, tpm)

	// The instance must be cached: a second dispatch returns the same TPM.
	again, err := provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTargetSimulator})
	require.NoError(t, err)
	assert.Same(t, tpm, again)
	require.NoError(t, provider.CloseTPM(simulatorCacheKey))
}
