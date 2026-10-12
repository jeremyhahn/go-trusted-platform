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

package luks

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// Environment variable names for service endpoints.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
)

// ServiceEndpoints collects per-transport endpoint strings.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints returns the default devcontainer endpoints.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: "localhost:10443",
		PlatformREST: "http://localhost:8443",
		PlatformQUIC: "localhost:9444",
		PlatformMCP:  "localhost:9445",
		PlatformUnix: "/run/platformd.sock",
		PlatformCTL:  "platformctl",
	}
}

// isBackendUnavailable reports whether err is a declared gap: a typed
// not-implemented declaration or one of the daemon's LUKS sentinels (backend
// not configured, root required). Any other error fails the test (#487).
func isBackendUnavailable(err error) bool {
	return surface.IsNotImplemented(err) || surface.IsDeclaredRefusal(err,
		daemonpkg.ErrLUKSNotConfigured,
		daemonpkg.ErrLUKSRootRequired,
		lukssdk.ErrNotYetWired,
		mcpapi.ErrPhase35NotConfigured,
	)
}

// SkipIfNotIntegration skips when INTEGRATION_TEST is not set.
func SkipIfNotIntegration(t interface {
	Skip(args ...any)
}) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}

// IsRoot returns true when the test is running as uid 0.
func IsRoot() bool { return os.Geteuid() == 0 }

// LoopDevice represents a loopback-backed LUKS2 volume created for a test.
// Tear it down with Cleanup when the test is finished.
type LoopDevice struct {
	// BackingFile is the sparse file backing the loop device.
	BackingFile string
	// DevicePath is the /dev/loopN path the kernel assigned.
	DevicePath string
	// InitialPassphrase is the first passphrase enrolled on the volume.
	InitialPassphrase string
}

// NewLoopDevice creates a 10 MiB sparse file, attaches it to a loop device,
// and formats it as LUKS2 via "cryptsetup luksFormat". Returns the device
// path plus the initial passphrase that was enrolled.
//
// Requires root. Callers should gate with IsRoot() first.
func NewLoopDevice(ctx context.Context) (*LoopDevice, error) {
	if !IsRoot() {
		return nil, fmt.Errorf("NewLoopDevice requires root")
	}

	f, err := os.CreateTemp("", "platformd-luks-loop-*.img")
	if err != nil {
		return nil, fmt.Errorf("create backing file: %w", err)
	}
	backing := f.Name()
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		os.Remove(backing)
		return nil, fmt.Errorf("truncate backing file: %w", err)
	}
	f.Close()

	losetup := exec.CommandContext(ctx, "losetup", "--find", "--show", backing)
	var lo bytes.Buffer
	losetup.Stdout = &lo
	losetup.Stderr = &bytes.Buffer{}
	if err := losetup.Run(); err != nil {
		os.Remove(backing)
		return nil, fmt.Errorf("losetup: %w", err)
	}
	device := strings.TrimSpace(lo.String())
	if device == "" {
		os.Remove(backing)
		return nil, fmt.Errorf("losetup returned empty device path")
	}

	passBytes := make([]byte, 16)
	if _, err := rand.Read(passBytes); err != nil {
		_ = exec.Command("losetup", "-d", device).Run()
		os.Remove(backing)
		return nil, fmt.Errorf("random passphrase: %w", err)
	}
	passphrase := fmt.Sprintf("%x", passBytes)

	// cryptsetup luksFormat expects the passphrase on stdin. Use --batch-mode
	// + --force-password to skip the interactive confirmation + warnings.
	format := exec.CommandContext(ctx, "cryptsetup", "luksFormat", "--batch-mode",
		"--force-password", "--pbkdf", "argon2id", "--iter-time", "100",
		"--type", "luks2", device)
	format.Stdin = strings.NewReader(passphrase)
	var ferr bytes.Buffer
	format.Stderr = &ferr
	if err := format.Run(); err != nil {
		_ = exec.Command("losetup", "-d", device).Run()
		os.Remove(backing)
		return nil, fmt.Errorf("cryptsetup luksFormat %s: %w: %s", device, err, ferr.String())
	}

	return &LoopDevice{
		BackingFile:       backing,
		DevicePath:        device,
		InitialPassphrase: passphrase,
	}, nil
}

// Cleanup detaches the loop device and removes the backing file. Safe to
// call on a zero-value LoopDevice.
func (d *LoopDevice) Cleanup(ctx context.Context) {
	if d == nil {
		return
	}
	if d.DevicePath != "" {
		_ = exec.CommandContext(ctx, "losetup", "-d", d.DevicePath).Run()
	}
	if d.BackingFile != "" {
		os.Remove(d.BackingFile)
	}
}
