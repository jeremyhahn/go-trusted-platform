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

package iso

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// Environment variable names for service endpoints
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
	EnvISOTestWorkDir       = "ISO_TEST_WORK_DIR"
	EnvISOTestSkipCleanup   = "ISO_TEST_SKIP_CLEANUP"
	EnvISOBinaryDir         = "PLATFORM_ISO_BINARY_DIR"
)

// Default test values
const (
	DefaultAlpineVersion = "3.22.2"
	DefaultArch          = "x86_64"
	DefaultMirror        = "http://mirror.cs.odu.edu/alpine"
	DefaultWorkDir       = "work-test"
	DefaultDiskSize      = "10G"
	DefaultMemoryMB      = 4096
	DefaultCPUs          = 2
)

// VM run bounds. The package runs under a 130m go test timeout
// (run-integration-tests.sh TARGET_TIMEOUTS[iso]); an install plus a boot,
// each with its stop grace, fit inside it with room for the other tests.
const (
	// vmInstallTimeout is the --timeout of iso test install.
	vmInstallTimeout = 45 * time.Minute
	// vmBootTimeout is the --timeout of iso test boot.
	vmBootTimeout = 20 * time.Minute
	// vmStopGrace is how long platformctl gets past --timeout to stop QEMU
	// and the software TPM and report ErrVMTimeout before it is killed.
	vmStopGrace = 2 * time.Minute
	// commandWaitDelay is how long a killed command's output pipe is
	// drained before CombinedOutput returns regardless.
	commandWaitDelay = 10 * time.Second
)

// ServiceEndpoints contains default endpoints for all protocols.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints returns the default service endpoints.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: "localhost:10443",
		PlatformREST: "https://localhost:8443",
		PlatformQUIC: "localhost:9444",
		PlatformMCP:  "localhost:9445",
		PlatformUnix: "/run/platformd.sock",
		PlatformCTL:  "platformctl",
	}
}

// PlatformConfigTemplate is the platform configuration `iso customize` bakes
// into the ISO: the single-node default template docs/installer/iso-building.md
// names, relative to this package's directory, which is go test's working
// directory.
const PlatformConfigTemplate = "../../../configs/platform/templates/single-node/default.yaml"

// ISOBinaryDir returns the directory, named by PLATFORM_ISO_BINARY_DIR, of the
// platformd that `iso customize` stages onto the media and the platformctl,
// platform-initrd and gatewayd it stages from beside platformd. They are the
// Makefile's CGO-free builds: the guest that runs them is the musl Alpine
// live environment, which cannot run the glibc-linked platformctl the suite
// drives on the host.
func ISOBinaryDir() (string, error) {
	dir := os.Getenv(EnvISOBinaryDir)
	if dir == "" {
		return "", ErrEnvNotSet{Name: EnvISOBinaryDir}
	}
	return dir, nil
}

// VM tool paths the devcontainer image installs (qemu-system-x86 and swtpm
// packages) and checks at build time.
const (
	QEMUBinaryPath  = "/usr/bin/qemu-system-x86_64"
	SwtpmBinaryPath = "/usr/bin/swtpm"
)

// ErrVMToolNotFound reports that a binary the VM tests need is missing.
type ErrVMToolNotFound struct {
	Path string
}

func (e ErrVMToolNotFound) Error() string {
	return fmt.Sprintf("VM tool not found at %s: run the VM tests in the devcontainer "+
		"(build/docker/devcontainer/Dockerfile installs qemu-system-x86 and swtpm)", e.Path)
}

// CheckVMTools returns ErrVMToolNotFound for the first missing VM tool.
func CheckVMTools() error {
	for _, path := range []string{QEMUBinaryPath, SwtpmBinaryPath} {
		if !FileExists(path) {
			return ErrVMToolNotFound{Path: path}
		}
	}
	return nil
}

// GetTestWorkDir returns the work directory for ISO tests.
func GetTestWorkDir() string {
	if dir := os.Getenv(EnvISOTestWorkDir); dir != "" {
		return dir
	}
	return DefaultWorkDir
}

// ShouldSkipCleanup returns true if cleanup should be skipped after tests.
func ShouldSkipCleanup() bool {
	return os.Getenv(EnvISOTestSkipCleanup) != ""
}

// =============================================================================
// Error Types
// =============================================================================

// ErrConnectionFailed indicates a connection failure.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection failed to %s: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrCallFailed indicates a protocol call failure.
type ErrCallFailed struct {
	Protocol string
	Method   string
	Err      error
}

func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s call %s failed: %v", e.Protocol, e.Method, e.Err)
}

func (e ErrCallFailed) Unwrap() error {
	return e.Err
}

// ErrISONotFound indicates an ISO file was not found.
type ErrISONotFound struct {
	Path string
}

func (e ErrISONotFound) Error() string {
	return fmt.Sprintf("ISO file not found: %s", e.Path)
}

// ErrProfileNotFound indicates a profile was not found.
type ErrProfileNotFound struct {
	ProfileName string
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("profile not found: %s", e.ProfileName)
}

// ErrDiskNotFound indicates a disk image was not found.
type ErrDiskNotFound struct {
	Path string
}

func (e ErrDiskNotFound) Error() string {
	return fmt.Sprintf("disk image not found: %s", e.Path)
}

// ErrBinaryNotFound indicates a binary the suite hands to platformctl was not found.
type ErrBinaryNotFound struct {
	Name string
	Path string
	Err  error
}

func (e ErrBinaryNotFound) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s binary not found at %s: %v", e.Name, e.Path, e.Err)
	}
	return fmt.Sprintf("%s binary not found at %s", e.Name, e.Path)
}

func (e ErrBinaryNotFound) Unwrap() error {
	return e.Err
}

// minInstalledDiskBytes is the size below which a disk image holds no
// installed system: the threshold iso test install applies to a VM that
// exits non-zero (pkg/cli/commands/iso/test.go installWaitResult).
const minInstalledDiskBytes = 100 * 1024 * 1024

// ErrDiskNotInstalled indicates a disk image too small to hold an installed system.
type ErrDiskNotInstalled struct {
	Path string
	Size int64
}

func (e ErrDiskNotInstalled) Error() string {
	return fmt.Sprintf("disk image %s is %d bytes, under the %d an installed system takes", e.Path, e.Size, minInstalledDiskBytes)
}

// InstalledDiskError reports whether path holds an installed system. A failed
// autoinstall powers the guest off just as a finished one does
// (run-autoinstall.sh in pkg/iso/customize.go), so a clean QEMU exit alone
// does not prove the install happened.
func InstalledDiskError(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return ErrDiskNotFound{Path: path}
	}
	if info.Size() < minInstalledDiskBytes {
		return ErrDiskNotInstalled{Path: path, Size: info.Size()}
	}
	return nil
}

// ErrEnvNotSet indicates an environment variable the suite needs is unset.
type ErrEnvNotSet struct {
	Name string
}

func (e ErrEnvNotSet) Error() string {
	return fmt.Sprintf("environment variable %s is not set", e.Name)
}

// ErrDirectoryNotFound indicates a directory was not found.
type ErrDirectoryNotFound struct {
	Path string
}

func (e ErrDirectoryNotFound) Error() string {
	return fmt.Sprintf("directory not found: %s", e.Path)
}

// ErrValidationFailed indicates validation failure.
type ErrValidationFailed struct {
	Reason string
}

func (e ErrValidationFailed) Error() string {
	return fmt.Sprintf("validation failed: %s", e.Reason)
}

// ErrCommandTimeout indicates a command timed out.
type ErrCommandTimeout struct {
	Command string
	Timeout string
}

func (e ErrCommandTimeout) Error() string {
	return fmt.Sprintf("command %s timed out after %s", e.Command, e.Timeout)
}

// ErrVerbFailed reports a platformctl verb that exited non-zero or printed no
// result, with the stderr it wrote.
type ErrVerbFailed struct {
	Stderr string
	Err    error
}

func (e ErrVerbFailed) Error() string {
	if e.Err == nil {
		return e.Stderr
	}
	return e.Err.Error() + ": " + e.Stderr
}

// Unwrap returns the process error.
func (e ErrVerbFailed) Unwrap() error { return e.Err }

// =============================================================================
// Test Helper Functions
// =============================================================================

// CreateTestWorkDir creates a temporary work directory for tests.
func CreateTestWorkDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create test work directory: %v", err)
	}
	return dir
}

// CleanupTestWorkDir removes a test work directory.
func CleanupTestWorkDir(t *testing.T, dir string) {
	t.Helper()
	if ShouldSkipCleanup() {
		t.Logf("Skipping cleanup of: %s", dir)
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: Failed to cleanup test work directory %s: %v", dir, err)
	}
}

// FileExists checks if a file exists.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists.
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// GetFileSize returns the size of a file in bytes.
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// CountFilesInDir returns the number of files in a directory (non-recursive).
func CountFilesInDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count, nil
}
