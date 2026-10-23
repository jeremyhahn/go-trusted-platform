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
	"os/exec"
	"path/filepath"
	"strings"
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

// PlatformBinaryDir returns the directory of the platformctl the suite drives,
// with symlinks resolved. `iso customize` takes platformd from there by default
// and stages platform-initrd and gatewayd from beside platformd.
func PlatformBinaryDir() (string, error) {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}
	resolved, err := exec.LookPath(binaryPath)
	if err != nil {
		return "", ErrBinaryNotFound{Name: "platformctl", Path: binaryPath, Err: err}
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", ErrBinaryNotFound{Name: "platformctl", Path: binaryPath, Err: err}
	}
	return filepath.Dir(resolved), nil
}

// VM tool paths the devcontainer image installs (qemu-system-x86 and swtpm
// packages) and checks at build time.
// VM wait budgets (CA m639). vmInstallTimeout bounds `iso test install`;
// grubMenuGrace is how long a GRUB menu on the serial console may wait for a
// kernel boot line before the install fails with ErrGRUBMenuNoBoot.
const (
	vmInstallTimeout = 20 * time.Minute
	grubMenuGrace    = 2 * time.Minute
)

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

// ErrOfflineRepositoryMissing reports a customized ISO tree without the
// pre-fetched APK repository. The autoinstall script installs lvm2, parted
// and the rest from it on a CD boot; the stock Alpine apks do not carry them.
type ErrOfflineRepositoryMissing struct {
	Index string
}

func (e ErrOfflineRepositoryMissing) Error() string {
	return fmt.Sprintf("customized ISO tree has no offline APK repository index at %s: the install would fail in the guest", e.Index)
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

// ErrGRUBMenuNoBoot is returned when a guest draws the GRUB menu on its serial
// console and no kernel boot line follows within grubMenuGrace: the guest is
// stuck at the menu, and waiting out the install timeout would only spend time.
type ErrGRUBMenuNoBoot struct {
	Waited    time.Duration
	LastLines []string
}

func (e ErrGRUBMenuNoBoot) Error() string {
	return fmt.Sprintf("guest stopped at the GRUB menu: no kernel boot line on the serial console %s after the menu appeared; last serial lines:\n%s",
		e.Waited, strings.Join(e.LastLines, "\n"))
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
