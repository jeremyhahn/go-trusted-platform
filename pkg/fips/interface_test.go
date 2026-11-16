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

package fips

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

// mockInstaller implements the Installer interface for testing
type mockInstaller struct {
	installErr          error
	installKernelErr    error
	configureOpenSSLErr error
	verifyErr           error
	kernelCommandLine   string
}

func (m *mockInstaller) Install(ctx context.Context) error {
	return m.installErr
}

func (m *mockInstaller) InstallKernel(ctx context.Context) error {
	return m.installKernelErr
}

func (m *mockInstaller) ConfigureOpenSSL(ctx context.Context) error {
	return m.configureOpenSSLErr
}

func (m *mockInstaller) Verify() error {
	return m.verifyErr
}

func (m *mockInstaller) GetKernelCommandLine() string {
	return m.kernelCommandLine
}

// mockInstallerFactory creates a mock installer
func mockInstallerFactory(config *Config) (Installer, error) {
	return &mockInstaller{
		kernelCommandLine: "fips=1",
	}, nil
}

// mockInstallerFactoryWithError returns an error when creating installer
func mockInstallerFactoryWithError(config *Config) (Installer, error) {
	return nil, ErrNotImplemented
}

func TestRegisterInstaller(t *testing.T) {
	// Clear registry before test
	originalRegistry := installerRegistry
	installerRegistry = make(map[string]InstallerFactory)
	defer func() {
		installerRegistry = originalRegistry
	}()

	tests := []struct {
		name    string
		os      string
		factory InstallerFactory
	}{
		{
			name:    "register ubuntu installer",
			os:      "ubuntu",
			factory: mockInstallerFactory,
		},
		{
			name:    "register alpine installer",
			os:      "alpine",
			factory: mockInstallerFactory,
		},
		{
			name:    "register debian installer",
			os:      "debian",
			factory: mockInstallerFactory,
		},
		{
			name:    "register custom os installer",
			os:      "custom-os",
			factory: mockInstallerFactory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RegisterInstaller(tt.os, tt.factory)

			// Verify installer was registered
			factory, ok := installerRegistry[tt.os]
			if !ok {
				t.Errorf("installer not registered for OS: %s", tt.os)
			}
			if factory == nil {
				t.Error("registered factory is nil")
			}
		})
	}
}

func TestRegisterInstallerOverwrite(t *testing.T) {
	// Clear registry before test
	originalRegistry := installerRegistry
	installerRegistry = make(map[string]InstallerFactory)
	defer func() {
		installerRegistry = originalRegistry
	}()

	// Register first factory
	firstFactory := mockInstallerFactory
	RegisterInstaller("test-os", firstFactory)

	// Register second factory (should overwrite)
	secondFactory := mockInstallerFactoryWithError
	RegisterInstaller("test-os", secondFactory)

	// Verify second factory is registered
	factory, ok := installerRegistry["test-os"]
	if !ok {
		t.Fatal("installer not registered")
	}

	// Try to create installer - should use second factory which returns error
	config := &Config{OS: "test-os"}
	_, err := factory(config)
	if err != ErrNotImplemented {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}

func TestNewInstaller(t *testing.T) {
	// Clear registry before test
	originalRegistry := installerRegistry
	installerRegistry = make(map[string]InstallerFactory)
	defer func() {
		installerRegistry = originalRegistry
	}()

	// Register mock installer
	RegisterInstaller("test-os", mockInstallerFactory)

	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		expectedErr error
	}{
		{
			name: "create installer with valid config",
			config: &Config{
				OS:         "test-os",
				Version:    "1.0",
				Arch:       "x86_64",
				WorkDir:    "/tmp",
				MountPoint: "/mnt",
			},
			wantErr: false,
		},
		{
			name: "create installer without logger",
			config: &Config{
				OS:      "test-os",
				Version: "1.0",
			},
			wantErr: false,
		},
		{
			name: "create installer with custom logger",
			config: &Config{
				OS:      "test-os",
				Version: "1.0",
				Logger:  slog.Default(),
			},
			wantErr: false,
		},
		{
			name: "unsupported OS",
			config: &Config{
				OS:      "unsupported-os",
				Version: "1.0",
			},
			wantErr:     true,
			expectedErr: ErrUnsupportedOS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer, err := NewInstaller(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
				if installer != nil {
					t.Error("expected nil installer when error occurs")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if installer == nil {
				t.Error("expected non-nil installer")
			}

			// Verify logger was set if it was nil
			if tt.config.Logger == nil {
				// Logger should have been set to default
				if tt.config.Logger == nil {
					t.Error("logger should have been set to default")
				}
			}
		})
	}
}

func TestNewInstallerWithFactoryError(t *testing.T) {
	// Clear registry before test
	originalRegistry := installerRegistry
	installerRegistry = make(map[string]InstallerFactory)
	defer func() {
		installerRegistry = originalRegistry
	}()

	// Register factory that returns error
	RegisterInstaller("error-os", mockInstallerFactoryWithError)

	config := &Config{
		OS:      "error-os",
		Version: "1.0",
	}

	installer, err := NewInstaller(config)
	if err == nil {
		t.Error("expected error from factory, got nil")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if installer != nil {
		t.Error("expected nil installer when factory returns error")
	}
}

func TestMockInstallerInterface(t *testing.T) {
	// Verify mock installer implements the interface correctly
	installer := &mockInstaller{
		installErr:          nil,
		installKernelErr:    nil,
		configureOpenSSLErr: nil,
		verifyErr:           nil,
		kernelCommandLine:   "fips=1",
	}

	ctx := context.Background()

	// Test Install
	if err := installer.Install(ctx); err != nil {
		t.Errorf("unexpected error from Install: %v", err)
	}

	// Test InstallKernel
	if err := installer.InstallKernel(ctx); err != nil {
		t.Errorf("unexpected error from InstallKernel: %v", err)
	}

	// Test ConfigureOpenSSL
	if err := installer.ConfigureOpenSSL(ctx); err != nil {
		t.Errorf("unexpected error from ConfigureOpenSSL: %v", err)
	}

	// Test Verify
	if err := installer.Verify(); err != nil {
		t.Errorf("unexpected error from Verify: %v", err)
	}

	// Test GetKernelCommandLine
	cmdLine := installer.GetKernelCommandLine()
	if cmdLine != "fips=1" {
		t.Errorf("expected 'fips=1', got '%s'", cmdLine)
	}
}

func TestMockInstallerErrors(t *testing.T) {
	testErr := errors.New("test error")
	installer := &mockInstaller{
		installErr:          testErr,
		installKernelErr:    testErr,
		configureOpenSSLErr: testErr,
		verifyErr:           testErr,
	}

	ctx := context.Background()

	// Test Install error
	if err := installer.Install(ctx); err != testErr {
		t.Errorf("expected test error from Install, got %v", err)
	}

	// Test InstallKernel error
	if err := installer.InstallKernel(ctx); err != testErr {
		t.Errorf("expected test error from InstallKernel, got %v", err)
	}

	// Test ConfigureOpenSSL error
	if err := installer.ConfigureOpenSSL(ctx); err != testErr {
		t.Errorf("expected test error from ConfigureOpenSSL, got %v", err)
	}

	// Test Verify error
	if err := installer.Verify(); err != testErr {
		t.Errorf("expected test error from Verify, got %v", err)
	}
}

func TestConfigZeroValues(t *testing.T) {
	// Test Config with zero values
	config := &Config{}

	if config.OS != "" {
		t.Errorf("expected empty OS, got '%s'", config.OS)
	}
	if config.Version != "" {
		t.Errorf("expected empty Version, got '%s'", config.Version)
	}
	if config.Debug {
		t.Error("expected Debug to be false by default")
	}
	if config.Logger != nil {
		t.Error("expected Logger to be nil by default")
	}
}

func TestMultipleOSRegistrations(t *testing.T) {
	// Clear registry before test
	originalRegistry := installerRegistry
	installerRegistry = make(map[string]InstallerFactory)
	defer func() {
		installerRegistry = originalRegistry
	}()

	// Register multiple OS installers
	oses := []string{"ubuntu", "debian", "alpine", "fedora", "rhel"}
	for _, os := range oses {
		RegisterInstaller(os, mockInstallerFactory)
	}

	// Verify all are registered
	if len(installerRegistry) != len(oses) {
		t.Errorf("expected %d installers registered, got %d", len(oses), len(installerRegistry))
	}

	// Verify each can create an installer
	for _, os := range oses {
		config := &Config{OS: os}
		installer, err := NewInstaller(config)
		if err != nil {
			t.Errorf("failed to create installer for %s: %v", os, err)
		}
		if installer == nil {
			t.Errorf("installer is nil for %s", os)
		}
	}
}
