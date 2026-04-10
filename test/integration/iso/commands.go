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
	"context"
	"time"
)

// ISOCommands defines the central command set for ISO integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type ISOCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Create command (all-in-one ISO creation)
	Create(ctx context.Context, opts CreateOptions) (*CreateResult, error)

	// Download command
	Download(ctx context.Context, opts DownloadOptions) (*DownloadResult, error)

	// Extract command
	Extract(ctx context.Context, opts ExtractOptions) (*ExtractResult, error)

	// Customize command
	Customize(ctx context.Context, opts CustomizeOptions) (*CustomizeResult, error)

	// Build command
	Build(ctx context.Context, opts BuildOptions) (*BuildResult, error)

	// Profile commands
	ProfileList(ctx context.Context) (*ProfileListResult, error)
	ProfileShow(ctx context.Context, name string) (*ProfileShowResult, error)
	ProfileValidate(ctx context.Context, path string) (*ProfileValidateResult, error)
	ProfileGenerate(ctx context.Context, opts ProfileGenerateOptions) (*ProfileGenerateResult, error)

	// Test commands
	TestInstall(ctx context.Context, opts TestInstallOptions) (*TestResult, error)
	TestFirstBoot(ctx context.Context, opts TestBootOptions) (*TestResult, error)
	TestBoot(ctx context.Context, opts TestBootOptions) (*TestResult, error)
	TestAll(ctx context.Context, opts TestAllOptions) (*TestResult, error)
	TestClientServer(ctx context.Context, opts TestClientServerOptions) (*TestResult, error)
	TestPXE(ctx context.Context, opts TestPXEOptions) (*TestResult, error)
}

// =============================================================================
// Create Types
// =============================================================================

// CreateOptions contains options for all-in-one ISO creation.
type CreateOptions struct {
	AlpineVersion   string
	Mirror          string
	Arch            string
	PlatformVersion string
	PlatformConfig  string
	PlatformType    string
	SecureBoot      bool
	TPMUnseal       bool
	LUKS            bool
	FIPS            bool
	FIDO2           bool
	Overlay         string
	Output          string
	KeysDir         string
	GenerateKeys    bool
	KeyBackend      string
	Force           bool
	WebUI           string
	ConfigFile      string
	WorkDir         string
	Debug           bool
	Verbose         bool
}

// CreateResult contains the result of ISO creation.
type CreateResult struct {
	Success     bool
	OutputISO   string
	SHA256      string
	SizeBytes   int64
	Message     string
	ElapsedTime time.Duration
}

// =============================================================================
// Download Types
// =============================================================================

// DownloadOptions contains options for downloading Alpine ISO.
type DownloadOptions struct {
	URL          string
	Version      string
	Mirror       string
	Arch         string
	Force        bool
	Verify       bool
	ResumeEnable bool
	ConfigFile   string
	WorkDir      string
	Debug        bool
	Verbose      bool
}

// DownloadResult contains the result of ISO download.
type DownloadResult struct {
	Success   bool
	ISOPath   string
	SHA256    string
	SizeBytes int64
	Verified  bool
	Message   string
}

// =============================================================================
// Extract Types
// =============================================================================

// ExtractOptions contains options for extracting ISO contents.
type ExtractOptions struct {
	ISO        string
	OutputDir  string
	Force      bool
	ConfigFile string
	WorkDir    string
	Debug      bool
	Verbose    bool
}

// ExtractResult contains the result of ISO extraction.
type ExtractResult struct {
	Success   bool
	OutputDir string
	FileCount int
	Message   string
}

// =============================================================================
// Customize Types
// =============================================================================

// CustomizeOptions contains options for customizing ISO contents.
type CustomizeOptions struct {
	ISODir          string
	Overlay         string
	KeysDir         string
	PlatformdPath   string
	Autoinstall     bool
	ModifyInitramfs bool
	ConfigFile      string
	WorkDir         string
	Debug           bool
	Verbose         bool
}

// CustomizeResult contains the result of ISO customization.
type CustomizeResult struct {
	Success bool
	Message string
}

// =============================================================================
// Build Types
// =============================================================================

// BuildOptions contains options for building final ISO.
type BuildOptions struct {
	SourceDir   string
	Output      string
	VolumeID    string
	GenerateSum bool
	ConfigFile  string
	WorkDir     string
	Debug       bool
	Verbose     bool
}

// BuildResult contains the result of ISO build.
type BuildResult struct {
	Success   bool
	OutputISO string
	SHA256    string
	SizeBytes int64
	Message   string
}

// =============================================================================
// Profile Types
// =============================================================================

// ProfileInfo contains information about an installation profile.
type ProfileInfo struct {
	Name        string
	Description string
	SecureBoot  bool
	TPMUnseal   bool
	LUKS        bool
	FIPS        bool
	Lockdown    string
}

// ProfileListResult contains the list of available profiles.
type ProfileListResult struct {
	Success  bool
	Profiles []ProfileInfo
	Message  string
}

// ProfileShowResult contains the full profile configuration.
type ProfileShowResult struct {
	Success bool
	Profile *ProfileInfo
	YAML    string
	Message string
}

// ProfileValidateResult contains the result of profile validation.
type ProfileValidateResult struct {
	Success  bool
	Valid    bool
	Errors   []string
	Warnings []string
	Message  string
}

// ProfileGenerateOptions contains options for generating a profile.
type ProfileGenerateOptions struct {
	ProfileName    string
	OutputFile     string
	OverrideDevice string
	Interactive    bool
}

// ProfileGenerateResult contains the result of profile generation.
type ProfileGenerateResult struct {
	Success    bool
	OutputFile string
	YAML       string
	Message    string
}

// =============================================================================
// Test Types
// =============================================================================

// TestInstallOptions contains options for ISO installation test.
type TestInstallOptions struct {
	ISO         string
	Disk        string
	DiskSize    string
	Memory      int
	CPUs        int
	WorkDir     string
	SecureBoot  bool
	FIDO2Enable bool
	FIDO2Mode   string
	CanoKeyFile string
	CanoKeyPcap string
	U2FPassthru string
	QEMUBinary  string
	NetworkMode string
	Debug       bool
}

// TestBootOptions contains options for boot tests.
type TestBootOptions struct {
	Disk        string
	Memory      int
	CPUs        int
	WorkDir     string
	SecureBoot  bool
	FIDO2Enable bool
	FIDO2Mode   string
	CanoKeyFile string
	CanoKeyPcap string
	U2FPassthru string
	QEMUBinary  string
	NetworkMode string
	Debug       bool
}

// TestAllOptions contains options for running all tests.
type TestAllOptions struct {
	ISO         string
	Disk        string
	DiskSize    string
	Memory      int
	CPUs        int
	WorkDir     string
	SecureBoot  bool
	FIDO2Enable bool
	FIDO2Mode   string
	Debug       bool
}

// TestClientServerOptions contains options for client-server tests.
type TestClientServerOptions struct {
	ISO              string
	ServerDisk       string
	ClientDisk       string
	ServerWorkDir    string
	ClientWorkDir    string
	DiskSize         string
	Memory           int
	CPUs             int
	SecureBoot       bool
	SkipInstall      bool
	ServerOnly       bool
	ClientOnly       bool
	FIDO2Enable      bool
	FIDO2Mode        string
	ServerConfigPath string
	ClientConfigPath string
	UserNetwork      bool
	ServerHostPort   int
	DNSHostPort      int
	UseOVS           bool
	PlatformdBinary  string
	ForceConsole     bool
	WebUIPath        string
	ServerProfile    string
	ClientProfile    string
	DynamicNetwork   bool
	EnableDHCP       bool
	Debug            bool
}

// TestPXEOptions contains options for PXE boot tests.
type TestPXEOptions struct {
	ISO        string
	Kernel     string
	Initrd     string
	Args       string
	Memory     int
	CPUs       int
	WorkDir    string
	SecureBoot bool
	Debug      bool
}

// TestResult contains the result of a test operation.
type TestResult struct {
	Success     bool
	Message     string
	ExitCode    int
	ElapsedTime time.Duration
}
