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
	WorkDir      string
	Debug        bool
}

// DownloadResult is the result `iso download` prints.
type DownloadResult struct {
	Success   bool   `json:"success" yaml:"success"`
	ISOPath   string `json:"iso_path" yaml:"iso_path"`
	SHA256    string `json:"sha256" yaml:"sha256"`
	SizeBytes int64  `json:"size_bytes" yaml:"size_bytes"`
	Verified  bool   `json:"verified" yaml:"verified"`
	Message   string `json:"message" yaml:"message"`
}

// =============================================================================
// Extract Types
// =============================================================================

// ExtractOptions contains options for extracting ISO contents.
type ExtractOptions struct {
	ISO       string
	OutputDir string
	Force     bool
	WorkDir   string
	Debug     bool
}

// ExtractResult is the result `iso extract` prints.
type ExtractResult struct {
	Success   bool   `json:"success" yaml:"success"`
	OutputDir string `json:"output_dir" yaml:"output_dir"`
	FileCount int    `json:"file_count" yaml:"file_count"`
	Message   string `json:"message" yaml:"message"`
}

// =============================================================================
// Customize Types
// =============================================================================

// CustomizeOptions contains options for customizing ISO contents.
type CustomizeOptions struct {
	ISODir        string
	Overlay       string
	KeysDir       string
	PlatformdPath string
	// PlatformctlStaticPath is the CGO_ENABLED=0 platformctl the media
	// installs (--platformctl-static-binary); customize refuses a dynamic
	// installer without it.
	PlatformctlStaticPath string
	PlatformConfig        string
	ConfigFile            string
	WorkDir               string
	Debug                 bool
}

// CustomizeResult is the result `iso customize` prints.
type CustomizeResult struct {
	Success bool   `json:"success" yaml:"success"`
	ISODir  string `json:"iso_dir" yaml:"iso_dir"`
	Message string `json:"message" yaml:"message"`
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
	Debug       bool
}

// BuildResult is the result `iso build` prints. Its --output flag shadows the
// global -o, so the verb prints YAML.
type BuildResult struct {
	Success      bool   `yaml:"success"`
	OutputISO    string `yaml:"output_iso"`
	SHA256       string `yaml:"sha256"`
	SizeBytes    int64  `yaml:"size_bytes"`
	ChecksumFile string `yaml:"checksum_file"`
	Message      string `yaml:"message"`
}

// =============================================================================
// Profile Types
// =============================================================================

// ProfileInfo contains information about an installation profile.
type ProfileInfo struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	SecureBoot  bool   `json:"secure_boot" yaml:"secure_boot"`
	TPMUnseal   bool   `json:"tpm_unseal" yaml:"tpm_unseal"`
	LUKS        bool   `json:"luks" yaml:"luks"`
	FIPS        bool   `json:"fips" yaml:"fips"`
	Lockdown    string `json:"lockdown" yaml:"lockdown"`
}

// ProfileListResult is the result `iso profile list` prints.
type ProfileListResult struct {
	Success  bool          `json:"success" yaml:"success"`
	Profiles []ProfileInfo `json:"profiles" yaml:"profiles"`
	Message  string        `json:"message" yaml:"message"`
}

// ProfileShowResult is the result `iso profile show` prints.
type ProfileShowResult struct {
	Success bool         `json:"success" yaml:"success"`
	Profile *ProfileInfo `json:"profile" yaml:"profile"`
	YAML    string       `json:"yaml" yaml:"yaml"`
	Message string       `json:"message" yaml:"message"`
}

// ProfileValidateResult is the result `iso profile validate` prints.
type ProfileValidateResult struct {
	Success bool     `json:"success" yaml:"success"`
	Valid   bool     `json:"valid" yaml:"valid"`
	Errors  []string `json:"errors" yaml:"errors"`
	Message string   `json:"message" yaml:"message"`
}

// ProfileGenerateOptions contains options for generating a profile.
type ProfileGenerateOptions struct {
	ProfileName    string
	OutputFile     string
	OverrideDevice string
}

// ProfileGenerateResult is the result `iso profile generate` prints. Its
// --output flag shadows the global -o, so the verb prints YAML.
type ProfileGenerateResult struct {
	Success    bool   `yaml:"success"`
	OutputFile string `yaml:"output_file"`
	YAML       string `yaml:"yaml"`
	Message    string `yaml:"message"`
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
	Timeout     time.Duration // --timeout: console to a log in WorkDir, its tail on failure
	Expect      string        // --expect: the serial-console milestone that ends the boot
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
