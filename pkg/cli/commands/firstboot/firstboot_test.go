package firstboot

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func testGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewCommand returned nil")
	}
	if cmd.Use != "firstboot" {
		t.Errorf("expected Use 'firstboot', got %s", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewCommandFlags(t *testing.T) {
	cmd := NewCommand(testGetFlags())

	expectedFlags := []string{
		"luks-device", "tpm-auto-unseal", "tpm-only",
		"swtpm-state-dir", "efi-mount", "pcrs",
		"config", "fips", "verbose", "debug",
		"platform-dir", "config-dir", "log-dir",
		"ca-dir", "tpm-path", "xkms-dir",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist", flagName)
		}
	}
}

func TestNewCommandFlagDefaults(t *testing.T) {
	cmd := NewCommand(testGetFlags())

	// Check some key default values
	tpmAutoUnseal := cmd.Flags().Lookup("tpm-auto-unseal")
	if tpmAutoUnseal != nil && tpmAutoUnseal.DefValue != "true" {
		t.Errorf("expected tpm-auto-unseal default 'true', got %s", tpmAutoUnseal.DefValue)
	}

	tpmOnly := cmd.Flags().Lookup("tpm-only")
	if tpmOnly != nil && tpmOnly.DefValue != "false" {
		t.Errorf("expected tpm-only default 'false', got %s", tpmOnly.DefValue)
	}

	swtpmDir := cmd.Flags().Lookup("swtpm-state-dir")
	if swtpmDir != nil && swtpmDir.DefValue != "/var/lib/swtpm" {
		t.Errorf("expected swtpm-state-dir default '/var/lib/swtpm', got %s", swtpmDir.DefValue)
	}

	efiMount := cmd.Flags().Lookup("efi-mount")
	if efiMount != nil && efiMount.DefValue != "/boot/efi" {
		t.Errorf("expected efi-mount default '/boot/efi', got %s", efiMount.DefValue)
	}
}

func TestNewCommandExample(t *testing.T) {
	cmd := NewCommand(testGetFlags())
	if cmd.Example == "" {
		t.Error("Example should not be empty")
	}
}

func TestConvertToUintSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		expected []uint
	}{
		{"empty", []int{}, []uint{}},
		{"single", []int{7}, []uint{7}},
		{"multiple", []int{0, 1, 7, 9}, []uint{0, 1, 7, 9}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToUintSlice(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected len %d, got %d", len(tt.expected), len(result))
			}
			for i, v := range tt.expected {
				if result[i] != v {
					t.Errorf("result[%d] = %d, want %d", i, result[i], v)
				}
			}
		})
	}
}

func TestConvertToUintSliceNil(t *testing.T) {
	result := convertToUintSlice(nil)
	if len(result) != 0 {
		t.Errorf("expected empty slice for nil input, got %v", result)
	}
}

func TestInitializeLogger(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		debug   bool
	}{
		{"default", false, false},
		{"verbose", true, false},
		{"debug", false, true},
		{"verbose and debug", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := initializeLogger(tt.verbose, tt.debug)
			if logger == nil {
				t.Fatal("logger should not be nil")
			}
		})
	}
}

func TestLoadPCRsFromConfig_NoConfigFiles(t *testing.T) {
	// Override package vars to point to nonexistent paths
	origConfig := firstbootConfig
	origConfigDir := firstbootConfigDir
	firstbootConfig = "/nonexistent/config.yaml"
	firstbootConfigDir = "/nonexistent"
	defer func() {
		firstbootConfig = origConfig
		firstbootConfigDir = origConfigDir
	}()

	logger := initializeLogger(false, false)
	_, err := loadPCRsFromConfig(logger)
	if err == nil {
		t.Error("expected error when no config files exist")
	}
}
