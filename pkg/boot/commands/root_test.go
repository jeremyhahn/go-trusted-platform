package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecute_VersionSubcommand(t *testing.T) {
	// Reset rootCmd args to version subcommand
	rootCmd.SetArgs([]string{"version"})
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("version command should not return error, got: %v", err)
	}
}

func TestRootCommandProperties(t *testing.T) {
	if rootCmd.Use != "platform-initrd" {
		t.Errorf("expected Use 'platform-initrd', got %s", rootCmd.Use)
	}
	if rootCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if rootCmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestRootCommandSubcommands(t *testing.T) {
	expectedSubs := []string{"version", "boot", "recovery"}
	commands := rootCmd.Commands()

	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}
}

func TestVersionCommandProperties(t *testing.T) {
	if versionCmd.Use != "version" {
		t.Errorf("expected Use 'version', got %s", versionCmd.Use)
	}
	if versionCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
}

func TestVersionVariableDefaults(t *testing.T) {
	// These should have default values set at package level
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}
	if BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
}

func TestLoadSealPCRsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "seal-pcrs=0,7,9\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	pcrs, err := loadSealPCRsFromFile(pcrFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != 3 {
		t.Fatalf("expected 3 PCRs, got %d", len(pcrs))
	}
	expected := []uint{0, 7, 9}
	for i, e := range expected {
		if pcrs[i] != e {
			t.Errorf("pcrs[%d] = %d, want %d", i, pcrs[i], e)
		}
	}
}

func TestLoadSealPCRsFromFile_MissingFile(t *testing.T) {
	_, err := loadSealPCRsFromFile("/nonexistent/path/pcr-banks")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadSealPCRsFromFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	if err := os.WriteFile(pcrFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := loadSealPCRsFromFile(pcrFile)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestLoadSealPCRsFromFile_NoSealPCRsKey(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "platform-pcr=23\nplatform-pcr-bank=sha256\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := loadSealPCRsFromFile(pcrFile)
	if err == nil {
		t.Error("expected error when seal-pcrs key is missing")
	}
}

func TestLoadSealPCRsFromFile_EmptySealPCRsValue(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "seal-pcrs=\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := loadSealPCRsFromFile(pcrFile)
	if err == nil {
		t.Error("expected error for empty seal-pcrs value")
	}
}

func TestLoadSealPCRsFromFile_InvalidPCRValue(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "seal-pcrs=0,abc,9\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := loadSealPCRsFromFile(pcrFile)
	if err == nil {
		t.Error("expected error for invalid PCR value")
	}
}

func TestLoadSealPCRsFromFile_SinglePCR(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "seal-pcrs=7\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	pcrs, err := loadSealPCRsFromFile(pcrFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != 1 || pcrs[0] != 7 {
		t.Errorf("expected [7], got %v", pcrs)
	}
}

func TestLoadSealPCRsFromFile_WithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "  seal-pcrs=0, 7, 9  \n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	pcrs, err := loadSealPCRsFromFile(pcrFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != 3 {
		t.Errorf("expected 3 PCRs, got %d: %v", len(pcrs), pcrs)
	}
}

func TestLoadSealPCRsFromFile_MultipleLines(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")

	content := "platform-pcr=23\nplatform-pcr-bank=sha256\nseal-pcrs=0,1,7\nkeystore-srk-handle=0x81000002\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	pcrs, err := loadSealPCRsFromFile(pcrFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != 3 {
		t.Errorf("expected 3 PCRs, got %d", len(pcrs))
	}
}

func TestBootCmdProperties(t *testing.T) {
	if BootCmd.Use != "boot" {
		t.Errorf("expected Use 'boot', got %s", BootCmd.Use)
	}
	if BootCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if BootCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestBootCmdFlags(t *testing.T) {
	expectedFlags := []string{
		"timeout", "pcrs", "fallback", "emergency",
		"device", "name", "tpm-path", "efi-path",
		"xkms-dir", "verbose", "debug", "fips",
		"diskless", "root-mount", "diskless-work-dir",
	}
	for _, flagName := range expectedFlags {
		flag := BootCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist on boot command", flagName)
		}
	}
	// The diskless root is described only by the signed command line; a flag
	// that overrode its URLs or root hash would bypass the signature.
	for _, flagName := range []string{"rootfs-url", "verity-url", "roothash"} {
		if BootCmd.Flags().Lookup(flagName) != nil {
			t.Errorf("flag %s must not exist on boot command", flagName)
		}
	}
}

func TestRecoveryCmdProperties(t *testing.T) {
	if RecoveryCmd.Use != "recovery" {
		t.Errorf("expected Use 'recovery', got %s", RecoveryCmd.Use)
	}
	if RecoveryCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if RecoveryCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestRecoveryCmdFlags(t *testing.T) {
	expectedFlags := []string{
		"reseal-pcrs", "fido2", "interactive",
		"device", "name", "tpm-path", "efi-path",
		"xkms-dir", "verbose", "debug", "fips",
	}
	for _, flagName := range expectedFlags {
		flag := RecoveryCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist on recovery command", flagName)
		}
	}
}

func TestInitializeLogger(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		verbose bool
		debug   bool
	}{
		{"boot mode", "boot", false, false},
		{"boot verbose", "boot", true, false},
		{"boot debug", "boot", false, true},
		{"recovery mode", "recovery", false, false},
		{"firstboot mode", "firstboot", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := InitializeLogger(tt.mode, tt.verbose, tt.debug)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if logger == nil {
				t.Fatal("logger should not be nil")
			}
		})
	}
}
