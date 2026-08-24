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

package firstboot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// TestUnmarshalTPMConfig_PlatformSRKDirectly verifies that when platform-srk
// is set directly in YAML, it is parsed correctly without needing keystore fallback.
func TestUnmarshalTPMConfig_PlatformSRKDirectly(t *testing.T) {
	yamlData := []byte(`
tpm:
  device: /dev/tpmrm0
  platform-pcr: 14
  platform-pcr-bank: sha384
  platform-srk:
    srk-handle: 0x81000003
    platform-policy: false
`)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformPCR != 14 {
		t.Errorf("expected PlatformPCR 14, got %d", cfg.PlatformPCR)
	}
	if cfg.PlatformPCRBank != "sha384" {
		t.Errorf("expected PlatformPCRBank sha384, got %s", cfg.PlatformPCRBank)
	}
	if cfg.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set")
	}
	if cfg.PlatformSRK.PlatformPolicy {
		t.Error("expected PlatformPolicy to be false")
	}
}

// TestUnmarshalTPMConfig_BothKeystoreAndPlatformSRK verifies that platform-srk
// takes precedence over keystore when both are present.
func TestUnmarshalTPMConfig_BothKeystoreAndPlatformSRK(t *testing.T) {
	yamlData := []byte(`
tpm:
  device: /dev/tpmrm0
  platform-pcr: 23
  platform-srk:
    srk-handle: 0x81000010
    platform-policy: true
  keystore:
    srk-handle: 0x81000020
    platform-policy: false
`)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set")
	}
	if cfg.PlatformSRK.SRKHandle != 0x81000010 {
		t.Errorf("expected SRKHandle 0x81000010, got 0x%08x", cfg.PlatformSRK.SRKHandle)
	}
}

// TestParsePCRBanksConfig_ValidContent verifies parsing of a valid pcr-banks file.
func TestParsePCRBanksConfig_ValidContent(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
golden-pcrs=0,1,2,3,7
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", cfg.PlatformPCR)
	}
	if cfg.PlatformPCRBank != "sha256" {
		t.Errorf("expected PlatformPCRBank sha256, got %s", cfg.PlatformPCRBank)
	}
	if cfg.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set")
	}
	if cfg.PlatformSRK.SRKHandle != 0x81000002 {
		t.Errorf("expected SRKHandle 0x81000002, got 0x%08x", cfg.PlatformSRK.SRKHandle)
	}
	if cfg.SSRK == nil {
		t.Fatal("expected SSRK to be set")
	}
	if cfg.SSRK.Handle != 0x81000001 {
		t.Errorf("expected SSRK Handle 0x81000001, got 0x%08x", cfg.SSRK.Handle)
	}
	if len(cfg.GoldenPCRs) != 5 {
		t.Errorf("expected 5 golden PCRs, got %d", len(cfg.GoldenPCRs))
	}
}

// TestParsePCRBanksConfig_MissingFile verifies nil return for missing file.
func TestParsePCRBanksConfig_MissingFile(t *testing.T) {
	logger := testLogger()
	cfg := parsePCRBanksConfig("/nonexistent/path/pcr-banks", logger)
	if cfg != nil {
		t.Error("expected nil config for missing file")
	}
}

// TestParsePCRBanksConfig_EmptyFile verifies nil return for empty file.
func TestParsePCRBanksConfig_EmptyFile(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	if err := os.WriteFile(pcrBanksPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg != nil {
		t.Error("expected nil config for empty file")
	}
}

// TestParsePCRBanksConfig_OldFormat verifies nil return for old format without key=value.
func TestParsePCRBanksConfig_OldFormat(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	if err := os.WriteFile(pcrBanksPath, []byte("sha256\n0,1,2,3,7"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg != nil {
		t.Error("expected nil config for old format")
	}
}

// TestParsePCRBanksConfig_MissingRequiredFields verifies nil for incomplete config.
func TestParsePCRBanksConfig_MissingRequiredFields(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{
			"missing_platform_pcr",
			"platform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n",
		},
		{
			"missing_platform_pcr_bank",
			"platform-pcr=23\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n",
		},
		{
			"missing_keystore_srk_handle",
			"platform-pcr=23\nplatform-pcr-bank=sha256\nssrk-handle=0x81000001\n",
		},
		{
			"missing_ssrk_handle",
			"platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\n",
		},
		{
			"invalid_platform_pcr",
			"platform-pcr=abc\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=0x81000001\n",
		},
		{
			"invalid_keystore_srk_handle",
			"platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=notahex\nssrk-handle=0x81000001\n",
		},
		{
			"invalid_ssrk_handle",
			"platform-pcr=23\nplatform-pcr-bank=sha256\nkeystore-srk-handle=0x81000002\nssrk-handle=notahex\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcrBanksPath := filepath.Join(tmpDir, "pcr-banks-"+tt.name)
			if err := os.WriteFile(pcrBanksPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}
			cfg := parsePCRBanksConfig(pcrBanksPath, logger)
			if cfg != nil {
				t.Errorf("expected nil config for %s", tt.name)
			}
		})
	}
}

// TestParsePCRBanksConfig_CommentsAndBlankLines verifies comments and blanks are ignored.
func TestParsePCRBanksConfig_CommentsAndBlankLines(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `# This is a comment
platform-pcr=23

# Another comment
platform-pcr-bank=sha256

keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", cfg.PlatformPCR)
	}
}

// TestParsePCRBanksConfig_DecimalHandles verifies decimal handle parsing.
func TestParsePCRBanksConfig_DecimalHandles(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=2164260866
ssrk-handle=2164260865
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformSRK.SRKHandle != 2164260866 {
		t.Errorf("expected SRKHandle 2164260866, got %d", cfg.PlatformSRK.SRKHandle)
	}
}

// TestParsePCRBanksConfig_EmptyGoldenPCRs verifies empty golden-pcrs handling.
func TestParsePCRBanksConfig_EmptyGoldenPCRs(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
golden-pcrs=
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.GoldenPCRs) != 0 {
		t.Errorf("expected 0 golden PCRs, got %d", len(cfg.GoldenPCRs))
	}
}

// TestDetectTPMDevice_EnvVariable verifies detectTPMDevice with environment variable.
func TestDetectTPMDevice_EnvVariable(t *testing.T) {
	logger := testLogger()

	t.Run("device_prefix", func(t *testing.T) {
		t.Setenv("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")
		device, err := detectTPMDevice(logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if device != "/dev/tpmrm0" {
			t.Errorf("expected /dev/tpmrm0, got %s", device)
		}
	})

	t.Run("swtpm_prefix", func(t *testing.T) {
		t.Setenv("TPM2TOOLS_TCTI", "swtpm:host=localhost,port=2321")
		device, err := detectTPMDevice(logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if device != "swtpm:host=localhost,port=2321" {
			t.Errorf("expected swtpm:host=localhost,port=2321, got %s", device)
		}
	})

	t.Run("direct_path", func(t *testing.T) {
		t.Setenv("TPM2TOOLS_TCTI", "/dev/tpm0")
		device, err := detectTPMDevice(logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if device != "/dev/tpm0" {
			t.Errorf("expected /dev/tpm0, got %s", device)
		}
	})
}

// TestNewFirstbootSealStrategy verifies strategy construction and basic methods.
func TestNewFirstbootSealStrategy(t *testing.T) {
	s := NewFirstbootSealStrategy(nil, nil, testLogger())
	if s == nil {
		t.Fatal("expected non-nil strategy")
	}
	if s.Name() != "Firstboot-Seal" {
		t.Errorf("expected name Firstboot-Seal, got %s", s.Name())
	}
	if s.Priority() != 0 {
		t.Errorf("expected priority 0, got %d", s.Priority())
	}
}

// TestFirstbootSealStrategy_Install verifies Install is a no-op.
func TestFirstbootSealStrategy_Install(t *testing.T) {
	s := NewFirstbootSealStrategy(nil, nil, testLogger())
	err := s.Install(context.Background(), nil, nil)
	if err != nil {
		t.Errorf("expected nil error from Install, got %v", err)
	}
}

// TestFirstbootSealStrategy_GetSecureWipePasses verifies default wipe passes.
func TestFirstbootSealStrategy_GetSecureWipePasses(t *testing.T) {
	s := NewFirstbootSealStrategy(nil, nil, testLogger())
	passes := s.getSecureWipePasses()
	if passes != 1 {
		t.Errorf("expected 1 wipe pass, got %d", passes)
	}
}

// TestFirstbootSealStrategy_GetEFIPath verifies EFI path return.
func TestFirstbootSealStrategy_GetEFIPath(t *testing.T) {
	s := NewFirstbootSealStrategy(nil, nil, testLogger())
	path := s.getEFIPath()
	if path == "" {
		t.Error("expected non-empty EFI path")
	}
}

// TestFirstbootSealStrategy_GetPlatformKeystoreSRKHandle_NilExecutor verifies default SRK handle.
func TestFirstbootSealStrategy_GetPlatformKeystoreSRKHandle_NilExecutor(t *testing.T) {
	executor := &Executor{
		tpm:    nil,
		logger: testLogger(),
		config: DefaultConfig(),
	}
	s := NewFirstbootSealStrategy(executor, nil, testLogger())

	handle := s.getPlatformKeystoreSRKHandle()
	if handle != 0x81000002 {
		t.Errorf("expected default handle 0x81000002, got 0x%08x", handle)
	}
}

// TestFirstbootSealStrategy_GetPlatformPolicy_NilTPM verifies default platform policy.
func TestFirstbootSealStrategy_GetPlatformPolicy_NilTPM(t *testing.T) {
	executor := &Executor{
		tpm:    nil,
		logger: testLogger(),
		config: DefaultConfig(),
	}
	s := NewFirstbootSealStrategy(executor, nil, testLogger())

	policy := s.getPlatformPolicy()
	if !policy {
		t.Error("expected default platform policy to be true")
	}
}

// TestExecutor_TPM_NilSafe verifies TPM accessor with nil TPM.
func TestExecutor_TPM_NilSafe(t *testing.T) {
	executor := &Executor{
		tpm:    nil,
		logger: testLogger(),
		config: DefaultConfig(),
	}
	if executor.TPM() != nil {
		t.Error("expected nil TPM")
	}
}

// TestExecutor_Config verifies Config accessor.
func TestExecutor_Config(t *testing.T) {
	cfg := DefaultConfig()
	executor := &Executor{
		tpm:    nil,
		logger: testLogger(),
		config: cfg,
	}
	if executor.Config() != cfg {
		t.Error("expected config to match")
	}
}

// TestExecutor_Close_NilTPM verifies Close with nil TPM.
func TestExecutor_Close_NilTPM(t *testing.T) {
	executor := &Executor{
		tpm:    nil,
		logger: testLogger(),
		config: DefaultConfig(),
	}
	err := executor.Close()
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// TestClearBytes verifies secure memory clearing.
func TestClearBytes(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43, 0x44}
	clearBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("expected byte %d to be 0, got %d", i, b)
		}
	}
}

// TestClearBytes_EmptySlice verifies clearing an empty slice.
func TestClearBytes_EmptySlice(t *testing.T) {
	data := []byte{}
	clearBytes(data) // should not panic
	if len(data) != 0 {
		t.Error("expected empty slice to remain empty")
	}
}

// TestWipeWithPattern verifies file wiping with a pattern.
func TestWipeWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "testfile")

	original := []byte("secret data that must be wiped")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	if err := wipeWithPattern(path, 0xFF); err != nil {
		t.Fatalf("wipeWithPattern failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read wiped file: %v", err)
	}
	if len(content) != len(original) {
		t.Errorf("expected file size %d, got %d", len(original), len(content))
	}
	for i, b := range content {
		if b != 0xFF {
			t.Errorf("expected byte %d to be 0xFF, got 0x%02x", i, b)
		}
	}
}

// TestWipeWithPattern_NonexistentFile verifies error on missing file.
func TestWipeWithPattern_NonexistentFile(t *testing.T) {
	err := wipeWithPattern("/nonexistent/path/file", 0x00)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestWipeWithPattern_ZeroPattern verifies wiping with zero pattern.
func TestWipeWithPattern_ZeroPattern(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	if err := wipeWithPattern(path, 0x00); err != nil {
		t.Fatalf("wipeWithPattern failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read wiped file: %v", err)
	}
	for i, b := range content {
		if b != 0x00 {
			t.Errorf("expected byte %d to be 0x00, got 0x%02x", i, b)
		}
	}
}

// TestSecureWipeFile_NonexistentFile verifies error for missing file.
func TestSecureWipeFile_NonexistentFile(t *testing.T) {
	err := secureWipeFile("/nonexistent/path/file", 1)
	// secureWipeFile calls luks2.Wipe which returns error for nonexistent devices
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestTPMDetector_CommandExists verifies command existence check.
func TestTPMDetector_CommandExists(t *testing.T) {
	detector := NewTPMDetector(testLogger())
	// Verify the function does not panic, even for non-existent command
	_ = detector.commandExists("ls")
	result := detector.commandExists("nonexistent_cmd_xyz_123")
	if result {
		t.Error("expected false for nonexistent command")
	}
}

// TestTPMDetector_IsSocket_NonexistentPath verifies false for missing path.
func TestTPMDetector_IsSocket_NonexistentPath(t *testing.T) {
	detector := NewTPMDetector(testLogger())
	if detector.isSocket("/nonexistent/path/socket") {
		t.Error("expected false for nonexistent path")
	}
}

// TestTPMDetector_IsDevice_NonexistentPath verifies false for missing path.
func TestTPMDetector_IsDevice_NonexistentPath(t *testing.T) {
	detector := NewTPMDetector(testLogger())
	if detector.isDevice("/nonexistent/path/device") {
		t.Error("expected false for nonexistent path")
	}
}

// TestTPMDetector_IsSocket_RegularFile verifies false for regular file.
func TestTPMDetector_IsSocket_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "regular")
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	detector := NewTPMDetector(testLogger())
	if detector.isSocket(path) {
		t.Error("expected false for regular file")
	}
}

// TestTPMDetector_IsDevice_RegularFile verifies false for regular file.
func TestTPMDetector_IsDevice_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "regular")
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	detector := NewTPMDetector(testLogger())
	if detector.isDevice(path) {
		t.Error("expected false for regular file")
	}
}

// TestProcessFirstbootMarkers_NonexistentDir verifies no panic for missing dir.
func TestProcessFirstbootMarkers_NonexistentDir(t *testing.T) {
	err := ProcessFirstbootMarkers("/nonexistent/efi/path")
	// No marker file means not first boot - should return nil
	if err != nil {
		t.Errorf("expected nil error for nonexistent dir (no markers), got %v", err)
	}
}

// TestCopyTmpfsToRoot_DelegatesToProcessFirstbootMarkers verifies alias.
func TestCopyTmpfsToRoot_DelegatesToProcessFirstbootMarkers(t *testing.T) {
	err := CopyTmpfsToRoot("/nonexistent/efi/path")
	if err != nil {
		t.Errorf("expected nil error (no markers), got %v", err)
	}
}

// TestParsePCRBanksConfig_NoGoldenPCRs verifies config without golden-pcrs key.
func TestParsePCRBanksConfig_NoGoldenPCRs(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.GoldenPCRs) != 0 {
		t.Errorf("expected 0 golden PCRs, got %d", len(cfg.GoldenPCRs))
	}
}

// TestParsePCRBanksConfig_KeystorePlatformPolicy verifies the parent
// authorization mode is read from pcr-banks, never assumed (#52): absent
// defaults to false — the strategy seal path's default — and explicit
// values are honored.
func TestParsePCRBanksConfig_KeystorePlatformPolicy(t *testing.T) {
	logger := testLogger()
	base := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"absent defaults to false", "", false},
		{"explicit true", "keystore-platform-policy=true\n", true},
		{"explicit false", "keystore-platform-policy=false\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcrBanksPath := filepath.Join(t.TempDir(), "pcr-banks")
			if err := os.WriteFile(pcrBanksPath, []byte(base+tc.line), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}
			cfg := parsePCRBanksConfig(pcrBanksPath, logger)
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if cfg.PlatformSRK.PlatformPolicy != tc.want {
				t.Errorf("PlatformPolicy = %v, want %v", cfg.PlatformSRK.PlatformPolicy, tc.want)
			}
		})
	}
}

// TestParsePCRBanksConfig_DefaultFields verifies EK/IAK/IDevID defaults.
func TestParsePCRBanksConfig_DefaultFields(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	pcrBanksPath := filepath.Join(tmpDir, "pcr-banks")

	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrBanksPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := parsePCRBanksConfig(pcrBanksPath, logger)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	defaultCfg := xkmssdk.DefaultTPMConfig
	if cfg.Hash != defaultCfg.Hash {
		t.Errorf("expected Hash %s, got %s", defaultCfg.Hash, cfg.Hash)
	}
	if cfg.EK == nil {
		t.Error("expected EK to be set from defaults")
	}
}

// TestCopyDirRecursive verifies recursive directory copy.
func TestCopyDirRecursive(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	// Create source structure
	subDir := filepath.Join(srcDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("world"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	if err := copyDirRecursive(srcDir, destDir); err != nil {
		t.Fatalf("copyDirRecursive failed: %v", err)
	}

	// Verify files were copied
	data, err := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	if err != nil {
		t.Fatalf("failed to read copied file: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}

	data, err = os.ReadFile(filepath.Join(destDir, "subdir", "file2.txt"))
	if err != nil {
		t.Fatalf("failed to read copied subdir file: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("expected 'world', got %q", string(data))
	}
}

// TestCopyDirRecursive_EmptyDir verifies copying an empty directory.
func TestCopyDirRecursive_EmptyDir(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	if err := copyDirRecursive(srcDir, destDir); err != nil {
		t.Fatalf("copyDirRecursive failed: %v", err)
	}
}
