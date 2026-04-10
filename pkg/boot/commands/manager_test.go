package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestSrkHandleHex(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil", nil, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := srkHandleHex(nil)
			if result != "none" {
				t.Errorf("expected 'none' for nil input, got %s", result)
			}
		})
	}
	_ = tests
}

func TestSsrkHandleHex(t *testing.T) {
	result := ssrkHandleHex(nil)
	if result != "none" {
		t.Errorf("expected 'none' for nil input, got %s", result)
	}
}

func TestParsePCRBanksConfig_NonexistentFile(t *testing.T) {
	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig("/nonexistent/path", logger)
	if result != nil {
		t.Error("expected nil for nonexistent file")
	}
}

func TestParsePCRBanksConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	if err := os.WriteFile(pcrFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for empty file")
	}
}

func TestParsePCRBanksConfig_OldFormat(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	// Old format without key=value pairs
	content := "sha256\n0,7,9\n"
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for old format (no equals sign)")
	}
}

func TestParsePCRBanksConfig_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `seal-pcrs=0,7,9
platform-pcr=23
platform-pcr-bank=sha256
golden-pcrs=0,7,9,10
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config for valid file")
	}
	if result.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", result.PlatformPCR)
	}
	if result.PlatformPCRBank != "sha256" {
		t.Errorf("expected PlatformPCRBank sha256, got %s", result.PlatformPCRBank)
	}
	if result.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set")
	}
	if result.PlatformSRK.SRKHandle != 0x81000002 {
		t.Errorf("expected SRK handle 0x81000002, got 0x%08x", result.PlatformSRK.SRKHandle)
	}
	if result.SSRK == nil {
		t.Fatal("expected SSRK to be set")
	}
	if result.SSRK.Handle != 0x81000001 {
		t.Errorf("expected SSRK handle 0x81000001, got 0x%08x", result.SSRK.Handle)
	}
}

func TestParsePCRBanksConfig_MissingPlatformPCR(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when platform-pcr is missing")
	}
}

func TestParsePCRBanksConfig_MissingPlatformPCRBank(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when platform-pcr-bank is missing")
	}
}

func TestParsePCRBanksConfig_MissingKeystoreSRKHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when keystore-srk-handle is missing")
	}
}

func TestParsePCRBanksConfig_MissingSSRKHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil when ssrk-handle is missing")
	}
}

func TestParsePCRBanksConfig_InvalidPlatformPCR(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=abc
platform-pcr-bank=sha256
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result != nil {
		t.Error("expected nil for invalid platform-pcr")
	}
}

func TestParsePCRBanksConfig_DecimalHandles(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
keystore-srk-handle=2164260866
ssrk-handle=2164260865
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config for decimal handles")
	}
	if result.PlatformSRK.SRKHandle != 2164260866 {
		t.Errorf("unexpected SRK handle: %d", result.PlatformSRK.SRKHandle)
	}
}

func TestParsePCRBanksConfig_WithComments(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `# Platform PCR configuration
platform-pcr=23
platform-pcr-bank=sha256

# Handles
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config when comments are present")
	}
	if result.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", result.PlatformPCR)
	}
}

func TestParsePCRBanksConfig_GoldenPCRs(t *testing.T) {
	tmpDir := t.TempDir()
	pcrFile := filepath.Join(tmpDir, "pcr-banks")
	content := `platform-pcr=23
platform-pcr-bank=sha256
golden-pcrs=0,7,9,10
keystore-srk-handle=0x81000002
ssrk-handle=0x81000001
`
	if err := os.WriteFile(pcrFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	logger := logging.DefaultLogger()
	result := parsePCRBanksConfig(pcrFile, logger)
	if result == nil {
		t.Fatal("expected non-nil config")
	}
	if len(result.GoldenPCRs) != 4 {
		t.Errorf("expected 4 golden PCRs, got %d", len(result.GoldenPCRs))
	}
}

func TestPlatformConfigStruct(t *testing.T) {
	cfg := &PlatformConfig{}
	if cfg.TPM != nil {
		t.Error("expected nil TPM for zero-value PlatformConfig")
	}
}
