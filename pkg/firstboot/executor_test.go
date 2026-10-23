package firstboot

import (
	"testing"
)

func TestTPMTypeString(t *testing.T) {
	tests := []struct {
		name     string
		tpmType  TPMType
		expected string
	}{
		{"HardwareTPM", HardwareTPM, "hardware"},
		{"SoftwareTPM", SoftwareTPM, "software"},
		{"Unknown", TPMType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tpmType.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestTPMTypeConstants(t *testing.T) {
	if HardwareTPM != 0 {
		t.Errorf("expected HardwareTPM to be 0, got %d", HardwareTPM)
	}
	if SoftwareTPM != 1 {
		t.Errorf("expected SoftwareTPM to be 1, got %d", SoftwareTPM)
	}
}

func TestUnmarshalTPMConfig_ValidYAML(t *testing.T) {
	yamlData := []byte(`
tpm:
  device: /dev/tpmrm0
  platform-pcr: 23
  platform-pcr-bank: sha256
  ssrk:
    handle: 0x81000001
`)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformPCR != 23 {
		t.Errorf("expected PlatformPCR 23, got %d", cfg.PlatformPCR)
	}
	if cfg.PlatformPCRBank != "sha256" {
		t.Errorf("expected PlatformPCRBank sha256, got %s", cfg.PlatformPCRBank)
	}
}

func TestUnmarshalTPMConfig_NilTPMSection(t *testing.T) {
	yamlData := []byte(`
other:
  key: value
`)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when tpm section is missing, got %+v", cfg)
	}
}

func TestUnmarshalTPMConfig_InvalidYAML(t *testing.T) {
	yamlData := []byte(`
tpm: [invalid yaml structure
`)
	_, err := unmarshalTPMConfig(yamlData)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestUnmarshalTPMConfig_KeystoreFallback(t *testing.T) {
	// When platform-srk is not set but keystore is provided,
	// it should use keystore as PlatformSRK
	yamlData := []byte(`
tpm:
  device: /dev/tpmrm0
  platform-pcr: 23
  platform-pcr-bank: sha256
  keystore:
    srk-handle: 0x81000002
    platform-policy: true
`)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PlatformSRK == nil {
		t.Fatal("expected PlatformSRK to be set from keystore fallback")
	}
	if !cfg.PlatformSRK.PlatformPolicy {
		t.Error("expected PlatformPolicy to be true")
	}
}

func TestUnmarshalTPMConfig_EmptyYAML(t *testing.T) {
	yamlData := []byte(``)
	cfg, err := unmarshalTPMConfig(yamlData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for empty YAML, got %+v", cfg)
	}
}

func TestNewTPMDetector(t *testing.T) {
	detector := NewTPMDetector(nil)
	if detector == nil {
		t.Fatal("expected non-nil detector")
	}
}

func TestNewTPMDetectorWithLogger(t *testing.T) {
	logger := testLogger()
	detector := NewTPMDetector(logger)
	if detector == nil {
		t.Fatal("expected non-nil detector")
	}
	if detector.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestPlatformConfigStruct(t *testing.T) {
	cfg := &PlatformConfig{}
	if cfg.TPM != nil {
		t.Error("expected nil TPM for zero-value PlatformConfig")
	}
}
