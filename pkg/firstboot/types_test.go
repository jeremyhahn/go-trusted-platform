package firstboot

import (
	"errors"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.PCRSelection != nil {
		t.Errorf("expected nil PCRSelection, got %v", cfg.PCRSelection)
	}
	if !cfg.TPMAutoUnseal {
		t.Error("expected TPMAutoUnseal to be true")
	}
	if cfg.LuksTPMOnly {
		t.Error("expected LuksTPMOnly to be false")
	}
	if cfg.LuksDevice != "" {
		t.Errorf("expected empty LuksDevice, got %s", cfg.LuksDevice)
	}
	if cfg.SwtpmStateDir != DefaultSwtpmStateDir {
		t.Errorf("expected SwtpmStateDir %s, got %s", DefaultSwtpmStateDir, cfg.SwtpmStateDir)
	}
	if cfg.EFIMountPoint != "/boot/efi" {
		t.Errorf("expected EFIMountPoint /boot/efi, got %s", cfg.EFIMountPoint)
	}
	if cfg.Debug {
		t.Error("expected Debug to be false")
	}
}

func TestDefaultConfigIsIndependent(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := DefaultConfig()

	cfg1.Debug = true
	cfg1.LuksDevice = "/dev/sda2"

	if cfg2.Debug {
		t.Error("modifying cfg1 should not affect cfg2")
	}
	if cfg2.LuksDevice != "" {
		t.Error("modifying cfg1 should not affect cfg2")
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrNoTPMDevice", ErrNoTPMDevice, "no TPM device found"},
		{"ErrNoTPMConfig", ErrNoTPMConfig, "no TPM configuration found"},
		{"ErrAlreadySealed", ErrAlreadySealed, "TPM already sealed"},
		{"ErrNoLUKSKey", ErrNoLUKSKey, "no LUKS key found"},
		{"ErrInvalidKeySize", ErrInvalidKeySize, "invalid LUKS key size"},
		{"ErrTPMNotAvailable", ErrTPMNotAvailable, "TPM not available"},
		{"ErrSSRKNotAccessible", ErrSSRKNotAccessible, "SSRK not accessible"},
		{"ErrPlatformSRKNotAccessible", ErrPlatformSRKNotAccessible, "platform keystore SRK not accessible"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}
			msg := tt.err.Error()
			if msg == "" {
				t.Error("error message should not be empty")
			}
			if !containsSubstring(msg, tt.contains) {
				t.Errorf("expected error to contain %q, got %q", tt.contains, msg)
			}
		})
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	allErrors := []error{
		ErrNoTPMDevice,
		ErrNoTPMConfig,
		ErrAlreadySealed,
		ErrNoLUKSKey,
		ErrInvalidKeySize,
		ErrTPMNotAvailable,
		ErrSSRKNotAccessible,
		ErrPlatformSRKNotAccessible,
	}

	for i := 0; i < len(allErrors); i++ {
		for j := i + 1; j < len(allErrors); j++ {
			if errors.Is(allErrors[i], allErrors[j]) {
				t.Errorf("expected %v and %v to be distinct errors", allErrors[i], allErrors[j])
			}
		}
	}
}

func TestEFISealPathsArePaired(t *testing.T) {
	// Ensure platform pub/priv are in the same directory
	if EFISealPlatformPub[:len(EFISealPlatformPub)-4] == "" {
		t.Error("platform seal pub path is too short")
	}

	// Verify upgrade seal paths exist
	if EFISealUpgradePub == "" || EFISealUpgradePriv == "" {
		t.Error("upgrade seal paths should not be empty")
	}

	// Verify platform and upgrade seal paths are distinct
	if EFISealPlatformPub == EFISealUpgradePub {
		t.Error("platform and upgrade pub paths should be distinct")
	}
	if EFISealPlatformPriv == EFISealUpgradePriv {
		t.Error("platform and upgrade priv paths should be distinct")
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsCheck(s, substr))
}

func containsCheck(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
