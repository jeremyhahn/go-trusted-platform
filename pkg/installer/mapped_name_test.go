package installer

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func mappedNameConfig(name string) *Config {
	return &Config{
		Disk: &DiskConfig{Device: "/dev/loop0", Encryption: &EncryptionConfig{MappedName: name}},
		OS:   &OSConfig{Architecture: "aarch64"},
	}
}

func TestValidate_AcceptsMappedNamesDeviceMapperTakes(t *testing.T) {
	for _, name := range []string{"", "cryptroot", "luks-root_1.2+x"} {
		if err := mappedNameConfig(name).Validate(); err != nil {
			t.Errorf("Validate() rejected mapped-name %q: %v", name, err)
		}
	}
}

// go-luks2 v0.1.10 made Unlock refuse names device-mapper would mangle. The
// installer formats the disk before it unlocks it, so the name must be
// refused at validation, not after the disk is wiped.
func TestValidate_RejectsMappedNamesUnlockWouldRefuse(t *testing.T) {
	for _, name := range []string{"-root", "crypt/root", "crypt root", "../cryptroot"} {
		err := mappedNameConfig(name).Validate()
		var invalid *InstallerError
		if !errors.As(err, &invalid) || invalid.Type != ErrorTypeInvalidConfig {
			t.Errorf("Validate() error for mapped-name %q = %v, want an invalid-config InstallerError", name, err)
			continue
		}
		if !errors.Is(err, luks2.ErrInvalidMappingName) {
			t.Errorf("Validate() error for mapped-name %q = %v, want it to wrap luks2.ErrInvalidMappingName", name, err)
		}
	}
}

func TestErrInvalidMappedName(t *testing.T) {
	cause := errors.New("bad name")
	err := ErrInvalidMappedName("crypt/root", cause)

	var invalid *InstallerError
	if !errors.As(err, &invalid) || invalid.Type != ErrorTypeInvalidConfig || !errors.Is(err, cause) {
		t.Fatalf("ErrInvalidMappedName = %#v, want an invalid-config InstallerError wrapping its cause", err)
	}
	if err.Error() == "" {
		t.Fatal("ErrInvalidMappedName has an empty message")
	}
}
