package firstboot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
)

// platformConfigPaths are the platformd configuration files firstboot reads,
// in order; the first one that carries the wanted section wins.
var platformConfigPaths = []string{
	"/mnt/installer/etc/trusted-platform/config.yaml",
	"/etc/trusted-platform/config.yaml",
	"/etc/trusted-platform/platformd.yaml",
	"/boot/efi/configs/platformd.yaml",
	"/media/cdrom/configs/platformd.yaml",
}

// ErrSOPINConfigNotFound is returned when no platformd configuration file
// carries a platform section, so firstboot cannot learn the SO PIN platformd
// will use.
var ErrSOPINConfigNotFound = errors.New("no platformd configuration with a platform section was found")

// ErrSOPINHandoffEmpty is returned when the SO PIN staged by an earlier
// attempt is empty: an empty owner auth is never taken as the SO PIN.
var ErrSOPINHandoffEmpty = errors.New("the staged SO PIN handoff file is empty")

// loadSOPINRef returns platform.so-pin from the first configuration file in
// paths that parses and carries a platform section.
func loadSOPINRef(paths []string) (string, error) {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var wrapper struct {
			Platform *struct {
				SOPin string `yaml:"so-pin"`
			} `yaml:"platform"`
		}
		if err := yaml.Unmarshal(data, &wrapper); err != nil || wrapper.Platform == nil {
			continue
		}
		return wrapper.Platform.SOPin, nil
	}
	return "", ErrSOPINConfigNotFound
}

// resolveSOPIN returns the SO PIN platformd will use, so the TPM owner auth
// firstboot sets is the one platformd presents (docs/tpm/engineering.md §4
// item 5). A literal platform.so-pin is the PIN. A kms:// reference has no
// KMS to read before platformd runs, so firstboot generates the PIN in the
// form the reference asks for and stages it at handoffFile, where platformd
// stores it at the reference's KMS path before it resolves its secrets. A PIN
// already staged by an earlier attempt in this boot is reused, so a retried
// provisioning proves and keeps the same owner auth.
func resolveSOPIN(configPaths []string, handoffFile string) (xkmssdk.Password, error) {
	value, err := loadSOPINRef(configPaths)
	if err != nil {
		return nil, err
	}
	ref, err := tpmowner.ParseSOPINRef(value)
	if err != nil {
		return nil, err
	}
	if !ref.IsKMS() {
		return newSOPINPassword(ref.Literal)
	}

	staged, err := os.ReadFile(handoffFile)
	if err == nil {
		if len(staged) == 0 {
			return nil, ErrSOPINHandoffEmpty
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Reusing the SO PIN staged for platformd at %s\n", handoffFile)
		return newSOPINPassword(staged)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, &WrappedError{Msg: fmt.Sprintf("read %s", handoffFile), Err: err}
	}

	pin, err := tpmowner.GenerateNumericSOPIN(ref.Length)
	if err != nil {
		return nil, err
	}
	if err := writeHandoffFile(handoffFile, pin); err != nil {
		clear(pin)
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] SO PIN generated and staged at %s for platformd to store at kms://%s\n", handoffFile, ref.KMSPath)
	return newSOPINPassword(pin)
}

// newSOPINPassword moves a PIN into an SDK password and wipes the source.
func newSOPINPassword(pin []byte) (xkmssdk.Password, error) {
	defer clear(pin)
	pw, err := xkmssdk.NewPassword(pin)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to hold the SO PIN", Err: err}
	}
	return pw, nil
}

// writeHandoffFile stages a secret on the firstboot tmpfs handoff for
// platformd: the directory is root only (0700) and the file 0600. O_EXCL
// refuses to clobber a pre-existing handoff file, so a stale consumer cannot
// silently overwrite a still-unconsumed secret. A file that cannot be written
// completely is removed.
func writeHandoffFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("mkdir %s", dir), Err: err}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0600)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("open %s", path), Err: err}
	}
	if _, err := f.Write(data); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("write %s", path), Err: errors.Join(err, f.Close(), os.Remove(path))}
	}
	if err := f.Sync(); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("sync %s", path), Err: errors.Join(err, f.Close(), os.Remove(path))}
	}
	if err := f.Close(); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("close %s", path), Err: errors.Join(err, os.Remove(path))}
	}
	return nil
}
