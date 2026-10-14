package diskimage

import "strings"

// ErrBuildFailed reports a failed image build.
type ErrBuildFailed struct {
	Reason string
}

func (e ErrBuildFailed) Error() string { return "diskimage build failed: " + e.Reason }

// ErrConfigRequired reports that assemble was given neither configuration.
type ErrConfigRequired struct{}

func (ErrConfigRequired) Error() string {
	return "diskimage assemble: exactly one of --config or --platform-config is required"
}

// ErrConfigLoadFailed reports an unreadable configuration.
type ErrConfigLoadFailed struct {
	Path string
	Err  error
}

func (e ErrConfigLoadFailed) Error() string {
	return "diskimage: failed to load " + e.Path + ": " + e.Err.Error()
}

func (e ErrConfigLoadFailed) Unwrap() error { return e.Err }

// ErrBinariesNotFound reports a missing target-architecture platformd.
type ErrBinariesNotFound struct {
	Dir string
}

func (e ErrBinariesNotFound) Error() string {
	return "diskimage: no platformd in " + e.Dir + " (build the target binaries with `make rpi-binaries` or pass --binaries-dir)"
}

// ErrRoleTemplate reports a --role the image builder cannot build: a target
// other than rpi, a model with no dedicated template for the role, or a
// --platform-config that already chose the template.
type ErrRoleTemplate struct {
	Target string
	Model  string
	Role   string
	Reason string
}

func (e ErrRoleTemplate) Error() string {
	return "diskimage: --role " + e.Role + " (target " + e.Target + ", model " + e.Model + "): " + e.Reason
}

// ErrInvalidPortForward reports a --forward value that is not
// host:guest[/tcp|udp].
type ErrInvalidPortForward struct {
	Spec string
}

func (e ErrInvalidPortForward) Error() string {
	return "diskimage test: invalid --forward " + e.Spec + " (want host:guest[/tcp|udp])"
}

// ErrSourceDateEpoch is a diskless build without a valid SOURCE_DATE_EPOCH,
// which every timestamp in the diskless root and its salt derive from.
type ErrSourceDateEpoch struct {
	Value string
}

func (e ErrSourceDateEpoch) Error() string {
	if e.Value == "" {
		return "diskimage netboot: --diskless needs --source-date-epoch or SOURCE_DATE_EPOCH"
	}
	return "diskimage netboot: invalid SOURCE_DATE_EPOCH " + e.Value + " (want seconds since 1970, >= 0)"
}

// ErrUnknownMediaSet is a --sets name the netboot build does not produce.
type ErrUnknownMediaSet struct {
	Name  string
	Known []string
}

func (e ErrUnknownMediaSet) Error() string {
	return "unknown media set " + e.Name + " (known: " + strings.Join(e.Known, ", ") + ")"
}

// ErrHTTPBootFlags is an HTTP boot flag given without --fleet-key, the flag
// that turns HTTP boot on (--source-date-epoch: without --diskless either).
type ErrHTTPBootFlags struct {
	Flag string
}

// ErrEEPROMHSMAlgorithm reports the algorithm requested by rpi-eeprom-digest's
// HSM wrapper contract is not the one the Raspberry Pi bootloader verifies.
type ErrEEPROMHSMAlgorithm struct {
	Algorithm string
}

func (e *ErrEEPROMHSMAlgorithm) Error() string {
	return "rpi-eeprom HSM wrapper: unsupported algorithm " + e.Algorithm + " (want rsa2048-sha256)"
}

// ErrEEPROMHSMFlag reports a missing wrapper flag.
type ErrEEPROMHSMFlag struct {
	Flag string
}

func (e *ErrEEPROMHSMFlag) Error() string {
	return "rpi-eeprom HSM wrapper: --" + e.Flag + " is required"
}

// ErrEEPROMHSMSign wraps a failure while signing a file for rpi-eeprom-digest.
type ErrEEPROMHSMSign struct {
	Step string
	Err  error
}

func (e *ErrEEPROMHSMSign) Error() string {
	return "rpi-eeprom HSM wrapper: " + e.Step + ": " + e.Err.Error()
}

func (e *ErrEEPROMHSMSign) Unwrap() error { return e.Err }

func (e ErrHTTPBootFlags) Error() string {
	if e.Flag == "source-date-epoch" {
		return "--source-date-epoch needs --fleet-key or --diskless: it times only the HTTP boot files and the diskless root"
	}
	return "--" + e.Flag + " needs --fleet-key: the HTTP boot files are only built when the fleet key is given"
}
