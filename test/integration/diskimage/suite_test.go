//go:build integration

// Package diskimage is the factory-image integration suite: it proves the
// Raspberry Pi image's boot chain on the QEMU virt stand-in (U-Boot →
// Secure Boot → UKI → platform-initrd → firstboot sealing → platformd)
// and checks the layout of both images. It runs in the devcontainer via
// `make integration-test-diskimage`; the images and U-Boot come from the
// host build through the environment. Missing inputs fail the suite —
// there are no skip guards, because a suite that skips reports the same
// green as one that passed.
package diskimage

import (
	"os"
	"path/filepath"
	"testing"
)

// Environment variables the runner sets (build/docker/devcontainer/run-integration-tests.sh).
const (
	envImage    = "DISKIMAGE_IMAGE"
	envRPIImage = "DISKIMAGE_RPI_IMAGE"
	envUBoot    = "DISKIMAGE_UBOOT"
	envWorkDir  = "DISKIMAGE_WORK_DIR"
)

// MissingInputError reports a required suite input that is unset or absent.
type MissingInputError struct {
	Variable string
	Path     string
	Err      error
}

func (e *MissingInputError) Error() string {
	if e.Variable != "" && e.Path == "" {
		return "diskimage suite: " + e.Variable + " is not set (run `make integration-test-diskimage`, which builds the inputs)"
	}
	return "diskimage suite: " + e.Variable + "=" + e.Path + ": " + e.Err.Error()
}

func (e *MissingInputError) Unwrap() error { return e.Err }

// inputs are the suite's resolved inputs.
type inputs struct {
	image    string
	rpiImage string
	uboot    string
	workDir  string
}

// requireInputs resolves the environment and fails the test when any
// input is unset or missing.
func requireInputs(t *testing.T) inputs {
	t.Helper()
	in := inputs{
		image:    os.Getenv(envImage),
		rpiImage: os.Getenv(envRPIImage),
		uboot:    os.Getenv(envUBoot),
		workDir:  os.Getenv(envWorkDir),
	}
	for _, v := range []struct{ name, value string }{{envImage, in.image}, {envRPIImage, in.rpiImage}, {envUBoot, in.uboot}} {
		if v.value == "" {
			t.Fatal(&MissingInputError{Variable: v.name})
		}
		if _, err := os.Stat(v.value); err != nil {
			t.Fatal(&MissingInputError{Variable: v.name, Path: v.value, Err: err})
		}
	}
	if in.workDir == "" {
		in.workDir = filepath.Join(os.TempDir(), "diskimage-integration")
	}
	if err := os.MkdirAll(in.workDir, 0o755); err != nil {
		t.Fatal(&MissingInputError{Variable: envWorkDir, Path: in.workDir, Err: err})
	}
	return in
}
