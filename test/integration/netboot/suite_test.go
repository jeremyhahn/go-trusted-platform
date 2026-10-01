//go:build integration

// Package netboot boots the Raspberry Pi stand-in over the network: QEMU
// virt started from the platform's qemu_arm64 U-Boot on the PXE test
// bridge, through `platformctl iso test pxe --architecture aarch64`. It
// proves the chain from U-Boot onward — DHCP client architecture 0x000b,
// the db-signed arm64 iPXE, the architecture-aware boot script, the
// db-signed kernel and its initrd — with the same firmware the factory
// image puts on the card. The Pi's EEPROM stage before U-Boot is covered
// by the Raspberry Pi netboot emulator suite and by hardware.
package netboot

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	envUBoot      = "NETBOOT_UBOOT"
	envIPXE       = "NETBOOT_IPXE"
	envKeysDir    = "NETBOOT_KEYS_DIR"
	envKernel     = "NETBOOT_KERNEL"
	envInitrd     = "NETBOOT_INITRD"
	envModloop    = "NETBOOT_MODLOOP"
	envAlpineRepo = "NETBOOT_ALPINE_REPO"
	envWorkDir    = "NETBOOT_WORK_DIR"
	envPlatformct = "PLATFORMCTL_PATH"
)

// MissingInputError names an input the suite cannot run without. The suite
// fails, never skips, when one is absent.
type MissingInputError struct {
	Variable string
	Path     string
	Err      error
}

func (e *MissingInputError) Error() string {
	if e.Variable != "" && e.Path == "" {
		return "netboot suite: " + e.Variable + " is not set (run `make integration-test-netboot`, which builds the inputs)"
	}
	return "netboot suite: " + e.Variable + "=" + e.Path + ": " + e.Err.Error()
}

func (e *MissingInputError) Unwrap() error { return e.Err }

type inputs struct {
	uboot       string
	ipxe        string
	keysDir     string
	kernel      string
	initrd      string
	modloop     string
	alpineRepo  string
	workDir     string
	platformctl string
}

func requireInputs(t *testing.T) inputs {
	t.Helper()
	in := inputs{
		uboot:       os.Getenv(envUBoot),
		ipxe:        os.Getenv(envIPXE),
		keysDir:     os.Getenv(envKeysDir),
		kernel:      os.Getenv(envKernel),
		initrd:      os.Getenv(envInitrd),
		modloop:     os.Getenv(envModloop),
		alpineRepo:  os.Getenv(envAlpineRepo),
		workDir:     os.Getenv(envWorkDir),
		platformctl: os.Getenv(envPlatformct),
	}
	for _, v := range []struct{ name, value string }{
		{envUBoot, in.uboot},
		{envIPXE, in.ipxe},
		{envKeysDir, in.keysDir},
		{envKernel, in.kernel},
		{envInitrd, in.initrd},
		{envModloop, in.modloop},
		{envPlatformct, in.platformctl},
	} {
		if v.value == "" {
			t.Fatal(&MissingInputError{Variable: v.name})
		}
		if _, err := os.Stat(v.value); err != nil {
			t.Fatal(&MissingInputError{Variable: v.name, Path: v.value, Err: err})
		}
	}
	if in.alpineRepo == "" {
		t.Fatal(&MissingInputError{Variable: envAlpineRepo})
	}
	if in.workDir == "" {
		in.workDir = filepath.Join(os.TempDir(), "netboot-integration")
	}
	if err := os.MkdirAll(in.workDir, 0o755); err != nil {
		t.Fatal(&MissingInputError{Variable: envWorkDir, Path: in.workDir, Err: err})
	}
	return in
}
