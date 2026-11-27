//go:build integration

package diskimage

import (
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// The x86 ISO path of the live event log check is opt-in: every input comes
// from the environment and none has a default, because no build in this
// tree writes a signed manifest for an ISO yet.
const (
	envX86ISO      = "DISKIMAGE_X86_ISO"
	envX86Manifest = "DISKIMAGE_X86_MANIFEST"
	envX86OVMFCode = "DISKIMAGE_X86_OVMF_CODE"
	envX86OVMFVars = "DISKIMAGE_X86_OVMF_VARS"
	// envX86Ready names the console text that says the guest is ready for
	// the login line; it defaults to defaultX86Ready.
	envX86Ready     = "DISKIMAGE_X86_READY"
	defaultX86Ready = "login:"
)

// x86Inputs are the files the x86 ISO boot needs, and the console text it
// waits for before it logs in.
type x86Inputs struct {
	iso, manifest, ovmfCode, ovmfVars, ready string
}

// x86InputsFromEnv resolves the x86 inputs through getenv. The first unset
// required variable is returned as a *MissingInputError naming it.
func x86InputsFromEnv(getenv func(string) string) (x86Inputs, error) {
	var in x86Inputs
	for _, v := range []struct {
		name string
		dst  *string
	}{
		{envX86ISO, &in.iso},
		{envX86Manifest, &in.manifest},
		{envX86OVMFCode, &in.ovmfCode},
		{envX86OVMFVars, &in.ovmfVars},
	} {
		*v.dst = getenv(v.name)
		if *v.dst == "" {
			return x86Inputs{}, &MissingInputError{Variable: v.name}
		}
	}
	in.ready = getenv(envX86Ready)
	if in.ready == "" {
		in.ready = defaultX86Ready
	}
	return in, nil
}

// x86BootConfig is the QEMU configuration that boots in's ISO under OVMF
// with every artifact under workDir, the serial port on a console socket
// mirrored to boot.log, and no network. EnableKVM is safe on any host: the
// qemu package falls back to TCG when KVM cannot accelerate the guest.
func x86BootConfig(in x86Inputs, workDir string) *qemu.Config {
	return &qemu.Config{
		Arch:              qemu.ArchX86_64,
		ISO:               in.iso,
		OVMFCode:          in.ovmfCode,
		OVMFVars:          in.ovmfVars,
		BootOrder:         "d",
		DiskPath:          filepath.Join(workDir, "x86.qcow2"),
		DiskFormat:        qemu.DiskFormatQCOW2,
		DiskSize:          "16384M",
		Memory:            4096,
		CPUs:              2,
		WorkDir:           workDir,
		EnableKVM:         true,
		NoGraphic:         true,
		SerialLogFile:     filepath.Join(workDir, "boot.log"),
		ConsoleSocketPath: filepath.Join(workDir, "console.sock"),
		NetworkMode:       "none",
	}
}
