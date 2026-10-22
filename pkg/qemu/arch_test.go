package qemu

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// archFixture lays out the files buildQEMUCommand stats: OVMF, a disk, an
// ISO, a TPM socket, a U-Boot binary and the NVRAM copy.
type archFixture struct {
	dir string
}

func newArchFixture(t *testing.T) archFixture {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"OVMF_CODE.fd", "OVMF_CODE.secboot.fd", "OVMF_VARS.fd", "disk.img", "iso.iso", "tpm.sock", "u-boot.bin"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nvram"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nvram", "OVMF_VARS.fd"), []byte("x"), 0o644))
	return archFixture{dir: dir}
}

func (f archFixture) path(name string) string { return filepath.Join(f.dir, name) }

// x86Config is the configuration the golden command lines were captured
// from, before the architecture profiles existed. QEMUBinary is explicit,
// as DefaultConfig sets it, so the -L ROM probe (host-dependent) stays off.
func (f archFixture) x86Config() *Config {
	return &Config{
		QEMUBinary: "qemu-system-x86_64",
		DiskPath:   f.path("disk.img"), DiskSize: "1G", Memory: 2048, CPUs: 2, WorkDir: f.dir,
		OVMFCode: f.path("OVMF_CODE.fd"), OVMFCodeSecure: f.path("OVMF_CODE.secboot.fd"), OVMFVars: f.path("OVMF_VARS.fd"),
		TPMSocket: f.path("tpm.sock"), NetworkMode: "user", NoGraphic: true, SerialLogFile: f.path("serial.log"),
		EnableKVM: true, ISO: f.path("iso.iso"), BootOrder: "d",
		HostArch: "amd64", KVMProbe: kvmUsable,
	}
}

func (f archFixture) aarch64Config() *Config {
	return &Config{
		Arch:     ArchAArch64,
		Firmware: f.path("u-boot.bin"),
		DiskPath: f.path("disk.img"), DiskSize: "1G", Memory: 2048, CPUs: 2, WorkDir: f.dir,
		TPMSocket: f.path("tpm.sock"), NetworkMode: "user", NoGraphic: true, SerialLogFile: f.path("serial.log"),
		EnableKVM: true, KVMProbe: kvmUsable,
	}
}

// kvmUsable and kvmMissing stand in for the /dev/kvm probe, so no test
// depends on the host's KVM device.
func kvmUsable() error { return nil }

func kvmMissing() error {
	return &SentinelCauseError{Sentinel: ErrKVMUnavailable, Cause: fs.ErrNotExist}
}

// withKVM prepends -enable-kvm after the ROM/binary position when the host
// can accelerate the guest, which is what the profiles decide from
// runtime.GOARCH.
func withKVM(hostArch string, args ...string) []string {
	if runtime.GOARCH != hostArch {
		return args
	}
	return append([]string{"-enable-kvm"}, args...)
}

func (f archFixture) x86Tail(ovmf string) []string {
	return []string{
		"-netdev", "user,id=net0",
		"-device", "virtio-net-pci,netdev=net0",
		"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + f.path(ovmf),
		"-drive", "if=pflash,unit=1,format=raw,file=" + f.path("nvram/OVMF_VARS.fd"),
	}
}

func (f archFixture) commonTail(tpmDevice, serial string) []string {
	return []string{
		"-chardev", "socket,id=chrtpm,path=" + f.path("tpm.sock"),
		"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
		"-device", tpmDevice + ",tpmdev=tpm0",
		"-object", "rng-random,filename=/dev/urandom,id=rng0",
		"-device", "virtio-rng-pci,rng=rng0",
		"-qmp", "unix:" + f.path("qmp.sock") + ",server,wait=off",
		"-serial", serial,
		"-nographic",
	}
}

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func buildArgs(t *testing.T, cfg *Config, mode BootMode) []string {
	t.Helper()
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)
	cmd, err := vm.buildQEMUCommand(context.Background(), mode)
	require.NoError(t, err)
	return cmd.Args
}

// TestBuildQEMUCommand_X86Golden pins the x86_64 command line to what the
// pre-profile builder produced (captured 2026-09-20 before arch.go
// existed) for the three boot modes. The profile refactor is only correct
// if these do not move.
func TestBuildQEMUCommand_X86Golden(t *testing.T) {
	f := newArchFixture(t)
	x86Head := func(machine string) []string {
		return concat([]string{"-enable-kvm"}, []string{
			"-machine", machine,
			"-cpu", "host",
			"-smp", "cores=2,threads=1",
			"-m", "2048",
			"-drive", "file=" + f.path("disk.img") + ",if=none,format=qcow2,cache=writethrough,id=hd0",
			"-device", "ahci,id=ahci0",
			"-device", "ide-hd,drive=hd0,bus=ahci0.0",
		})
	}

	t.Run("boot with Secure Boot", func(t *testing.T) {
		cfg := f.x86Config()
		cfg.SecureBoot = true
		want := concat([]string{"qemu-system-x86_64"}, x86Head("q35,smm=on"),
			[]string{"-boot", "menu=on,strict=off", "-device", "VGA"},
			f.x86Tail("OVMF_CODE.secboot.fd"),
			[]string{"-global", "driver=cfi.pflash01,property=secure,value=on"},
			f.commonTail("tpm-tis", "file:"+f.path("serial.log")))
		assert.Equal(t, want, buildArgs(t, cfg, BootModeBoot))
	})

	t.Run("install from ISO", func(t *testing.T) {
		want := concat([]string{"qemu-system-x86_64"}, x86Head("q35"),
			[]string{
				"-boot", "order=d",
				"-drive", "file=" + f.path("iso.iso") + ",if=none,media=cdrom,readonly=on,id=cd0",
				"-device", "ide-cd,drive=cd0,bus=ahci0.1",
				"-device", "VGA",
			},
			f.x86Tail("OVMF_CODE.fd"),
			f.commonTail("tpm-tis", "file:"+f.path("serial.log")))
		assert.Equal(t, want, buildArgs(t, f.x86Config(), BootModeInstall))
	})

	t.Run("PXE without network and with a stdio console", func(t *testing.T) {
		cfg := f.x86Config()
		cfg.NetworkMode = "none"
		cfg.SerialLogFile = ""
		cfg.SerialConsole = true
		want := concat([]string{"qemu-system-x86_64"}, x86Head("q35"),
			[]string{"-boot", "order=n,menu=on,strict=off", "-device", "VGA"},
			[]string{
				"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + f.path("OVMF_CODE.fd"),
				"-drive", "if=pflash,unit=1,format=raw,file=" + f.path("nvram/OVMF_VARS.fd"),
			},
			f.commonTail("tpm-tis", "stdio"))
		assert.Equal(t, want, buildArgs(t, cfg, BootModePXE))
	})

	t.Run("an empty binary still probes the ROM directory as it always did", func(t *testing.T) {
		cfg := f.x86Config()
		cfg.QEMUBinary = ""
		args := buildArgs(t, cfg, BootModeBoot)
		assert.Equal(t, "qemu-system-x86_64", args[0])
		if _, err := os.Stat("/usr/share/seabios/vgabios-stdvga.bin"); err == nil {
			assert.Equal(t, []string{"-L", "/usr/share/seabios"}, args[1:3])
		}
	})
}

func TestBuildQEMUCommand_AArch64Boot(t *testing.T) {
	f := newArchFixture(t)
	machine, cpu := "virt,gic-version=3", "cortex-a72"
	if runtime.GOARCH == "arm64" {
		machine, cpu = "virt,gic-version=host", "host"
	}
	want := concat([]string{"qemu-system-aarch64"}, withKVM("arm64",
		"-machine", machine,
		"-cpu", cpu,
		"-smp", "cores=2,threads=1",
		"-m", "2048",
		"-drive", "file="+f.path("disk.img")+",if=none,format=raw,cache=writethrough,id=hd0",
		"-device", "virtio-blk-pci,drive=hd0",
		"-netdev", "user,id=net0",
		"-device", "virtio-net-pci,netdev=net0",
		"-bios", f.path("u-boot.bin"),
	), f.commonTail("tpm-tis-device", "file:"+f.path("serial.log")))

	assert.Equal(t, want, buildArgs(t, f.aarch64Config(), BootModeBoot))
}

func TestBuildQEMUCommand_AArch64NeverAsksForKVMOnAForeignHost(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64Config()
	cfg.HostArch = "amd64"
	args := buildArgs(t, cfg, BootModeBoot)
	assert.NotContains(t, args, "-enable-kvm")
	assert.NotContains(t, args, "-L")
}

func TestBuildQEMUCommand_AArch64PXEHasNoBootOrderOrDisplay(t *testing.T) {
	f := newArchFixture(t)
	args := buildArgs(t, f.aarch64Config(), BootModePXE)
	assert.NotContains(t, args, "-boot")
	assert.NotContains(t, args, "VGA")
	assert.NotContains(t, args, "virtio-vga")
}

func TestBuildQEMUCommand_AArch64RefusesInstallMode(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64Config()
	cfg.ISO = f.path("iso.iso")
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)

	_, err = vm.buildQEMUCommand(context.Background(), BootModeInstall)

	assert.ErrorIs(t, err, ErrUnsupportedBootMode)
}

// unvalidatedVM bypasses NewVM's validation so the builder's own checks
// are exercised, not only the ones Validate runs first.
func unvalidatedVM(cfg *Config) *VM {
	return &VM{config: cfg, logger: logging.DefaultLogger()}
}

func TestBuildQEMUCommand_AArch64RequiresFirmware(t *testing.T) {
	f := newArchFixture(t)
	for name, firmware := range map[string]string{"unset": "", "absent": f.path("missing-u-boot.bin")} {
		t.Run(name, func(t *testing.T) {
			cfg := f.aarch64Config()
			cfg.Firmware = firmware

			_, err := NewVM(cfg, nil)
			assert.ErrorIs(t, err, ErrFirmwareMissing, "NewVM validates the firmware up front")

			_, err = unvalidatedVM(cfg).buildQEMUCommand(context.Background(), BootModeBoot)
			assert.ErrorIs(t, err, ErrFirmwareMissing, "the builder checks it again")
		})
	}
}

func TestBuildQEMUCommand_UnknownArch(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.x86Config()
	cfg.Arch = "riscv64"
	cfg.DiskPath = f.path("not-yet-created.img") // CreateDisk must reach the profile lookup

	_, err := NewVM(cfg, nil)
	assert.ErrorIs(t, err, ErrUnsupportedArch)

	vm := unvalidatedVM(cfg)
	_, err = vm.buildQEMUCommand(context.Background(), BootModeBoot)
	assert.ErrorIs(t, err, ErrUnsupportedArch)
	assert.ErrorIs(t, vm.initializeNVRAM(), ErrUnsupportedArch)
	assert.ErrorIs(t, vm.CreateDisk(), ErrUnsupportedArch)
}

func TestConfigValidate_AArch64DoesNotNeedOVMF(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64Config()
	cfg.OVMFCode = f.path("no-such-OVMF.fd")
	cfg.OVMFVars = f.path("no-such-VARS.fd")

	assert.NoError(t, cfg.Validate())
}

func TestConfigDiskFormat(t *testing.T) {
	f := newArchFixture(t)
	x86 := f.x86Config()
	arm := f.aarch64Config()
	x86p, _ := x86.profile()
	armp, _ := arm.profile()

	assert.Equal(t, DiskFormatQCOW2, x86.diskFormat(x86p))
	assert.Equal(t, DiskFormatRaw, arm.diskFormat(armp))

	x86.DiskFormat = DiskFormatRaw
	assert.Equal(t, DiskFormatRaw, x86.diskFormat(x86p))
	args := buildArgs(t, x86, BootModeBoot)
	assert.Contains(t, args, "file="+f.path("disk.img")+",if=none,format=raw,cache=writethrough,id=hd0")

	x86.DiskFormat = "vmdk"
	assert.ErrorIs(t, x86.Validate(), ErrInvalidConfiguration)
}

func TestConfigTPMDeviceOverride(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64Config()
	cfg.TPMDevice = "tpm-crb"

	assert.Contains(t, buildArgs(t, cfg, BootModeBoot), "tpm-crb,tpmdev=tpm0")
}

func TestInitializeNVRAM_NoOpForBIOSFirmware(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64Config()
	cfg.WorkDir = filepath.Join(f.dir, "aarch64-work")
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, vm.initializeNVRAM())

	_, err = os.Stat(cfg.GetNVRAMPath())
	assert.True(t, os.IsNotExist(err), "no NVRAM file may be created for a -bios firmware")
}

func TestConfigQEMUBinaryDefaultsPerArch(t *testing.T) {
	x86 := &Config{}
	arm := &Config{Arch: ArchAArch64}
	x86p, _ := x86.profile()
	armp, _ := arm.profile()

	assert.Equal(t, "qemu-system-x86_64", x86.qemuBinary(x86p))
	assert.Equal(t, "qemu-system-aarch64", arm.qemuBinary(armp))
	arm.QEMUBinary = "/opt/qemu/bin/qemu-system-aarch64"
	assert.Equal(t, "/opt/qemu/bin/qemu-system-aarch64", arm.qemuBinary(armp))
}

// aarch64UEFIConfig is an aarch64 compute VM on an arm64 host booting UEFI
// (AAVMF) from pflash: the firmware paths are set and no -bios image is.
func (f archFixture) aarch64UEFIConfig() *Config {
	cfg := f.aarch64Config()
	cfg.Firmware = ""
	cfg.OVMFCode = f.path("OVMF_CODE.fd")
	cfg.OVMFCodeSecure = f.path("OVMF_CODE.secboot.fd")
	cfg.OVMFVars = f.path("OVMF_VARS.fd")
	cfg.HostArch = "arm64"
	return cfg
}

func TestBuildQEMUCommand_AArch64UEFIOnArm64Host(t *testing.T) {
	f := newArchFixture(t)
	want := concat([]string{"qemu-system-aarch64",
		"-enable-kvm",
		"-machine", "virt,gic-version=host",
		"-cpu", "host",
		"-smp", "cores=2,threads=1",
		"-m", "2048",
		"-drive", "file=" + f.path("disk.img") + ",if=none,format=raw,cache=writethrough,id=hd0",
		"-device", "virtio-blk-pci,drive=hd0",
		"-netdev", "user,id=net0",
		"-device", "virtio-net-pci,netdev=net0",
		"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + f.path("OVMF_CODE.fd"),
		"-drive", "if=pflash,unit=1,format=raw,file=" + f.path("nvram/OVMF_VARS.fd"),
	}, f.commonTail("tpm-tis-device", "file:"+f.path("serial.log")))

	assert.Equal(t, want, buildArgs(t, f.aarch64UEFIConfig(), BootModeBoot))
}

func TestBuildQEMUCommand_AArch64UEFISecureBootUsesSecureCode(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64UEFIConfig()
	cfg.SecureBoot = true

	args := buildArgs(t, cfg, BootModeBoot)
	assert.Contains(t, args, "if=pflash,unit=0,format=raw,readonly=on,file="+f.path("OVMF_CODE.secboot.fd"))
	assert.NotContains(t, args, "driver=cfi.pflash01,property=secure,value=on",
		"the SMM-protected varstore is an x86 q35 feature; the virt machine has no SMM")
}

func TestBuildQEMUCommand_AArch64UEFIOnForeignHostUsesTCG(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64UEFIConfig()
	cfg.HostArch = "amd64"

	args := buildArgs(t, cfg, BootModeBoot)
	assert.NotContains(t, args, "-enable-kvm")
	assert.Equal(t, "virt,gic-version=3", argAfter(t, args, "-machine"))
	assert.Equal(t, "cortex-a72", argAfter(t, args, "-cpu"))
}

func TestBuildQEMUCommand_X86OnForeignHostUsesTCG(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.x86Config()
	cfg.HostArch = "arm64"

	args := buildArgs(t, cfg, BootModeBoot)
	assert.NotContains(t, args, "-enable-kvm")
	assert.Equal(t, "max", argAfter(t, args, "-cpu"))
}

// An arm64 host with KVM turned off runs TCG, which cannot take
// gic-version=host: the fixed GICv3 stays, whatever the host's GIC is.
func TestBuildQEMUCommand_AArch64KVMDisabledKeepsTheFixedGIC(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64UEFIConfig()
	cfg.EnableKVM = false

	args := buildArgs(t, cfg, BootModeBoot)
	assert.NotContains(t, args, "-enable-kvm")
	assert.Equal(t, "virt,gic-version=3", argAfter(t, args, "-machine"))
	assert.Equal(t, "cortex-a72", argAfter(t, args, "-cpu"))
}

func TestConfigValidate_AArch64UEFIRequiresTheVarsTemplate(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64UEFIConfig()
	cfg.OVMFVars = f.path("no-such-VARS.fd")

	assert.ErrorIs(t, cfg.Validate(), ErrOVMFNotFound)
}

func TestInitializeNVRAM_AArch64UEFICopiesTheVarsPerInstance(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.aarch64UEFIConfig()
	cfg.WorkDir = filepath.Join(f.dir, "aarch64-work")
	template := []byte("AAVMF vars template")
	require.NoError(t, os.WriteFile(cfg.OVMFVars, template, 0o644))
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, vm.initializeNVRAM())

	got, err := os.ReadFile(cfg.GetNVRAMPath())
	require.NoError(t, err)
	assert.Equal(t, template, got)
	assert.NotEqual(t, cfg.OVMFVars, cfg.GetNVRAMPath(), "the template itself is never written")
}

// A qcow2 NVRAM is converted from the raw vars template and attached as
// qcow2, so savevm finds no writable drive that cannot hold a snapshot.
func TestInitializeNVRAM_QCOW2ConvertsTheVarsTemplate(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.x86Config()
	cfg.WorkDir = filepath.Join(f.dir, "qcow2-work")
	cfg.NVRAMFormat = DiskFormatQCOW2
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)
	var converted []string
	vm.convertImage = func(src, format, dst string) ([]byte, error) {
		converted = []string{src, format, dst}
		return nil, os.WriteFile(dst, []byte("qcow2 vars"), 0o644)
	}

	require.NoError(t, vm.initializeNVRAM())

	nvram := filepath.Join(cfg.WorkDir, "nvram", "OVMF_VARS.qcow2")
	assert.Equal(t, []string{cfg.OVMFVars, DiskFormatQCOW2, nvram}, converted)
	assert.Contains(t, buildArgs(t, cfg, BootModeBoot), "if=pflash,unit=1,format=qcow2,file="+nvram)
}

func TestInitializeNVRAM_QCOW2ConversionFailureLeavesNoNVRAM(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.x86Config()
	cfg.WorkDir = filepath.Join(f.dir, "qcow2-work")
	cfg.NVRAMFormat = DiskFormatQCOW2
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)
	vm.convertImage = func(_, _, dst string) ([]byte, error) {
		if err := os.WriteFile(dst, []byte("partial"), 0o644); err != nil {
			return nil, err
		}
		return []byte("qemu-img: write failed"), &MessageError{Msg: "exit status 1"}
	}

	err = vm.initializeNVRAM()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "qemu-img: write failed")
	_, statErr := os.Stat(cfg.GetNVRAMPath())
	assert.True(t, os.IsNotExist(statErr), "a failed conversion must not leave an NVRAM the next start would reuse")
}

// qcow2NVRAMVM is a qcow2-NVRAM VM whose work directory already holds the raw
// NVRAM a VM created before the qcow2 default persisted.
func qcow2NVRAMVM(t *testing.T, raw []byte) (*VM, *Config) {
	t.Helper()
	f := newArchFixture(t)
	cfg := f.x86Config()
	cfg.WorkDir = filepath.Join(f.dir, "existing-work")
	cfg.NVRAMFormat = DiskFormatQCOW2
	require.NoError(t, os.WriteFile(cfg.OVMFVars, []byte("pristine template"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.WorkDir, "nvram"), 0o755))
	require.NoError(t, os.WriteFile(cfg.rawNVRAMPath(), raw, 0o644))
	vm, err := NewVM(cfg, nil)
	require.NoError(t, err)
	return vm, cfg
}

func TestInitializeNVRAM_QCOW2ConvertsTheExistingRawNVRAM(t *testing.T) {
	raw := []byte("boot entries and enrolled PK/KEK/db")
	vm, cfg := qcow2NVRAMVM(t, raw)
	var source string
	vm.convertImage = func(src, _, dst string) ([]byte, error) {
		source = src
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(dst, data, 0o644)
	}

	require.NoError(t, vm.initializeNVRAM())

	assert.Equal(t, cfg.rawNVRAMPath(), source, "the guest's own NVRAM is the source, not the template")
	got, err := os.ReadFile(cfg.GetNVRAMPath())
	require.NoError(t, err)
	assert.Equal(t, raw, got)
	kept, err := os.ReadFile(cfg.rawNVRAMPath())
	require.NoError(t, err)
	assert.Equal(t, raw, kept, "the raw NVRAM is kept")
}

func TestInitializeNVRAM_QCOW2ReusesTheExistingQCOW2(t *testing.T) {
	vm, cfg := qcow2NVRAMVM(t, []byte("stale raw"))
	existing := []byte("qcow2 vars in use")
	require.NoError(t, os.WriteFile(cfg.GetNVRAMPath(), existing, 0o644))
	vm.convertImage = func(src, _, _ string) ([]byte, error) {
		t.Errorf("an existing qcow2 NVRAM must not be converted again (source %s)", src)
		return nil, nil
	}

	require.NoError(t, vm.initializeNVRAM())

	got, err := os.ReadFile(cfg.GetNVRAMPath())
	require.NoError(t, err)
	assert.Equal(t, existing, got)
}

func TestInitializeNVRAM_QCOW2RawConversionFailureKeepsTheRawNVRAM(t *testing.T) {
	raw := []byte("boot entries and enrolled PK/KEK/db")
	vm, cfg := qcow2NVRAMVM(t, raw)
	vm.convertImage = func(_, _, dst string) ([]byte, error) {
		if err := os.WriteFile(dst, []byte("partial"), 0o644); err != nil {
			return nil, err
		}
		return []byte("qemu-img: write failed"), &MessageError{Msg: "exit status 1"}
	}

	err := vm.initializeNVRAM()

	var cmdErr *CommandOutputError
	require.ErrorAs(t, err, &cmdErr)
	assert.Contains(t, err.Error(), "the existing raw NVRAM")
	_, statErr := os.Stat(cfg.GetNVRAMPath())
	assert.True(t, os.IsNotExist(statErr), "no partial qcow2 is left for the next start to reuse")
	kept, readErr := os.ReadFile(cfg.rawNVRAMPath())
	require.NoError(t, readErr)
	assert.Equal(t, raw, kept, "a failed conversion leaves the raw NVRAM untouched")
}

func TestConfigValidate_NVRAMFormat(t *testing.T) {
	f := newArchFixture(t)
	cfg := f.x86Config()
	assert.Equal(t, f.path("nvram/OVMF_VARS.fd"), cfg.GetNVRAMPath(), "raw stays the default")

	cfg.NVRAMFormat = "vmdk"
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidConfiguration)
}

func TestConfigKVM_FollowsTheInjectedHostArch(t *testing.T) {
	cases := []struct {
		arch     Arch
		hostArch string
		want     bool
	}{
		{ArchX86_64, "amd64", true},
		{ArchX86_64, "arm64", false},
		{ArchAArch64, "arm64", true},
		{ArchAArch64, "amd64", false},
	}
	for _, tc := range cases {
		t.Run(string(tc.arch)+"-on-"+tc.hostArch, func(t *testing.T) {
			probed := false
			probe := func() error { probed = true; return nil }
			cfg := &Config{Arch: tc.arch, HostArch: tc.hostArch, EnableKVM: true, KVMProbe: probe}
			p, err := cfg.profile()
			require.NoError(t, err)
			kvm, err := cfg.kvm(p)
			require.NoError(t, err)
			assert.Equal(t, tc.want, kvm)
			assert.Equal(t, tc.want, probed, "only a native guest probes the KVM device")
		})
	}
}

func TestConfigKVM_NotRequestedNeverProbes(t *testing.T) {
	probe := func() error {
		t.Fatal("the KVM device was probed although KVM was not requested")
		return nil
	}
	cfg := &Config{HostArch: "amd64", EnableKVM: false, KVMProbe: probe}
	p, err := cfg.profile()
	require.NoError(t, err)
	kvm, err := cfg.kvm(p)
	require.NoError(t, err)
	assert.False(t, kvm)
}

func TestConfigKVM_UnusableDeviceFallsBackToTCG(t *testing.T) {
	cfg := &Config{HostArch: "amd64", EnableKVM: true, KVMProbe: kvmMissing}
	p, err := cfg.profile()
	require.NoError(t, err)
	kvm, err := cfg.kvm(p)
	assert.False(t, kvm)
	assert.ErrorIs(t, err, ErrKVMUnavailable)
	assert.ErrorIs(t, err, fs.ErrNotExist, "the reason names the open failure")
}

func TestBuildQEMUCommand_UnusableKVMRunsTCG(t *testing.T) {
	f := newArchFixture(t)

	t.Run("x86_64", func(t *testing.T) {
		cfg := f.x86Config()
		cfg.KVMProbe = kvmMissing
		args := buildArgs(t, cfg, BootModeBoot)
		assert.NotContains(t, args, "-enable-kvm")
		assert.Equal(t, "q35", argAfter(t, args, "-machine"))
		assert.Equal(t, "max", argAfter(t, args, "-cpu"), "TCG cannot take -cpu host")
	})

	t.Run("aarch64 on arm64", func(t *testing.T) {
		cfg := f.aarch64UEFIConfig()
		cfg.KVMProbe = kvmMissing
		args := buildArgs(t, cfg, BootModeBoot)
		assert.NotContains(t, args, "-enable-kvm")
		assert.Equal(t, "virt,gic-version=3", argAfter(t, args, "-machine"))
		assert.Equal(t, "cortex-a72", argAfter(t, args, "-cpu"))
	})
}

func TestProbeDeviceRW(t *testing.T) {
	t.Run("a read-write device is usable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kvm")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		assert.NoError(t, probeDeviceRW(path))
	})

	t.Run("a missing device is unusable", func(t *testing.T) {
		err := probeDeviceRW(filepath.Join(t.TempDir(), "kvm"))
		assert.ErrorIs(t, err, ErrKVMUnavailable)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("a directory cannot be opened read-write", func(t *testing.T) {
		assert.ErrorIs(t, probeDeviceRW(t.TempDir()), ErrKVMUnavailable)
	})
}

// argAfter returns the value that follows flag in args.
func argAfter(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i, a := range args[:len(args)-1] {
		if a == flag {
			return args[i+1]
		}
	}
	t.Fatalf("%s not in %v", flag, args)
	return ""
}
