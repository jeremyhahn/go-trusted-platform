package uki

import "runtime"

// stubPaths maps each architecture to the systemd-stub file Alpine's
// systemd-efistub package installs for it.
var stubPaths = map[Architecture]string{
	ArchX86_64:  DefaultStubPath,
	ArchAArch64: "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
	ArchARM:     "/usr/lib/systemd/boot/efi/linuxarm.efi.stub",
	ArchRISCV64: "/usr/lib/systemd/boot/efi/linuxriscv64.efi.stub",
}

// bootFileNames maps each architecture to the UEFI removable-media boot file
// name (UEFI specification §3.5.1.1) that firmware loads from EFI/BOOT.
var bootFileNames = map[Architecture]string{
	ArchX86_64:  "BOOTX64.EFI",
	ArchAArch64: "BOOTAA64.EFI",
	ArchARM:     "BOOTARM.EFI",
	ArchRISCV64: "BOOTRISCV64.EFI",
}

// goArchNames maps GOARCH values and common aliases onto Architecture.
var goArchNames = map[string]Architecture{
	"amd64":   ArchX86_64,
	"x86_64":  ArchX86_64,
	"arm64":   ArchAArch64,
	"aarch64": ArchAArch64,
	"arm":     ArchARM,
	"riscv64": ArchRISCV64,
}

// StubPath returns the systemd-stub location for arch.
func StubPath(arch Architecture) (string, error) {
	path, ok := stubPaths[arch]
	if !ok {
		return "", &UnsupportedArchitectureError{Arch: string(arch)}
	}
	return path, nil
}

// BootFileName returns the UEFI removable-media boot file name for arch, the
// file the installer writes the unified kernel image to under EFI/BOOT.
func BootFileName(arch Architecture) (string, error) {
	name, ok := bootFileNames[arch]
	if !ok {
		return "", &UnsupportedArchitectureError{Arch: string(arch)}
	}
	return name, nil
}

// ParseArchitecture accepts an Architecture name or its GOARCH alias
// ("amd64", "arm64") and returns the canonical Architecture. The empty
// string means the historical default, x86_64.
func ParseArchitecture(name string) (Architecture, error) {
	if name == "" {
		return ArchX86_64, nil
	}
	arch, ok := goArchNames[name]
	if !ok {
		return "", &UnsupportedArchitectureError{Arch: name}
	}
	return arch, nil
}

// HostArchitecture returns the Architecture of the running binary.
func HostArchitecture() Architecture {
	arch, ok := goArchNames[runtime.GOARCH]
	if !ok {
		return ArchX86_64
	}
	return arch
}
