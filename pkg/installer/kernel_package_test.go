package installer

import (
	"testing"
)

func TestAlpineInstallerKernelPackage(t *testing.T) {
	logger := createTestLogger()

	inst, err := newAlpineInstaller(logger, &OSConfig{OS: OSAlpine, Version: "3.22"})
	if err != nil {
		t.Fatal(err)
	}
	if got := inst.(*alpineInstaller).kernelPackage(); got != "linux-lts" {
		t.Errorf("default kernelPackage() = %q, want linux-lts", got)
	}

	inst, err = newAlpineInstaller(logger, &OSConfig{OS: OSAlpine, Version: "3.22", Architecture: "aarch64", KernelPackage: "linux-rpi"})
	if err != nil {
		t.Fatal(err)
	}
	if got := inst.(*alpineInstaller).kernelPackage(); got != "linux-rpi" {
		t.Errorf("kernelPackage() = %q, want linux-rpi", got)
	}
}
