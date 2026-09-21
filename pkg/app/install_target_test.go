package app

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"gopkg.in/yaml.v2"
)

func TestGetInstallerConfigCarriesTargetAndBoot(t *testing.T) {
	var a App
	if err := yaml.Unmarshal([]byte(`
install-target: image
boot:
  firmware: uboot
  firmware-stage-dir: /media/cdrom/boot-firmware
os:
  architecture: aarch64
  kernel-package: linux-rpi
disk:
  device: /dev/mmcblk0
  partition-table: mbr
hardware-manufacturer: Raspberry Pi
hardware-model: Raspberry Pi 4 Model B
`), &a); err != nil {
		t.Fatal(err)
	}
	cfg := a.GetInstallerConfig()
	if cfg.Target != installer.InstallTargetImage {
		t.Errorf("Target = %q", cfg.Target)
	}
	if cfg.Boot == nil || cfg.Boot.Firmware != installer.BootFirmwareUBoot || cfg.Boot.FirmwareStageDir != "/media/cdrom/boot-firmware" {
		t.Errorf("Boot = %+v", cfg.Boot)
	}
	if cfg.OS.Architecture != "aarch64" || cfg.OS.KernelPackage != "linux-rpi" {
		t.Errorf("OS = %+v", cfg.OS)
	}
	if cfg.Disk.Device != "/dev/mmcblk0" || cfg.Disk.PartitionTable != installer.PartitionTableMBR {
		t.Errorf("Disk = %+v", cfg.Disk)
	}
	if cfg.HardwareManufacturer != "Raspberry Pi" {
		t.Errorf("HardwareManufacturer = %q", cfg.HardwareManufacturer)
	}

	// A platform config without the keys yields the historical defaults.
	empty := (&App{OSConfig: &installer.OSConfig{}, DiskConfig: &installer.DiskConfig{Device: "/dev/sda"}}).GetInstallerConfig()
	if empty.Target != "" || empty.Boot != nil {
		t.Errorf("defaults changed: target=%q boot=%+v", empty.Target, empty.Boot)
	}
}
