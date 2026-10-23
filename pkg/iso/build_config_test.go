package iso

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v2"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func writePlatformConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "platform.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEnsureSecureBootKeysDecisions asserts the Step-3 gate: local key
// generation never runs for a platform config whose finalized secure-boot
// db reference is remote/KMS, Secure Boot off or generation off never
// generates, and media-signing / config-less builds do.
func TestEnsureSecureBootKeysDecisions(t *testing.T) {
	ctx := context.Background()
	logger := logging.DefaultLogger()

	if d, err := EnsureSecureBootKeys(ctx, logger, &ISOBuildConfig{SecureBoot: false, GenerateKeys: true}); err != nil || d != SecureBootKeysDisabled {
		t.Errorf("secure boot off: %s, %v", d, err)
	}
	if d, err := EnsureSecureBootKeys(ctx, logger, &ISOBuildConfig{SecureBoot: true, GenerateKeys: false}); err != nil || d != SecureBootKeysNotRequested {
		t.Errorf("generation off: %s, %v", d, err)
	}
	remote := writePlatformConfig(t, "secure-boot:\n  enabled: true\n  db: { key-uri: \"kms://platform/secureboot/db\", cert-uri: \"kms://platform/secureboot/db-cert\" }\n")
	if d, err := EnsureSecureBootKeys(ctx, logger, &ISOBuildConfig{SecureBoot: true, GenerateKeys: true, PlatformConfigFile: remote, KeysDir: t.TempDir()}); err != nil || d != SecureBootKeysRemote {
		t.Errorf("remote db ref: %s, %v (a remote/KMS db ref must never trigger local key generation)", d, err)
	}
	bad := writePlatformConfig(t, "secure-boot:\n  enabled: true\n  db: { key-uri: \"https://example/db\", cert-uri: \"https://example/db-cert\" }\n")
	if _, err := EnsureSecureBootKeys(ctx, logger, &ISOBuildConfig{SecureBoot: true, GenerateKeys: true, PlatformConfigFile: bad}); err == nil {
		t.Error("unresolvable db ref did not error")
	}
	if _, err := EnsureSecureBootKeys(ctx, logger, &ISOBuildConfig{SecureBoot: true, GenerateKeys: true, PlatformConfigFile: filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Error("missing config file did not error")
	}
}

func TestEnsureSecureBootKeysGeneratesThenReuses(t *testing.T) {
	ctx := context.Background()
	logger := logging.DefaultLogger()
	media := writePlatformConfig(t, "secure-boot:\n  enabled: true\n  db: { key-uri: \"file:///media/cdrom/secure-boot-keys/DB.key\", cert-uri: \"file:///media/cdrom/secure-boot-keys/DB.crt\" }\n")
	cfg := &ISOBuildConfig{SecureBoot: true, GenerateKeys: true, PlatformConfigFile: media, WorkDir: t.TempDir()}
	d, err := EnsureSecureBootKeys(ctx, logger, cfg)
	if err != nil || d != SecureBootKeysGenerated {
		t.Fatalf("first call: %s, %v", d, err)
	}
	if cfg.KeysDir != filepath.Join(cfg.WorkDir, "secure-boot-keys") {
		t.Errorf("KeysDir = %q", cfg.KeysDir)
	}
	for _, name := range []string{"PK.crt", "KEK.crt", "DB.crt", "DB.key"} {
		if _, err := os.Stat(filepath.Join(cfg.KeysDir, name)); err != nil {
			t.Errorf("%s not generated: %v", name, err)
		}
	}
	d, err = EnsureSecureBootKeys(ctx, logger, cfg)
	if err != nil || d != SecureBootKeysExisting {
		t.Errorf("second call: %s, %v", d, err)
	}
}

func TestNewPlatformISOConfigCarriesEveryField(t *testing.T) {
	build := &ISOBuildConfig{
		AlpineVersion: "3.22.2", AlpineMirror: "http://m", APKMirror: "http://apk", Architecture: "arm64", PlatformVersion: "9.9.9",
		KeysDir: "/keys", PlatformdBinary: "/bin/platformd", PlatformConfigFile: "/cfg.yaml", CABundlePath: "/ca.pem",
		CAKeyAlgorithm: "ecdsa", WebUIPath: "/web", PlatformType: PlatformTypeServer, ConfigServerURL: "https://cs",
		BootstrapStrategy: "dane", BootstrapDNS: "1.1.1.1", BootstrapNoiseKey: "ab", BootstrapSPKIPin: "cd",
		SecureBoot: true, TPMAutoUnseal: true, TPMAutoUpgradeSeal: true, FIPS: false, Lockdown: true,
		EnableFIDO2: true, LUKSTPMOnly: true, RootFS: "lvm", Debug: true, PreFetch: true, OutputLabel: "TP",
	}
	cfg := NewPlatformISOConfig(build, "/work")
	if cfg.Alpine.Architecture != "aarch64" || cfg.Alpine.Version != "3.22.2" || cfg.Alpine.APKMirror != "http://apk" {
		t.Errorf("Alpine = %+v", cfg.Alpine)
	}
	if cfg.Directories.Work != "/work" || cfg.Directories.ISO != "/work/iso" || cfg.Directories.Overlay != "/work/overlay" || cfg.Directories.Keys != "/keys" {
		t.Errorf("Directories = %+v", cfg.Directories)
	}
	if cfg.Platform.Version != "9.9.9" || cfg.Platform.PlatformdBinary != "/bin/platformd" || cfg.Platform.ConfigFile != "/cfg.yaml" || cfg.Platform.BootstrapSPKIPin != "cd" || cfg.Platform.ObjcopyBinary != "objcopy" {
		t.Errorf("Platform = %+v", cfg.Platform)
	}
	if !cfg.Security.SecureBoot || !cfg.Security.TPM.AutoUnseal || !cfg.Security.TPM.AutoUpgradeSeal || !cfg.Security.Lockdown || !cfg.Security.EnableFIDO2 {
		t.Errorf("Security = %+v", cfg.Security)
	}
	if !cfg.LUKS.Enabled || !cfg.LUKS.TPMOnly || cfg.RootFS.Type != "lvm" || !cfg.Build.Debug || !cfg.Build.PreFetch || cfg.Output.Label != "TP" {
		t.Errorf("LUKS/RootFS/Build/Output = %+v %+v %+v %+v", cfg.LUKS, cfg.RootFS, cfg.Build, cfg.Output)
	}
}

func TestApplyInstallerOverridesBakesTargetSettings(t *testing.T) {
	template := "os:\n  architecture: x86_64\n  hostname: node\ndisk:\n  device: \"\"\n  partition-table: gpt\nseal-pcrs: [0, 7, 9]\n"
	// No overrides: the x86_64 template keeps its values.
	plain := validPlatformISOConfig()
	plain.SetDefaults()
	out, err := NewCustomizer(plain, logging.DefaultLogger()).applyInstallerOverrides([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"architecture: x86_64", "partition-table: gpt", "hostname: node"} {
		if !contains1(string(out), want) {
			t.Errorf("plain output lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"kernel-package", "kernel-artifacts-dir", "install-target", "boot:", "hardware-manufacturer"} {
		if contains1(string(out), bad) {
			t.Errorf("plain output gained %q:\n%s", bad, out)
		}
	}

	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "arm64"
	cfg.SetDefaults()
	cfg.Installer = InstallerOverrides{Device: "/dev/mmcblk0", PartitionTable: "mbr", KernelPackage: "linux-rpi",
		HardwareManufacturer: "Raspberry Pi", HardwareModel: "Raspberry Pi 4 Model B", Target: "image", BootFirmware: "uboot"}
	out, err = NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"architecture: aarch64", "kernel-package: linux-rpi", "device: /dev/mmcblk0", "partition-table: mbr",
		"hardware-manufacturer: Raspberry Pi", "hardware-model: Raspberry Pi 4 Model B", "install-target: image", "firmware: uboot", "seal-pcrs:"} {
		if !contains1(string(out), want) {
			t.Errorf("override output lacks %q:\n%s", want, out)
		}
	}
	// A platform-built kernel names its media directory beside the flavour.
	virt := validPlatformISOConfig()
	virt.Alpine.Architecture = "aarch64"
	virt.SetDefaults()
	virt.Installer = InstallerOverrides{KernelPackage: "linux-virt", KernelArtifactsDir: "/media/cdrom/kernel-artifacts/virt"}
	out, err = NewCustomizer(virt, logging.DefaultLogger()).applyInstallerOverrides([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kernel-package: linux-virt", "kernel-artifacts-dir: /media/cdrom/kernel-artifacts/virt"} {
		if !contains1(string(out), want) {
			t.Errorf("built-kernel output lacks %q:\n%s", want, out)
		}
	}

	// A template without os:/disk:/boot: sections gets them created.
	out, err = NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte("seal-pcrs: [0]\n"))
	if err != nil || !contains1(string(out), "architecture: aarch64") || !contains1(string(out), "firmware: uboot") {
		t.Errorf("sections not created: %s, %v", out, err)
	}
	if _, err := NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte("[not yaml")); err == nil {
		t.Error("malformed YAML accepted")
	}
	var wrapped *WrappedError
	_, err = NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte(": : :"))
	if err != nil && !errors.As(err, &wrapped) {
		t.Errorf("error type %T", err)
	}
}

// bakedOSLists reads os.packages and os.services back out of a baked
// installer.yaml: the lists the installer installs and enables.
func bakedOSLists(t *testing.T, out []byte) (packages, services []string) {
	t.Helper()
	var doc struct {
		OS struct {
			Packages []string `yaml:"packages"`
			Services []string `yaml:"services"`
		} `yaml:"os"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("baked config does not parse: %v\n%s", err, out)
	}
	return doc.OS.Packages, doc.OS.Services
}

// TestApplyInstallerOverridesInstallsWhatTheMediaPrefetches pins the baked
// installer.yaml, the file the installer installs from on the ISO and the
// factory-image paths alike, to what the media prefetches for the installed
// system. A package that is prefetched but missing from os.packages never
// reaches the node: the Raspberry Pi token stack and pcscd (#689), the
// gateway's Jool translator (#603).
func TestApplyInstallerOverridesInstallsWhatTheMediaPrefetches(t *testing.T) {
	bake := func(t *testing.T, cfg *PlatformISOConfig, template string) []byte {
		t.Helper()
		out, err := NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte(template))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("raspberry pi token stack", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.Alpine.Architecture = "arm64"
		cfg.SetDefaults()
		cfg.Installer = InstallerOverrides{
			KernelPackage: "linux-rpi",
			ExtraPackages: []string{"raspberrypi-bootloader", "pcsc-lite", "pcsc-lite-openrc", "ccid", "opensc", "yubico-piv-tool-libs"},
			ExtraServices: []string{"pcscd"},
		}
		template := "os:\n  packages: [tpm2-tools, ccid]\n  services: [chronyd]\nseal-pcrs: [0, 7, 9]\n"
		packages, services := bakedOSLists(t, bake(t, cfg, template))
		// The template's own entries keep their place; ccid is not repeated.
		want := []string{"tpm2-tools", "ccid", "raspberrypi-bootloader", "pcsc-lite", "pcsc-lite-openrc", "opensc", "yubico-piv-tool-libs"}
		if !slices.Equal(packages, want) {
			t.Errorf("os.packages = %v, want %v", packages, want)
		}
		if !slices.Equal(services, []string{"chronyd", "pcscd"}) {
			t.Errorf("os.services = %v, want [chronyd pcscd]", services)
		}
	})

	t.Run("platform apk dir", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.SetDefaults()
		cfg.Installer = InstallerOverrides{PlatformAPKDir: "/builder/output"}
		packages, _ := bakedOSLists(t, bake(t, cfg, "seal-pcrs: [0]\n"))
		if !slices.Equal(packages, PlatformPackages()) {
			t.Errorf("os.packages = %v, want the IPsec transport %v", packages, PlatformPackages())
		}
	})

	gateway := writePlatformConfig(t, "gateway:\n  enabled: true\n")
	for _, tc := range []struct {
		name          string
		fips          bool
		kernel        string
		kernelBuiltAt string
		jool          bool
	}{
		{name: "gateway on the stock kernel", jool: true},
		{name: "gateway on a FIPS kernel", fips: true},
		{name: "gateway on another kernel", kernel: "linux-virt"},
		{name: "gateway on a platform-built kernel", kernelBuiltAt: "/media/cdrom/kernel-artifacts/lts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validPlatformISOConfig()
			cfg.SetDefaults()
			cfg.Platform.ConfigFile = gateway
			cfg.Security.FIPS = tc.fips
			cfg.Installer = InstallerOverrides{KernelPackage: tc.kernel, KernelArtifactsDir: tc.kernelBuiltAt}
			packages, _ := bakedOSLists(t, bake(t, cfg, "seal-pcrs: [0]\n"))

			prefetch, err := NewCustomizer(cfg, logging.DefaultLogger()).preFetchConfig()
			if err != nil {
				t.Fatal(err)
			}
			prefetched := CollectRequiredPackages(prefetch)
			for _, pkg := range tpconfig.GatewaydPackages {
				if got := slices.Contains(packages, pkg); got != tc.jool {
					t.Errorf("%s installed = %v, want %v: %v", pkg, got, tc.jool, packages)
				}
				if got := slices.Contains(prefetched, pkg); got != tc.jool {
					t.Errorf("%s prefetched = %v, want %v", pkg, got, tc.jool)
				}
			}
		})
	}

	t.Run("a gateway template that lists jool keeps one entry", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.SetDefaults()
		cfg.Platform.ConfigFile = gateway
		packages, _ := bakedOSLists(t, bake(t, cfg, "os:\n  packages: [jool-tools, vim]\n"))
		want := []string{"jool-tools", "vim", "jool-modules-lts", "jool-tools-openrc"}
		if !slices.Equal(packages, want) {
			t.Errorf("os.packages = %v, want %v", packages, want)
		}
	})

	t.Run("nothing to install leaves the template alone", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.SetDefaults()
		out := bake(t, cfg, "os:\n  hostname: node\n")
		if contains1(string(out), "packages:") || contains1(string(out), "services:") {
			t.Errorf("empty lists were added:\n%s", out)
		}
	})

	t.Run("os.packages that is not a list is refused", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.SetDefaults()
		cfg.Installer = InstallerOverrides{ExtraPackages: []string{"pcsc-lite"}}
		_, err := NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte("os:\n  packages: pcsc-lite\n"))
		var notList *InstallerListError
		if !errors.As(err, &notList) || notList.Key != "packages" {
			t.Errorf("error = %v (%T), want *InstallerListError for packages", err, err)
		}
	})

	t.Run("an unreadable bundled config fails the bake", func(t *testing.T) {
		cfg := validPlatformISOConfig()
		cfg.SetDefaults()
		cfg.Platform.ConfigFile = filepath.Join(t.TempDir(), "missing.yaml")
		if _, err := NewCustomizer(cfg, logging.DefaultLogger()).applyInstallerOverrides([]byte("seal-pcrs: [0]\n")); err == nil {
			t.Error("a bundled config that cannot be read was baked without its gateway decision")
		}
	})
}

func contains1(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestReadVersionFile(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if v := ReadVersionFile(); v != "dev" {
		t.Errorf("without VERSION: %q", v)
	}
	if err := os.WriteFile(VersionFileName, []byte("  1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := ReadVersionFile(); v != "1.2.3" {
		t.Errorf("with VERSION: %q", v)
	}
	if err := os.WriteFile(VersionFileName, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := ReadVersionFile(); v != "dev" {
		t.Errorf("with empty VERSION: %q", v)
	}
}
