// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package container

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testDataDir lays out a container data directory: the named media sets
// under media/, as a netboot media build stages them.
func testDataDir(t *testing.T, sets ...MediaSet) string {
	t.Helper()
	dataDir := t.TempDir()
	write := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// payload writes a set's payload list for the files the installer
	// fetches, destination to source.
	payload := func(dir string, files map[string]string) {
		t.Helper()
		var entries []PayloadEntry
		for dest, src := range files {
			write(filepath.Join(dir, src), "content of "+src+" for "+dir)
			sum, err := artifacts.FileSHA256(filepath.Join(dir, src))
			if err != nil {
				t.Fatal(err)
			}
			entries = append(entries, PayloadEntry{SHA256: sum, Kind: PayloadFile, Dest: dest, Src: src})
		}
		f, err := os.Create(filepath.Join(dir, PayloadListName))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := WritePayloadList(f, entries); err != nil {
			t.Fatal(err)
		}
	}
	for _, set := range sets {
		dir := filepath.Join(dataDir, "media", set.Name)
		for _, f := range []string{set.Kernel, set.Initrd, set.Modloop} {
			write(filepath.Join(dir, f), f)
		}
		files := map[string]string{InstallerEntryPoint: "cdrom/platformd-bin/platformctl"}
		if set.Diskless {
			write(filepath.Join(dir, disklessroot.RootFSFile), "squashfs")
			write(filepath.Join(dir, disklessroot.VerityFile), "hash tree")
			for _, name := range []string{disklessroot.ManifestFile, disklessroot.SignatureFile} {
				files[disklessroot.Dir+"/"+name] = "cdrom/" + disklessroot.Dir + "/" + name
			}
		}
		data, err := yaml.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(dir, MediaSetDescriptor), string(data))
		payload(dir, files)
	}
	return dataDir
}

// x86Set is the x86_64 installer set, x86_64's default.
func x86Set() MediaSet {
	return MediaSet{
		Name: MediaSetX86_64, Architecture: "x86_64", Default: true,
		Kernel: "vmlinuz-lts", Initrd: "initramfs-lts", Modloop: "modloop-lts",
		KernelArgs: "modules=loop,squashfs,igb,af_packet console=ttyS0,115200n8",
	}
}

// piSet is the aarch64 Raspberry Pi media set as the build writes it.
func piSet() MediaSet {
	return MediaSet{
		Name: "aarch64-rpi", Architecture: "arm64",
		Kernel: "vmlinuz-rpi", Initrd: "initramfs-rpi", Modloop: "modloop-rpi",
		KernelArgs: "modules=loop,squashfs,sd-mod,genet,af_packet console=ttyAMA0,115200 console=tty1",
	}
}

// virtSet is the aarch64 set for the QEMU virt stand-in, arm64's default.
func virtSet() MediaSet {
	return MediaSet{
		Name: "aarch64-virt", Architecture: "arm64", Default: true,
		Kernel: "vmlinuz-virt", Initrd: "initramfs-virt", Modloop: "modloop-virt",
		KernelArgs: "modules=loop,squashfs,virtio_net,af_packet console=ttyAMA0,115200",
	}
}

const testManifest = `nodes:
  - mac: "aa:bb:cc:dd:ee:01"
    role: "control-plane"
    hostname: "cp-01"
  - mac: "dc:a6:32:01:36:c2"
    role: "worker"
    hostname: "pi-01"
    architecture: "arm64"
    media_set: "aarch64-rpi"
  - mac: "52:54:00:12:34:56"
    role: "worker"
    hostname: "arm-01"
    architecture: "arm64"
`

// newTestContainer builds a container server the way pxeboot does,
// against a temporary data directory holding the x86_64 set and sets.
func newTestContainer(t *testing.T, manifest string, sets ...MediaSet) (*Server, error) {
	t.Helper()
	dataDir := testDataDir(t, append([]MediaSet{x86Set()}, sets...)...)
	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &ServerConfig{
		Interface:    "lo",
		ManifestPath: manifestPath,
		DataDir:      dataDir,
		MediaDir:     filepath.Join(dataDir, "media"),
		HTTPPort:     8080,
		DHCPConfig: DHCPConfig{
			ServerIP: "192.168.1.1", RangeStart: "192.168.1.100", RangeEnd: "192.168.1.200", SubnetMask: "255.255.255.0",
		},
	}
	return NewServer(cfg, testLogger())
}

func deviceScript(t *testing.T, server *Server, path string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	server.HandleDeviceBootScript(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Result().StatusCode, w.Body.String()
}

func TestHandleDeviceBootScript_X86Node(t *testing.T) {
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)

	code, body := deviceScript(t, server, "/boot/device/aa:bb:cc:dd:ee:01.ipxe")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "kernel http://192.168.1.1:8080/data/media/x86_64/vmlinuz-lts ")
	assert.Contains(t, body, "initrd http://192.168.1.1:8080/data/media/x86_64/initramfs-lts")
	assert.Contains(t, body, "platform_role=control-plane")
	assert.Contains(t, body, "platform_hostname=cp-01")
	assert.Contains(t, body, "modloop=http://192.168.1.1:8080/data/media/x86_64/modloop-lts")
	assert.Contains(t, body, "platform_bin_url=http://192.168.1.1:8080/data/media/x86_64 ")
	assert.Contains(t, body, "console=ttyS0,115200n8", "the x86 flavour's consoles")
	assert.Contains(t, body, "iseq ${buildarch} x86_64 || iseq ${buildarch} i386 ||", "a BIOS-booted x86 server passes the guard")
	assert.Contains(t, body, ":boot_retry")
}

func TestHandleDeviceBootScript_RaspberryPiNodeBootsItsSet(t *testing.T) {
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)

	code, body := deviceScript(t, server, "/boot/device/dc-a6-32-01-36-c2.ipxe")
	require.Equal(t, http.StatusOK, code, "iPXE's dashed ${mac:hexhyp} resolves")
	assert.Contains(t, body, "kernel http://192.168.1.1:8080/data/media/aarch64-rpi/vmlinuz-rpi ")
	assert.Contains(t, body, "initrd http://192.168.1.1:8080/data/media/aarch64-rpi/initramfs-rpi")
	assert.Contains(t, body, "modloop=http://192.168.1.1:8080/data/media/aarch64-rpi/modloop-rpi")
	assert.Contains(t, body, "platform_bin_url=http://192.168.1.1:8080/data/media/aarch64-rpi ", "the set's own arm64 binaries")
	assert.Contains(t, body, "console=ttyAMA0,115200", "the Pi flavour's arguments")
	assert.NotContains(t, body, "ttyS0", "not the x86 flavour's")
	assert.Contains(t, body, "iseq ${buildarch} arm64 || chain /menu.ipxe")
	assert.Contains(t, body, "platform_hostname=pi-01")
}

func TestHandleDeviceBootScript_Arm64NodeWithoutASetBootsTheDefault(t *testing.T) {
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)
	code, body := deviceScript(t, server, "/boot/device/52:54:00:12:34:56.ipxe")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "/data/media/aarch64-virt/vmlinuz-virt ")
}

func TestHandleDeviceBootScript_UnknownDeviceChainsBootIPXE(t *testing.T) {
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)
	code, body := deviceScript(t, server, "/boot/device/00:00:00:00:00:00.ipxe")
	require.Equal(t, http.StatusOK, code, "the deploy gate's probe gets an iPXE script")
	assert.Equal(t, "#!ipxe\nchain http://192.168.1.1:8080/boot.ipxe\n", body, "the architecture picks the default there")
	assert.NotContains(t, body, "kernel ")
}

func TestHandleDeviceBootScript_MissingMAC(t *testing.T) {
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)
	code, _ := deviceScript(t, server, "/boot/device/")
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestDeviceBootInfo_MatchesTheIPXERoute(t *testing.T) {
	// The container's listener and the iPXE server's own route render one
	// script: the same lookup, the same generator.
	server, err := newTestContainer(t, testManifest, piSet(), virtSet())
	require.NoError(t, err)
	info, err := server.deviceBootInfo("dc:a6:32:01:36:c2")
	require.NoError(t, err)
	_, body := deviceScript(t, server, "/boot/device/dc:a6:32:01:36:c2.ipxe")
	assert.Equal(t, server.scriptGen.GenerateScript(info), body)

	_, err = server.deviceBootInfo("00:00:00:00:00:00")
	assert.ErrorIs(t, err, ipxe.ErrDeviceNotFound)
}

func TestNewServer_MediaSetsAreCheckedAgainstTheManifest(t *testing.T) {
	_, err := newTestContainer(t, testManifest, virtSet())
	var unknown ErrUnknownMediaSet
	require.ErrorAs(t, err, &unknown, "the Pi's set is not staged")
	assert.Equal(t, "aarch64-rpi", unknown.MediaSet)

	_, err = newTestContainer(t, testManifest, piSet())
	require.ErrorAs(t, err, &unknown, "arm64 has no default for arm-01")
	assert.Equal(t, "arm64", unknown.Architecture)

	_, err = newTestContainer(t, "nodes:\n  - mac: \"aa:bb:cc:dd:ee:01\"\n    role: worker\n    hostname: x\n")
	require.NoError(t, err, "an x86-only fleet needs only the x86_64 set")
}

func TestMediaSets_Rules(t *testing.T) {
	manifest := "nodes: []\n"

	server, err := newTestContainer(t, manifest)
	require.NoError(t, err)
	assert.Equal(t, MediaSetX86_64, server.defaults["x86_64"].Name)

	x86 := MediaSet{Name: "x86_64-new", Architecture: "x86_64", Default: true, Kernel: "k", Initrd: "i", Modloop: "m"}
	_, err = newTestContainer(t, manifest, x86)
	var setErr ErrMediaSet
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "both the x86_64 default")

	second := virtSet()
	second.Name = "aarch64-lts"
	_, err = newTestContainer(t, manifest, virtSet(), second)
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "both the arm64 default")

	bad := piSet()
	bad.Architecture = "riscv64"
	_, err = newTestContainer(t, manifest, bad)
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "architecture")
}

func TestNewServer_RequiresMediaSets(t *testing.T) {
	dataDir := t.TempDir()
	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte("nodes: []\n"), 0o644))
	_, err := NewServer(&ServerConfig{
		Interface: "lo", ManifestPath: manifestPath, DataDir: dataDir, MediaDir: filepath.Join(dataDir, "media"), HTTPPort: 8080,
		DHCPConfig: DHCPConfig{ServerIP: "192.168.1.1", RangeStart: "192.168.1.100", RangeEnd: "192.168.1.200", SubnetMask: "255.255.255.0"},
	}, testLogger())
	var setErr ErrMediaSet
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "holds no media set")
}

func TestLoadMediaSets_Validation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "media")
	sets, err := LoadMediaSets(root, "/data/media")
	require.NoError(t, err)
	assert.Empty(t, sets, "no media directory is no sets")

	dir := filepath.Join(root, "aarch64-rpi")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	write := func(set MediaSet) {
		data, err := yaml.Marshal(set)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, MediaSetDescriptor), data, 0o644))
	}
	var setErr ErrMediaSet

	write(piSet())
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr, "the kernel is not there")
	assert.Contains(t, setErr.Error(), "kernel vmlinuz-rpi is missing")

	for _, f := range []string{"vmlinuz-rpi", "initramfs-rpi", "modloop-rpi"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644))
	}
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr, "a set must say what its installer fetches")
	assert.Contains(t, setErr.Error(), "no payload list")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "platformctl"), []byte("arm64 platformctl"), 0o644))
	sum, err := artifacts.FileSHA256(filepath.Join(dir, "platformctl"))
	require.NoError(t, err)
	list := sum + " file platformd-bin/platformctl platformctl\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, PayloadListName), []byte(list), 0o644))
	sets, err = LoadMediaSets(root, "/data/media")
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, "/data/media/aarch64-rpi/vmlinuz-rpi", sets[0].url("", "vmlinuz-rpi"))

	renamed := piSet()
	renamed.Name = "other"
	write(renamed)
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "is not its directory's")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "platformctl"), []byte("changed after the list"), 0o644))
	write(piSet())
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr, "a payload that no longer matches its list")
	assert.Contains(t, setErr.Error(), "does not match")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "platformctl"), []byte("arm64 platformctl"), 0o644))

	escaping := piSet()
	escaping.Kernel = "../vmlinuz"
	write(escaping)
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "file name in the set's directory")

	require.NoError(t, os.WriteFile(filepath.Join(dir, MediaSetDescriptor), []byte("name: [unterminated"), 0o644))
	_, err = LoadMediaSets(root, "/data/media")
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "cannot parse")
}

func disklessVirtSet() MediaSet {
	set := virtSet()
	set.Diskless = true
	return set
}

func TestLoadMediaSets_DisklessRoot(t *testing.T) {
	dataDir := testDataDir(t, disklessVirtSet())
	sets, err := LoadMediaSets(filepath.Join(dataDir, "media"), "/data/media")
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.True(t, sets[0].Diskless)
	// The set's own arguments name no root: the root hash is in the signed
	// manifest alone, and a set is diskless only for a diskless node.
	args := sets[0].bootArgs(&ServerConfig{DHCPConfig: DHCPConfig{ServerIP: "192.168.1.1"}, HTTPPort: 8080, APKMirror: "https://dl-cdn.alpinelinux.org/alpine", AlpineVersion: "3.22"})
	for _, param := range []string{disklessroot.ParamBootModel, disklessroot.ParamRootHash, disklessroot.ParamRootFSURL, "roothash="} {
		assert.NotContains(t, args, param)
	}
}

func TestLoadMediaSets_DisklessRootValidation(t *testing.T) {
	var setErr ErrMediaSet
	dataDir := testDataDir(t, disklessVirtSet())
	setDir := filepath.Join(dataDir, "media", "aarch64-virt")
	require.NoError(t, os.Remove(filepath.Join(setDir, disklessroot.VerityFile)))
	_, err := LoadMediaSets(filepath.Join(dataDir, "media"), "/data/media")
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "verity "+disklessroot.VerityFile+" is missing")

	// A diskless set whose install media lacks the signed manifest could
	// only boot an unverified root.
	dataDir = testDataDir(t, virtSet())
	setDir = filepath.Join(dataDir, "media", "aarch64-virt")
	for _, f := range []string{disklessroot.RootFSFile, disklessroot.VerityFile} {
		require.NoError(t, os.WriteFile(filepath.Join(setDir, f), []byte(f), 0o644))
	}
	data, err := yaml.Marshal(disklessVirtSet())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(setDir, MediaSetDescriptor), data, 0o644))
	_, err = LoadMediaSets(filepath.Join(dataDir, "media"), "/data/media")
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), "provides no "+disklessroot.Dir+"/"+disklessroot.ManifestFile)
}

const disklessManifest = `nodes:
  - mac: "52:54:00:12:34:56"
    role: "worker"
    hostname: "arm-diskless"
    architecture: "arm64"
    boot_model: "diskless"
  - mac: "52:54:00:12:34:57"
    role: "worker"
    hostname: "arm-disk"
    architecture: "arm64"
`

func TestDeviceBootInfo_BootModelIsPerNode(t *testing.T) {
	server, err := newTestContainer(t, disklessManifest, disklessVirtSet())
	require.NoError(t, err)
	selector := disklessroot.ParamBootModel + "=" + disklessroot.BootModel

	info, err := server.deviceBootInfo("52:54:00:12:34:56")
	require.NoError(t, err)
	assert.Contains(t, info.ExtraKernelArgs[0], selector, "the diskless node is told its boot model")
	assert.NotContains(t, info.ExtraKernelArgs[0], disklessroot.ParamRootHash, "never the root, which nothing on this line signs")

	// The same set boots a disk node, which installs to its disk.
	info, err = server.deviceBootInfo("52:54:00:12:34:57")
	require.NoError(t, err)
	assert.NotContains(t, info.ExtraKernelArgs[0], selector)

	// The architecture's default entry, for machines the manifest does not
	// know, is never diskless.
	set := disklessVirtSet()
	assert.NotContains(t, set.bootEntry(server.config).Args, selector)
}

func TestDeviceBootInfo_DisklessNodeNeedsADisklessSet(t *testing.T) {
	server, err := newTestContainer(t, disklessManifest, virtSet())
	require.NoError(t, err)
	_, err = server.deviceBootInfo("52:54:00:12:34:56")
	var unavailable ErrDisklessUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "aarch64-virt", unavailable.MediaSet)
	assert.Contains(t, unavailable.Error(), "--diskless")

	code, _ := deviceScript(t, server, "/boot/device/52:54:00:12:34:56.ipxe")
	assert.NotEqual(t, http.StatusOK, code, "a diskless node is not sent to install onto a disk")
}

func TestNodeBootArgs_DisklessNBDNode(t *testing.T) {
	config := &ServerConfig{DHCPConfig: DHCPConfig{ServerIP: "192.168.1.1"}, HTTPPort: 8080, APKMirror: "https://dl-cdn.alpinelinux.org/alpine", AlpineVersion: "3.22"}
	config.ApplyDefaults()
	set := piSet()
	selector := disklessroot.ParamBootModel + "=" + nbd.BootModel
	server := nbd.ParamServer + "=192.168.1.1:10809"

	args, err := nodeBootArgs(&ManifestEntry{MAC: "dc:a6:32:01:36:c2", Hostname: "nbd-01", BootModel: nbd.BootModel}, set, config)
	require.NoError(t, err, "an NBD root needs no diskless root in the set")
	assert.True(t, strings.HasSuffix(args, " "+selector+" "+server), "the node is told its boot model and the export server's listener: %s", args)
	assert.Contains(t, args, "alpine_start=autoinstall", "it boots the set's installer, which installs onto the export")

	// No other boot model is told an NBD server.
	disklessSet := set
	disklessSet.Diskless = true
	for _, entry := range []ManifestEntry{
		{MAC: "dc:a6:32:01:36:c3", Hostname: "sd-01", BootModel: "sd"},
		{MAC: "dc:a6:32:01:36:c4", Hostname: "disk-01"},
		{MAC: "dc:a6:32:01:36:c5", Hostname: "diskless-01", BootModel: disklessroot.BootModel},
	} {
		args, err = nodeBootArgs(&entry, disklessSet, config)
		require.NoError(t, err)
		assert.NotContains(t, args, nbd.ParamServer, "a %q node attaches no export", entry.BootModel)
		assert.NotContains(t, args, selector)
	}
	args, err = nodeBootArgs(&ManifestEntry{MAC: "dc:a6:32:01:36:c3", Hostname: "sd-01", BootModel: "sd"}, set, config)
	require.NoError(t, err)
	assert.NotContains(t, args, disklessroot.ParamBootModel, "an SD node gets the set's arguments alone")
}

func TestNodeBootArgs_NBDServerAddress(t *testing.T) {
	entry := &ManifestEntry{MAC: "dc:a6:32:01:36:c2", Hostname: "nbd-01", BootModel: nbd.BootModel}
	tests := []struct {
		listenAddr string
		want       string
	}{
		{"192.0.2.1:10809", "192.0.2.1:10809"},
		{":10811", "192.168.1.1:10811"},
		{"0.0.0.0:10809", "192.168.1.1:10809"},
		{"[::]:10809", "192.168.1.1:10809"},
		{"[fd00:405::1]:10809", "[fd00:405::1]:10809"},
	}
	for _, tc := range tests {
		config := &ServerConfig{DHCPConfig: DHCPConfig{ServerIP: "192.168.1.1"}, NBD: NBDConfig{ListenAddr: tc.listenAddr}}
		args, err := nodeBootArgs(entry, piSet(), config)
		require.NoError(t, err, tc.listenAddr)
		assert.True(t, strings.HasSuffix(args, " "+nbd.ParamServer+"="+tc.want), "listen %s: %s", tc.listenAddr, args)
	}
}

func TestNodeBootArgs_NBDServerAddressUnknown(t *testing.T) {
	entry := &ManifestEntry{MAC: "dc:a6:32:01:36:c2", Hostname: "nbd-01", BootModel: nbd.BootModel}
	for _, config := range []*ServerConfig{
		{},                                     // no listener and no provisioning address
		{NBD: NBDConfig{ListenAddr: ":10809"}}, // a wildcard bind and no provisioning address
		{NBD: NBDConfig{ListenAddr: "192.0.2.1"}},
		{NBD: NBDConfig{ListenAddr: "192.0.2.1:0"}},
	} {
		_, err := nodeBootArgs(entry, piSet(), config)
		var unknown ErrNBDServerAddress
		require.ErrorAs(t, err, &unknown, "listen %q", config.NBD.ListenAddr)
		assert.Equal(t, config.NBD.ListenAddr, unknown.ListenAddr)
		assert.Contains(t, unknown.Error(), "nbd.listen_addr")
	}
}

func TestServerConfig_Validate_PathsMustBeServed(t *testing.T) {
	cfg := &ServerConfig{
		ManifestPath: "/m.yaml", DataDir: "/data",
		DHCPConfig: DHCPConfig{ServerIP: "1.1.1.1", RangeStart: "1.1.1.2", RangeEnd: "1.1.1.3", SubnetMask: "255.0.0.0"},
	}
	var invalid ErrInvalidServerConfig
	require.ErrorAs(t, cfg.Validate(), &invalid)
	assert.Equal(t, "media_dir", invalid.Field, "the media sets are required")

	cfg.MediaDir = "/opt/media"
	require.ErrorAs(t, cfg.Validate(), &invalid)
	assert.Equal(t, "media_dir", invalid.Field)

	cfg.MediaDir = "/data/media"
	cfg.TFTPDir = filepath.Join(t.TempDir(), "absent")
	require.ErrorAs(t, cfg.Validate(), &invalid)
	assert.Equal(t, "tftp_dir", invalid.Field)

	cfg.TFTPDir = t.TempDir()
	cfg.FirmwareOverrides = map[string]string{"snponly-aarch64.efi": ""}
	require.ErrorAs(t, cfg.Validate(), &invalid)
	assert.Equal(t, "firmware_overrides", invalid.Field)

	cfg.FirmwareOverrides = map[string]string{"snponly-aarch64.efi": "/data/firmware/snponly-aarch64.efi"}
	assert.NoError(t, cfg.Validate())
}

// TestNewServer_Errors covers each refusal before the iPXE server is built:
// a nil config, a nil logger, a config that fails Validate, and a manifest
// path that does not exist.
func TestNewServer_Errors(t *testing.T) {
	validButNoManifest := func() *ServerConfig {
		return &ServerConfig{
			ManifestPath: "/nonexistent/manifest.yaml",
			DataDir:      "/tmp",
			MediaDir:     "/tmp/media",
			DHCPConfig: DHCPConfig{
				ServerIP:   "192.168.1.1",
				RangeStart: "192.168.1.100",
				RangeEnd:   "192.168.1.200",
				SubnetMask: "255.255.255.0",
			},
		}
	}
	tests := []struct {
		name      string
		config    *ServerConfig
		logger    *slog.Logger
		wantField string // the ErrInvalidServerConfig field; empty means ErrManifestNotFound
	}{
		{name: "nil config", config: nil, logger: testLogger(), wantField: "config"},
		{name: "nil logger", config: &ServerConfig{}, logger: nil, wantField: "logger"},
		{name: "invalid config", config: &ServerConfig{ManifestPath: ""}, logger: testLogger(), wantField: "manifest_path"},
		{name: "manifest not found", config: validButNoManifest(), logger: testLogger()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServer(tc.config, tc.logger)
			if tc.wantField == "" {
				var notFound ErrManifestNotFound
				require.ErrorAs(t, err, &notFound)
				return
			}
			var invalid ErrInvalidServerConfig
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tc.wantField, invalid.Field)
		})
	}
}

func TestExtractMACFromPath(t *testing.T) {
	tests := []struct {
		name     string
		route    string // empty means the device script route and suffix
		suffix   string
		path     string
		expected string
	}{
		{
			name:     "colon separated with suffix",
			path:     "/boot/device/aa:bb:cc:dd:ee:ff.ipxe",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "dash separated with suffix",
			path:     "/boot/device/aa-bb-cc-dd-ee-ff.ipxe",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "no suffix",
			path:     "/boot/device/aa:bb:cc:dd:ee:ff",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "upper case is canonicalised",
			path:     "/boot/device/AA-BB-CC-DD-EE-FF.ipxe",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "empty",
			path:     "/boot/device/",
			expected: "",
		},
		{
			name:     "not a MAC",
			path:     "/boot/device/<script>alert(1)</script>.ipxe",
			expected: "",
		},
		{
			name:     "EUI-64 is not a 48-bit MAC",
			path:     "/boot/device/00:11:22:33:44:55:66:77.ipxe",
			expected: "",
		},
		{name: "installed UKI dash separated", route: installedUKIRoute, suffix: installedUKISuffix, path: "/boot/uki/DC-A6-32-01-36-C2.efi", expected: "dc:a6:32:01:36:c2"},
		{name: "installed UKI colon separated", route: installedUKIRoute, suffix: installedUKISuffix, path: "/boot/uki/dc:a6:32:01:36:c2.efi", expected: "dc:a6:32:01:36:c2"},
		{name: "installed UKI wrong suffix", route: installedUKIRoute, suffix: installedUKISuffix, path: "/boot/uki/dc:a6:32:01:36:c2.ipxe", expected: ""},
		{name: "installed UKI path traversal", route: installedUKIRoute, suffix: installedUKISuffix, path: "/boot/uki/../tpm2/installer.luks", expected: ""},
		{name: "installed UKI wrong route", route: installedUKIRoute, suffix: installedUKISuffix, path: "/boot/device/dc:a6:32:01:36:c2.efi", expected: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route, suffix := deviceScriptRoute, deviceScriptSuffix
			if tc.route != "" {
				route, suffix = tc.route, tc.suffix
			}
			result := extractMACFromPath(tc.path, route, suffix)
			if result != tc.expected {
				t.Errorf("extractMACFromPath(%q) = %q, want %q", tc.path, result, tc.expected)
			}
		})
	}
}
