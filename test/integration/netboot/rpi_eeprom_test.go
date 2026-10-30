//go:build integration

package netboot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/netboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

const (
	envUBootDir      = "NETBOOT_UBOOT_DIR"
	envRPiAPKDir     = "NETBOOT_RPI_APK_DIR"
	envAlpineMirror  = "NETBOOT_ALPINE_MIRROR"
	envAlpineVersion = "NETBOOT_ALPINE_VERSION"

	// eepromProbeTimeout bounds one probe; the bootloader's own DHCP
	// timeout is 45 s and every file fetch is local.
	eepromProbeTimeout = 3 * time.Minute
)

// rpiPackages is what the Pi's boot partition is staged from.
var rpiPackages = []string{"raspberrypi-bootloader", "raspberrypi-bootloader-common", "linux-rpi"}

// TestRaspberryPiEEPROMStage proves the boot server's side of the stage a
// QEMU cannot emulate: the Pi bootloader's DHCP exchange and its TFTP
// fetch of the firmware set, from the emulator that speaks the
// bootloader's protocol (pkg/rpinetboot), against the PXE test environment
// serving a tree staged from the same inputs the factory image is built
// from. It runs the exchange twice: with the environment as the segment's
// DHCP server, and as a proxy beside another one — both ways a Pi is
// booted in practice.
func TestRaspberryPiEEPROMStage(t *testing.T) {
	in := requireInputs(t)
	logger := logging.DefaultLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	treeDir, art := stageRPiTree(t, ctx, in, "rpi-tftp", logger)

	// A per-device directory for one Pi: its own config.txt, everything
	// else from the root — the shape TFTP_PREFIX is for.
	mac, err := net.ParseMAC("dc:a6:32:01:36:c2")
	require.NoError(t, err)
	pi := rpinetboot.Identity{Serial: 0x9ffefdef, MAC: mac, Revision: 0x00c03111}
	deviceDir := filepath.Join(treeDir, "9ffefdef")
	require.NoError(t, os.MkdirAll(deviceDir, 0o755))
	deviceConfig := "# this Pi only\narm_64bit=1\nenable_uart=1\ndtoverlay=disable-bt\ndtoverlay=tpm-soft-spi\nkernel=kernel8.img\n"
	require.NoError(t, os.WriteFile(filepath.Join(deviceDir, "config.txt"), []byte(deviceConfig), 0o644))
	ubootSum := fileSHA256(t, art.Binary)

	for _, mode := range []struct {
		name  string
		proxy bool
	}{{"as the segment's DHCP server", false}, {"as a proxy DHCP server", true}} {
		t.Run(mode.name, func(t *testing.T) {
			cfg := ipxe.DefaultTestEnvConfig()
			cfg.TFTPDir = treeDir
			cfg.ProxyDHCP = mode.proxy
			cfg.LocalFilesDir = filepath.Join(in.workDir, "pxe-files")
			require.NoError(t, os.MkdirAll(cfg.LocalFilesDir, 0o755))
			cfg.BootEntries = []ipxe.BootEntry{{Name: "unused", Description: "unused", Kernel: "http://10.99.99.1:8080/files/none"}}
			startPXEEnv(t, ctx, cfg, logger)

			// The Pi: its own network namespace on the bridge, as a board
			// on the segment is, driven through the operator's command. A
			// probe on the server's own host would talk to it over
			// loopback, where the harness NAT (-s 10.99.99.0/24 ! -o pxe-br
			// MASQUERADE) rewrites the TFTP reply's source and the client
			// rightly drops it — a topology no Pi is ever in.
			ns := attachProbeNamespace(t, cfg.BridgeName)
			probeCtx, cancelProbe := context.WithTimeout(ctx, eepromProbeTimeout)
			defer cancelProbe()
			report := runProbeCLI(t, probeCtx, in.platformctl, ns, pi)

			assert.Equal(t, mode.proxy, report.Offer.Proxy)
			assert.Equal(t, "10.99.99.1", report.Offer.TFTPServer, "siaddr names the environment's server")
			opt43, err := hex.DecodeString(report.Offer.Option43)
			require.NoError(t, err)
			assert.True(t, rpinetboot.Option43Matches(opt43, rpinetboot.Option43Match))
			if mode.proxy {
				assert.Nil(t, report.Lease, "a proxy leases nothing")
			} else {
				require.NotNil(t, report.Lease)
				assert.NotNil(t, net.ParseIP(report.Lease.IP).To4())
			}
			assert.Equal(t, "9ffefdef/", report.Prefix)

			byName := map[string]probeFile{}
			for _, f := range report.Files {
				byName[f.Name] = f
			}
			assert.Equal(t, "start4.elf", byName["start4.elf"].Path, "no per-device start4.elf: the root's")
			assert.Equal(t, "9ffefdef/config.txt", byName["config.txt"].Path, "the device's own config.txt")
			assert.Equal(t, int64(len(deviceConfig)), byName["config.txt"].Bytes)
			assert.Equal(t, ubootSum, byName["kernel8.img"].SHA256, "kernel8.img is the rpi_arm64 U-Boot, byte for byte")
			assert.Equal(t, "overlays/tpm-soft-spi.dtbo", byName["overlays/tpm-soft-spi.dtbo"].Path)
			assert.Equal(t, fileSHA256(t, filepath.Join(art.OverlaysDir, "tpm-soft-spi.dtbo")), byName["overlays/tpm-soft-spi.dtbo"].SHA256)
			assert.True(t, byName["cmdline.txt"].Missing, "no cmdline.txt on the boot partition: the UKI carries the command line")
			for _, name := range []string{"fixup4.dat", "bcm2711-rpi-4-b.dtb", "overlays/disable-bt.dtbo"} {
				assert.Greater(t, byName[name].Bytes, int64(0), name)
			}
		})
	}
}

// startPXEEnv sets up and starts the PXE test environment for cfg and stops it
// when the test ends.
// stageRPiTree stages the Pi's boot partition under the work directory: U-Boot
// from the builder, firmware from the Alpine packages (fetched once into the
// cache directory the Makefile passes).
func stageRPiTree(t *testing.T, ctx context.Context, in inputs, name string, logger *logging.Logger) (string, uboot.Artifacts) {
	t.Helper()
	ubootDir := requireEnvPath(t, envUBootDir)
	apkDir := os.Getenv(envRPiAPKDir)
	mirror, version := os.Getenv(envAlpineMirror), os.Getenv(envAlpineVersion)
	if apkDir == "" || mirror == "" || version == "" {
		t.Fatal(&MissingInputError{Variable: envRPiAPKDir + ", " + envAlpineMirror + ", " + envAlpineVersion})
	}
	boards, err := uboot.Locate(ubootDir)
	require.NoError(t, err)
	art := boards[uboot.BoardRPiArm64]
	fetchRPiPackages(t, ctx, apkDir, mirror, version, logger)
	treeDir := filepath.Join(in.workDir, name)
	require.NoError(t, netboot.Stage(ctx, netboot.Inputs{Model: "rpi4", PrefetchDir: apkDir, UBoot: art}, treeDir))
	return treeDir, art
}

func startPXEEnv(t *testing.T, ctx context.Context, cfg *ipxe.TestEnvConfig, logger *logging.Logger) {
	t.Helper()
	env, err := ipxe.NewTestEnv(cfg, logger)
	require.NoError(t, err)
	require.NoError(t, env.Setup())
	t.Cleanup(func() { _ = env.Cleanup() })
	envCtx, stopEnv := context.WithCancel(ctx)
	t.Cleanup(stopEnv)
	started := make(chan error, 1)
	go func() { started <- env.Start(envCtx) }()
	select {
	case <-env.Ready():
	case err := <-started:
		t.Fatalf("the PXE environment did not start: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the PXE environment did not become ready")
	}
}

// probeReport is the JSON `platformctl bootstrap probe rpi -o json` prints.
type probeReport struct {
	Offer struct {
		TFTPServer string `json:"tftp_server"`
		Proxy      bool   `json:"proxy"`
		Option43   string `json:"option43_hex"`
	} `json:"offer"`
	Lease *struct {
		IP string `json:"ip"`
	} `json:"lease"`
	Prefix string      `json:"prefix"`
	Files  []probeFile `json:"files"`
}

type probeFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
	Missing bool   `json:"missing"`
}

// Names of the emulated Pi's namespace and veth pair.
const (
	probeNamespace = "rpi-probe"
	probeVeth      = "veth-rpi"
	probeVethPeer  = "veth-rpi-br"
	probeAddress   = "10.99.99.50/24"
)

// attachProbeNamespace creates a network namespace joined to bridge by a
// veth pair, with a static address on the segment (a probe host is a host
// on the boot segment; the address it leases is reported, not used), and
// removes it when the test ends.
func attachProbeNamespace(t *testing.T, bridge string) string {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %s: %s", strings.Join(args, " "), out)
	}
	// A previous run killed before its cleanup leaves the namespace behind.
	if out, err := exec.Command("ip", "netns", "list").Output(); err == nil && strings.Contains(string(out), probeNamespace) {
		run("netns", "del", probeNamespace)
	}
	run("netns", "add", probeNamespace)
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", probeNamespace).CombinedOutput(); err != nil {
			t.Logf("removing namespace %s: %v: %s", probeNamespace, err, out)
		}
	})
	run(testenv.VethArgs(probeVeth, probeVethPeer)...)
	run("link", "set", probeVethPeer, "master", bridge)
	run("link", "set", probeVethPeer, "up")
	run("link", "set", probeVeth, "netns", probeNamespace)
	run("-n", probeNamespace, "addr", "add", probeAddress, "dev", probeVeth)
	run("-n", probeNamespace, "link", "set", probeVeth, "up")
	run("-n", probeNamespace, "link", "set", "lo", "up")
	return probeNamespace
}

// runProbeCLI runs `platformctl bootstrap probe rpi` for pi inside the
// namespace and returns its JSON report; a failed probe fails the test
// with the report and the log it printed.
func runProbeCLI(t *testing.T, ctx context.Context, platformctl, ns string, pi rpinetboot.Identity) probeReport {
	t.Helper()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, platformctl, "bootstrap", "probe", "rpi",
		"--interface", probeVeth,
		"--serial", fmt.Sprintf("%08x", pi.Serial),
		"--mac", pi.MAC.String(),
		"--revision", fmt.Sprintf("%x", pi.Revision),
		"--model", "rpi4",
		"-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var report probeReport
	decodeErr := json.Unmarshal(stdout.Bytes(), &report)
	if err != nil || decodeErr != nil {
		t.Fatalf("probe: %v (decode: %v)\n--- report ---\n%s\n--- log tail ---\n%s", err, decodeErr, stdout.String(), tail(stderr.Bytes(), 4096))
	}
	return report
}

// fetchRPiPackages fills apkDir with the Pi's boot packages unless it
// already holds them.
func fetchRPiPackages(t *testing.T, ctx context.Context, apkDir, mirror, version string, logger *logging.Logger) {
	t.Helper()
	entries, err := os.ReadDir(apkDir)
	if err == nil {
		have := map[string]bool{}
		for _, e := range entries {
			for _, pkg := range rpiPackages {
				if len(e.Name()) > len(pkg) && e.Name()[:len(pkg)+1] == pkg+"-" {
					have[pkg] = true
				}
			}
		}
		if len(have) == len(rpiPackages) {
			return
		}
	}
	require.NoError(t, os.MkdirAll(apkDir, 0o755))
	fetcher := iso.NewPreFetchBuilder(&iso.PreFetchConfig{Mirror: mirror, Version: version, Architecture: "aarch64", WorkDir: filepath.Join(apkDir, ".work"), ISODir: apkDir}, logger)
	require.NoError(t, fetcher.FetchPackages(ctx, rpiPackages, apkDir))
}

func requireEnvPath(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatal(&MissingInputError{Variable: name})
	}
	if _, err := os.Stat(v); err != nil {
		t.Fatal(&MissingInputError{Variable: name, Path: v, Err: err})
	}
	return v
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
