//go:build integration

// Package userspace is the arm64 userspace half of the factory-image
// suite: the aarch64 platformd and platformctl, on musl, inside an arm64
// Alpine container against a swtpm, without booting anything. It proves
// in minutes what the emulated first boot proves in an hour — that the
// platform's TPM, sealing, LUKS2 and daemon paths run on the Raspberry
// Pi's architecture and C library — and it runs as a compiled test binary
// (`make integration-test-diskimage-userspace` cross-compiles it) because
// there is no Go toolchain in the container.
package userspace

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// Environment the Makefile target sets.
const (
	envPlatformd   = "PLATFORMD_BIN"
	envPlatformctl = "PLATFORMCTL_BIN"
	envConfig      = "PLATFORM_CONFIG"
	envSwtpmSocket = "SWTPM_SOCKET"
)

// socketPath is where platformd listens and where platformctl, running as
// root, looks first (pkg/cli.AutoDetectContext).
const socketPath = "/run/platformd.sock"

// Persistent handles the suite configuration provisions.
const (
	ekHandle  = "0x81010001"
	srkHandle = "0x81000001"
)

// Timeouts. Everything here runs under qemu-user emulation, which is
// several times slower than the Pi itself.
const (
	daemonStartTimeout = 5 * time.Minute
	commandTimeout     = 3 * time.Minute
	pollInterval       = 500 * time.Millisecond
)

// MissingInputError reports a required input that is unset or absent.
type MissingInputError struct {
	Variable string
	Path     string
	Err      error
}

func (e *MissingInputError) Error() string {
	if e.Path == "" {
		return "userspace suite: " + e.Variable + " is not set (run `make integration-test-diskimage-userspace`)"
	}
	return "userspace suite: " + e.Variable + "=" + e.Path + ": " + e.Err.Error()
}

func (e *MissingInputError) Unwrap() error { return e.Err }

// DaemonError reports a platformd that did not come up.
type DaemonError struct {
	Reason string
	Log    string
}

func (e *DaemonError) Error() string {
	return "userspace suite: platformd " + e.Reason + "; log tail:\n" + e.Log
}

// inputs are the resolved environment.
type inputs struct {
	platformd, platformctl, config, swtpm string
}

func requireInputs(t *testing.T) inputs {
	t.Helper()
	in := inputs{
		platformd:   os.Getenv(envPlatformd),
		platformctl: os.Getenv(envPlatformctl),
		config:      os.Getenv(envConfig),
		swtpm:       os.Getenv(envSwtpmSocket),
	}
	for _, v := range []struct{ name, value string }{
		{envPlatformd, in.platformd}, {envPlatformctl, in.platformctl}, {envConfig, in.config}, {envSwtpmSocket, in.swtpm},
	} {
		if v.value == "" {
			t.Fatal(&MissingInputError{Variable: v.name})
		}
		if _, err := os.Stat(v.value); err != nil {
			t.Fatal(&MissingInputError{Variable: v.name, Path: v.value, Err: err})
		}
	}
	return in
}

// daemon is a running platformd.
type daemon struct {
	cmd    *exec.Cmd
	logDir string
	log    *bytes.Buffer
	in     inputs
}

// startDaemon runs platformd serve the way the integration runner does
// (build/docker/devcontainer/run-integration-tests.sh start_platformd).
// --enable-mtls stays: the CLI talks over the Unix socket, but a fresh
// swtpm has no EK certificate and platformd issues one from its CA, which
// takes the identity that flag sets up. The suite's config is daemon-only
// (no webservices section); the runner's adds one webservice listener.
func startDaemon(t *testing.T, in inputs) *daemon {
	t.Helper()
	logDir := t.TempDir()
	d := &daemon{in: in, logDir: logDir, log: &bytes.Buffer{}}
	d.cmd = exec.Command(in.platformd, "serve",
		"--config", in.config,
		"--enable-mtls",
		"--skip-iam-validation",
		"--socket-path="+socketPath,
		"--rest-port=8443",
		"--grpc-port=10443",
		"--quic-port=9444",
		"--mcp-port=9445",
		"--raw-so-pin=123456",
		"--raw-pin=123456",
		"--debug",
	)
	d.cmd.Stdout = d.log
	d.cmd.Stderr = d.log
	require.NoError(t, d.cmd.Start(), "starting platformd")
	t.Cleanup(d.stop)

	exited := make(chan error, 1)
	go func() { exited <- d.cmd.Wait() }()

	deadline := time.NewTimer(daemonStartTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			d.cmd = nil
			t.Fatal(&DaemonError{Reason: "exited during startup: " + errString(err), Log: d.tail()})
		case <-deadline.C:
			t.Fatal(&DaemonError{Reason: "never created " + socketPath, Log: d.tail()})
		case <-ticker.C:
			if info, err := os.Stat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
				return d
			}
		}
	}
}

func (d *daemon) stop() {
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Kill()
	_ = d.cmd.Wait()
	_ = os.Remove(socketPath)
}

// tail is the end of the daemon's output for a failure message: its
// stdout/stderr, then the end of the platform log it writes under
// platform-dir, which is where the structured startup errors go.
func (d *daemon) tail() string {
	out := d.log.String()
	if len(out) > 4096 {
		out = out[len(out)-4096:]
	}
	if platformDir := configValueOrEmpty(d.in.config, "platform-dir"); platformDir != "" {
		if data, err := os.ReadFile(filepath.Join(platformDir, "log", "trusted-platform.log")); err == nil {
			text := string(data)
			if len(text) > 4096 {
				text = text[len(text)-4096:]
			}
			out += "\n--- trusted-platform.log ---\n" + text
		}
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return "status 0"
	}
	return err.Error()
}

// platformctl runs the CLI with JSON output and decodes it into out.
func (d *daemon) platformctl(t *testing.T, out any, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	full := append(append([]string{}, args...), "-o", "json")
	output, err := exec.CommandContext(ctx, d.in.platformctl, full...).CombinedOutput()
	require.NoError(t, err, "platformctl %s: %s\ndaemon log tail:\n%s", strings.Join(args, " "), output, d.tail())
	if out != nil {
		require.NoError(t, json.Unmarshal(jsonPart(output), out), "platformctl %s output: %s", strings.Join(args, " "), output)
	}
}

// jsonPart drops anything the CLI printed before the JSON document.
func jsonPart(output []byte) []byte {
	if i := bytes.IndexAny(output, "{["); i >= 0 {
		return output[i:]
	}
	return output
}

// espMountPoint is where platformd's TPM seal guard looks for the EFI
// system partition (pkg/app/tpm_seal_guard.go): it refuses to provision a
// fresh TPM unless a vfat ESP is mounted there, because an unmounted ESP
// could be hiding a seal a TPM2_Clear would destroy. The suite gives the
// container what the Pi has — a real FAT ESP on a block device.
const espMountPoint = "/boot/efi"

// mountESP creates a 64 MiB FAT32 image, attaches it to a loop device,
// mounts it at /boot/efi with an EFI directory, and undoes all of it on
// cleanup.
func mountESP(t *testing.T) {
	t.Helper()
	backing := filepath.Join(t.TempDir(), "esp.img")
	f, err := os.Create(backing)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(64<<20))
	require.NoError(t, f.Close())
	loop := attachLoop(t, backing)
	out, err := exec.Command("mkfs.vfat", "-F", "32", "-n", "EFI", loop).CombinedOutput()
	require.NoError(t, err, "mkfs.vfat: %s", out)
	require.NoError(t, os.MkdirAll(espMountPoint, 0o755))
	require.NoError(t, unix.Mount(loop, espMountPoint, "vfat", 0, ""), "mounting the ESP")
	t.Cleanup(func() { _ = unix.Unmount(espMountPoint, unix.MNT_DETACH) })
	require.NoError(t, os.MkdirAll(filepath.Join(espMountPoint, "EFI"), 0o755))
}

// TestAArch64Userspace is one daemon lifetime with the checks as subtests,
// in the order the first boot exercises them.
func TestAArch64Userspace(t *testing.T) {
	in := requireInputs(t)
	mountESP(t)
	d := startDaemon(t, in)

	t.Run("health", func(t *testing.T) {
		// The overall status folds in every registered component, and a
		// single node with no SDN or tenant configuration legitimately
		// reports some of them unhealthy. What the first boot depends on
		// is the CA and the KMS, so those are the ones that must be up.
		var health struct {
			Status     string `json:"status"`
			Components []struct {
				Name    string `json:"name"`
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"components"`
		}
		d.platformctl(t, &health, "health")
		t.Logf("health: %s; components: %+v", health.Status, health.Components)
		assert.NotEmpty(t, health.Status, "platformd reports a health status")
		for _, component := range health.Components {
			switch component.Name {
			case "ca", "kms":
				assert.NotEqual(t, "unhealthy", strings.ToLower(component.Status),
					"%s must be healthy on a single node: %s", component.Name, component.Message)
			}
		}
	})

	t.Run("tpm is the swtpm, not the simulator", func(t *testing.T) {
		// `tpm info -o json` carries go-xkms's report verbatim under
		// "info" plus the simulator flag.
		var info struct {
			IsSimulator bool   `json:"is_simulator"`
			Info        string `json:"info"`
		}
		d.platformctl(t, &info, "tpm", "info")
		assert.False(t, info.IsSimulator, "tpm.device names the swtpm socket; the in-process simulator must not be used")
		assert.Contains(t, info.Info, "Manufacturer:", "the daemon reached a TPM and read its capabilities")
		assert.Contains(t, info.Info, "2.0", "a TPM 2.0 family device")
	})

	t.Run("EK and SSRK are provisioned at their handles", func(t *testing.T) {
		var ek map[string]any
		d.platformctl(t, &ek, "tpm", "ek", "info", "--handle", ekHandle)
		assert.NotEmpty(t, ek, "EK info")
		var srk map[string]any
		d.platformctl(t, &srk, "tpm", "srk", "info", "--handle", srkHandle)
		assert.NotEmpty(t, srk, "SSRK info")
	})

	t.Run("seal and unseal through the daemon", func(t *testing.T) {
		secret := "aarch64-sealed-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		var seal struct {
			Success bool `json:"success"`
		}
		// Parented on the SSRK with password auth: the path the TPM
		// multi-protocol suite proves on x86 (SealAndUnsealWithPassword).
		d.platformctl(t, &seal, "tpm", "seal", "--cn", "userspace-suite", "--data", secret, "--password", "userspace-suite-auth")
		var unseal struct {
			Success bool   `json:"success"`
			Data    string `json:"data"`
		}
		d.platformctl(t, &unseal, "tpm", "unseal", "--cn", "userspace-suite", "--password", "userspace-suite-auth")
		assert.Equal(t, secret, unseal.Data, "what was sealed is what unseals")
	})

	t.Run("platform state persisted under the platform directory", func(t *testing.T) {
		platformDir := configValue(t, in.config, "platform-dir")
		entries, err := os.ReadDir(platformDir)
		require.NoError(t, err)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		assert.NotEmpty(t, names, "platformd wrote its state (datastore, keystore, CA) under %s", platformDir)
	})
}

// TestLUKS2OnAArch64 formats a file-backed LUKS2 volume with go-luks2 the
// way the installer does, attaches it to a loop device, unlocks it through
// device-mapper and locks it again. It is the primitive both Phase A
// (format + install) and Phase B (unlock, seal, re-key) stand on, running
// on the target architecture.
func TestLUKS2OnAArch64(t *testing.T) {
	requireInputs(t)
	dir := t.TempDir()
	backing := filepath.Join(dir, "volume.img")
	f, err := os.Create(backing)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(64<<20))
	require.NoError(t, f.Close())

	loop := attachLoop(t, backing)
	passphrase := []byte("aarch64-luks2-passphrase")
	require.NoError(t, luks2.Format(luks2.FormatOptions{
		Device:     loop,
		Passphrase: passphrase,
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		KeySize:    512,
		HashAlgo:   "sha256",
		KDFType:    fips.KDFPBKDF2,
	}), "luks2.Format on %s", loop)

	info, err := luks2.GetVolumeInfo(loop)
	require.NoError(t, err)
	assert.NotEmpty(t, info.UUID, "the formatted volume has a UUID")

	const name = "userspace-suite-root"
	require.NoError(t, luks2.Unlock(loop, passphrase, name), "luks2.Unlock through device-mapper")
	t.Cleanup(func() { _ = luks2.Lock(name) })
	_, err = os.Stat("/dev/mapper/" + name)
	assert.NoError(t, err, "the mapping exists")

	require.NoError(t, luks2.Lock(name))
	_, err = os.Stat("/dev/mapper/" + name)
	assert.True(t, os.IsNotExist(err), "the mapping is gone after Lock")

	assert.Error(t, luks2.Unlock(loop, []byte("wrong"), name), "a wrong passphrase must not unlock")
}

// attachLoop attaches a file to a free loop device and detaches it on cleanup.
func attachLoop(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("losetup", "--find", "--show", path).CombinedOutput()
	require.NoError(t, err, "losetup: %s", out)
	loop := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("losetup", "--detach", loop).Run() })
	return loop
}

// configValue reads one top-level scalar from the platform YAML without a
// YAML dependency the test binary would otherwise carry for one key.
func configValue(t *testing.T, path, key string) string {
	t.Helper()
	value := configValueOrEmpty(path, key)
	if value == "" {
		t.Fatalf("%s has no top-level %s", path, key)
	}
	return value
}

// configValueOrEmpty is configValue for callers that cannot fail a test.
func configValueOrEmpty(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+":"))
		}
	}
	return ""
}
