//go:build integration

package netboot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// Serial milestones of the network boot, in order, as the guest prints
// them. Each names the stage that produced it, so a failure says where the
// chain stopped.
var netbootMilestones = []string{
	"U-Boot 20",                              // U-Boot, the platform build, as -bios
	"Scanning bootdev 'virtio-net",           // the disk is empty; bootflow reaches the NIC
	"DHCP client bound to address",           // the PXE server leased an address (arch 0x000b was sent)
	"Filename 'snponly-aarch64.efi'",         // the server chose the arm64 iPXE for that architecture
	"Bytes transferred",                      // TFTP delivered it (unicast replies reach the bridge)
	"Booting /snponly-aarch64.efi",           // U-Boot verified the db signature (an unsigned image is refused before this line)
	"iPXE initialising devices",              // the platform-built iPXE runs (upstream's would halt after this at its banner)
	"Configuring (net0",                      // iPXE's own DHCP, on U-Boot's SNP
	"/files/kernel.signed.efi...",            // the per-architecture script fetches the signed kernel (iPXE may print progress before "ok"; the next milestone proves it arrived and verified)
	"EFI stub: UEFI Secure Boot is enabled.", // U-Boot verified the kernel; its EFI stub runs under Secure Boot
	"Linux version",                          // the kernel
	"Welcome to Alpine",                      // the initramfs got its lease, mounted the modloop; userspace
}

// netbootTimeout bounds one emulated boot under TCG on a development host.
const netbootTimeout = 25 * time.Minute

// TestAArch64NetbootFromUBoot drives `platformctl iso test pxe --architecture
// aarch64` — the PXE server on its isolated bridge and QEMU virt booted
// from the platform's U-Boot on the TAP — to the Alpine login banner, then
// checks every milestone in the transcript and that nothing was rejected
// by Secure Boot along the way.
func TestAArch64NetbootFromUBoot(t *testing.T) {
	in := requireInputs(t)
	workDir := filepath.Join(in.workDir, "aarch64")
	serialLog := filepath.Join(workDir, "serial.log")
	last := netbootMilestones[len(netbootMilestones)-1]

	// The files directory is served at /files/; the modloop goes there so
	// the initramfs can mount its kernel modules from the boot server.
	filesDir := filepath.Join(workDir, "pxe-files")
	require.NoError(t, os.MkdirAll(filesDir, 0o755))
	require.NoError(t, copyFile(in.modloop, filepath.Join(filesDir, "modloop-lts")))

	// The Alpine netboot initramfs installs alpine-base into its tmpfs root
	// from alpine_repo before it can hand over to /sbin/init; the mirror
	// is reached through the boot server's HTTPS relay, the way a PXE
	// client on a provisioning segment reaches anything.
	repo, err := serverProxyURL(in.alpineRepo)
	require.NoError(t, err)
	args := "console=ttyAMA0,115200 ip=dhcp modules=loop,squashfs" +
		" modloop=" + serverFilesURL + "/modloop-lts alpine_repo=" + repo

	ctx, cancel := context.WithTimeout(context.Background(), netbootTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.platformctl, "iso", "test", "pxe",
		"--architecture", "aarch64",
		"--uboot", in.uboot,
		"--ipxe", in.ipxe,
		"--keys-dir", in.keysDir,
		"--kernel", "file://"+in.kernel,
		"--initrd", "file://"+in.initrd,
		"--args", args,
		"--work-dir", workDir,
		"--memory", "2048",
		"--cpus", "2",
		"--serial-log", serialLog,
		"--expect", last,
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("platformctl iso test pxe: %v\n%s\n--- output tail ---\n%s", err,
			harness.MissingMilestone(serialLog, netbootMilestones), tail(output.Bytes(), 4096))
	}

	for _, m := range netbootMilestones {
		found, err := harness.SerialContains(serialLog, m)
		require.NoError(t, err)
		assert.True(t, found, "milestone %q missing from the boot", m)
	}
	for _, bad := range []string{"Image not authenticated", "Security violation", "Retry count exceeded", "Kernel panic", "Could not boot"} {
		found, err := harness.SerialContains(serialLog, bad)
		require.NoError(t, err)
		assert.False(t, found, "the boot printed %q", bad)
	}
}

// The PXE test environment's server, as ipxe.DefaultTestEnvConfig builds it.
const (
	serverBaseURL  = "http://10.99.99.1:8080"
	serverFilesURL = serverBaseURL + "/files"
)

// serverProxyURL turns an https:// URL into the boot server's relay form
// (/proxy/https/<host>/<path>); an http:// URL is returned as is.
func serverProxyURL(raw string) (string, error) {
	switch {
	case strings.HasPrefix(raw, "https://"):
		return serverBaseURL + "/proxy/https/" + strings.TrimPrefix(raw, "https://"), nil
	case strings.HasPrefix(raw, "http://"):
		return raw, nil
	default:
		return "", &MissingInputError{Variable: envAlpineRepo, Path: raw, Err: errNotAURL}
	}
}

var errNotAURL = errors.New("not an http(s) URL")

// copyFile copies src to dst, replacing dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// tail returns the last n bytes of b.
func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
