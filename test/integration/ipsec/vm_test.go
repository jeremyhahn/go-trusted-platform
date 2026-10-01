//go:build integration

package ipsec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Inputs of the aarch64 VM run (Makefile IPSEC_SUITE_ENV).
const (
	envVMKernel  = "IPSEC_VM_KERNEL"
	envVMInitrd  = "IPSEC_VM_INITRD"
	envTestARM64 = "IPSEC_TEST_ARM64"
)

// vmResult is the marker the VM's init prints after the suite ran.
var vmResult = regexp.MustCompile(`IPSEC-VM-RESULT rc=(\d+)`)

// TestSuiteInARM64VM proves the arm64 build the way the amd64 tests prove
// theirs: it boots an aarch64 VM (qemu-system-aarch64, TCG) whose init runs
// this suite's own tests, cross-compiled for arm64, against the arm64 peer
// root filesystems and the arm64 module host. Two arm64 charon peers then
// authenticate through the go-xkms module and install ESP SAs in a real
// aarch64 kernel.
func TestSuiteInARM64VM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	kernel := requireFile(t, envVMKernel)
	initrd := requireFile(t, envVMInitrd)
	share := filepath.Join(os.TempDir(), "ipsec-vm-share")
	if wd := os.Getenv(envWorkDir); wd != "" {
		share = filepath.Join(wd, "vm-share")
	}
	require.NoError(t, os.RemoveAll(share))
	require.NoError(t, os.MkdirAll(share, 0o755))
	// The test binary goes over 9p under the name the VM's init runs; the
	// two tarballs become read-only virtio disks (vda, vdb, in that order).
	binary := filepath.Join(share, "ipsec-arm64.test")
	require.NoError(t, os.WriteFile(binary, nil, 0o755))
	mount(t, ctx, "--bind", requireFile(t, envTestARM64), binary)
	rootfs := requireFile(t, envRootfsPrefix+"ARM64")
	moduleHost := requireFile(t, envModuleHostPrefix+"ARM64")

	serial := filepath.Join(share, "..", "vm-serial.log")
	cmd := exec.CommandContext(ctx, "qemu-system-aarch64",
		// cortex-a72: -cpu max emulates the architected pointer-authentication
		// algorithm, which is slow under TCG. Unpacking the module host from
		// a virtio disk took 110 s with max and 9 s with cortex-a72; over 9p
		// it took 45 s even with cortex-a72, hence the disks.
		"-M", "virt", "-cpu", "cortex-a72", "-smp", "4", "-m", "4096",
		"-accel", "tcg,thread=multi",
		"-kernel", kernel, "-initrd", initrd,
		"-append", "console=ttyAMA0 rdinit=/init quiet",
		"-drive", "file="+rootfs+",format=raw,if=virtio,readonly=on",
		"-drive", "file="+moduleHost+",format=raw,if=virtio,readonly=on",
		"-virtfs", "local,path="+share+",mount_tag=suite,security_model=none,id=suite",
		"-display", "none", "-monitor", "none", "-no-reboot",
		"-serial", "file:"+serial,
	)
	out, err := cmd.CombinedOutput()
	transcript, readErr := os.ReadFile(serial)
	require.NoError(t, readErr)
	t.Logf("aarch64 VM serial console:\n%s", transcript)
	require.NoError(t, err, "qemu-system-aarch64:\n%s", out)

	m := vmResult.FindSubmatch(transcript)
	require.NotNil(t, m, "the VM's init never reported a result")
	assert.Equal(t, "0", string(m[1]), "the suite inside the aarch64 VM failed")
	for _, name := range []string{"TestESPTransportThroughPKCS11Module", "TestUntrustedPeerIsRefused"} {
		assert.Contains(t, string(transcript), "--- PASS: "+name, "%s ran and passed on arm64", name)
	}
	assert.Contains(t, string(transcript), "peers: arm64", "the peers inside the VM are arm64")
	assert.Contains(t, string(transcript), "ipsec vm: aarch64", "the VM ran an aarch64 kernel")
}
