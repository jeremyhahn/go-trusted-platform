//go:build integration

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

// Package nat64 runs the NAT64 suite (#601) in a VM that carries its own
// kernel.
//
// The translator is a kernel module, and a container shares the host's
// kernel: the devcontainer cannot load jool into a host that does not ship
// it, and a host that does ships whatever version its distribution builds.
// So the suite boots Alpine's linux-lts kernel with the jool-modules-lts
// built for exactly that kernel -- the fleet's own pairing -- under QEMU,
// and runs there. This harness assembles the initramfs (the VM rootfs plus
// the suite binary), boots it, streams the guest's console into the test
// log, and passes or fails on the guest's exit status.
//
// The guest suite is test/integration/sdn built with the nat64vm tag; it
// drives the real Jool driver and a real gateway on a real OVS bridge.
package nat64

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/iso/isotest"
)

const (
	envKernel = "NAT64_VM_KERNEL"
	envRootfs = "NAT64_VM_ROOTFS"
	envSuite  = "NAT64_VM_SUITE"
	envRun    = "NAT64_VM_RUN"

	// bootTimeout bounds the whole guest run: boot, module load, OVS and
	// the suite. Under KVM the guest is up in seconds.
	bootTimeout = 10 * time.Minute
)

// sentinel is the line the guest's init prints when the suite exits.
var sentinel = regexp.MustCompile(`NAT64-VM-RESULT rc=(\d+)`)

// passLine is a top-level test's pass line in the guest's -test.v output.
var passLine = regexp.MustCompile(`^--- PASS: (\S+)`)

// requiredGuestTests must each pass in the guest. They are the suite: the
// Jool driver against the real module, and the datapath end to end.
var requiredGuestTests = []string{
	"TestJoolDriver_ProgramsARealInstance",
	"TestJoolDriver_ConvergesAChangedPool",
	"TestJoolDriver_RecreatesForANewPrefix",
	"TestNAT64Datapath_UntaggedEveryZone",
	"TestNAT64Datapath_TaggedClientZone",
}

// requireInput returns the path in the named variable, failing the test
// when it is unset or missing: the suite never skips itself green.
func requireInput(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	require.NotEmpty(t, path, "%s is not set: run `make integration-test-nat64`, which builds the VM and the suite", name)
	_, err := os.Stat(path)
	require.NoError(t, err, "%s=%s", name, path)
	return path
}

func TestNAT64InAlpineVM(t *testing.T) {
	kernel := requireInput(t, envKernel)
	rootfs := requireInput(t, envRootfs)
	suite := requireInput(t, envSuite)
	_, err := os.Stat("/dev/kvm")
	require.NoError(t, err, "the NAT64 VM needs KVM; the devcontainer runs --privileged and must see /dev/kvm")
	_, err = exec.LookPath("qemu-system-x86_64")
	require.NoError(t, err, "qemu-system-x86_64 is not in the devcontainer")

	// The guest initramfs is the VM rootfs with the suite appended as a
	// second newc archive; the kernel unpacks concatenated archives in
	// order.
	suiteBin, err := os.ReadFile(suite)
	require.NoError(t, err)
	args := "-test.timeout=8m"
	if run := os.Getenv(envRun); run != "" {
		args += " -test.run=" + run
	}
	overlay, err := isotest.Initramfs(map[string]string{
		"nat64-suite.test": string(suiteBin),
		"nat64-suite.args": args,
	})
	require.NoError(t, err)
	base, err := os.ReadFile(rootfs)
	require.NoError(t, err)
	initrd := filepath.Join(t.TempDir(), "initrd.gz")
	require.NoError(t, os.WriteFile(initrd, append(base, overlay...), 0o600))

	ctx, cancel := context.WithTimeout(context.Background(), bootTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "qemu-system-x86_64",
		"-machine", "q35,accel=kvm",
		"-cpu", "host",
		"-m", "2048",
		"-smp", "2",
		"-display", "none",
		"-serial", "stdio",
		"-no-reboot",
		"-kernel", kernel,
		"-initrd", initrd,
		"-append", "console=ttyS0 rdinit=/init panic=-1 quiet",
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start())

	rc := -1
	passed := map[string]bool{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		t.Log(line)
		if m := passLine.FindStringSubmatch(line); m != nil {
			passed[m[1]] = true
		}
		if m := sentinel.FindStringSubmatch(line); m != nil {
			rc, err = strconv.Atoi(m[1])
			require.NoError(t, err)
		}
	}
	waitErr := cmd.Wait()
	require.NoError(t, ctx.Err(), "the guest did not power off within %s", bootTimeout)
	require.NoError(t, waitErr, "qemu exited abnormally")
	require.NotEqual(t, -1, rc, "the guest never reported a result: the VM did not reach the suite")
	require.Zero(t, rc, "the NAT64 suite failed in the guest (exit %d); its output is above", rc)
	// Exit 0 with nothing run is not a pass.
	for _, name := range requiredGuestTests {
		require.True(t, passed[name], "the guest never ran %s; a suite that passes without running proves nothing", name)
	}
}
