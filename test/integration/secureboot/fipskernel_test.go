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

//go:build integration

package secureboot

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/modulesign"
	pkgsecureboot "github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// Serial markers emitted by the initramfs init script.
const (
	markerBoot             = "TP-MODSIG-BOOT"
	markerUnsignedLoaded   = "TP-MODSIG-UNSIGNED-LOADED"
	markerUnsignedRejected = "TP-MODSIG-UNSIGNED-REJECTED"
	markerOriginalLoaded   = "TP-MODSIG-ORIGINAL-LOADED"
	markerResignedLoaded   = "TP-MODSIG-RESIGNED-LOADED"
	markerResignedFailed   = "TP-MODSIG-RESIGNED-FAILED"
	markerRmmodFailed      = "TP-MODSIG-RMMOD-FAILED"
	markerDone             = "TP-MODSIG-DONE"
	markerNoCandidate      = "TP-MODSIG-NO-CANDIDATE"

	// enokeyMessage is glibc's strerror(ENOKEY), which the kernel returns
	// for modules lacking a trusted signature under CONFIG_MODULE_SIG_FORCE.
	enokeyMessage = "Required key not available"

	// fipsBootTimeout bounds the whole kernel boot + insmod cycle under TCG.
	fipsBootTimeout = 8 * time.Minute

	// maxInsmodCandidates limits how many zero-dependency modules are staged.
	maxInsmodCandidates = 5
)

// busyboxCandidates are probed for a static busybox to populate the test
// initramfs (busybox-static in the devcontainer).
var busyboxCandidates = []string{
	"/bin/busybox",
	"/usr/bin/busybox",
	"/sbin/busybox",
}

// findBusybox locates the static busybox binary.
func findBusybox(t *testing.T) string {
	t.Helper()
	for _, p := range busyboxCandidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal(ErrMissingTool{Tool: "busybox", Purpose: "populate the FIPS kernel test initramfs (install busybox-static in the devcontainer)"})
	return ""
}

// buildInsmodInitramfs assembles a gzip cpio initramfs containing busybox, a
// /dev/console node and, per candidate module i: /mod/<i>-original.ko (as
// shipped, build-signed), /mod/<i>-unsigned.ko (signature stripped) and
// /mod/<i>-resigned.ko (stripped then re-signed with pkg/modulesign using the
// stable platform key). The init script proves, on the FIRST candidate whose
// build-signed variant loads: unsigned -> rejected with ENOKEY, resigned ->
// loads, original -> loads.
func buildInsmodInitramfs(t *testing.T, busyboxPath string, candidates []string, mods *fipsModules, msk *pkgsecureboot.ModuleSigningKey) string {
	t.Helper()

	busybox, err := os.ReadFile(busyboxPath)
	if err != nil {
		t.Fatalf("read busybox: %v", err)
	}

	entries := []cpioEntry{
		{Name: "dev", Mode: 040755},
		// /dev/console (char 5:1) so the kernel wires init's stdio to the
		// serial console.
		{Name: "dev/console", Mode: 020600, RdevMajor: 5, RdevMinor: 1},
		{Name: "bin", Mode: 040755},
		{Name: "bin/busybox", Mode: 0100755, Data: busybox},
		{Name: "mod", Mode: 040755},
		{Name: "tmp", Mode: 040755},
	}

	var script strings.Builder
	script.WriteString("#!/bin/busybox sh\n")
	script.WriteString("bb=/bin/busybox\n")
	script.WriteString("echo " + markerBoot + "\n")

	stageDir := t.TempDir()
	for i, rel := range candidates {
		original := mods.Files[rel]
		if !hasModuleSignature(original) {
			t.Fatalf("module %s from the FIPS tarball is not build-signed — the kernel was built without CONFIG_MODULE_SIG_ALL", rel)
		}
		unsigned := stripModuleSignature(t, original)

		// Re-sign the stripped module with the stable platform key via
		// pkg/modulesign — the exact out-of-tree signing path.
		resignedPath := filepath.Join(stageDir, fmt.Sprintf("%d-resigned.ko", i))
		if err := os.WriteFile(resignedPath, unsigned, 0644); err != nil {
			t.Fatalf("stage resign candidate: %v", err)
		}
		if err := modulesign.SignModule(resignedPath, msk.Signer, msk.Certificate); err != nil {
			t.Fatalf("modulesign re-sign %s: %v", rel, err)
		}
		resigned, err := os.ReadFile(resignedPath)
		if err != nil {
			t.Fatalf("read re-signed module: %v", err)
		}

		entries = append(entries,
			cpioEntry{Name: fmt.Sprintf("mod/%d-original.ko", i), Mode: 0100644, Data: original},
			cpioEntry{Name: fmt.Sprintf("mod/%d-unsigned.ko", i), Mode: 0100644, Data: unsigned},
			cpioEntry{Name: fmt.Sprintf("mod/%d-resigned.ko", i), Mode: 0100644, Data: resigned},
		)

		modName := strings.ReplaceAll(strings.TrimSuffix(path.Base(rel), ".ko"), "-", "_")
		// Per candidate: (1) the unsigned variant must be rejected, (2) the
		// build-signed variant must load — which also proves the module's
		// init succeeds in this bare VM, qualifying it as the candidate —
		// and (3) the pkg/modulesign-resigned variant must load after the
		// original is unloaded. A failed rmmod would make step 3 fail with
		// EEXIST for reasons unrelated to signing, so it moves on to the
		// next candidate instead of reporting a false signature failure.
		fmt.Fprintf(&script, `
# candidate %[1]d: %[2]s
if $bb insmod /mod/%[1]d-unsigned.ko 2>/tmp/err-%[1]d; then
    echo %[3]s
else
    echo "%[4]s (candidate %[1]d)"
    $bb cat /tmp/err-%[1]d
fi
if $bb insmod /mod/%[1]d-original.ko 2>/tmp/oerr-%[1]d; then
    echo "%[5]s (candidate %[1]d %[2]s)"
    if $bb rmmod %[6]s 2>/tmp/dmerr-%[1]d; then
        if $bb insmod /mod/%[1]d-resigned.ko 2>/tmp/rerr-%[1]d; then
            echo "%[7]s (candidate %[1]d %[2]s)"
        else
            echo "%[8]s (candidate %[1]d)"
            $bb cat /tmp/rerr-%[1]d
        fi
        echo %[10]s
        $bb poweroff -f
    else
        echo "%[9]s (candidate %[1]d %[6]s) - trying next candidate"
        $bb cat /tmp/dmerr-%[1]d
    fi
fi
`,
			i, rel,
			markerUnsignedLoaded,
			markerUnsignedRejected,
			markerOriginalLoaded,
			modName,
			markerResignedLoaded,
			markerResignedFailed,
			markerRmmodFailed,
			markerDone)
	}
	script.WriteString("echo " + markerNoCandidate + "\n")
	script.WriteString("$bb poweroff -f\n")

	entries = append(entries, cpioEntry{Name: "init", Mode: 0100755, Data: []byte(script.String())})

	initramfsPath := filepath.Join(stageDir, "initramfs.cpio.gz")
	f, err := os.Create(initramfsPath)
	if err != nil {
		t.Fatalf("create initramfs: %v", err)
	}
	defer f.Close()
	if err := writeCPIO(f, entries); err != nil {
		t.Fatalf("write initramfs: %v", err)
	}
	return initramfsPath
}

// TestFIPSKernelModuleSignatureEnforcement boots the prebuilt FIPS kernel
// (CONFIG_MODULE_SIG_FORCE) under QEMU and proves, on a real in-tree module:
//
//  1. the build-signed module loads (the baked CONFIG_MODULE_SIG_KEY chain
//     works end to end),
//  2. the same module with its signature stripped is REJECTED at insmod with
//     ENOKEY ("Required key not available"),
//  3. the stripped module re-signed by pkg/modulesign with the stable
//     platform key loads — proving the platform signer against the real
//     kernel verifier.
//
// The FIPS kernel takes hours to build, so this test consumes prebuilt
// artifacts and FAILS with a typed setup error when they are absent (the
// secureboot target is excluded from the `all` sweep for this reason).
func TestFIPSKernelModuleSignatureEnforcement(t *testing.T) {
	ctx := context.Background()

	kernel := requireArtifact(t, EnvFIPSKernelImage, "prebuilt vmlinuz-fips image")
	modulesTar := requireArtifact(t, EnvFIPSModulesTar, "matching modules-fips-<kver>.tar.gz")
	signingKeyPath := requireArtifact(t, EnvFIPSModuleSigningKey, "stable module-signing key the kernel was built with")
	busybox := findBusybox(t)

	msk, err := pkgsecureboot.LoadModuleSigningKey(signingKeyPath)
	if err != nil {
		t.Fatalf("load stable module-signing key: %v", err)
	}

	mods := loadFIPSModules(t, modulesTar)
	candidates := pickInsmodCandidates(t, mods, maxInsmodCandidates)
	t.Logf("kernel %s, insmod candidates: %v", mods.KernelVersion, candidates)

	initramfs := buildInsmodInitramfs(t, busybox, candidates, mods, msk)

	bctx, cancel := context.WithTimeout(ctx, fipsBootTimeout)
	defer cancel()

	args := []string{
		"-machine", "q35",
		"-accel", "tcg",
		"-m", "1024",
		"-display", "none",
		"-serial", "stdio",
		"-net", "none",
		"-no-reboot",
		"-kernel", kernel,
		"-initrd", initramfs,
		"-append", "console=ttyS0 rdinit=/init panic=-1 loglevel=4",
	}
	res := runQEMU(t, bctx, args, markerDone, markerNoCandidate, markerUnsignedLoaded)

	switch res.Marker {
	case markerDone:
		// Fall through to transcript assertions.
	case markerUnsignedLoaded:
		t.Fatalf("FIPS kernel LOADED an unsigned module — CONFIG_MODULE_SIG_FORCE is not enforcing; transcript:\n%s", res.Output)
	case markerNoCandidate:
		t.Fatalf("no candidate module's build-signed variant loaded in the VM; transcript:\n%s", res.Output)
	default:
		t.Fatal(ErrSerialTimeout{Markers: []string{markerDone}, Output: res.Output})
	}

	if !strings.Contains(res.Output, markerUnsignedRejected) {
		t.Fatalf("unsigned module was not rejected; transcript:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, enokeyMessage) {
		t.Fatalf("unsigned-module rejection did not report ENOKEY (%q); transcript:\n%s", enokeyMessage, res.Output)
	}
	if !strings.Contains(res.Output, markerOriginalLoaded) {
		t.Fatalf("build-signed module did not load; transcript:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, markerResignedLoaded) {
		t.Fatalf("pkg/modulesign-signed module did not load in the FIPS kernel; transcript:\n%s", res.Output)
	}
	if strings.Contains(res.Output, markerResignedFailed) {
		t.Fatalf("pkg/modulesign re-sign failed in the FIPS kernel; transcript:\n%s", res.Output)
	}
}
