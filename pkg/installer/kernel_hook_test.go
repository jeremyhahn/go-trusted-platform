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

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestWriteKernelUpdateHook verifies the kernel-install drop-in is written to the
// expected target path, is executable, and invokes the uki-rebuild verb with the
// kernel version on add.
func TestWriteKernelUpdateHook(t *testing.T) {
	root := t.TempDir()

	path, err := writeKernelUpdateHook(root)
	if err != nil {
		t.Fatalf("writeKernelUpdateHook: %v", err)
	}

	want := filepath.Join(root, "etc/kernel/install.d/90-trusted-platform-uki.install")
	if path != want {
		t.Errorf("hook path = %q, want %q", path, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat hook: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("hook mode = %v, want 0755", info.Mode().Perm())
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	s := string(body)
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Errorf("hook must start with a #!/bin/sh shebang, got:\n%s", s)
	}
	if !strings.Contains(s, "install uki-rebuild --kver") {
		t.Errorf("hook must invoke 'install uki-rebuild --kver', got:\n%s", s)
	}
	if !strings.Contains(s, `KERNEL_VERSION="${2:-}"`) {
		t.Errorf("hook must read the kernel version from kernel-install arg $2, got:\n%s", s)
	}
	if !strings.Contains(s, "/usr/bin/platformctl") {
		t.Errorf("hook must reference the installed platformctl path, got:\n%s", s)
	}
}

// TestWriteKernelUpdateAPKTrigger verifies the apk commit-hook bridge is written
// to the expected target path, is executable, and gates on a newer kernel before
// invoking the verb.
func TestWriteKernelUpdateAPKTrigger(t *testing.T) {
	root := t.TempDir()

	path, err := writeKernelUpdateAPKTrigger(root)
	if err != nil {
		t.Fatalf("writeKernelUpdateAPKTrigger: %v", err)
	}

	want := filepath.Join(root, "etc/apk/commit_hooks.d/90-trusted-platform-uki")
	if path != want {
		t.Errorf("trigger path = %q, want %q", path, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat trigger: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("trigger mode = %v, want 0755", info.Mode().Perm())
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trigger: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "post-commit") {
		t.Errorf("apk bridge must act on post-commit, got:\n%s", s)
	}
	if !strings.Contains(s, "install uki-rebuild --kver") {
		t.Errorf("apk bridge must invoke the verb, got:\n%s", s)
	}
	if !strings.Contains(s, "-nt") {
		t.Errorf("apk bridge must gate on a newer kernel (-nt test), got:\n%s", s)
	}
}

// TestInstallKernelUpdateHook_SkippedWhenSecureBootDisabled verifies the step is
// a no-op (writes nothing) when Secure Boot is not enabled.
func TestInstallKernelUpdateHook_SkippedWhenSecureBootDisabled(t *testing.T) {
	i := &installer{
		logger: logging.DefaultLogger(),
		config: &Config{SecureBoot: &SecureBootConfig{Enabled: false}},
	}
	if err := i.installKernelUpdateHook(); err != nil {
		t.Fatalf("installKernelUpdateHook (disabled) returned error: %v", err)
	}
	// With Secure Boot disabled it must not have attempted to write to /mnt.
	if _, err := os.Stat("/mnt/etc/kernel/install.d/90-trusted-platform-uki.install"); err == nil {
		t.Error("hook should not be written when Secure Boot is disabled")
	}
}

// TestWriteTargetHook_Idempotent verifies re-writing the hook overwrites cleanly
// and keeps the executable mode.
func TestWriteTargetHook_Idempotent(t *testing.T) {
	root := t.TempDir()
	if _, err := writeKernelUpdateHook(root); err != nil {
		t.Fatalf("first write: %v", err)
	}
	path, err := writeKernelUpdateHook(root)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode after rewrite = %v, want 0755", info.Mode().Perm())
	}
}
