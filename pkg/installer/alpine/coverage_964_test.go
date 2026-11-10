package alpine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// fakeChrootScript stands in for chroot(8) so the FIPS OpenSSL flow runs
// without root. It records each invocation in $FAKE_CHROOT_LOG, fails with
// exit 1 when its first command equals $FAKE_CHROOT_FAIL, and, like
// `openssl fipsinstall`, writes <root>/etc/ssl/fipsmodule.cnf unless
// $FAKE_CHROOT_SKIP_CNF is 1.
const fakeChrootScript = `#!/bin/sh
root="$1"
shift
echo "$*" >> "$FAKE_CHROOT_LOG"
if [ "$1" = "$FAKE_CHROOT_FAIL" ]; then
	echo "fake $1 failure"
	exit 1
fi
if [ "$1" = "openssl" ] && [ "$FAKE_CHROOT_SKIP_CNF" != "1" ]; then
	: > "$root/etc/ssl/fipsmodule.cnf"
fi
exit 0
`

// fipsFixture is a FIPS installer wired to a temporary ISO artifacts
// directory and mount point, with the fake chroot first on PATH.
type fipsFixture struct {
	installer  *FIPSInstaller
	artifacts  string
	mountPoint string
	chrootLog  string
}

var fakeFIPSModule = []byte("validated fips provider module")

func newFIPSFixture(t *testing.T, failCmd string, skipCnf bool) *fipsFixture {
	t.Helper()
	tmpDir := t.TempDir()

	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "chroot"), []byte(fakeChrootScript), 0755); err != nil {
		t.Fatalf("write fake chroot: %v", err)
	}
	chrootLog := filepath.Join(tmpDir, "chroot.log")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CHROOT_LOG", chrootLog)
	t.Setenv("FAKE_CHROOT_FAIL", failCmd)
	skip := "0"
	if skipCnf {
		skip = "1"
	}
	t.Setenv("FAKE_CHROOT_SKIP_CNF", skip)

	artifacts := filepath.Join(tmpDir, "fips-artifacts")
	moduleDir := filepath.Join(artifacts, "usr", "lib", "ossl-modules")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		t.Fatalf("create artifacts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "fips.so"), fakeFIPSModule, 0644); err != nil {
		t.Fatalf("write fips.so: %v", err)
	}

	mountPoint := filepath.Join(tmpDir, "mnt")
	opensslDir := filepath.Join(mountPoint, "usr", "bin")
	if err := os.MkdirAll(opensslDir, 0755); err != nil {
		t.Fatalf("create mount point: %v", err)
	}
	if err := os.WriteFile(filepath.Join(opensslDir, "openssl"), []byte("binary"), 0755); err != nil {
		t.Fatalf("write openssl: %v", err)
	}

	installer, err := NewFIPSInstaller(&fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewFIPSInstaller: %v", err)
	}
	fipsInstaller := installer.(*FIPSInstaller)
	fipsInstaller.artifactsDir = artifacts

	return &fipsFixture{
		installer:  fipsInstaller,
		artifacts:  artifacts,
		mountPoint: mountPoint,
		chrootLog:  chrootLog,
	}
}

// addKernelArtifacts puts the pre-built FIPS kernel and modules archive on
// the fixture's ISO so Install can run its kernel stage.
func (f *fipsFixture) addKernelArtifacts(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.artifacts, "vmlinuz-fips"), []byte("kernel"), 0644); err != nil {
		t.Fatalf("write kernel: %v", err)
	}
	if err := createMockModulesArchive(filepath.Join(f.artifacts, "modules-fips.tar.gz")); err != nil {
		t.Fatalf("write modules archive: %v", err)
	}
}

func (f *fipsFixture) chrootCalls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.chrootLog)
	if err != nil {
		t.Fatalf("read chroot log: %v", err)
	}
	return string(data)
}

func TestFIPSInstaller_ConfigureOpenSSL_964_Success(t *testing.T) {
	f := newFIPSFixture(t, "", false)

	if err := f.installer.ConfigureOpenSSL(context.Background()); err != nil {
		t.Fatalf("ConfigureOpenSSL: %v", err)
	}

	copied, err := os.ReadFile(filepath.Join(f.mountPoint, "usr", "lib", "ossl-modules", "fips.so"))
	if err != nil {
		t.Fatalf("fips.so not installed: %v", err)
	}
	if !bytes.Equal(copied, fakeFIPSModule) {
		t.Errorf("installed fips.so = %q, want the ISO module %q", copied, fakeFIPSModule)
	}
	cnf, err := os.ReadFile(filepath.Join(f.mountPoint, "etc", "ssl", "openssl.cnf"))
	if err != nil {
		t.Fatalf("openssl.cnf not written: %v", err)
	}
	if !strings.Contains(string(cnf), "default_properties = fips=yes") {
		t.Errorf("openssl.cnf does not default to FIPS properties:\n%s", cnf)
	}

	calls := f.chrootCalls(t)
	for _, want := range []string{
		"apk add openssl",
		"openssl fipsinstall -out /etc/ssl/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("chroot was not run with %q; calls:\n%s", want, calls)
		}
	}
	if err := f.installer.Verify(); err != nil {
		t.Errorf("Verify after ConfigureOpenSSL: %v", err)
	}
}

func TestFIPSInstaller_ConfigureOpenSSL_964_Errors(t *testing.T) {
	tests := []struct {
		name       string
		failCmd    string
		skipCnf    bool
		removeISO  bool
		noOpenSSL  bool
		wantPrefix string
		wantInner  string
		check      func(t *testing.T, err error)
	}{
		{
			name:       "apk add fails",
			failCmd:    "apk",
			wantPrefix: "failed to install OpenSSL FIPS",
			wantInner:  "failed to install OpenSSL package",
			check: func(t *testing.T, err error) {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Errorf("error does not unwrap to *exec.ExitError: %v", err)
				}
			},
		},
		{
			name:       "fips.so missing on ISO",
			removeISO:  true,
			wantPrefix: "failed to install OpenSSL FIPS",
			wantInner:  "Was the ISO built with --fips flag?",
			check: func(t *testing.T, err error) {
				var msgErr *MessageError
				if !errors.As(err, &msgErr) {
					t.Errorf("error does not unwrap to *MessageError: %v", err)
				}
			},
		},
		{
			name:       "openssl binary missing in chroot",
			noOpenSSL:  true,
			wantPrefix: "failed to configure OpenSSL FIPS",
			wantInner:  "openssl binary not found in chroot",
			check: func(t *testing.T, err error) {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("error does not unwrap to fs.ErrNotExist: %v", err)
				}
			},
		},
		{
			name:       "openssl fipsinstall fails",
			failCmd:    "openssl",
			wantPrefix: "failed to configure OpenSSL FIPS",
			wantInner:  "fake openssl failure",
			check: func(t *testing.T, err error) {
				var cmdErr *CommandOutputError
				if !errors.As(err, &cmdErr) {
					t.Fatalf("error does not unwrap to *CommandOutputError: %v", err)
				}
				var exitErr *exec.ExitError
				if !errors.As(cmdErr, &exitErr) {
					t.Errorf("CommandOutputError does not unwrap to *exec.ExitError: %v", cmdErr)
				}
			},
		},
		{
			name:       "fipsinstall writes no config",
			skipCnf:    true,
			wantPrefix: "failed to configure OpenSSL FIPS",
			wantInner:  "fipsmodule.cnf was not created",
			check: func(t *testing.T, err error) {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("error does not unwrap to fs.ErrNotExist: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFIPSFixture(t, tt.failCmd, tt.skipCnf)
			if tt.removeISO {
				if err := os.Remove(filepath.Join(f.artifacts, "usr", "lib", "ossl-modules", "fips.so")); err != nil {
					t.Fatalf("remove fips.so: %v", err)
				}
			}
			if tt.noOpenSSL {
				if err := os.Remove(filepath.Join(f.mountPoint, "usr", "bin", "openssl")); err != nil {
					t.Fatalf("remove openssl: %v", err)
				}
			}

			err := f.installer.ConfigureOpenSSL(context.Background())
			if err == nil {
				t.Fatal("ConfigureOpenSSL succeeded, want an error")
			}
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tt.wantPrefix {
				t.Fatalf("error = %v, want a *WrappedError %q", err, tt.wantPrefix)
			}
			if !strings.Contains(err.Error(), tt.wantInner) {
				t.Errorf("error %q does not mention %q", err, tt.wantInner)
			}
			tt.check(t, err)
		})
	}
}

func TestFIPSInstaller_Install_964_Success(t *testing.T) {
	f := newFIPSFixture(t, "", false)
	f.addKernelArtifacts(t)

	if err := f.installer.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	kernel, err := os.ReadFile(filepath.Join(f.mountPoint, "boot", "vmlinuz-fips"))
	if err != nil || string(kernel) != "kernel" {
		t.Errorf("boot/vmlinuz-fips = %q, %v; want the ISO kernel", kernel, err)
	}
	if !strings.Contains(f.chrootCalls(t), "depmod -a 6.1.0-fips") {
		t.Errorf("depmod was not run for the FIPS kernel; calls:\n%s", f.chrootCalls(t))
	}
	if _, err := os.Stat(filepath.Join(f.mountPoint, "etc", "ssl", "fipsmodule.cnf")); err != nil {
		t.Errorf("fipsmodule.cnf missing after Install: %v", err)
	}
}

func TestFIPSInstaller_Install_964_Errors(t *testing.T) {
	tests := []struct {
		name       string
		failCmd    string
		removeISO  bool
		noOpenSSL  bool
		wantPrefix string
	}{
		{name: "OpenSSL package install fails", failCmd: "apk", wantPrefix: "failed to install OpenSSL FIPS"},
		{name: "fips.so missing on ISO", removeISO: true, wantPrefix: "failed to install OpenSSL FIPS"},
		{name: "openssl binary missing", noOpenSSL: true, wantPrefix: "failed to configure OpenSSL FIPS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFIPSFixture(t, tt.failCmd, false)
			f.addKernelArtifacts(t)
			if tt.removeISO {
				if err := os.Remove(filepath.Join(f.artifacts, "usr", "lib", "ossl-modules", "fips.so")); err != nil {
					t.Fatalf("remove fips.so: %v", err)
				}
			}
			if tt.noOpenSSL {
				if err := os.Remove(filepath.Join(f.mountPoint, "usr", "bin", "openssl")); err != nil {
					t.Fatalf("remove openssl: %v", err)
				}
			}

			err := f.installer.Install(context.Background())
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tt.wantPrefix {
				t.Fatalf("Install error = %v, want a *WrappedError %q", err, tt.wantPrefix)
			}
			if _, statErr := os.Stat(filepath.Join(f.mountPoint, "boot", "vmlinuz-fips")); statErr != nil {
				t.Errorf("kernel stage should have completed before the OpenSSL failure: %v", statErr)
			}
		})
	}
}

func TestErrors_964_UnwrapChains(t *testing.T) {
	cause := &MessageError{Msg: "root cause"}

	tests := []struct {
		name    string
		err     error
		wantMsg string
		wantIs  []error
	}{
		{
			name:    "WrappedError",
			err:     &WrappedError{Msg: "outer", Err: cause},
			wantMsg: "outer: root cause",
			wantIs:  []error{cause},
		},
		{
			name:    "SentinelCauseError",
			err:     &SentinelCauseError{Sentinel: fips.ErrVerificationFailed, Cause: cause},
			wantMsg: fips.ErrVerificationFailed.Error() + ": root cause",
			wantIs:  []error{fips.ErrVerificationFailed, cause},
		},
		{
			name:    "CommandOutputError",
			err:     &CommandOutputError{Msg: "run", Err: cause, Detail: "\nOutput: x"},
			wantMsg: "run: root cause\nOutput: x",
			wantIs:  []error{cause},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
			for _, target := range tt.wantIs {
				if !errors.Is(tt.err, target) {
					t.Errorf("errors.Is(%v, %v) = false", tt.err, target)
				}
			}
			if errors.Is(tt.err, fips.ErrOpenSSLNotConfigured) {
				t.Errorf("%v must not match an unrelated sentinel", tt.err)
			}
		})
	}
}
