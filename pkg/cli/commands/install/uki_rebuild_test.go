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

package install

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
)

func TestIsFileURI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"file:///etc/secure-boot/DB.key", true},
		{"FILE:///etc/secure-boot/DB.key", true},
		{"kms://platform/secureboot/db", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isFileURI(c.uri); got != c.want {
			t.Errorf("isFileURI(%q) = %v, want %v", c.uri, got, c.want)
		}
	}
}

func TestNewUKIRebuildCommand_Flags(t *testing.T) {
	cmd := newUKIRebuildCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	if cmd.Use != "uki-rebuild" {
		t.Errorf("Use = %q, want uki-rebuild", cmd.Use)
	}
	for _, name := range []string{"kver", "config", "uki"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected --%s flag", name)
		}
	}
}

func TestLoadUKIRebuildConfig_NotFound(t *testing.T) {
	// Neutralise the host fallbacks so the test never reads a real
	// /etc/platformd config.
	orig := ukiRebuildConfigFallbacks
	ukiRebuildConfigFallbacks = []string{filepath.Join(t.TempDir(), "nope.yaml")}
	t.Cleanup(func() { ukiRebuildConfigFallbacks = orig })

	_, err := loadUKIRebuildConfig(getInstallLogger(false, false), filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected ErrUKIRebuildConfigNotFound, got nil")
	}
	var nf ErrUKIRebuildConfigNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrUKIRebuildConfigNotFound, got %T: %v", err, err)
	}
}

func TestRunUKIRebuild_DisabledSecureBootNoop(t *testing.T) {
	// A config without a secure-boot section yields SecureBoot == nil, so the
	// verb logs "nothing to re-sign" and returns nil without touching the ESP or
	// connecting to a daemon.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("os:\n  hostname: test\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := runUKIRebuild(&cli.CommonFlags{}, &ukiRebuildFlags{config: cfgPath})
	if err != nil {
		t.Fatalf("runUKIRebuild with Secure Boot disabled should be a no-op, got: %v", err)
	}
}

// writeUKIRebuildConfig writes a platform config enabling Secure Boot with the
// given resign-mode and DB key-uri, and returns its path.
func writeUKIRebuildConfig(t *testing.T, resignMode, keyURI string) string {
	t.Helper()
	cfg := "os:\n  hostname: test\nsecure-boot:\n  enabled: true\n" +
		"  resign-mode: " + resignMode + "\n" +
		"  db:\n    key-uri: \"" + keyURI + "\"\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRunUKIRebuild_RemoteModeWithoutKMSKeyRef(t *testing.T) {
	// resign-mode remote needs a KMS key identifier; an empty key-uri or a
	// bare "kms://" scheme is refused before any SDK connection is attempted.
	for _, keyURI := range []string{"", "kms://"} {
		t.Run(keyURI, func(t *testing.T) {
			cfgPath := writeUKIRebuildConfig(t, installer.SecureBootResignModeRemote, keyURI)
			err := runUKIRebuild(&cli.CommonFlags{}, &ukiRebuildFlags{config: cfgPath})
			var refErr ErrRemoteSignKeyRef
			if !errors.As(err, &refErr) {
				t.Fatalf("expected ErrRemoteSignKeyRef, got %T: %v", err, err)
			}
			if refErr.KeyURI != keyURI {
				t.Errorf("KeyURI = %q, want %q", refErr.KeyURI, keyURI)
			}
		})
	}
}

func TestRunUKIRebuild_RemoteModeWithoutContext(t *testing.T) {
	// A kms:// DB key in remote mode needs the platform SDK client; with no CLI
	// context the setup fails with the typed error wrapping the CLI cause.
	cfgPath := writeUKIRebuildConfig(t, installer.SecureBootResignModeRemote, "kms://platform/secureboot/db")
	err := runUKIRebuild(&cli.CommonFlags{}, &ukiRebuildFlags{config: cfgPath})
	var setupErr ErrRemoteSignerSetup
	if !errors.As(err, &setupErr) {
		t.Fatalf("expected ErrRemoteSignerSetup, got %T: %v", err, err)
	}
	var noCtx cli.ErrNoContextSet
	if !errors.As(err, &noCtx) {
		t.Fatalf("expected the wrapped cli.ErrNoContextSet, got %v", err)
	}
}

func TestRunUKIRebuild_FailureLeavesExistingUKI(t *testing.T) {
	// A local file:// DB key needs no SDK connection. The kernel version does
	// not exist and the key file is absent, so the rebuild must fail before it
	// writes anything, leaving the installed UKI untouched.
	keyPath := filepath.Join(t.TempDir(), "DB.key")
	cfgPath := writeUKIRebuildConfig(t, installer.SecureBootResignModeLocal, "file://"+keyPath)
	espUKI := filepath.Join(t.TempDir(), "platform.efi")
	original := []byte("installed UKI")
	if err := os.WriteFile(espUKI, original, 0o644); err != nil {
		t.Fatalf("write ESP UKI: %v", err)
	}

	err := runUKIRebuild(&cli.CommonFlags{}, &ukiRebuildFlags{
		config:     cfgPath,
		kver:       "0.0.0-uki-rebuild-test-absent",
		espUKIPath: espUKI,
	})
	if err == nil {
		t.Fatal("expected the rebuild to fail without a kernel or DB key")
	}
	got, readErr := os.ReadFile(espUKI)
	if readErr != nil {
		t.Fatalf("read ESP UKI: %v", readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("ESP UKI was modified on failure: %q", got)
	}
}

func TestNewRemoteSignerSeam(t *testing.T) {
	sb := &installer.SecureBootConfig{
		Enabled:    true,
		ResignMode: installer.SecureBootResignModeRemote,
		DB:         installer.SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
	}

	t.Run("nil flags => setup error", func(t *testing.T) {
		seam, closeFn, err := newRemoteSignerSeam(nil, sb)
		var setupErr ErrRemoteSignerSetup
		if !errors.As(err, &setupErr) || seam != nil || closeFn != nil {
			t.Fatalf("newRemoteSignerSeam(nil) = %v, %v, %v", seam != nil, closeFn != nil, err)
		}
	})

	t.Run("a context yields a seam bound to the SDK client", func(t *testing.T) {
		socket := filepath.Join(socktest.Dir(t), "platformd.sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		flags := &cli.CommonFlags{GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "local", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: socket}}, nil
		}}

		seam, closeFn, err := newRemoteSignerSeam(flags, sb)
		if err != nil {
			t.Fatalf("newRemoteSignerSeam: %v", err)
		}
		if seam == nil || closeFn == nil {
			t.Fatal("expected a seam and a close function")
		}
		defer func() {
			if err := closeFn(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()

		// The seam resolves the signer over the SDK client; a cancelled
		// context must surface as an error, never a nil signer.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		signer, cert, err := seam(ctx, nil)
		if err == nil || signer != nil || cert != nil {
			t.Fatalf("seam(cancelled) = %v, %v, %v", signer, cert, err)
		}
	})
}
