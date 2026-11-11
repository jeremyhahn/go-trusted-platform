package firstboot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// errSentinel is the cause wrapped by WrappedError in these tests.
type errSentinel struct{}

func (errSentinel) Error() string { return "sentinel cause" }

// withConfigFile points the package config flags at a temp file holding
// content and restores them when the test ends. The explicit --config path
// is the first candidate loadPCRsFromConfig stats, so the host's
// /etc/trusted-platform and /boot/efi files are never consulted.
func withConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	origConfig, origConfigDir := firstbootConfig, firstbootConfigDir
	firstbootConfig, firstbootConfigDir = path, dir
	t.Cleanup(func() {
		firstbootConfig, firstbootConfigDir = origConfig, origConfigDir
	})
	return path
}

func TestMessageError_ReturnsMessage(t *testing.T) {
	err := error(&MessageError{Msg: "no config file found"})
	if got := err.Error(); got != "no config file found" {
		t.Fatalf("Error() = %q, want %q", got, "no config file found")
	}
}

func TestWrappedError_FormatsAndUnwraps(t *testing.T) {
	cause := errSentinel{}
	err := error(&WrappedError{Msg: "failed to read config", Err: cause})

	if got, want := err.Error(), "failed to read config: sentinel cause"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is did not reach the wrapped cause")
	}
	var target errSentinel
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not reach the wrapped cause")
	}
	if errors.Is(&WrappedError{Msg: "x", Err: &MessageError{Msg: "y"}}, cause) {
		t.Fatal("errors.Is matched an unrelated cause")
	}
}

func TestLoadPCRsFromConfig_SealPCRKeys(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []uint
	}{
		{
			name:    "root seal-pcrs",
			content: "seal-pcrs: [0, 7]\n",
			want:    []uint{0, 7},
		},
		{
			name:    "tpm.seal-pcrs",
			content: "tpm:\n  seal-pcrs: [4, 9, 11]\n",
			want:    []uint{4, 9, 11},
		},
		{
			name:    "installer.seal-pcrs",
			content: "installer:\n  seal-pcrs: [7]\n",
			want:    []uint{7},
		},
		{
			name:    "root wins over tpm",
			content: "seal-pcrs: [1]\ntpm:\n  seal-pcrs: [2]\n",
			want:    []uint{1},
		},
		{
			name:    "tpm wins over installer",
			content: "tpm:\n  seal-pcrs: [2]\ninstaller:\n  seal-pcrs: [3]\n",
			want:    []uint{2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withConfigFile(t, tt.content)
			got, err := loadPCRsFromConfig(initializeLogger(false, false))
			if err != nil {
				t.Fatalf("loadPCRsFromConfig: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pcrs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadPCRsFromConfig_Errors(t *testing.T) {
	t.Run("seal-pcrs absent", func(t *testing.T) {
		withConfigFile(t, "tpm:\n  device: /dev/tpmrm0\n")
		pcrs, err := loadPCRsFromConfig(initializeLogger(false, false))
		var msgErr *MessageError
		if !errors.As(err, &msgErr) {
			t.Fatalf("err = %v (%T), want *MessageError", err, err)
		}
		if msgErr.Msg != "seal-pcrs not found in config" {
			t.Fatalf("Msg = %q", msgErr.Msg)
		}
		if pcrs != nil {
			t.Fatalf("pcrs = %v, want nil", pcrs)
		}
	})

	t.Run("unparseable yaml", func(t *testing.T) {
		withConfigFile(t, "seal-pcrs: [0, 7\n  : :\n")
		pcrs, err := loadPCRsFromConfig(initializeLogger(false, false))
		var wrapped *WrappedError
		if !errors.As(err, &wrapped) {
			t.Fatalf("err = %v (%T), want *WrappedError", err, err)
		}
		if wrapped.Msg != "failed to read config" || wrapped.Err == nil {
			t.Fatalf("wrapped = %+v", wrapped)
		}
		if pcrs != nil {
			t.Fatalf("pcrs = %v, want nil", pcrs)
		}
	})
}

// TestRunFirstboot_RefusesWithoutPCRSelection covers the guard before the
// executor is built: with no --pcrs and no seal-pcrs in the config (missing
// key or unreadable file), runFirstboot refuses with a typed error rather
// than sealing to an empty PCR policy.
func TestRunFirstboot_RefusesWithoutPCRSelection(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "config without seal-pcrs", content: "tpm:\n  device: /dev/tpmrm0\n"},
		{name: "unparseable config", content: "seal-pcrs: [0, 7\n  : :\n"},
		{name: "empty seal-pcrs", content: "seal-pcrs: []\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withConfigFile(t, tt.content)
			origPCRs := firstbootPCRSelection
			firstbootPCRSelection = nil
			t.Cleanup(func() { firstbootPCRSelection = origPCRs })

			err := runFirstboot(context.Background())
			var msgErr *MessageError
			if !errors.As(err, &msgErr) {
				t.Fatalf("err = %v (%T), want *MessageError", err, err)
			}
			want := "no PCR selection provided - use --pcrs flag or configure seal-pcrs in config.yaml"
			if msgErr.Msg != want {
				t.Fatalf("Msg = %q, want %q", msgErr.Msg, want)
			}
		})
	}
}

// TestNewCommand_RunEReachesPCRGuard drives the command through cobra: the
// --config flag lands in the package state runFirstboot reads, and the
// PCR-selection refusal surfaces as the command's error.
func TestNewCommand_RunEReachesPCRGuard(t *testing.T) {
	path := withConfigFile(t, "tpm:\n  device: /dev/tpmrm0\n")
	origPCRs := firstbootPCRSelection
	t.Cleanup(func() { firstbootPCRSelection = origPCRs })

	cmd := NewCommand(testGetFlags())
	cmd.SetArgs([]string{"--config", path, "--config-dir", filepath.Dir(path)})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.ExecuteContext(context.Background())
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("err = %v (%T), want *MessageError", err, err)
	}
	if firstbootConfig != path {
		t.Fatalf("firstbootConfig = %q, want %q", firstbootConfig, path)
	}
}
