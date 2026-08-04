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

package luks

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func testFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
}

func isRoot() bool { return os.Geteuid() == 0 }

func TestNewCommand_Structure(t *testing.T) {
	cmd := NewCommand(testFlags())

	if cmd.Use != "luks" {
		t.Errorf("expected Use 'luks', got %q", cmd.Use)
	}
	if cmd.Long == "" {
		t.Error("expected non-empty Long")
	}
	if !strings.Contains(cmd.Long, "enroll-fido2") {
		t.Error("expected Long to mention enroll-fido2 migration")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	cmd := NewCommand(testFlags())

	expected := map[string]bool{
		"status":            false,
		"list-slots":        false,
		"info":              false,
		"enroll-passphrase": false,
		"enroll-fido2":      false,
		"enroll-tpm":        false,
		"enroll-recovery":   false,
		"remove-key":        false,
		"test-unlock":       false,
		"change-passphrase": false,
	}

	for _, sub := range cmd.Commands() {
		if _, ok := expected[sub.Use]; ok {
			expected[sub.Use] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
}

func TestStatus_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("could not find status: %v", err)
	}
	if sub.Flags().Lookup("device") == nil {
		t.Error("status: missing --device")
	}
}

func TestEnrollPassphrase_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"enroll-passphrase"})
	if err != nil {
		t.Fatalf("could not find enroll-passphrase: %v", err)
	}
	for _, n := range []string{"device", "existing-passphrase", "new-passphrase"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("enroll-passphrase: missing --%s", n)
		}
	}
}

func TestEnrollFIDO2_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"enroll-fido2"})
	if err != nil {
		t.Fatalf("could not find enroll-fido2: %v", err)
	}
	for _, n := range []string{"device", "existing-passphrase", "credential-id", "require-pin", "require-uv"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("enroll-fido2: missing --%s", n)
		}
	}
}

func TestEnrollTPM_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"enroll-tpm"})
	if err != nil {
		t.Fatalf("could not find enroll-tpm: %v", err)
	}
	for _, n := range []string{"device", "existing-passphrase", "pcrs", "handle"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("enroll-tpm: missing --%s", n)
		}
	}
}

func TestEnrollRecovery_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"enroll-recovery"})
	if err != nil {
		t.Fatalf("could not find enroll-recovery: %v", err)
	}
	for _, n := range []string{"device", "existing-passphrase", "output"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("enroll-recovery: missing --%s", n)
		}
	}
}

func TestRemoveKey_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"remove-key"})
	if err != nil {
		t.Fatalf("could not find remove-key: %v", err)
	}
	for _, n := range []string{"device", "slot"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("remove-key: missing --%s", n)
		}
	}
}

func TestTestUnlock_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"test-unlock"})
	if err != nil {
		t.Fatalf("could not find test-unlock: %v", err)
	}
	for _, n := range []string{"device", "slot"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("test-unlock: missing --%s", n)
		}
	}
}

func TestChangePassphrase_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"change-passphrase"})
	if err != nil {
		t.Fatalf("could not find change-passphrase: %v", err)
	}
	for _, n := range []string{"device", "slot", "old-passphrase", "new-passphrase"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("change-passphrase: missing --%s", n)
		}
	}
}

// =============================================================================
// Validation tests. All mutating runXxx helpers bail out on root check when
// not root, so we structure these to work both as root and non-root.
// =============================================================================

func TestRunStatus_RequiresRoot(t *testing.T) {
	if isRoot() {
		t.Skip("running as root; root check is not the error path here")
	}
	err := runStatus(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &statusFlags{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(ErrRootRequired); !ok {
		t.Errorf("expected ErrRootRequired, got %T: %v", err, err)
	}
}

func TestRunEnrollPassphrase_Validation(t *testing.T) {
	if isRoot() {
		t.Skip("running as root; validation happens after root check")
	}
	err := runEnrollPassphrase(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &enrollPassphraseFlags{})
	var root ErrRootRequired
	if !errors.As(err, &root) {
		t.Errorf("expected ErrRootRequired (non-root), got %T", err)
	}
}

func TestValidateSlot(t *testing.T) {
	tests := []struct {
		slot    int32
		wantErr bool
	}{
		{0, false},
		{15, false},
		{31, false},
		{-1, true},
		{32, true},
		{100, true},
	}
	for _, tc := range tests {
		err := validateSlot(tc.slot)
		if tc.wantErr && err == nil {
			t.Errorf("validateSlot(%d): expected error", tc.slot)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateSlot(%d): unexpected error %v", tc.slot, err)
		}
	}
}

func TestResolveDevice_Explicit(t *testing.T) {
	path, err := resolveDevice("/dev/custom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/dev/custom" {
		t.Errorf("expected /dev/custom, got %q", path)
	}
}

func TestResolveDevice_AutoDetectFail(t *testing.T) {
	// In a container/CI with no candidate block devices, autoDetectLUKSDevice
	// must return ErrDeviceAutoDetectFailed.
	_, err := resolveDevice("")
	if err != nil {
		var autoErr ErrDeviceAutoDetectFailed
		if !errors.As(err, &autoErr) {
			t.Errorf("expected ErrDeviceAutoDetectFailed, got %T: %v", err, err)
		}
	}
	// If err is nil, the host happens to have a LUKS device; accept that.
}

func TestErrors_Messages(t *testing.T) {
	tests := []error{
		ErrRootRequired{},
		ErrDeviceAutoDetectFailed{},
		ErrExistingPassphraseRequired{},
		ErrNewPassphraseRequired{},
		ErrOldPassphraseRequired{},
		ErrCredentialIDRequired{},
		ErrOutputPathRequired{},
		ErrSlotRequired{},
		ErrInvalidSlot{Slot: 99},
		ErrRecoveryKeyWrite{Path: "/tmp/x", Cause: errors.New("boom")},
	}
	for _, e := range tests {
		if !strings.HasPrefix(e.Error(), "luks:") {
			t.Errorf("expected %T to start with 'luks:', got %q", e, e.Error())
		}
	}
}

func TestCheckRoot_NonRootPath(t *testing.T) {
	// Can't force non-root from inside the process; just confirm that the
	// function returns a specific error type shape when not root.
	err := checkRoot()
	if isRoot() {
		if err != nil {
			t.Errorf("expected nil error as root, got %v", err)
		}
		return
	}
	var rootErr ErrRootRequired
	if !errors.As(err, &rootErr) {
		t.Errorf("expected ErrRootRequired, got %T: %v", err, err)
	}
}

func TestCandidateDevices_NonEmpty(t *testing.T) {
	if len(candidateDevices) == 0 {
		t.Error("expected non-empty candidateDevices list")
	}
}

func TestAutoDetectLUKSDevice(t *testing.T) {
	// Either a LUKS device is found (host has LUKS set up) or the canonical
	// auto-detect error is returned.
	_, err := autoDetectLUKSDevice()
	if err == nil {
		return
	}
	var autoErr ErrDeviceAutoDetectFailed
	if !errors.As(err, &autoErr) {
		t.Errorf("expected ErrDeviceAutoDetectFailed, got %T: %v", err, err)
	}
}
