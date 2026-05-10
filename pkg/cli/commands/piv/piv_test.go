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

package piv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func testFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
}

func TestNewCommand_Structure(t *testing.T) {
	cmd := NewCommand(testFlags())
	if cmd.Use != "piv" {
		t.Errorf("expected Use 'piv', got %q", cmd.Use)
	}
	if cmd.Long == "" {
		t.Error("expected non-empty Long")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	cmd := NewCommand(testFlags())

	expected := map[string]bool{
		"list-devices": false,
		"list-slots":   false,
		"info":         false,
		"generate":     false,
		"import":       false,
		"sign":         false,
		"attest":       false,
		"reset":        false,
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

func TestListDevices_NoLocalFlags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"list-devices"})
	if err != nil {
		t.Fatalf("could not find list-devices: %v", err)
	}
	if sub.Flags().HasFlags() {
		t.Error("list-devices: expected zero local flags")
	}
}

func TestListSlots_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"list-slots"})
	if err != nil {
		t.Fatalf("could not find list-slots: %v", err)
	}
	if sub.Flags().Lookup("device") == nil {
		t.Error("list-slots: missing --device")
	}
}

func TestInfo_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"info"})
	if err != nil {
		t.Fatalf("could not find info: %v", err)
	}
	for _, n := range []string{"slot", "device"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("info: missing --%s", n)
		}
	}
}

func TestGenerate_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"generate"})
	if err != nil {
		t.Fatalf("could not find generate: %v", err)
	}
	for _, n := range []string{"slot", "algorithm", "pin"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("generate: missing --%s", n)
		}
	}
}

func TestImport_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"import"})
	if err != nil {
		t.Fatalf("could not find import: %v", err)
	}
	for _, n := range []string{"slot", "key-file", "pin"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("import: missing --%s", n)
		}
	}
}

func TestSign_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"sign"})
	if err != nil {
		t.Fatalf("could not find sign: %v", err)
	}
	for _, n := range []string{"slot", "input-file", "pin"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("sign: missing --%s", n)
		}
	}
}

func TestAttest_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"attest"})
	if err != nil {
		t.Fatalf("could not find attest: %v", err)
	}
	if sub.Flags().Lookup("slot") == nil {
		t.Error("attest: missing --slot")
	}
}

func TestReset_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"reset"})
	if err != nil {
		t.Fatalf("could not find reset: %v", err)
	}
	for _, n := range []string{"device", "yes-i-understand"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("reset: missing --%s", n)
		}
	}
}

// =============================================================================
// runXxx validation-path tests (don't touch the network)
// =============================================================================

func TestRunListSlots_DeviceRequired(t *testing.T) {
	err := runListSlots(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &listSlotsFlags{})
	if err == nil {
		t.Fatal("expected ErrDeviceRequired, got nil")
	}
	if _, ok := err.(ErrDeviceRequired); !ok {
		t.Errorf("expected ErrDeviceRequired, got %T", err)
	}
}

func TestRunInfo_SlotRequired(t *testing.T) {
	err := runInfo(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &infoFlags{})
	if err == nil {
		t.Fatal("expected ErrSlotRequired, got nil")
	}
	if _, ok := err.(ErrSlotRequired); !ok {
		t.Errorf("expected ErrSlotRequired, got %T", err)
	}
}

func TestRunGenerate_Validation(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name    string
		flags   *generateFlags
		checkFn func(error) bool
	}{
		{
			name:    "missing slot",
			flags:   &generateFlags{},
			checkFn: func(err error) bool { _, ok := err.(ErrSlotRequired); return ok },
		},
		{
			name:    "invalid algorithm",
			flags:   &generateFlags{slot: "9a", algorithm: "ghost"},
			checkFn: func(err error) bool { _, ok := err.(ErrInvalidAlgorithm); return ok },
		},
		{
			name:    "missing pin",
			flags:   &generateFlags{slot: "9a", algorithm: "rsa"},
			checkFn: func(err error) bool { _, ok := err.(ErrPINRequired); return ok },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runGenerate(commonFlags, tc.flags)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.checkFn(err) {
				t.Errorf("unexpected error type %T: %v", err, err)
			}
		})
	}
}

func TestRunImport_Validation(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runImport(commonFlags, &importFlags{}); err == nil {
		t.Error("expected ErrSlotRequired")
	} else if _, ok := err.(ErrSlotRequired); !ok {
		t.Errorf("unexpected error type: %T", err)
	}

	if err := runImport(commonFlags, &importFlags{slot: "9a"}); err == nil {
		t.Error("expected ErrKeyFileRequired")
	} else if _, ok := err.(ErrKeyFileRequired); !ok {
		t.Errorf("unexpected error type: %T", err)
	}

	if err := runImport(commonFlags, &importFlags{slot: "9a", keyFile: "k"}); err == nil {
		t.Error("expected ErrPINRequired")
	} else if _, ok := err.(ErrPINRequired); !ok {
		t.Errorf("unexpected error type: %T", err)
	}

	if err := runImport(commonFlags, &importFlags{slot: "9a", keyFile: "/tmp/does-not-exist-piv-import", pin: "123"}); err == nil {
		t.Error("expected ErrKeyFileRead")
	} else {
		var readErr ErrKeyFileRead
		if !errors.As(err, &readErr) {
			t.Errorf("expected ErrKeyFileRead, got %T: %v", err, err)
		}
	}
}

func TestRunImport_ReadsValidFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "key.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runImport(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &importFlags{
		slot: "9a", keyFile: path, pin: "123",
	})
	if err == nil {
		t.Fatal("expected error (no context / not wired), got nil")
	}
	var readErr ErrKeyFileRead
	if errors.As(err, &readErr) {
		t.Errorf("unexpected ErrKeyFileRead: %v", err)
	}
}

func TestRunSign_Validation(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runSign(commonFlags, &signFlags{}); err == nil {
		t.Error("expected ErrSlotRequired")
	} else if _, ok := err.(ErrSlotRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}

	if err := runSign(commonFlags, &signFlags{slot: "9a"}); err == nil {
		t.Error("expected ErrInputFileRequired")
	} else if _, ok := err.(ErrInputFileRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}

	if err := runSign(commonFlags, &signFlags{slot: "9a", inputFile: "x"}); err == nil {
		t.Error("expected ErrPINRequired")
	} else if _, ok := err.(ErrPINRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}

	if err := runSign(commonFlags, &signFlags{slot: "9a", inputFile: "/tmp/does-not-exist-piv-sign", pin: "123"}); err == nil {
		t.Error("expected ErrInputFileRead")
	} else {
		var readErr ErrInputFileRead
		if !errors.As(err, &readErr) {
			t.Errorf("expected ErrInputFileRead, got %T: %v", err, err)
		}
	}
}

func TestRunAttest_SlotRequired(t *testing.T) {
	err := runAttest(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &attestFlags{})
	if err == nil {
		t.Fatal("expected ErrSlotRequired")
	}
	if _, ok := err.(ErrSlotRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}
}

func TestRunReset_Validation(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runReset(commonFlags, &resetFlags{}); err == nil {
		t.Error("expected ErrDeviceRequired")
	} else if _, ok := err.(ErrDeviceRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}

	if err := runReset(commonFlags, &resetFlags{device: "dev"}); err == nil {
		t.Error("expected ErrResetNotConfirmed")
	} else if _, ok := err.(ErrResetNotConfirmed); !ok {
		t.Errorf("unexpected type: %T", err)
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []error{
		ErrDeviceRequired{},
		ErrSlotRequired{},
		ErrPINRequired{},
		ErrInvalidAlgorithm{Value: "x"},
		ErrKeyFileRequired{},
		ErrInputFileRequired{},
		ErrKeyFileRead{Path: "/tmp/x", Cause: errors.New("boom")},
		ErrInputFileRead{Path: "/tmp/x", Cause: errors.New("boom")},
		ErrResetNotConfirmed{},
	}
	for _, e := range tests {
		if !strings.HasPrefix(e.Error(), "piv:") {
			t.Errorf("expected %T error to start with 'piv:', got %q", e, e.Error())
		}
	}
}

func TestAlgorithmsMap(t *testing.T) {
	for _, name := range []string{"rsa", "ecdsa", "ed25519"} {
		if _, ok := algorithms[name]; !ok {
			t.Errorf("algorithms missing %q", name)
		}
	}
}
