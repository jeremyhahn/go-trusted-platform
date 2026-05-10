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

package fido2

import (
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

	if cmd.Use != "fido2" {
		t.Errorf("expected Use 'fido2', got %q", cmd.Use)
	}
	if cmd.Long == "" {
		t.Error("expected non-empty Long")
	}
	if !strings.Contains(cmd.Long, "Migration note") {
		t.Error("expected Long to contain migration note")
	}
	if strings.Contains(cmd.Long, "LUKS disk encryption") {
		t.Error("Long should no longer describe LUKS")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	cmd := NewCommand(testFlags())

	expected := map[string]bool{
		"list-devices": false,
		"wait-device":  false,
		"info":         false,
		"register":     false,
		"authenticate": false,
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

	// Legacy LUKS-flavored subcommands MUST be gone.
	removed := []string{"enroll", "list", "remove", "test"}
	for _, gone := range removed {
		for _, sub := range cmd.Commands() {
			if sub.Use == gone {
				t.Errorf("legacy LUKS subcommand %q should have been removed", gone)
			}
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

func TestWaitDevice_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"wait-device"})
	if err != nil {
		t.Fatalf("could not find wait-device: %v", err)
	}
	if sub.Flags().Lookup("timeout") == nil {
		t.Error("wait-device: missing --timeout")
	}
}

func TestInfo_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"info"})
	if err != nil {
		t.Fatalf("could not find info: %v", err)
	}
	if sub.Flags().Lookup("device") == nil {
		t.Error("info: missing --device")
	}
}

func TestRegister_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"register"})
	if err != nil {
		t.Fatalf("could not find register: %v", err)
	}
	for _, n := range []string{"username", "role", "require-pin", "require-uv", "rp-id"} {
		if sub.Flags().Lookup(n) == nil {
			t.Errorf("register: missing --%s", n)
		}
	}
}

func TestAuthenticate_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"authenticate"})
	if err != nil {
		t.Fatalf("could not find authenticate: %v", err)
	}
	if sub.Flags().Lookup("credential-id") == nil {
		t.Error("authenticate: missing --credential-id")
	}
}

// =============================================================================
// Validation tests
// =============================================================================

func TestRunInfo_DeviceRequired(t *testing.T) {
	err := runInfo(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &infoFlags{})
	if err == nil {
		t.Fatal("expected ErrDeviceRequired, got nil")
	}
	if _, ok := err.(ErrDeviceRequired); !ok {
		t.Errorf("expected ErrDeviceRequired, got %T", err)
	}
}

func TestRunRegister_Validation(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runRegister(commonFlags, &registerFlags{}); err == nil {
		t.Error("expected ErrUsernameRequired")
	} else if _, ok := err.(ErrUsernameRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}

	// Invalid role
	if err := runRegister(commonFlags, &registerFlags{username: "u", role: "ghost"}); err == nil {
		t.Error("expected ErrInvalidRole")
	} else if _, ok := err.(ErrInvalidRole); !ok {
		t.Errorf("unexpected type: %T", err)
	}
}

func TestRunAuthenticate_Validation(t *testing.T) {
	err := runAuthenticate(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &authenticateFlags{})
	if err == nil {
		t.Fatal("expected ErrCredentialIDRequired")
	}
	if _, ok := err.(ErrCredentialIDRequired); !ok {
		t.Errorf("unexpected type: %T", err)
	}
}

func TestRunWaitDevice_Validation(t *testing.T) {
	err := runWaitDevice(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &waitDeviceFlags{timeout: -1})
	if err == nil {
		t.Fatal("expected ErrInvalidTimeout")
	}
	if _, ok := err.(ErrInvalidTimeout); !ok {
		t.Errorf("unexpected type: %T", err)
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []error{
		ErrDeviceRequired{},
		ErrUsernameRequired{},
		ErrCredentialIDRequired{},
		ErrInvalidRole{Value: "x"},
		ErrInvalidTimeout{Value: -1},
	}
	for _, e := range tests {
		if !strings.HasPrefix(e.Error(), "fido2:") {
			t.Errorf("expected %T to start with 'fido2:', got %q", e, e.Error())
		}
	}
}

func TestRolesMap(t *testing.T) {
	for _, name := range []string{"", "so", "admin", "user"} {
		if _, ok := roles[name]; !ok {
			t.Errorf("roles missing %q", name)
		}
	}
}
