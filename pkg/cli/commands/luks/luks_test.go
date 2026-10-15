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
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

func testFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
}

// asUID makes checkRoot see uid as the effective user ID for one test.
// The package seam makes these tests unsafe to run in parallel.
func asUID(t *testing.T, uid int) {
	t.Helper()
	saved := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = saved })
}

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
// Validation tests. Every mutating runXxx helper checks root first; asUID
// sets the effective user ID checkRoot sees.
// =============================================================================

func TestRunStatus_RequiresRoot(t *testing.T) {
	asUID(t, 1000)
	err := runStatus(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &statusFlags{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(ErrRootRequired); !ok {
		t.Errorf("expected ErrRootRequired, got %T: %v", err, err)
	}
}

func TestRunEnrollPassphrase_Validation(t *testing.T) {
	tests := []struct {
		name  string
		uid   int
		flags enrollPassphraseFlags
		want  error
	}{
		{"not root", 1000, enrollPassphraseFlags{existingPassphrase: "old", newPassphrase: "new"}, ErrRootRequired{}},
		{"no existing passphrase", 0, enrollPassphraseFlags{newPassphrase: "new"}, ErrExistingPassphraseRequired{}},
		{"no new passphrase", 0, enrollPassphraseFlags{existingPassphrase: "old"}, ErrNewPassphraseRequired{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asUID(t, tt.uid)
			err := runEnrollPassphrase(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &tt.flags)
			if !errors.Is(err, tt.want) {
				t.Errorf("expected %T, got %T: %v", tt.want, err, err)
			}
		})
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

type luksOnlyClient struct {
	platform.Client
	rpc platformv1.LUKSServiceClient
}

func (c luksOnlyClient) LUKS() platformv1.LUKSServiceClient { return c.rpc }

type statusRPC struct {
	platformv1.LUKSServiceClient
	device string
}

func (s *statusRPC) Status(_ context.Context, req *platformv1.LUKSStatusRequest, _ ...grpc.CallOption) (*platformv1.LUKSStatusResponse, error) {
	s.device = req.GetDevice()
	return &platformv1.LUKSStatusResponse{Device: req.GetDevice(), IsLuks: true}, nil
}

func TestNewService_DispatchesOverTheSDKClient(t *testing.T) {
	rpc := &statusRPC{}

	svc, err := newService(luksOnlyClient{rpc: rpc})
	if err != nil {
		t.Fatalf("newService() error = %v", err)
	}
	resp, err := svc.Status(context.Background(), &lukssvc.StatusRequest{Device: "/dev/sda2"})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if rpc.device != "/dev/sda2" || !resp.IsLUKS {
		t.Errorf("Status() reached device %q with IsLUKS %v; want /dev/sda2 and true", rpc.device, resp.IsLUKS)
	}
}

func TestNewService_RefusesAClientWithoutTheLUKSService(t *testing.T) {
	svc, err := newService(luksOnlyClient{})
	if svc != nil {
		t.Errorf("expected no service, got %v", svc)
	}

	var unavailable platform.ErrServiceUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected platform.ErrServiceUnavailable, got %v", err)
	}
	if unavailable.Service != lukssvcName {
		t.Errorf("ErrServiceUnavailable.Service = %q, want %q", unavailable.Service, lukssvcName)
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

func TestGeteuidSeamDefault(t *testing.T) {
	if reflect.ValueOf(geteuid).Pointer() != reflect.ValueOf(os.Geteuid).Pointer() {
		t.Error("geteuid should default to os.Geteuid")
	}
}

func TestCheckRoot(t *testing.T) {
	asUID(t, 0)
	if err := checkRoot(); err != nil {
		t.Errorf("expected nil error as root, got %v", err)
	}
}

func TestCheckRoot_NonRootPath(t *testing.T) {
	asUID(t, 1000)
	var rootErr ErrRootRequired
	if err := checkRoot(); !errors.As(err, &rootErr) {
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
