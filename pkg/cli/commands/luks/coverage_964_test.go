// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// errLUKSRefused is what the fake LUKS server answers when told to fail.
type errLUKSRefused struct{}

func (errLUKSRefused) Error() string { return "luks service refused the request" }

// fakeLUKSServer records the last request each verb received and answers
// with an empty response, or with err when it is set.
type fakeLUKSServer struct {
	platformv1.UnimplementedLUKSServiceServer
	err         error
	recoveryKey string
	got         proto.Message
}

func (s *fakeLUKSServer) Status(_ context.Context, req *platformv1.LUKSStatusRequest) (*platformv1.LUKSStatusResponse, error) {
	s.got = req
	return &platformv1.LUKSStatusResponse{Device: req.GetDevice(), IsLuks: true}, s.err
}

func (s *fakeLUKSServer) ListSlots(_ context.Context, req *platformv1.LUKSListSlotsRequest) (*platformv1.LUKSListSlotsResponse, error) {
	s.got = req
	return &platformv1.LUKSListSlotsResponse{}, s.err
}

func (s *fakeLUKSServer) Info(_ context.Context, req *platformv1.LUKSInfoRequest) (*platformv1.LUKSInfoResponse, error) {
	s.got = req
	return &platformv1.LUKSInfoResponse{}, s.err
}

func (s *fakeLUKSServer) EnrollPassphrase(_ context.Context, req *platformv1.LUKSEnrollPassphraseRequest) (*platformv1.LUKSEnrollPassphraseResponse, error) {
	s.got = req
	return &platformv1.LUKSEnrollPassphraseResponse{}, s.err
}

func (s *fakeLUKSServer) EnrollFIDO2(_ context.Context, req *platformv1.LUKSEnrollFIDO2Request) (*platformv1.LUKSEnrollFIDO2Response, error) {
	s.got = req
	return &platformv1.LUKSEnrollFIDO2Response{}, s.err
}

func (s *fakeLUKSServer) EnrollTPM(_ context.Context, req *platformv1.LUKSEnrollTPMRequest) (*platformv1.LUKSEnrollTPMResponse, error) {
	s.got = req
	return &platformv1.LUKSEnrollTPMResponse{}, s.err
}

func (s *fakeLUKSServer) EnrollRecovery(_ context.Context, req *platformv1.LUKSEnrollRecoveryRequest) (*platformv1.LUKSEnrollRecoveryResponse, error) {
	s.got = req
	return &platformv1.LUKSEnrollRecoveryResponse{Slot: 2, RecoveryKey: s.recoveryKey}, s.err
}

func (s *fakeLUKSServer) RemoveKey(_ context.Context, req *platformv1.LUKSRemoveKeyRequest) (*platformv1.LUKSRemoveKeyResponse, error) {
	s.got = req
	return &platformv1.LUKSRemoveKeyResponse{}, s.err
}

func (s *fakeLUKSServer) TestUnlock(_ context.Context, req *platformv1.LUKSTestUnlockRequest) (*platformv1.LUKSTestUnlockResponse, error) {
	s.got = req
	return &platformv1.LUKSTestUnlockResponse{}, s.err
}

func (s *fakeLUKSServer) ChangePassphrase(_ context.Context, req *platformv1.LUKSChangePassphraseRequest) (*platformv1.LUKSChangePassphraseResponse, error) {
	s.got = req
	return &platformv1.LUKSChangePassphraseResponse{}, s.err
}

// luksHost hosts the fake LUKS server in-process for an embedded context.
type luksHost struct {
	services *embedded.ServiceRegistry
	stops    int
}

func (h *luksHost) Services() *embedded.ServiceRegistry { return h.services }

func (h *luksHost) Stop(context.Context) error {
	h.stops++
	return nil
}

// embeddedLUKS runs the command as root against srv over the embedded
// transport and returns the common flags plus the host, so a test can
// assert the command stopped it.
func embeddedLUKS(t *testing.T, srv *fakeLUKSServer) (*cli.CommonFlags, *luksHost) {
	t.Helper()
	asUID(t, 0)
	host := &luksHost{services: &embedded.ServiceRegistry{LUKS: srv}}
	c := &cli.Context{Name: "standalone", Type: cli.ContextTypeEmbedded}
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		GetContext:   func() (*cli.Context, error) { return c, nil },
		StartEmbedded: func(context.Context, *cli.Context) (cli.EmbeddedHost, error) {
			return host, nil
		},
	}, host
}

// verbCase runs one LUKS verb with valid flags and names the request the
// server must receive.
type verbCase struct {
	name string
	run  func(*cli.CommonFlags) error
	want proto.Message
}

func luksVerbs(recoveryPath string) []verbCase {
	return []verbCase{
		{
			name: "status",
			run:  func(cf *cli.CommonFlags) error { return runStatus(cf, &statusFlags{device: "/dev/vda2"}) },
			want: &platformv1.LUKSStatusRequest{Device: "/dev/vda2"},
		},
		{
			name: "list-slots",
			run:  func(cf *cli.CommonFlags) error { return runListSlots(cf, &listSlotsFlags{device: "/dev/vda2"}) },
			want: &platformv1.LUKSListSlotsRequest{Device: "/dev/vda2"},
		},
		{
			name: "info",
			run:  func(cf *cli.CommonFlags) error { return runInfo(cf, &infoFlags{device: "/dev/vda2"}) },
			want: &platformv1.LUKSInfoRequest{Device: "/dev/vda2"},
		},
		{
			name: "enroll-passphrase",
			run: func(cf *cli.CommonFlags) error {
				return runEnrollPassphrase(cf, &enrollPassphraseFlags{device: "/dev/vda2", existingPassphrase: "old", newPassphrase: "new"})
			},
			want: &platformv1.LUKSEnrollPassphraseRequest{Device: "/dev/vda2", ExistingPassphrase: "old", NewPassphrase: "new"},
		},
		{
			name: "enroll-fido2",
			run: func(cf *cli.CommonFlags) error {
				return runEnrollFIDO2(cf, &enrollFIDO2Flags{device: "/dev/vda2", existingPassphrase: "old", credentialID: "cred-1", requirePIN: true, requireUV: true})
			},
			want: &platformv1.LUKSEnrollFIDO2Request{Device: "/dev/vda2", ExistingPassphrase: "old", CredentialId: "cred-1", RequirePin: true, RequireUv: true},
		},
		{
			name: "enroll-tpm",
			run: func(cf *cli.CommonFlags) error {
				return runEnrollTPM(cf, &enrollTPMFlags{device: "/dev/vda2", existingPassphrase: "old", pcrs: []int32{7, 11}, handle: "0x81000010"})
			},
			want: &platformv1.LUKSEnrollTPMRequest{Device: "/dev/vda2", ExistingPassphrase: "old", Pcrs: []int32{7, 11}, Handle: "0x81000010"},
		},
		{
			name: "enroll-recovery",
			run: func(cf *cli.CommonFlags) error {
				return runEnrollRecovery(cf, &enrollRecoveryFlags{device: "/dev/vda2", existingPassphrase: "old", output: recoveryPath})
			},
			want: &platformv1.LUKSEnrollRecoveryRequest{Device: "/dev/vda2", ExistingPassphrase: "old"},
		},
		{
			name: "remove-key",
			run: func(cf *cli.CommonFlags) error {
				return runRemoveKey(cf, &removeKeyFlags{device: "/dev/vda2", slot: 3})
			},
			want: &platformv1.LUKSRemoveKeyRequest{Device: "/dev/vda2", Slot: 3},
		},
		{
			name: "test-unlock",
			run: func(cf *cli.CommonFlags) error {
				return runTestUnlock(cf, &testUnlockFlags{device: "/dev/vda2", slot: 4})
			},
			want: &platformv1.LUKSTestUnlockRequest{Device: "/dev/vda2", Slot: 4},
		},
		{
			name: "change-passphrase",
			run: func(cf *cli.CommonFlags) error {
				return runChangePassphrase(cf, &changePassphraseFlags{device: "/dev/vda2", slot: 5, oldPassphrase: "old", newPassphrase: "new"})
			},
			want: &platformv1.LUKSChangePassphraseRequest{Device: "/dev/vda2", Slot: 5, OldPassphrase: "old", NewPassphrase: "new"},
		},
	}
}

// Every verb forwards its flags to the LUKS service unchanged and closes the
// embedded host it started.
func TestRunVerbs_ForwardTheFlagsToTheLUKSService(t *testing.T) {
	for _, tc := range luksVerbs(filepath.Join(t.TempDir(), "recovery.key")) {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeLUKSServer{}
			cf, host := embeddedLUKS(t, srv)

			if err := tc.run(cf); err != nil {
				t.Fatalf("run error = %v", err)
			}
			if !proto.Equal(srv.got, tc.want) {
				t.Errorf("service received %v; want %v", srv.got, tc.want)
			}
			if host.stops != 1 {
				t.Errorf("embedded host stopped %d times; want 1", host.stops)
			}
		})
	}
}

// A service failure is returned to the caller, never swallowed into output.
func TestRunVerbs_ReturnTheServiceError(t *testing.T) {
	for _, tc := range luksVerbs(filepath.Join(t.TempDir(), "recovery.key")) {
		t.Run(tc.name, func(t *testing.T) {
			cf, _ := embeddedLUKS(t, &fakeLUKSServer{err: errLUKSRefused{}})

			err := tc.run(cf)
			if err == nil || !strings.Contains(err.Error(), errLUKSRefused{}.Error()) {
				t.Errorf("run error = %v; want the service refusal", err)
			}
		})
	}
}

// Without a context the base command cannot connect, and every verb stops
// there before calling the service.
func TestRunVerbs_RefuseWithoutAContext(t *testing.T) {
	for _, tc := range luksVerbs(filepath.Join(t.TempDir(), "recovery.key")) {
		t.Run(tc.name, func(t *testing.T) {
			asUID(t, 0)
			err := tc.run(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON})
			if !errors.As(err, new(cli.ErrNoContextSet)) {
				t.Errorf("run error = %T %v; want cli.ErrNoContextSet", err, err)
			}
		})
	}
}

// Every verb refuses a non-root caller before it touches flags or the service.
func TestRunVerbs_RequireRoot(t *testing.T) {
	for _, tc := range luksVerbs(filepath.Join(t.TempDir(), "recovery.key")) {
		t.Run(tc.name, func(t *testing.T) {
			asUID(t, 1000)
			if err := tc.run(&cli.CommonFlags{}); !errors.As(err, new(ErrRootRequired)) {
				t.Errorf("run error = %T %v; want ErrRootRequired", err, err)
			}
		})
	}
}

// Missing or out-of-range flags are refused with their typed error.
func TestRunVerbs_FlagValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*cli.CommonFlags) error
		want error
	}{
		{"fido2 without existing passphrase", func(cf *cli.CommonFlags) error {
			return runEnrollFIDO2(cf, &enrollFIDO2Flags{credentialID: "cred-1"})
		}, ErrExistingPassphraseRequired{}},
		{"fido2 without credential", func(cf *cli.CommonFlags) error {
			return runEnrollFIDO2(cf, &enrollFIDO2Flags{existingPassphrase: "old"})
		}, ErrCredentialIDRequired{}},
		{"tpm without existing passphrase", func(cf *cli.CommonFlags) error {
			return runEnrollTPM(cf, &enrollTPMFlags{})
		}, ErrExistingPassphraseRequired{}},
		{"recovery without existing passphrase", func(cf *cli.CommonFlags) error {
			return runEnrollRecovery(cf, &enrollRecoveryFlags{output: "/tmp/key"})
		}, ErrExistingPassphraseRequired{}},
		{"recovery without output", func(cf *cli.CommonFlags) error {
			return runEnrollRecovery(cf, &enrollRecoveryFlags{existingPassphrase: "old"})
		}, ErrOutputPathRequired{}},
		{"remove-key without slot", func(cf *cli.CommonFlags) error {
			return runRemoveKey(cf, &removeKeyFlags{slot: -1})
		}, ErrSlotRequired{}},
		{"remove-key slot out of range", func(cf *cli.CommonFlags) error {
			return runRemoveKey(cf, &removeKeyFlags{slot: 32})
		}, ErrInvalidSlot{Slot: 32}},
		{"test-unlock without slot", func(cf *cli.CommonFlags) error {
			return runTestUnlock(cf, &testUnlockFlags{slot: -1})
		}, ErrSlotRequired{}},
		{"test-unlock slot out of range", func(cf *cli.CommonFlags) error {
			return runTestUnlock(cf, &testUnlockFlags{slot: 40})
		}, ErrInvalidSlot{Slot: 40}},
		{"change-passphrase without slot", func(cf *cli.CommonFlags) error {
			return runChangePassphrase(cf, &changePassphraseFlags{slot: -1, oldPassphrase: "old", newPassphrase: "new"})
		}, ErrSlotRequired{}},
		{"change-passphrase slot out of range", func(cf *cli.CommonFlags) error {
			return runChangePassphrase(cf, &changePassphraseFlags{slot: 99, oldPassphrase: "old", newPassphrase: "new"})
		}, ErrInvalidSlot{Slot: 99}},
		{"change-passphrase without old passphrase", func(cf *cli.CommonFlags) error {
			return runChangePassphrase(cf, &changePassphraseFlags{slot: 1, newPassphrase: "new"})
		}, ErrOldPassphraseRequired{}},
		{"change-passphrase without new passphrase", func(cf *cli.CommonFlags) error {
			return runChangePassphrase(cf, &changePassphraseFlags{slot: 1, oldPassphrase: "old"})
		}, ErrNewPassphraseRequired{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeLUKSServer{}
			cf, _ := embeddedLUKS(t, srv)

			err := tc.run(cf)
			if !reflect.DeepEqual(err, tc.want) {
				t.Errorf("run error = %T %v; want %T %v", err, err, tc.want, tc.want)
			}
			if srv.got != nil {
				t.Errorf("service was called with %v; want no call", srv.got)
			}
		})
	}
}

// The recovery key the service returns is written to --output, readable by
// the owner only.
func TestRunEnrollRecovery_WritesTheRecoveryKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "recovery.key")
	cf, _ := embeddedLUKS(t, &fakeLUKSServer{recoveryKey: "abcd-efgh-ijkl"})

	err := runEnrollRecovery(cf, &enrollRecoveryFlags{device: "/dev/vda2", existingPassphrase: "old", output: out})
	if err != nil {
		t.Fatalf("runEnrollRecovery() error = %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read recovery key: %v", err)
	}
	if string(data) != "abcd-efgh-ijkl" {
		t.Errorf("recovery key file = %q; want abcd-efgh-ijkl", data)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat recovery key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("recovery key mode = %o; want 600", perm)
	}
}

// A key the command cannot write is reported with its path and cause.
func TestRunEnrollRecovery_UnwritableOutputIsTyped(t *testing.T) {
	out := filepath.Join(t.TempDir(), "missing-dir", "recovery.key")
	cf, _ := embeddedLUKS(t, &fakeLUKSServer{recoveryKey: "abcd-efgh-ijkl"})

	err := runEnrollRecovery(cf, &enrollRecoveryFlags{device: "/dev/vda2", existingPassphrase: "old", output: out})
	var writeErr ErrRecoveryKeyWrite
	if !errors.As(err, &writeErr) {
		t.Fatalf("runEnrollRecovery() error = %T %v; want ErrRecoveryKeyWrite", err, err)
	}
	if writeErr.Path != out {
		t.Errorf("ErrRecoveryKeyWrite.Path = %q; want %q", writeErr.Path, out)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ErrRecoveryKeyWrite does not unwrap to os.ErrNotExist: %v", err)
	}
}

// Each subcommand binds its command-line flags into the service request the
// way luksVerbs builds it directly.
func TestNewCommand_SubcommandsBindTheirFlags(t *testing.T) {
	recoveryPath := filepath.Join(t.TempDir(), "recovery.key")
	args := map[string][]string{
		"status":            {"status", "--device", "/dev/vda2"},
		"list-slots":        {"list-slots", "--device", "/dev/vda2"},
		"info":              {"info", "--device", "/dev/vda2"},
		"enroll-passphrase": {"enroll-passphrase", "--device", "/dev/vda2", "--existing-passphrase", "old", "--new-passphrase", "new"},
		"enroll-fido2":      {"enroll-fido2", "--device", "/dev/vda2", "--existing-passphrase", "old", "--credential-id", "cred-1", "--require-pin", "--require-uv"},
		"enroll-tpm":        {"enroll-tpm", "--device", "/dev/vda2", "--existing-passphrase", "old", "--pcrs", "7,11", "--handle", "0x81000010"},
		"enroll-recovery":   {"enroll-recovery", "--device", "/dev/vda2", "--existing-passphrase", "old", "--output", recoveryPath},
		"remove-key":        {"remove-key", "--device", "/dev/vda2", "--slot", "3"},
		"test-unlock":       {"test-unlock", "--device", "/dev/vda2", "--slot", "4"},
		"change-passphrase": {"change-passphrase", "--device", "/dev/vda2", "--slot", "5", "--old-passphrase", "old", "--new-passphrase", "new"},
	}
	for _, tc := range luksVerbs(recoveryPath) {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeLUKSServer{}
			cf, _ := embeddedLUKS(t, srv)
			cmd := NewCommand(func() *cli.CommonFlags { return cf })
			cmd.SetArgs(args[tc.name])

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute(%v) error = %v", args[tc.name], err)
			}
			if !proto.Equal(srv.got, tc.want) {
				t.Errorf("service received %v; want %v", srv.got, tc.want)
			}
		})
	}
}
