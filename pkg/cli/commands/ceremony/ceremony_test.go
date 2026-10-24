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

package ceremony

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func testFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}
}

func TestNewCommand_Structure(t *testing.T) {
	cmd := NewCommand(testFlags())

	if cmd.Use != "ceremony" {
		t.Errorf("expected Use 'ceremony', got %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("expected non-empty Short")
	}
	if cmd.Long == "" {
		t.Error("expected non-empty Long")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	cmd := NewCommand(testFlags())

	expected := map[string]bool{
		"init":        false,
		"status":      false,
		"claim-cert":  false,
		"claim-share": false,
		"sign-csr":    false,
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

// TestInitCommand_RedirectsToRootInit verifies that the legacy
// "platformctl ceremony init" subcommand emits CanonicalRedirectError
// pointing at the root "platformctl init" command per
// docs/08-bootstrap-auth-architecture.md §6. The legacy flag set is
// not exposed on the redirect stub.
func TestInitCommand_RedirectsToRootInit(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("could not find init: %v", err)
	}
	if sub.RunE == nil {
		t.Fatal("legacy ceremony init must have a RunE that emits CanonicalRedirectError")
	}
	runErr := sub.RunE(sub, nil)
	if runErr == nil {
		t.Fatal("expected CanonicalRedirectError from legacy ceremony init")
	}
	var redirect *CanonicalRedirectError
	if !errors.As(runErr, &redirect) {
		t.Fatalf("expected *CanonicalRedirectError, got %T: %v", runErr, runErr)
	}
	if redirect.Old != "platformctl ceremony init" {
		t.Errorf("expected Old=\"platformctl ceremony init\", got %q", redirect.Old)
	}
	for _, name := range []string{"so-pin", "user-pin", "threshold", "hostname", "sans", "credential-seal-strategy"} {
		if sub.Flags().Lookup(name) != nil {
			t.Errorf("legacy --%s flag must not be exposed on the redirect stub", name)
		}
	}
}

func TestStatusCommand_NoLocalFlags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("could not find status: %v", err)
	}

	if sub.Flags().HasFlags() {
		t.Errorf("status: expected zero local flags, got some")
	}
}

func TestClaimCert_Subcommands(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"claim-cert"})
	if err != nil {
		t.Fatalf("could not find claim-cert: %v", err)
	}

	expected := map[string]bool{"begin": false, "complete": false}
	for _, s := range sub.Commands() {
		if _, ok := expected[s.Use]; ok {
			expected[s.Use] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("claim-cert: missing subcommand %q", name)
		}
	}
}

func TestClaimCertBegin_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"claim-cert", "begin"})
	if err != nil {
		t.Fatalf("could not find claim-cert begin: %v", err)
	}

	for _, name := range []string{"username", "authenticator-type", "slot", "credential-id"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("claim-cert begin: missing flag %q", name)
		}
	}
}

func TestClaimCertComplete_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"claim-cert", "complete"})
	if err != nil {
		t.Fatalf("could not find claim-cert complete: %v", err)
	}

	for _, name := range []string{"username", "nonce", "signature"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("claim-cert complete: missing flag %q", name)
		}
	}
}

func TestClaimShare_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())

	sub, _, err := cmd.Find([]string{"claim-share", "begin"})
	if err != nil {
		t.Fatalf("could not find claim-share begin: %v", err)
	}
	if sub.Flags().Lookup("username") == nil {
		t.Error("claim-share begin: missing flag --username")
	}

	sub, _, err = cmd.Find([]string{"claim-share", "complete"})
	if err != nil {
		t.Fatalf("could not find claim-share complete: %v", err)
	}
	for _, name := range []string{"username", "nonce", "signature"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("claim-share complete: missing flag %q", name)
		}
	}
}

func TestSignCSR_Flags(t *testing.T) {
	cmd := NewCommand(testFlags())
	sub, _, err := cmd.Find([]string{"sign-csr"})
	if err != nil {
		t.Fatalf("could not find sign-csr: %v", err)
	}

	for _, name := range []string{"username", "so-pin", "csr-file", "role"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("sign-csr: missing flag %q", name)
		}
	}
}

func TestRunClaimCertBegin_ValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		f      *claimCertBeginFlags
		expect any
	}{
		{
			name:   "missing username",
			f:      &claimCertBeginFlags{},
			expect: ErrUsernameRequired{},
		},
		{
			name:   "invalid authenticator type",
			f:      &claimCertBeginFlags{username: "u", authenticatorType: "ghost"},
			expect: ErrInvalidAuthenticatorType{Value: "ghost"},
		},
		{
			name:   "piv without slot",
			f:      &claimCertBeginFlags{username: "u", authenticatorType: "piv"},
			expect: ErrAuthenticatorSelectorRequired{Type: "piv", Flag: "--slot"},
		},
		{
			name:   "fido2 without credential-id",
			f:      &claimCertBeginFlags{username: "u", authenticatorType: "fido2"},
			expect: ErrAuthenticatorSelectorRequired{Type: "fido2", Flag: "--credential-id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runClaimCertBegin(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, tc.f)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.expect != err {
				// Structural equality since errors are value types here.
				if err.Error() == "" {
					t.Errorf("expected %v, got empty error", tc.expect)
				}
				if tc.name == "missing username" {
					if _, ok := err.(ErrUsernameRequired); !ok {
						t.Errorf("expected ErrUsernameRequired, got %T: %v", err, err)
					}
				}
			}
		})
	}
}

func TestRunClaimCertComplete_ValidationErrors(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runClaimCertComplete(commonFlags, &claimCertCompleteFlags{}); err == nil {
		t.Error("expected ErrUsernameRequired, got nil")
	} else if _, ok := err.(ErrUsernameRequired); !ok {
		t.Errorf("expected ErrUsernameRequired, got %T", err)
	}

	if err := runClaimCertComplete(commonFlags, &claimCertCompleteFlags{username: "u"}); err == nil {
		t.Error("expected ErrNonceRequired, got nil")
	} else if _, ok := err.(ErrNonceRequired); !ok {
		t.Errorf("expected ErrNonceRequired, got %T", err)
	}

	if err := runClaimCertComplete(commonFlags, &claimCertCompleteFlags{username: "u", nonce: "n"}); err == nil {
		t.Error("expected ErrSignatureRequired, got nil")
	} else if _, ok := err.(ErrSignatureRequired); !ok {
		t.Errorf("expected ErrSignatureRequired, got %T", err)
	}
}

func TestRunClaimShareBegin_ValidationErrors(t *testing.T) {
	err := runClaimShareBegin(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &claimShareBeginFlags{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(ErrUsernameRequired); !ok {
		t.Errorf("expected ErrUsernameRequired, got %T", err)
	}
}

func TestRunClaimShareComplete_ValidationErrors(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := runClaimShareComplete(commonFlags, &claimShareCompleteFlags{}); err == nil {
		t.Error("expected ErrUsernameRequired, got nil")
	} else if _, ok := err.(ErrUsernameRequired); !ok {
		t.Errorf("expected ErrUsernameRequired, got %T", err)
	}

	if err := runClaimShareComplete(commonFlags, &claimShareCompleteFlags{username: "u"}); err == nil {
		t.Error("expected ErrNonceRequired, got nil")
	} else if _, ok := err.(ErrNonceRequired); !ok {
		t.Errorf("expected ErrNonceRequired, got %T", err)
	}

	if err := runClaimShareComplete(commonFlags, &claimShareCompleteFlags{username: "u", nonce: "n"}); err == nil {
		t.Error("expected ErrSignatureRequired, got nil")
	} else if _, ok := err.(ErrSignatureRequired); !ok {
		t.Errorf("expected ErrSignatureRequired, got %T", err)
	}

	if err := runClaimShareComplete(commonFlags, &claimShareCompleteFlags{username: "u", nonce: "n", signature: "!!!not-base64!!!"}); err == nil {
		t.Error("expected ErrSignatureDecode, got nil")
	} else if _, ok := err.(ErrSignatureDecode); !ok {
		t.Errorf("expected ErrSignatureDecode, got %T", err)
	}
}

func TestRunSignCSR_ValidationErrors(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name    string
		flags   *signCSRFlags
		checkFn func(err error) bool
	}{
		{
			name:  "missing username",
			flags: &signCSRFlags{},
			checkFn: func(err error) bool {
				_, ok := err.(ErrUsernameRequired)
				return ok
			},
		},
		{
			name:  "missing so-pin",
			flags: &signCSRFlags{username: "u"},
			checkFn: func(err error) bool {
				_, ok := err.(ErrSOPinRequired)
				return ok
			},
		},
		{
			name:  "missing csr-file",
			flags: &signCSRFlags{username: "u", soPIN: "pin"},
			checkFn: func(err error) bool {
				_, ok := err.(ErrCSRFileRequired)
				return ok
			},
		},
		{
			name:  "invalid role",
			flags: &signCSRFlags{username: "u", soPIN: "pin", csrFile: "x", role: "ghost"},
			checkFn: func(err error) bool {
				_, ok := err.(ErrInvalidRole)
				return ok
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runSignCSR(commonFlags, tc.flags)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.checkFn(err) {
				t.Errorf("unexpected error type %T: %v", err, err)
			}
		})
	}
}

func TestRunSignCSR_MissingFile(t *testing.T) {
	commonFlags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	f := &signCSRFlags{
		username: "u", soPIN: "pin",
		csrFile: "/tmp/does-not-exist-" + t.Name(),
		role:    "admin",
	}
	err := runSignCSR(commonFlags, f)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var readErr ErrCSRFileRead
	if !errors.As(err, &readErr) {
		t.Errorf("expected ErrCSRFileRead, got %T: %v", err, err)
	}
}

func TestRunSignCSR_ReadsFile(t *testing.T) {
	// Without a context the dial fails after the file is read; the full
	// dispatch is covered by TestRunCommands_InProcess.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "csr.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE REQUEST-----\nxx\n-----END CERTIFICATE REQUEST-----\n"), 0o600); err != nil {
		t.Fatalf("write csr: %v", err)
	}

	err := runSignCSR(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &signCSRFlags{
		username: "u", soPIN: "pin", csrFile: path, role: "admin",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Expect the error came from NewBaseCommand (no context) or the ceremony
	// service call. In either case we should NOT get ErrCSRFileRead here.
	var readErr ErrCSRFileRead
	if errors.As(err, &readErr) {
		t.Errorf("unexpected ErrCSRFileRead: %v", err)
	}
}

func TestErrors_HaveNonEmptyMessages(t *testing.T) {
	tests := []error{
		ErrUsernameRequired{},
		ErrInvalidAuthenticatorType{Value: "x"},
		ErrAuthenticatorSelectorRequired{Type: "piv", Flag: "--slot"},
		ErrInvalidRole{Value: "x"},
		ErrCSRFileRequired{},
		ErrCSRFileRead{Path: "/tmp/x", Cause: errors.New("boom")},
		ErrSOPinRequired{},
		ErrNonceRequired{},
		ErrSignatureRequired{},
	}

	for _, e := range tests {
		if e.Error() == "" {
			t.Errorf("expected non-empty message for %T", e)
		}
		if !strings.Contains(e.Error(), "ceremony") {
			t.Errorf("expected %T message to contain 'ceremony': %q", e, e.Error())
		}
	}
}

func TestAuthenticatorTypes_Map(t *testing.T) {
	for _, name := range []string{"piv", "fido2", "software"} {
		if _, ok := authenticatorTypes[name]; !ok {
			t.Errorf("authenticatorTypes missing %q", name)
		}
	}
}

func TestOfficerRoles_Map(t *testing.T) {
	for _, name := range []string{"so", "admin", "user"} {
		if _, ok := officerRoles[name]; !ok {
			t.Errorf("officerRoles missing %q", name)
		}
	}
}

type ceremonyOnlyClient struct {
	platform.Client
	rpc platformv1.CeremonyServiceClient
}

func (c ceremonyOnlyClient) Ceremony() platformv1.CeremonyServiceClient { return c.rpc }

type statusRPC struct {
	platformv1.CeremonyServiceClient
	called bool
}

func (s *statusRPC) Status(_ context.Context, _ *platformv1.CeremonyStatusRequest, _ ...grpc.CallOption) (*platformv1.CeremonyStatusResponse, error) {
	s.called = true
	return &platformv1.CeremonyStatusResponse{}, nil
}

func TestNewService_DispatchesOverTheSDKClient(t *testing.T) {
	rpc := &statusRPC{}

	svc, err := NewService(ceremonyOnlyClient{rpc: rpc})
	if err != nil {
		t.Fatalf("newService() error = %v", err)
	}
	if _, err := svc.Status(context.Background()); err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !rpc.called {
		t.Error("expected Status to reach the SDK ceremony client")
	}
}

func TestNewService_RefusesAClientWithoutTheCeremonyService(t *testing.T) {
	svc, err := NewService(ceremonyOnlyClient{})
	if svc != nil {
		t.Errorf("expected no service, got %v", svc)
	}

	var unavailable platform.ErrServiceUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected platform.ErrServiceUnavailable, got %v", err)
	}
	if unavailable.Service != ceremonysvcName {
		t.Errorf("ErrServiceUnavailable.Service = %q, want %q", unavailable.Service, ceremonysvcName)
	}
}
