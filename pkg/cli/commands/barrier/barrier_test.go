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

package barrier

import (
	"testing"

	"github.com/spf13/pflag"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ---------------------------------------------------------------------------
// Root command structure
// ---------------------------------------------------------------------------

func TestNewCommand_Structure(t *testing.T) {
	cmd := NewCommand(noopFlags)
	if cmd.Use != "barrier" {
		t.Errorf("expected Use 'barrier', got %q", cmd.Use)
	}
	if cmd.Short != "Barrier storage management" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}
	if cmd.Long == "" {
		t.Error("expected non-empty Long")
	}
}

// TestNewCommand_Canonical9VerbTree verifies the exact set of
// subcommands matches qrdbctl / xkmsctl / quicbaas per
// docs/08-bootstrap-auth-architecture.md §6. Any drift from the
// canonical tree fails the test on purpose.
func TestNewCommand_Canonical9VerbTree(t *testing.T) {
	cmd := NewCommand(noopFlags)

	// barrier has 8 direct subcommands (recovery is a group); the 9th
	// verb is "recovery recover", checked separately below.
	expected := map[string]bool{
		"status":        false,
		"init":          false,
		"init-shamir":   false,
		"unseal":        false,
		"unseal-shares": false,
		"seal":          false,
		"rekey":         false,
		"recovery":      false,
	}
	for _, sub := range cmd.Commands() {
		if _, ok := expected[sub.Use]; ok {
			expected[sub.Use] = true
		} else {
			t.Errorf("unexpected subcommand %q", sub.Use)
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("canonical subcommand %q missing", name)
		}
	}

	recovery, _, err := cmd.Find([]string{"recovery"})
	if err != nil {
		t.Fatalf("recovery group not found: %v", err)
	}
	rExpected := map[string]bool{"generate": false, "recover": false}
	for _, sub := range recovery.Commands() {
		if _, ok := rExpected[sub.Use]; ok {
			rExpected[sub.Use] = true
		} else {
			t.Errorf("unexpected recovery subcommand %q", sub.Use)
		}
	}
	for name, found := range rExpected {
		if !found {
			t.Errorf("canonical recovery subcommand %q missing", name)
		}
	}
}

// TestInitCommand_IsRealVerbNotRedirect verifies that "barrier init"
// is a real dispatcher (with its canonical flag set) — replacing the
// historical "redirect to root platformctl init" stub that the locked
// architecture rejects.
func TestInitCommand_IsRealVerbNotRedirect(t *testing.T) {
	cmd := NewCommand(noopFlags)
	initCmd, _, err := cmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init subcommand not found: %v", err)
	}
	if initCmd.RunE == nil {
		t.Fatal("expected RunE on barrier init")
	}
	expectFlags := []string{"barrier-strategy", "passphrase", "so-pin", "user-pin"}
	for _, name := range expectFlags {
		if initCmd.Flags().Lookup(name) == nil {
			t.Errorf("canonical flag --%s missing on barrier init", name)
		}
	}
}

// ---------------------------------------------------------------------------
// init flag validation
// ---------------------------------------------------------------------------

func TestValidateInitFlags(t *testing.T) {
	cases := []struct {
		name    string
		in      initFlags
		wantErr any
	}{
		{
			name: "passphrase with secret OK",
			in:   initFlags{strategy: "passphrase", secret: "p"},
		},
		{
			name: "passphrase with secret and pins OK",
			in:   initFlags{strategy: "passphrase", secret: "p", soPin: "1", userPin: "2"},
		},
		{
			name:    "passphrase requires secret",
			in:      initFlags{strategy: "passphrase"},
			wantErr: ErrSecretRequired{},
		},
		{
			name:    "user-pin requires so-pin",
			in:      initFlags{strategy: "passphrase", secret: "p", userPin: "2"},
			wantErr: ErrUserPinRequiresSOPin{},
		},
		{
			name:    "so-pin requires user-pin (bidirectional dual-control)",
			in:      initFlags{strategy: "passphrase", secret: "p", soPin: "1"},
			wantErr: ErrSOPinRequiresUserPin{},
		},
		{
			name:    "shamir requires secret",
			in:      initFlags{strategy: "shamir"},
			wantErr: ErrSecretRequired{},
		},
		{
			name: "none with no secret/pins OK",
			in:   initFlags{strategy: "none"},
		},
		{
			name:    "none rejects --passphrase",
			in:      initFlags{strategy: "none", secret: "p"},
			wantErr: ErrSecretNotAllowed{},
		},
		{
			name:    "none rejects --so-pin (PINsNotAllowedError)",
			in:      initFlags{strategy: "none", soPin: "1"},
			wantErr: PINsNotAllowedError{},
		},
		{
			name:    "none rejects --user-pin (PINsNotAllowedError)",
			in:      initFlags{strategy: "none", userPin: "2"},
			wantErr: PINsNotAllowedError{},
		},
		{
			name:    "unknown strategy rejected",
			in:      initFlags{strategy: "bogus"},
			wantErr: ErrInvalidBarrierStrategy{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInitFlags(&tc.in)
			assertErrorMatches(t, err, tc.wantErr)
		})
	}
}

// TestValidateInitFlags_PINsNotAllowedError_HasFlagName verifies the
// PINsNotAllowedError carries the rejected flag verbatim so callers
// can surface it.
func TestValidateInitFlags_PINsNotAllowedError_HasFlagName(t *testing.T) {
	err := validateInitFlags(&initFlags{strategy: "none", soPin: "1"})
	pe, ok := err.(PINsNotAllowedError)
	if !ok {
		t.Fatalf("expected PINsNotAllowedError, got %T", err)
	}
	if pe.Flag != "so-pin" {
		t.Errorf("expected Flag=so-pin, got %q", pe.Flag)
	}
	if pe.Strategy != "none" {
		t.Errorf("expected Strategy=none, got %q", pe.Strategy)
	}
}

// ---------------------------------------------------------------------------
// init-shamir flag validation
// ---------------------------------------------------------------------------

func TestValidateInitShamirFlags(t *testing.T) {
	cases := []struct {
		name    string
		in      initShamirFlags
		wantErr any
	}{
		{
			name: "valid 3-of-5",
			in:   initShamirFlags{secret: "p", threshold: 3, total: 5},
		},
		{
			name: "valid 2-of-2",
			in:   initShamirFlags{secret: "p", threshold: 2, total: 2},
		},
		{
			name:    "missing secret",
			in:      initShamirFlags{threshold: 3, total: 5},
			wantErr: ErrMissingSecret{},
		},
		{
			name:    "total < 2",
			in:      initShamirFlags{secret: "p", threshold: 2, total: 1},
			wantErr: ErrInvalidTotal{},
		},
		{
			name:    "threshold < 2",
			in:      initShamirFlags{secret: "p", threshold: 1, total: 5},
			wantErr: ErrInvalidThreshold{},
		},
		{
			name:    "threshold > total",
			in:      initShamirFlags{secret: "p", threshold: 5, total: 3},
			wantErr: ErrInvalidThreshold{},
		},
		{
			name:    "user-pin without so-pin",
			in:      initShamirFlags{secret: "p", threshold: 3, total: 5, userPin: "u"},
			wantErr: ErrUserPinRequiresSOPin{},
		},
		{
			name:    "so-pin without user-pin (bidirectional dual-control)",
			in:      initShamirFlags{secret: "p", threshold: 3, total: 5, soPin: "s"},
			wantErr: ErrSOPinRequiresUserPin{},
		},
		{
			name: "both pins OK",
			in:   initShamirFlags{secret: "p", threshold: 3, total: 5, soPin: "s", userPin: "u"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInitShamirFlags(&tc.in)
			assertErrorMatches(t, err, tc.wantErr)
		})
	}
}

// ---------------------------------------------------------------------------
// rekey flag validation
// ---------------------------------------------------------------------------

func TestValidateRekeyFlags(t *testing.T) {
	cases := []struct {
		name    string
		in      rekeyFlags
		wantErr any
	}{
		{
			name: "no flags (server-generated key, preserve share layout)",
			in:   rekeyFlags{},
		},
		{
			name: "paired thresholds",
			in:   rekeyFlags{threshold: 3, total: 5},
		},
		{
			name: "so-pin only (no --user-pin counterpart)",
			in:   rekeyFlags{soPin: "so"},
		},
		{
			name:    "threshold without total",
			in:      rekeyFlags{threshold: 3},
			wantErr: ErrRekeyPartialFlags{},
		},
		{
			name:    "total without threshold",
			in:      rekeyFlags{total: 5},
			wantErr: ErrRekeyPartialFlags{},
		},
		{
			name:    "threshold > total",
			in:      rekeyFlags{threshold: 5, total: 3},
			wantErr: ErrInvalidThreshold{},
		},
		{
			name:    "total below minimum",
			in:      rekeyFlags{threshold: 1, total: 1},
			wantErr: ErrInvalidTotal{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRekeyFlags(&tc.in)
			assertErrorMatches(t, err, tc.wantErr)
		})
	}
}

// TestRekeyCommand_NoUserPinFlag verifies the canonical PIN matrix
// rule: rekey accepts --so-pin only; --user-pin is NOT exposed because
// the wire BarrierRekeyRequest has no UserPin field.
func TestRekeyCommand_NoUserPinFlag(t *testing.T) {
	cmd := newRekeyCommand(noopFlags)
	if cmd.Flags().Lookup("user-pin") != nil {
		t.Error("rekey must NOT expose --user-pin (wire request has no UserPin field)")
	}
	if cmd.Flags().Lookup("so-pin") == nil {
		t.Error("rekey must expose --so-pin")
	}
}

// ---------------------------------------------------------------------------
// recovery generate / recover flag validation
// ---------------------------------------------------------------------------

func TestValidateRecoveryGenerateFlags(t *testing.T) {
	cases := []struct {
		name    string
		in      recoveryGenerateFlags
		wantErr any
	}{
		{name: "valid", in: recoveryGenerateFlags{threshold: 3, total: 5}},
		{name: "total < 2", in: recoveryGenerateFlags{threshold: 2, total: 1}, wantErr: ErrInvalidTotal{}},
		{name: "threshold < 2", in: recoveryGenerateFlags{threshold: 1, total: 5}, wantErr: ErrInvalidThreshold{}},
		{name: "threshold > total", in: recoveryGenerateFlags{threshold: 6, total: 5}, wantErr: ErrInvalidThreshold{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRecoveryGenerateFlags(&tc.in)
			assertErrorMatches(t, err, tc.wantErr)
		})
	}
}

func TestValidateRecoveryRecoverFlags(t *testing.T) {
	if err := validateRecoveryRecoverFlags(&recoveryRecoverFlags{shares: []string{"s1"}}); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if err := validateRecoveryRecoverFlags(&recoveryRecoverFlags{}); err == nil {
		t.Error("expected ErrMissingShares")
	}
}

// ---------------------------------------------------------------------------
// Command structure / flag wiring
// ---------------------------------------------------------------------------

func TestSubcommandUseStrings(t *testing.T) {
	cmd := NewCommand(noopFlags)
	checks := []struct{ path, use string }{
		{"status", "status"},
		{"init", "init"},
		{"init-shamir", "init-shamir"},
		{"unseal", "unseal"},
		{"unseal-shares", "unseal-shares"},
		{"seal", "seal"},
		{"rekey", "rekey"},
	}
	for _, c := range checks {
		t.Run(c.path, func(t *testing.T) {
			sub, _, err := cmd.Find([]string{c.path})
			if err != nil {
				t.Fatalf("find %q: %v", c.path, err)
			}
			if sub.Use != c.use {
				t.Errorf("Use=%q want %q", sub.Use, c.use)
			}
		})
	}
}

func TestInitShamirCommand_Flags(t *testing.T) {
	cmd := newInitShamirCommand(noopFlags)
	for _, name := range []string{"passphrase", "threshold", "total", "so-pin", "user-pin"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("init-shamir missing flag --%s", name)
		}
	}
}

func TestUnsealCommand_Flags(t *testing.T) {
	cmd := newUnsealCommand(noopFlags)
	if cmd.Flags().Lookup("passphrase") == nil {
		t.Error("unseal missing --passphrase")
	}
	// "--share" is reserved for unseal-shares; the single-secret unseal
	// MUST NOT expose it.
	if cmd.Flags().Lookup("share") != nil {
		t.Error("unseal must not expose --share")
	}
}

func TestUnsealSharesCommand_Flags(t *testing.T) {
	cmd := newUnsealSharesCommand(noopFlags)
	for _, name := range []string{"share", "shares-file"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("unseal-shares missing flag --%s", name)
		}
	}
}

func TestSealCommand_Flags(t *testing.T) {
	cmd := newSealCommand(noopFlags)
	if cmd.Flags().Lookup("so-pin") == nil {
		t.Error("seal missing --so-pin")
	}
	if cmd.Flags().Lookup("assume-yes") == nil {
		t.Error("seal missing --assume-yes")
	}
	if cmd.Flags().ShorthandLookup("y") == nil {
		t.Error("seal missing -y shorthand")
	}
}

func TestRecoveryGroup_Subcommands(t *testing.T) {
	cmd := newRecoveryCommand(noopFlags)
	expect := map[string]bool{"generate": false, "recover": false}
	for _, sub := range cmd.Commands() {
		if _, ok := expect[sub.Use]; ok {
			expect[sub.Use] = true
		}
	}
	for k, v := range expect {
		if !v {
			t.Errorf("recovery missing %q", k)
		}
	}
}

// TestStatusCommand_NoLocalFlags retains the legacy guarantee that
// "barrier status" has no command-specific flags.
func TestStatusCommand_NoLocalFlags(t *testing.T) {
	cmd := newStatusCommand(noopFlags)
	count := 0
	cmd.LocalFlags().VisitAll(func(*pflag.Flag) { count++ })
	if count != 0 {
		t.Errorf("expected no local flags on status, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func noopFlags() *cli.CommonFlags { return &cli.CommonFlags{} }
