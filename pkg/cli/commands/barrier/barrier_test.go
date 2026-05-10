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
	"errors"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	barriersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/barrier"
)

func TestNewCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	if cmd.Use != "barrier" {
		t.Errorf("expected Use 'barrier', got %q", cmd.Use)
	}

	if cmd.Short != "Barrier storage management" {
		t.Errorf("expected Short 'Barrier storage management', got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	expectedNames := map[string]bool{
		"init":   false,
		"status": false,
		"unseal": false,
		"seal":   false,
		"rekey":  false,
	}

	for _, sub := range subcommands {
		if _, ok := expectedNames[sub.Use]; ok {
			expectedNames[sub.Use] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}

	if len(subcommands) != len(expectedNames) {
		t.Errorf("expected %d subcommands, got %d", len(expectedNames), len(subcommands))
	}
}

func TestNewCommand_SubcommandDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	tests := []struct {
		name          string
		expectedShort string
	}{
		{name: "init", expectedShort: "REMOVED: use the root 'platformctl init' command instead"},
		{name: "status", expectedShort: "Show barrier status"},
		{name: "unseal", expectedShort: "Unseal the barrier"},
		{name: "seal", expectedShort: "Seal the barrier"},
		{name: "rekey", expectedShort: "Rekey the barrier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, _, err := cmd.Find([]string{tt.name})
			if err != nil {
				t.Fatalf("failed to find subcommand %q: %v", tt.name, err)
			}
			if sub.Short != tt.expectedShort {
				t.Errorf("expected Short %q, got %q", tt.expectedShort, sub.Short)
			}
		})
	}
}

// TestInitCommand_RedirectsToRootInit verifies that the legacy
// "platformctl barrier init" subcommand emits CanonicalRedirectError
// pointing at the root "platformctl init" command per
// docs/08-bootstrap-auth-architecture.md §6.
func TestInitCommand_RedirectsToRootInit(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	initCmd, _, err := cmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("failed to find init subcommand: %v", err)
	}
	if initCmd.RunE == nil {
		t.Fatal("legacy barrier init must have a RunE that emits CanonicalRedirectError")
	}

	runErr := initCmd.RunE(initCmd, nil)
	if runErr == nil {
		t.Fatal("expected CanonicalRedirectError from legacy barrier init")
	}
	var redirect *CanonicalRedirectError
	if !errors.As(runErr, &redirect) {
		t.Fatalf("expected *CanonicalRedirectError, got %T: %v", runErr, runErr)
	}
	if redirect.Old != "platformctl barrier init" {
		t.Errorf("expected Old=\"platformctl barrier init\", got %q", redirect.Old)
	}
}

// TestInitCommand_RedirectIgnoresLegacyFlags verifies the redirect
// stub disables flag parsing entirely so legacy --secret / --threshold
// / --shares arguments are passed through to the redirect handler.
func TestInitCommand_RedirectIgnoresLegacyFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	initCmd, _, err := cmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("failed to find init subcommand: %v", err)
	}

	// The redirect command MUST NOT register the legacy flags; the
	// canonical flag set lives on the root "platformctl init" command.
	if flag := initCmd.Flags().Lookup("secret"); flag != nil {
		t.Error("legacy --secret flag must not be exposed on the redirect stub")
	}
	if flag := initCmd.Flags().Lookup("threshold"); flag != nil {
		t.Error("legacy --threshold flag must not be exposed on the redirect stub")
	}
	if flag := initCmd.Flags().Lookup("shares"); flag != nil {
		t.Error("legacy --shares flag must not be exposed on the redirect stub")
	}
}

func TestUnsealCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	unsealCmd, _, err := cmd.Find([]string{"unseal"})
	if err != nil {
		t.Fatalf("failed to find unseal subcommand: %v", err)
	}

	tests := []struct {
		flagName     string
		defaultValue string
	}{
		{flagName: "secret", defaultValue: ""},
		{flagName: "share", defaultValue: ""},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := unsealCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Fatalf("expected flag %q not found", tt.flagName)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("expected default %q, got %q", tt.defaultValue, flag.DefValue)
			}
		})
	}
}

func TestRekeyCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	rekeyCmd, _, err := cmd.Find([]string{"rekey"})
	if err != nil {
		t.Fatalf("failed to find rekey subcommand: %v", err)
	}

	tests := []struct {
		flagName     string
		defaultValue string
	}{
		{flagName: "threshold", defaultValue: "1"},
		{flagName: "shares", defaultValue: "1"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := rekeyCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Fatalf("expected flag %q not found", tt.flagName)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("expected default %q, got %q", tt.defaultValue, flag.DefValue)
			}
		})
	}
}

func TestValidateInitParams_SingleKeyValid(t *testing.T) {
	err := validateInitParams("my-secret", 1, 1)
	if err != nil {
		t.Errorf("expected no error for valid single-key params, got: %v", err)
	}
}

func TestValidateInitParams_SingleKeyMissingSecret(t *testing.T) {
	err := validateInitParams("", 1, 1)
	if err == nil {
		t.Error("expected error for missing secret in single-key mode")
	}

	if _, ok := err.(ErrMissingSecret); !ok {
		t.Errorf("expected ErrMissingSecret, got %T: %v", err, err)
	}
}

func TestValidateInitParams_ShamirValid(t *testing.T) {
	err := validateInitParams("", 3, 5)
	if err != nil {
		t.Errorf("expected no error for valid Shamir params, got: %v", err)
	}
}

func TestValidateInitParams_ShamirInvalidThreshold(t *testing.T) {
	err := validateInitParams("", 5, 3)
	if err == nil {
		t.Error("expected error when threshold > shares")
	}

	e, ok := err.(ErrInvalidThreshold)
	if !ok {
		t.Errorf("expected ErrInvalidThreshold, got %T: %v", err, err)
	}

	if e.Threshold != 5 || e.Shares != 3 {
		t.Errorf("expected threshold=5 shares=3, got threshold=%d shares=%d", e.Threshold, e.Shares)
	}
}

func TestValidateInitParams_ShamirEqualThresholdAndShares(t *testing.T) {
	err := validateInitParams("", 3, 3)
	if err != nil {
		t.Errorf("expected no error when threshold == shares, got: %v", err)
	}
}

func TestValidateInitParams_ShamirWithSecret(t *testing.T) {
	// Shamir mode should work even if secret is provided (threshold >= 2 takes precedence)
	err := validateInitParams("some-secret", 3, 5)
	if err != nil {
		t.Errorf("expected no error for Shamir mode with secret, got: %v", err)
	}
}

func TestFormatStrategy(t *testing.T) {
	tests := []struct {
		strategy barriersvc.Strategy
		expected string
	}{
		{strategy: barriersvc.StrategyUnspecified, expected: "unspecified"},
		{strategy: barriersvc.StrategySingleKey, expected: "single-key"},
		{strategy: barriersvc.StrategyShamir, expected: "shamir"},
		{strategy: barriersvc.Strategy("bogus"), expected: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatStrategy(tt.strategy)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrBarrierInitFailed",
			err:      ErrBarrierInitFailed{Err: ErrMissingSecret{}},
			contains: "barrier initialization failed",
		},
		{
			name:     "ErrBarrierStatusFailed",
			err:      ErrBarrierStatusFailed{Err: ErrMissingSecret{}},
			contains: "failed to get barrier status",
		},
		{
			name:     "ErrBarrierUnsealFailed",
			err:      ErrBarrierUnsealFailed{Err: ErrMissingSecret{}},
			contains: "barrier unseal failed",
		},
		{
			name:     "ErrBarrierSealFailed",
			err:      ErrBarrierSealFailed{Err: ErrMissingSecret{}},
			contains: "barrier seal failed",
		},
		{
			name:     "ErrBarrierRekeyFailed",
			err:      ErrBarrierRekeyFailed{Err: ErrMissingSecret{}},
			contains: "barrier rekey failed",
		},
		{
			name:     "ErrInvalidThreshold",
			err:      ErrInvalidThreshold{Threshold: 5, Shares: 3},
			contains: "invalid threshold",
		},
		{
			name:     "ErrInvalidShares",
			err:      ErrInvalidShares{Shares: 0},
			contains: "invalid shares",
		},
		{
			name:     "ErrMissingSecret",
			err:      ErrMissingSecret{},
			contains: "secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Error("expected non-empty error message")
			}
			if !strings.Contains(msg, tt.contains) {
				t.Errorf("expected error to contain %q, got %q", tt.contains, msg)
			}
		})
	}
}

func TestSealCommand_NoLocalFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	sealCmd, _, err := cmd.Find([]string{"seal"})
	if err != nil {
		t.Fatalf("failed to find seal subcommand: %v", err)
	}

	// Seal should have no command-specific flags
	count := 0
	sealCmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		count++
	})
	if count != 0 {
		t.Errorf("expected no local flags on seal command, got %d", count)
	}
}

func TestStatusCommand_NoLocalFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	statusCmd, _, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("failed to find status subcommand: %v", err)
	}

	// Status should have no command-specific flags
	count := 0
	statusCmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		count++
	})
	if count != 0 {
		t.Errorf("expected no local flags on status command, got %d", count)
	}
}

func TestErrors_Wrapping(t *testing.T) {
	// Verify that wrapped errors preserve the inner error message
	inner := ErrMissingSecret{}

	tests := []struct {
		name string
		err  error
	}{
		{name: "init", err: ErrBarrierInitFailed{Err: inner}},
		{name: "status", err: ErrBarrierStatusFailed{Err: inner}},
		{name: "unseal", err: ErrBarrierUnsealFailed{Err: inner}},
		{name: "seal", err: ErrBarrierSealFailed{Err: inner}},
		{name: "rekey", err: ErrBarrierRekeyFailed{Err: inner}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !strings.Contains(msg, inner.Error()) {
				t.Errorf("expected wrapped error to contain inner error message %q, got %q", inner.Error(), msg)
			}
		})
	}
}
