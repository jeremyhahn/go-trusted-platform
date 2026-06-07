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
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// brokenFlagsCtor returns a getFlags that supplies a broken-context
// CommonFlags. Used to drive each verb's RunE past validation but
// short-circuit at the dial step.
func brokenFlagsCtor() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	}
}

// runCobra is a small helper that drives a cobra command's RunE in
// isolation: it sets stdin / stdout buffers, parses the flag set, and
// returns the resulting error.
func runCobra(cmd *cobra.Command, args []string, stdin string) error {
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

// TestCobra_StatusRunE_NoContext drives the cobra status command end
// to end past flag parsing.
func TestCobra_StatusRunE_NoContext(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"status"}, "")
	if err == nil {
		t.Fatal("expected error from broken context")
	}
}

// TestCobra_InitRunE_ValidationError drives barrier init through cobra
// with a flag set that fails validation (--barrier-strategy missing).
func TestCobra_InitRunE_ValidationError(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"init"}, "")
	if err == nil {
		t.Fatal("expected validation error from empty strategy")
	}
}

// TestCobra_InitRunE_PINsNotAllowed exercises the canonical
// "--barrier-strategy=none --so-pin X" rejection path end-to-end.
func TestCobra_InitRunE_PINsNotAllowed(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"init", "--barrier-strategy", "none", "--so-pin", "1234"}, "")
	if err == nil {
		t.Fatal("expected PINsNotAllowedError")
	}
	if _, ok := err.(PINsNotAllowedError); !ok {
		t.Errorf("expected PINsNotAllowedError, got %T: %v", err, err)
	}
}

// TestCobra_InitShamirRunE_ValidationError drives barrier init-shamir.
func TestCobra_InitShamirRunE_ValidationError(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"init-shamir", "--passphrase", "p", "--threshold", "5", "--total", "3"}, "")
	if _, ok := err.(ErrInvalidThreshold); !ok {
		t.Errorf("expected ErrInvalidThreshold, got %T: %v", err, err)
	}
}

// TestCobra_UnsealRunE_MissingSecret exercises barrier unseal.
func TestCobra_UnsealRunE_MissingSecret(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"unseal"}, "")
	if _, ok := err.(ErrMissingSecret); !ok {
		t.Errorf("expected ErrMissingSecret, got %T: %v", err, err)
	}
}

// TestCobra_UnsealSharesRunE_MissingShares exercises barrier
// unseal-shares.
func TestCobra_UnsealSharesRunE_MissingShares(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"unseal-shares"}, "")
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares, got %T: %v", err, err)
	}
}

// TestCobra_UnsealSharesRunE_StdinShares exercises the --shares-file=-
// path including stdin handling and verifies the dial fails (no live
// daemon) after a successful share load.
func TestCobra_UnsealSharesRunE_StdinShares(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"unseal-shares", "--shares-file", "-"}, "s1\ns2\n")
	if err == nil {
		t.Fatal("expected dial error after share load")
	}
}

// TestCobra_SealRunE_DeclinePrompt drives barrier seal end-to-end with
// an "n" response so the prompt is exercised.
func TestCobra_SealRunE_DeclinePrompt(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"seal"}, "n\n")
	if _, ok := err.(ErrSealCancelled); !ok {
		t.Errorf("expected ErrSealCancelled, got %T: %v", err, err)
	}
}

// TestCobra_SealRunE_AssumeYesSkipsPrompt verifies -y short-circuits
// the prompt.
func TestCobra_SealRunE_AssumeYesSkipsPrompt(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"seal", "-y"}, "")
	if err == nil {
		t.Fatal("expected dial error after prompt bypass")
	}
	if _, ok := err.(ErrSealCancelled); ok {
		t.Error("--assume-yes must not return ErrSealCancelled")
	}
}

// TestCobra_RekeyRunE_PartialFlags drives barrier rekey through cobra
// with only --threshold (no --total).
func TestCobra_RekeyRunE_PartialFlags(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"rekey", "--passphrase", "new", "--threshold", "3"}, "")
	if _, ok := err.(ErrRekeyPartialFlags); !ok {
		t.Errorf("expected ErrRekeyPartialFlags, got %T: %v", err, err)
	}
}

// TestCobra_RecoveryGenerateRunE_Validation drives recovery generate.
func TestCobra_RecoveryGenerateRunE_Validation(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"recovery", "generate", "--threshold", "6", "--total", "5"}, "")
	if _, ok := err.(ErrInvalidThreshold); !ok {
		t.Errorf("expected ErrInvalidThreshold, got %T: %v", err, err)
	}
}

// TestCobra_RecoveryRecoverRunE_MissingShares drives recovery recover.
func TestCobra_RecoveryRecoverRunE_MissingShares(t *testing.T) {
	root := NewCommand(brokenFlagsCtor())
	err := runCobra(root, []string{"recovery", "recover"}, "")
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares, got %T: %v", err, err)
	}
}
