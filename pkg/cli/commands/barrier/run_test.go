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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// flagsWithBrokenContext returns a CommonFlags whose GetContext always
// returns an error. Used to exercise the runXxx happy path past the
// validate -> NewBaseCommand boundary without dialing a daemon.
func flagsWithBrokenContext() *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "test"}
		},
	}
}

// ---------------------------------------------------------------------------
// runInit
// ---------------------------------------------------------------------------

func TestRunInit_ValidationErrorWinsBeforeDial(t *testing.T) {
	// strategy=none + secret should fail validation before any dial.
	err := runInit(flagsWithBrokenContext(), &initFlags{strategy: "none", secret: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(ErrSecretNotAllowed); !ok {
		t.Errorf("expected ErrSecretNotAllowed, got %T: %v", err, err)
	}
}

func TestRunInit_NoContextSurfacedAfterValidation(t *testing.T) {
	// Validation passes; NewBaseCommand fails because GetContext errors.
	err := runInit(flagsWithBrokenContext(), &initFlags{strategy: "none"})
	if err == nil {
		t.Fatal("expected error from NewBaseCommand")
	}
}

// ---------------------------------------------------------------------------
// runInitShamir
// ---------------------------------------------------------------------------

func TestRunInitShamir_ValidationError(t *testing.T) {
	err := runInitShamir(flagsWithBrokenContext(), &initShamirFlags{secret: "p", threshold: 5, total: 3})
	if _, ok := err.(ErrInvalidThreshold); !ok {
		t.Errorf("expected ErrInvalidThreshold, got %T: %v", err, err)
	}
}

func TestRunInitShamir_NoContextSurfacedAfterValidation(t *testing.T) {
	err := runInitShamir(flagsWithBrokenContext(), &initShamirFlags{secret: "p", threshold: 2, total: 3})
	if err == nil {
		t.Fatal("expected error from NewBaseCommand")
	}
}

// ---------------------------------------------------------------------------
// runUnseal
// ---------------------------------------------------------------------------

func TestRunUnseal_MissingSecret(t *testing.T) {
	err := runUnseal(flagsWithBrokenContext(), &unsealFlags{})
	if _, ok := err.(ErrMissingSecret); !ok {
		t.Errorf("expected ErrMissingSecret, got %T: %v", err, err)
	}
}

func TestRunUnseal_NoContextAfterValidation(t *testing.T) {
	err := runUnseal(flagsWithBrokenContext(), &unsealFlags{secret: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// runUnsealShares
// ---------------------------------------------------------------------------

func TestRunUnsealShares_MissingShares(t *testing.T) {
	err := runUnsealShares(strings.NewReader(""), flagsWithBrokenContext(), &unsealSharesFlags{})
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares, got %T: %v", err, err)
	}
}

func TestRunUnsealShares_Conflict(t *testing.T) {
	err := runUnsealShares(strings.NewReader(""), flagsWithBrokenContext(),
		&unsealSharesFlags{shares: []string{"s"}, sharesFile: "x"})
	if _, ok := err.(ErrShareSourcesConflict); !ok {
		t.Errorf("expected ErrShareSourcesConflict, got %T: %v", err, err)
	}
}

func TestRunUnsealShares_NoContextAfterValidation(t *testing.T) {
	err := runUnsealShares(strings.NewReader(""), flagsWithBrokenContext(),
		&unsealSharesFlags{shares: []string{"s"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// runSeal
// ---------------------------------------------------------------------------

func TestRunSeal_DeclinesPromptShortCircuits(t *testing.T) {
	stdin := strings.NewReader("n\n")
	stdout := &bytes.Buffer{}
	err := runSeal(stdin, stdout, flagsWithBrokenContext(), &sealFlags{})
	if _, ok := err.(ErrSealCancelled); !ok {
		t.Errorf("expected ErrSealCancelled, got %T: %v", err, err)
	}
}

func TestRunSeal_AssumeYes_BypassesPrompt(t *testing.T) {
	stdin := strings.NewReader("")
	stdout := &bytes.Buffer{}
	err := runSeal(stdin, stdout, flagsWithBrokenContext(), &sealFlags{assumeYes: true})
	if err == nil {
		t.Fatal("expected error from NewBaseCommand (prompt was bypassed)")
	}
	if _, ok := err.(ErrSealCancelled); ok {
		t.Errorf("--assume-yes must bypass confirmation, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// runRekey
// ---------------------------------------------------------------------------

func TestRunRekey_PartialShamirFlags(t *testing.T) {
	err := runRekey(flagsWithBrokenContext(), &rekeyFlags{threshold: 3})
	if _, ok := err.(ErrRekeyPartialFlags); !ok {
		t.Errorf("expected ErrRekeyPartialFlags, got %T: %v", err, err)
	}
}

func TestRunRekey_NoContextAfterValidation(t *testing.T) {
	err := runRekey(flagsWithBrokenContext(), &rekeyFlags{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// runRecoveryGenerate / runRecoveryRecover
// ---------------------------------------------------------------------------

func TestRunRecoveryGenerate_Validation(t *testing.T) {
	err := runRecoveryGenerate(flagsWithBrokenContext(), &recoveryGenerateFlags{threshold: 6, total: 5})
	if _, ok := err.(ErrInvalidThreshold); !ok {
		t.Errorf("expected ErrInvalidThreshold, got %T: %v", err, err)
	}
}

func TestRunRecoveryGenerate_NoContextAfterValidation(t *testing.T) {
	err := runRecoveryGenerate(flagsWithBrokenContext(), &recoveryGenerateFlags{threshold: 2, total: 3})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunRecoveryRecover_MissingShares(t *testing.T) {
	err := runRecoveryRecover(flagsWithBrokenContext(), &recoveryRecoverFlags{})
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares, got %T: %v", err, err)
	}
}

func TestRunRecoveryRecover_NoContextAfterValidation(t *testing.T) {
	err := runRecoveryRecover(flagsWithBrokenContext(), &recoveryRecoverFlags{shares: []string{"a"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Errors_Wrap chain — verify Unwrap works for every typed error.
// ---------------------------------------------------------------------------

func TestErrors_UnwrapChain(t *testing.T) {
	inner := errors.New("inner")
	cases := []error{
		ErrBarrierInitFailed{Err: inner},
		ErrBarrierInitShamirFailed{Err: inner},
		ErrBarrierStatusFailed{Err: inner},
		ErrBarrierUnsealFailed{Err: inner},
		ErrBarrierUnsealSharesFailed{Err: inner},
		ErrBarrierSealFailed{Err: inner},
		ErrBarrierRekeyFailed{Err: inner},
		ErrBarrierRecoveryGenerateFailed{Err: inner},
		ErrBarrierRecoveryRecoverFailed{Err: inner},
		ErrSharesFileReadFailed{Path: "x", Err: inner},
	}
	for _, e := range cases {
		t.Run(e.Error(), func(t *testing.T) {
			if !errors.Is(e, inner) {
				t.Errorf("errors.Is must reach inner for %T", e)
			}
		})
	}
}

// TestErrorTypes_Messages verifies each typed error produces a stable
// message with the expected substring.
func TestErrorTypes_Messages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrInvalidBarrierStrategy{Strategy: "bogus"}, "invalid --barrier-strategy"},
		{ErrSecretRequired{Strategy: "passphrase"}, "--passphrase is required"},
		{ErrSecretNotAllowed{Strategy: "none"}, "--passphrase is not allowed"},
		{PINsNotAllowedError{Flag: "so-pin", Strategy: "none"}, "--so-pin is not allowed"},
		{ErrUserPinRequiresSOPin{}, "--user-pin requires --so-pin"},
		{ErrSOPinRequiresUserPin{}, "--so-pin requires --user-pin"},
		{ErrInvalidThreshold{Threshold: 5, Total: 3}, "invalid threshold"},
		{ErrInvalidTotal{Total: 1}, "invalid total"},
		{ErrMissingSecret{}, "passphrase is required"},
		{ErrMissingShares{}, "at least one share is required"},
		{ErrShareSourcesConflict{}, "either --share"},
		{ErrSealCancelled{}, "cancelled"},
		{ErrRekeyPartialFlags{}, "set together"},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			if !strings.Contains(tc.err.Error(), tc.want) {
				t.Errorf("expected %q in %q", tc.want, tc.err.Error())
			}
		})
	}
}
