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

// canonical_init_strategies_test.go verifies the pluggable
// --barrier-strategy contract per docs/08-bootstrap-auth-architecture.md
// §6 (Task #126).
//
// The test exercises each of the 9 canonical strategies end-to-end at
// the CLI/SDK boundary:
//
//	software, shamir, pkcs11, tpm2, awskms, gcpkms, azurekv, vault, none
//
// Strategy-specific flag validation, SDK request mapping, and the
// environment variable surface (PLATFORMCTL_BARRIER_STRATEGY) are all
// covered. Backend-specific behavior (HSM seal, TPM seal, cloud-KMS
// envelope) lives downstream of the CLI in qrdb's ceremony service and
// is exercised by integration tests in test/integration/ceremony.

package commands

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// canonicalStrategies enumerates every strategy the CLI must accept.
// The list intentionally mirrors validBarrierStrategies so the test
// fails when a new strategy is added without test coverage.
var canonicalStrategies = []string{
	"software",
	"shamir",
	"pkcs11",
	"tpm2",
	"awskms",
	"gcpkms",
	"azurekv",
	"vault",
	"none",
}

// newInitCmdForTest builds an isolated cobra "init" command bound to
// a fresh flag struct and applies the supplied flag values via
// cmd.Flags().Set. Tests use this rather than the global rootCmd so
// flag.Changed() state does not bleed across cases. Going through
// cmd.Flags().Set (rather than direct struct assignment) is essential
// because pflag.StringVar / pflag.IntVar overwrite the bound address
// with their declared default at registration time, so any field set
// before wireCanonicalInitFlags would be clobbered.
func newInitCmdForTest(t *testing.T, fields map[string]string) (*cobra.Command, *canonicalInitFlags) {
	t.Helper()
	f := &canonicalInitFlags{}
	cmd := &cobra.Command{Use: "init"}
	wireCanonicalInitFlags(cmd, f)
	for name, value := range fields {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s=%s: %v", name, value, err)
		}
	}
	return cmd, f
}

// strategyFlags returns the canonical flag set for a given strategy
// pre-populated with valid PINs. Shamir gets a 3-of-5 quorum by
// default; non-shamir strategies have no shares/threshold flags so
// they exercise the "shamir-flags-only" rejection branch in the
// validator.
func strategyFlags(strategy string, shares, threshold int) map[string]string {
	out := map[string]string{
		"so-pin":           "so",
		"user-pin":         "user",
		"barrier-strategy": strategy,
	}
	if shares != 0 {
		out["shares"] = strconv.Itoa(shares)
	}
	if threshold != 0 {
		out["threshold"] = strconv.Itoa(threshold)
	}
	return out
}

// TestCanonicalInit_AllStrategiesAreRegistered guards the registry
// against silent removal. validBarrierStrategies is the sole source of
// truth for which strategies the CLI accepts; this test asserts every
// canonical strategy is present.
func TestCanonicalInit_AllStrategiesAreRegistered(t *testing.T) {
	if len(validBarrierStrategies) != len(canonicalStrategies) {
		t.Fatalf("strategy count drift: registry=%d, canonical=%d",
			len(validBarrierStrategies), len(canonicalStrategies))
	}
	for _, s := range canonicalStrategies {
		if _, ok := validBarrierStrategies[s]; !ok {
			t.Errorf("canonical strategy %q missing from validBarrierStrategies", s)
		}
	}
}

// TestCanonicalInit_StrategyValidationMatrix exercises every canonical
// strategy through resolveAndValidateCanonicalInit:
//
//   - software / pkcs11 / tpm2 / awskms / gcpkms / azurekv / vault / none
//     pass with no shamir flags;
//   - shamir requires --shares >= 2 and 2 <= --threshold <= shares;
//   - non-shamir strategies must reject --shares / --threshold > 0.
//
// Backend-specific availability (TPM / HSM / cloud creds) is not
// asserted here because the CLI is opaque about backend wiring; those
// failures surface from qrdb's ceremony service at runtime.
func TestCanonicalInit_StrategyValidationMatrix(t *testing.T) {
	type tc struct {
		name      string
		strategy  string
		shares    int
		threshold int
		wantErr   bool
		errSubstr string
	}

	cases := []tc{
		// Happy paths.
		{name: "software", strategy: "software"},
		{name: "pkcs11", strategy: "pkcs11"},
		{name: "tpm2", strategy: "tpm2"},
		{name: "awskms", strategy: "awskms"},
		{name: "gcpkms", strategy: "gcpkms"},
		{name: "azurekv", strategy: "azurekv"},
		{name: "vault", strategy: "vault"},
		{name: "none", strategy: "none"},
		{name: "shamir-3-of-5", strategy: "shamir", shares: 5, threshold: 3},
		{name: "shamir-2-of-2", strategy: "shamir", shares: 2, threshold: 2},

		// Shamir invariants.
		{
			name: "shamir-shares-too-small", strategy: "shamir",
			shares: 1, threshold: 1, wantErr: true, errSubstr: "shares >= 2",
		},
		{
			name: "shamir-threshold-greater-than-shares", strategy: "shamir",
			shares: 3, threshold: 5, wantErr: true, errSubstr: "threshold",
		},
		{
			name: "shamir-threshold-zero", strategy: "shamir",
			shares: 5, threshold: 0, wantErr: true, errSubstr: "threshold",
		},

		// Non-shamir rejecting --shares / --threshold.
		{
			name: "software-with-shares-rejected", strategy: "software",
			shares: 3, threshold: 2, wantErr: true, errSubstr: "shamir",
		},
		{
			name: "tpm2-with-threshold-rejected", strategy: "tpm2",
			shares: 0, threshold: 2, wantErr: true, errSubstr: "shamir",
		},
		{
			name: "vault-with-shares-rejected", strategy: "vault",
			shares: 5, threshold: 0, wantErr: true, errSubstr: "shamir",
		},
		{
			name: "none-with-shares-rejected", strategy: "none",
			shares: 5, threshold: 0, wantErr: true, errSubstr: "shamir",
		},

		// Unknown strategies must be rejected outright.
		{
			name: "unknown-strategy", strategy: "bogus",
			wantErr: true, errSubstr: "invalid --barrier-strategy",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cmd, f := newInitCmdForTest(t, strategyFlags(c.strategy, c.shares, c.threshold))
			err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_NOENV")

			if c.wantErr {
				if err == nil {
					t.Fatalf("strategy %q: expected error, got nil", c.strategy)
				}
				if c.errSubstr != "" && !strings.Contains(err.Error(), c.errSubstr) {
					t.Errorf("strategy %q: error %q missing substring %q",
						c.strategy, err.Error(), c.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("strategy %q: unexpected error: %v", c.strategy, err)
			}
		})
	}
}

// TestCanonicalInit_BuildInitRequest_StrategyPropagation verifies the
// SDK request that runCanonicalInit dispatches carries the operator's
// strategy choice verbatim. The platform is opaque about the backend;
// the only contract here is that the strategy string flows through
// without mutation so the qrdb ceremony service can dispatch.
func TestCanonicalInit_BuildInitRequest_StrategyPropagation(t *testing.T) {
	for _, strategy := range canonicalStrategies {
		strategy := strategy
		t.Run(strategy, func(t *testing.T) {
			fields := strategyFlags(strategy, 0, 0)
			fields["hostname"] = "host.example.com"
			fields["sans"] = "alt.example.com"
			if strategy == "shamir" {
				fields["shares"] = "5"
				fields["threshold"] = "3"
			}
			_, f := newInitCmdForTest(t, fields)

			req := buildInitRequest(f)
			if req == nil {
				t.Fatal("buildInitRequest returned nil")
			}
			if req.CredentialSealStrategy != strategy {
				t.Errorf("CredentialSealStrategy: want %q, got %q",
					strategy, req.CredentialSealStrategy)
			}
			if req.SOPIN != "so" || req.UserPIN != "user" {
				t.Errorf("PIN propagation broken: SOPIN=%q UserPIN=%q",
					req.SOPIN, req.UserPIN)
			}
			if req.Hostname != "host.example.com" {
				t.Errorf("Hostname: want %q, got %q",
					"host.example.com", req.Hostname)
			}
			if len(req.SANs) != 1 || req.SANs[0] != "alt.example.com" {
				t.Errorf("SANs: want [alt.example.com], got %v", req.SANs)
			}

			// Threshold must only be populated for shamir; every
			// other strategy ignores it and emitting "0-of-0" leaks
			// an internal default into the wire request.
			if strategy == "shamir" {
				if req.Threshold != "3-of-5" {
					t.Errorf("shamir Threshold: want %q, got %q",
						"3-of-5", req.Threshold)
				}
			} else {
				if req.Threshold != "" {
					t.Errorf("non-shamir Threshold: want empty, got %q",
						req.Threshold)
				}
			}
		})
	}
}

// TestCanonicalInit_BuildInitRequest_NoSANsYieldsNilSlice verifies the
// empty-SAN edge case so the SDK does not record an empty list. Empty
// SAN lists confuse downstream validators that distinguish "no SANs"
// from "explicit empty SANs".
func TestCanonicalInit_BuildInitRequest_NoSANsYieldsNilSlice(t *testing.T) {
	_, f := newInitCmdForTest(t, strategyFlags("software", 0, 0))
	req := buildInitRequest(f)
	if req.SANs != nil {
		t.Errorf("SANs: want nil, got %v", req.SANs)
	}
}

// TestCanonicalInit_BarrierStrategyEnvVar verifies that
// PLATFORMCTL_BARRIER_STRATEGY drives the strategy selection when no
// CLI flag is set. Each canonical strategy is exercised because the
// env binding is the documented contract per the Long help text.
func TestCanonicalInit_BarrierStrategyEnvVar(t *testing.T) {
	for _, strategy := range canonicalStrategies {
		strategy := strategy
		t.Run(strategy, func(t *testing.T) {
			t.Setenv("PLATFORMCTL_TEST_ENV_SO_PIN", "so")
			t.Setenv("PLATFORMCTL_TEST_ENV_USER_PIN", "user")
			t.Setenv("PLATFORMCTL_TEST_ENV_BARRIER_STRATEGY", strategy)
			if strategy == "shamir" {
				t.Setenv("PLATFORMCTL_TEST_ENV_SHARES", "5")
				t.Setenv("PLATFORMCTL_TEST_ENV_THRESHOLD", "3")
			}

			// No flag overrides; the validator must hydrate every
			// field from PLATFORMCTL_TEST_ENV_*.
			cmd, f := newInitCmdForTest(t, nil)
			if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_ENV"); err != nil {
				t.Fatalf("strategy %q: validation failed: %v", strategy, err)
			}
			if f.barrierStrategy != strategy {
				t.Errorf("barrierStrategy: want %q, got %q",
					strategy, f.barrierStrategy)
			}
			if strategy == "shamir" {
				if f.shares != 5 || f.threshold != 3 {
					t.Errorf("shamir env: shares=%d threshold=%d",
						f.shares, f.threshold)
				}
			}
			req := buildInitRequest(f)
			if req.CredentialSealStrategy != strategy {
				t.Errorf("env -> SDK propagation broken: want %q, got %q",
					strategy, req.CredentialSealStrategy)
			}
		})
	}
}

// TestCanonicalInit_ShamirThresholdFormat verifies the canonical
// "M-of-N" Shamir threshold descriptor matches what the SDK and qrdb
// ceremony service expect. Drift here would silently break Shamir
// share recovery on the platform side.
func TestCanonicalInit_ShamirThresholdFormat(t *testing.T) {
	cases := []struct {
		shares    int
		threshold int
		want      string
	}{
		{shares: 2, threshold: 2, want: "2-of-2"},
		{shares: 5, threshold: 3, want: "3-of-5"},
		{shares: 7, threshold: 4, want: "4-of-7"},
	}
	for _, c := range cases {
		_, f := newInitCmdForTest(t, strategyFlags("shamir", c.shares, c.threshold))
		req := buildInitRequest(f)
		if req.Threshold != c.want {
			t.Errorf("threshold %d-of-%d: want %q, got %q",
				c.threshold, c.shares, c.want, req.Threshold)
		}
	}
}

// TestCanonicalInit_StrategyEndToEnd documents which strategies are
// fully exercisable at unit-test scope and which require external
// dependencies (hardware, cloud creds) that live in the integration
// suite.
//
// Per the locked Phase 3 SDK contract (sdk/go/services/ceremony):
// NewClient() returns a stub that returns ErrNotYetWired for every
// method until the in-process server-side handlers land in Phase 3.5.
// The grpc-backed client wires through to the real qrdb ceremony
// service when a daemon is reachable.
//
// What this test asserts:
//
//   - software:  validation + SDK request mapping covered;
//     Argon2id derivation runs server-side in the qrdb
//     ceremony service.
//   - shamir:    validation + SDK request mapping + threshold format
//     covered; share splitting + recovery runs server-side.
//   - pkcs11:    validation + mapping covered; HSM-bound seal runs
//     server-side and is gated on HSM availability.
//   - tpm2:      validation + mapping covered; TPM-bound seal runs
//     server-side and is gated on TPM availability.
//   - awskms / gcpkms / azurekv / vault:
//     validation + mapping covered; envelope encryption
//     runs server-side and is gated on cloud credentials.
//   - none:      validation + mapping covered; the qrdb ceremony
//     service installs a passthrough barrier with no
//     encryption (dev/test).
//
// Backend-specific happy paths are exercised by
// test/integration/ceremony, which runs the CLI against a real qrdb
// ceremony service in the devcontainer.
func TestCanonicalInit_StrategyEndToEnd(t *testing.T) {
	for _, strategy := range canonicalStrategies {
		strategy := strategy
		t.Run(strategy, func(t *testing.T) {
			fields := strategyFlags(strategy, 0, 0)
			if strategy == "shamir" {
				fields["shares"] = "5"
				fields["threshold"] = "3"
			}
			cmd, f := newInitCmdForTest(t, fields)
			if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_E2E"); err != nil {
				t.Fatalf("strategy %q validation: %v", strategy, err)
			}

			req := buildInitRequest(f)
			if req.CredentialSealStrategy != strategy {
				t.Fatalf("strategy %q not propagated", strategy)
			}

			// The Phase 3 stub client deliberately fails so callers
			// observe the wiring rather than a silent no-op. Verify
			// the failure mode is the typed ErrInitFailed wrapping
			// ErrNotYetWired so the strategy plumbing is reachable
			// regardless of which backend the daemon would invoke.
			client := ceremonysvc.NewClient()
			_, err := client.Init(t.Context(), req)
			if err == nil {
				t.Fatal("Phase 3 stub client must surface ErrNotYetWired")
			}
			var initFailed *ceremonysvc.ErrInitFailed
			if !errors.As(err, &initFailed) {
				t.Fatalf("strategy %q: want *ceremonysvc.ErrInitFailed, got %T",
					strategy, err)
			}
			if !errors.Is(initFailed.Cause, ceremonysvc.ErrNotYetWired) {
				t.Errorf("strategy %q: want ErrNotYetWired, got %v",
					strategy, initFailed.Cause)
			}
		})
	}
}

// TestCanonicalInit_NoneStrategyAcceptsNoPins verifies the
// --barrier-strategy=none surface: when the passthrough barrier is
// selected, --so-pin and --user-pin are optional because there is no
// key material to gate. Operators selecting "none" for dev/test must
// be able to invoke `platformctl init --barrier-strategy=none` without
// supplying any PIN material.
func TestCanonicalInit_NoneStrategyAcceptsNoPins(t *testing.T) {
	// No so-pin / user-pin in the flag set; only the strategy flag is
	// set to "none". Every other strategy would fail with ErrMissingPIN.
	cmd, f := newInitCmdForTest(t, map[string]string{
		"barrier-strategy": "none",
	})
	if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_NONE_NOENV"); err != nil {
		t.Fatalf("strategy=none with no PINs must validate cleanly; got: %v", err)
	}
	if f.soPin != "" || f.userPin != "" {
		t.Errorf("PINs unexpectedly populated: soPin=%q userPin=%q",
			f.soPin, f.userPin)
	}
	if f.barrierStrategy != "none" {
		t.Errorf("barrierStrategy: want %q, got %q", "none", f.barrierStrategy)
	}
}

// TestCanonicalInit_NoneStrategyProducesWorkingInitRequest verifies
// that selecting --barrier-strategy=none builds an SDK InitRequest
// that carries the strategy string verbatim and leaves PIN fields
// empty (because they were not supplied), with no shamir threshold
// leak. The qrdb ceremony service interprets an empty PIN + "none"
// strategy as a request to install the passthrough barrier.
func TestCanonicalInit_NoneStrategyProducesWorkingInitRequest(t *testing.T) {
	cmd, f := newInitCmdForTest(t, map[string]string{
		"barrier-strategy": "none",
		"hostname":         "dev.example.com",
		"sans":             "alt.example.com,127.0.0.1",
	})
	if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_NONE_REQ"); err != nil {
		t.Fatalf("strategy=none validation: %v", err)
	}

	req := buildInitRequest(f)
	if req == nil {
		t.Fatal("buildInitRequest returned nil")
	}
	if req.CredentialSealStrategy != "none" {
		t.Errorf("CredentialSealStrategy: want %q, got %q",
			"none", req.CredentialSealStrategy)
	}
	if req.SOPIN != "" || req.UserPIN != "" {
		t.Errorf("none-strategy InitRequest must carry empty PINs; got SOPIN=%q UserPIN=%q",
			req.SOPIN, req.UserPIN)
	}
	if req.Threshold != "" {
		t.Errorf("none-strategy InitRequest must not carry a Shamir threshold; got %q",
			req.Threshold)
	}
	if req.Hostname != "dev.example.com" {
		t.Errorf("Hostname: want %q, got %q", "dev.example.com", req.Hostname)
	}
	if len(req.SANs) != 2 || req.SANs[0] != "alt.example.com" || req.SANs[1] != "127.0.0.1" {
		t.Errorf("SANs: want [alt.example.com 127.0.0.1], got %v", req.SANs)
	}

	// Drive the same request through the Phase 3 stub client to
	// confirm the strategy plumbing is reachable end-to-end. The stub
	// surfaces ErrNotYetWired wrapped in ErrInitFailed; what we are
	// asserting here is that "none" is dispatchable rather than
	// silently filtered upstream.
	client := ceremonysvc.NewClient()
	_, callErr := client.Init(t.Context(), req)
	if callErr == nil {
		t.Fatal("Phase 3 stub client must surface ErrNotYetWired")
	}
	var initFailed *ceremonysvc.ErrInitFailed
	if !errors.As(callErr, &initFailed) {
		t.Fatalf("none-strategy: want *ceremonysvc.ErrInitFailed, got %T", callErr)
	}
	if !errors.Is(initFailed.Cause, ceremonysvc.ErrNotYetWired) {
		t.Errorf("none-strategy: want ErrNotYetWired, got %v", initFailed.Cause)
	}
}

// TestCanonicalInit_NoneStrategyAcceptsExplicitPins verifies that the
// "none" passthrough does not REJECT PINs when an operator supplies
// them. PINs are simply optional, not forbidden; rejecting them would
// surprise operators who paste a shared template.
func TestCanonicalInit_NoneStrategyAcceptsExplicitPins(t *testing.T) {
	cmd, f := newInitCmdForTest(t, map[string]string{
		"so-pin":           "so",
		"user-pin":         "user",
		"barrier-strategy": "none",
	})
	if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_NONE_PINS"); err != nil {
		t.Fatalf("strategy=none with PINs must validate cleanly; got: %v", err)
	}
	req := buildInitRequest(f)
	if req.SOPIN != "so" || req.UserPIN != "user" {
		t.Errorf("PIN propagation broken: SOPIN=%q UserPIN=%q", req.SOPIN, req.UserPIN)
	}
}

// TestCanonicalInit_NonsenseStrategyRejectedWithTypedError verifies
// that an unrecognised --barrier-strategy value produces the typed
// ErrInvalidBarrierStrategy error rather than a free-form string.
// Operators and wrappers (e.g. devcontainer scripts) match on the
// typed error to decide whether to retry with a corrected flag.
func TestCanonicalInit_NonsenseStrategyRejectedWithTypedError(t *testing.T) {
	cases := []string{"nonsense", "softwareX", "shamir2", "none ", "NONE"}
	for _, bogus := range cases {
		bogus := bogus
		t.Run(bogus, func(t *testing.T) {
			cmd, f := newInitCmdForTest(t, map[string]string{
				"so-pin":           "so",
				"user-pin":         "user",
				"barrier-strategy": bogus,
			})
			err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_NONSENSE")
			if err == nil {
				t.Fatalf("strategy %q: expected typed ErrInvalidBarrierStrategy, got nil", bogus)
			}
			var typed *ErrInvalidBarrierStrategy
			if !errors.As(err, &typed) {
				t.Fatalf("strategy %q: want *ErrInvalidBarrierStrategy, got %T: %v",
					bogus, err, err)
			}
			if typed.Strategy != bogus {
				t.Errorf("strategy %q: typed.Strategy = %q, want %q",
					bogus, typed.Strategy, bogus)
			}
			if !strings.Contains(typed.Error(), "invalid --barrier-strategy") {
				t.Errorf("strategy %q: error message missing canonical substring: %q",
					bogus, typed.Error())
			}
			if !strings.Contains(typed.Error(), bogus) {
				t.Errorf("strategy %q: error message missing offending value: %q",
					bogus, typed.Error())
			}
		})
	}
}

// TestCanonicalInit_MissingPinReturnsTypedError verifies that a
// missing PIN for a non-"none" strategy surfaces the typed
// ErrMissingPIN error so callers can introspect which flag (so-pin or
// user-pin) is missing without parsing a free-form string.
func TestCanonicalInit_MissingPinReturnsTypedError(t *testing.T) {
	cases := []struct {
		name     string
		fields   map[string]string
		wantFlag string
		wantEnv  string
	}{
		{
			name: "missing-so-pin",
			fields: map[string]string{
				"user-pin":         "user",
				"barrier-strategy": "software",
			},
			wantFlag: "so-pin",
			wantEnv:  "PLATFORMCTL_TEST_PIN_SO_PIN",
		},
		{
			name: "missing-user-pin",
			fields: map[string]string{
				"so-pin":           "so",
				"barrier-strategy": "software",
			},
			wantFlag: "user-pin",
			wantEnv:  "PLATFORMCTL_TEST_PIN_USER_PIN",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cmd, f := newInitCmdForTest(t, c.fields)
			err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_PIN")
			if err == nil {
				t.Fatalf("expected typed ErrMissingPIN, got nil")
			}
			var typed *ErrMissingPIN
			if !errors.As(err, &typed) {
				t.Fatalf("want *ErrMissingPIN, got %T: %v", err, err)
			}
			if typed.Flag != c.wantFlag {
				t.Errorf("Flag: want %q, got %q", c.wantFlag, typed.Flag)
			}
			if typed.EnvVar != c.wantEnv {
				t.Errorf("EnvVar: want %q, got %q", c.wantEnv, typed.EnvVar)
			}
		})
	}
}
