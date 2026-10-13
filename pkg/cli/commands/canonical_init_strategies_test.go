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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

// addOfficers sets n --officer flags, officer-1 … officer-n, each naming a
// CSR file in a temporary directory whose content is "csr-<username>". The
// CLI only reads the files; the gate is what parses them.
func addOfficers(t *testing.T, cmd *cobra.Command, n int) {
	t.Helper()
	dir := t.TempDir()
	for i := 1; i <= n; i++ {
		username := "officer-" + strconv.Itoa(i)
		path := filepath.Join(dir, username+".csr")
		if err := os.WriteFile(path, []byte("csr-"+username), 0o600); err != nil {
			t.Fatalf("write officer CSR: %v", err)
		}
		if err := cmd.Flags().Set("officer", username+"="+path); err != nil {
			t.Fatalf("set --officer: %v", err)
		}
	}
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
			if c.strategy == "shamir" {
				addOfficers(t, cmd, c.shares)
			}
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
			// The daemon refuses unknown /init fields and takes the barrier
			// strategy from its own configuration, so the body never names one.
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal init request: %v", err)
			}
			if strings.Contains(string(body), "barrier_strategy") {
				t.Errorf("init body names a barrier strategy: %s", body)
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

			// Shares/Threshold must only be populated for shamir;
			// every other strategy ignores them.
			wantShares, wantThreshold := 0, 0
			if strategy == "shamir" {
				wantShares, wantThreshold = 5, 3
			}
			if req.Shares != wantShares || req.Threshold != wantThreshold {
				t.Errorf("quorum: want %d-of-%d, got %d-of-%d",
					wantThreshold, wantShares, req.Threshold, req.Shares)
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
			// field from PLATFORMCTL_TEST_ENV_*. --officer has no
			// environment variable, so shamir still names its officers
			// as flags.
			cmd, f := newInitCmdForTest(t, nil)
			if strategy == "shamir" {
				addOfficers(t, cmd, 5)
			}
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

// TestCanonicalInit_ShamirQuorumNotSwapped verifies --shares and
// --threshold reach the /init request in their own fields. The daemon
// formats the "M-of-N" descriptor; a swap here would silently break
// Shamir share recovery on the platform side.
func TestCanonicalInit_ShamirQuorumNotSwapped(t *testing.T) {
	cases := []struct {
		shares    int
		threshold int
	}{
		{shares: 2, threshold: 2},
		{shares: 5, threshold: 3},
		{shares: 7, threshold: 4},
	}
	for _, c := range cases {
		_, f := newInitCmdForTest(t, strategyFlags("shamir", c.shares, c.threshold))
		req := buildInitRequest(f)
		if req.Shares != c.shares || req.Threshold != c.threshold {
			t.Errorf("quorum %d-of-%d: got shares=%d threshold=%d",
				c.threshold, c.shares, req.Shares, req.Threshold)
		}
	}
}

// TestCanonicalInit_ShamirOfficersSent reads each --officer CSR file and
// sends it, under its username and in flag order, in the /init body.
func TestCanonicalInit_ShamirOfficersSent(t *testing.T) {
	cmd, f := newInitCmdForTest(t, strategyFlags("shamir", 3, 2))
	addOfficers(t, cmd, 3)
	if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_OFFICERS"); err != nil {
		t.Fatalf("validation: %v", err)
	}
	req := buildInitRequest(f)
	if len(req.Officers) != 3 {
		t.Fatalf("officers: want 3, got %d", len(req.Officers))
	}
	for i, officer := range req.Officers {
		username := "officer-" + strconv.Itoa(i+1)
		if officer.Username != username || officer.CSRPEM != "csr-"+username {
			t.Errorf("officer %d: got %+v, want %s with its CSR", i, officer, username)
		}
	}
}

// TestCanonicalInit_OfficerFlagErrors refuses every officer set the gate
// could not enroll, before anything is sent.
func TestCanonicalInit_OfficerFlagErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.csr")
	cases := []struct {
		name     string
		strategy string
		shares   int
		officers []string
		want     any
	}{
		{"shamir without officers", "shamir", 2, nil, new(*ErrOfficerCount)},
		{"fewer officers than shares", "shamir", 3, []string{"a=x", "b=y"}, new(*ErrOfficerCount)},
		{"no separator", "shamir", 2, []string{"a", "b=y"}, new(*ErrInvalidOfficerFlag)},
		{"empty username", "shamir", 2, []string{"=x", "b=y"}, new(*ErrInvalidOfficerFlag)},
		{"empty path", "shamir", 2, []string{"a=", "b=y"}, new(*ErrInvalidOfficerFlag)},
		{"duplicate username", "shamir", 2, []string{"a=" + missing, "a=" + missing}, new(*ErrInvalidOfficerFlag)},
		{"unreadable CSR", "shamir", 2, []string{"a=" + missing, "b=" + missing}, new(*ErrOfficerCSRUnreadable)},
		{"officer without shamir", "software", 0, []string{"a=x"}, new(*MessageError)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			threshold := 0
			if c.strategy == "shamir" {
				threshold = 2
			}
			cmd, f := newInitCmdForTest(t, strategyFlags(c.strategy, c.shares, threshold))
			for _, value := range c.officers {
				if err := cmd.Flags().Set("officer", value); err != nil {
					t.Fatalf("set --officer: %v", err)
				}
			}
			err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_OFFICER_ERR")
			if !errors.As(err, c.want) {
				t.Fatalf("got %v (%T), want %T", err, err, c.want)
			}
			if f.officers != nil {
				t.Errorf("a refused officer set was kept: %+v", f.officers)
			}
		})
	}
}

// TestCanonicalInit_OfficerErrorMessages names the offending value, the
// counts, and the unreadable file, so the operator can fix the command.
func TestCanonicalInit_OfficerErrorMessages(t *testing.T) {
	cases := map[string]error{
		`invalid --officer "a": want username=path`:            &ErrInvalidOfficerFlag{Value: "a", Reason: "want username=path"},
		"got 2 for --shares 3":                                 &ErrOfficerCount{Officers: 2, Shares: 3},
		`officer "a": cannot read CSR /x: file does not exist`: &ErrOfficerCSRUnreadable{Username: "a", Path: "/x", Err: os.ErrNotExist},
	}
	for want, err := range cases {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}
	if !errors.Is(&ErrOfficerCSRUnreadable{Err: os.ErrNotExist}, os.ErrNotExist) {
		t.Error("ErrOfficerCSRUnreadable does not unwrap its read failure")
	}
}

// TestCanonicalInit_StrategyEndToEnd documents which strategies are
// fully exercisable at unit-test scope and which require external
// dependencies (hardware, cloud creds) that live in the integration
// suite.
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
			if strategy == "shamir" {
				addOfficers(t, cmd, 5)
			}
			if err := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL_TEST_E2E"); err != nil {
				t.Fatalf("strategy %q validation: %v", strategy, err)
			}

			req := buildInitRequest(f)
			if req.CredentialSealStrategy != strategy {
				t.Fatalf("strategy %q not propagated", strategy)
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
	if req.Shares != 0 || req.Threshold != 0 {
		t.Errorf("none-strategy InitRequest must not carry a Shamir quorum; got %d-of-%d",
			req.Threshold, req.Shares)
	}
	if req.Hostname != "dev.example.com" {
		t.Errorf("Hostname: want %q, got %q", "dev.example.com", req.Hostname)
	}
	if len(req.SANs) != 2 || req.SANs[0] != "alt.example.com" || req.SANs[1] != "127.0.0.1" {
		t.Errorf("SANs: want [alt.example.com 127.0.0.1], got %v", req.SANs)
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
