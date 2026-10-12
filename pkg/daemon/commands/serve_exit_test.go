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

package commands

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// #53 was a discontinuity BETWEEN layers: fifteen startup failures returned
// from a cobra `Run` that cannot report one, unwound to a successful process
// exit, and a service manager with Restart=on-failure treated a node that never
// came up as one that came up and was stopped.
//
// A test that a function returns an error would not have caught it — the
// functions did not return anything, and adding returns without changing the
// cobra wiring would still exit 0. So these assert the SEAM: that the command
// is wired to a handler capable of reporting failure, and that both run
// functions are typed to produce one.
//
// # Where the last link is proved
//
// The final links — Execute() handing the error back to main() rather than
// exiting itself, and cmd/platformd/main.go turning it into exit 1 — are
// asserted against the running process by cmd/platformd/main_test.go (#352),
// which re-executes its test binary as `platformd serve` with an unreadable
// config, beside a control run that exits 0. This file establishes the
// preconditions; that one the property.

// TestServeCmdReportsFailureToCobra is the structural half. `Run` cannot report
// a failure however carefully its body is written; only `RunE` can.
//
// Mutation: change `RunE:` back to `Run:` and this fails.
func TestServeCmdReportsFailureToCobra(t *testing.T) {
	if serveCmd.Run != nil {
		t.Error("serveCmd uses Run, which discards failures: a startup error unwinds to exit 0 " +
			"and a service manager reads the failed start as a clean shutdown (#53)")
	}
	if serveCmd.RunE == nil {
		t.Fatal("serveCmd has no RunE: nothing can report a startup failure to cobra")
	}

	// A startup failure is not a usage error; printing the usage block after it
	// buries the cause.
	if !serveCmd.SilenceUsage {
		t.Error("serveCmd.SilenceUsage is false: a startup failure will print the usage block")
	}
}

// TestRunFunctionsAreTypedToFail is the compile-time half, and it is the one
// that survives refactoring. If either signature loses its error return, this
// file stops compiling — which is a louder failure than an assertion, and
// cannot be skipped.
func TestRunFunctionsAreTypedToFail(t *testing.T) {
	// Passing each function to a parameter of the required shape is the check.
	//
	// The obvious spelling — `var _ func(...) error = runWithWebservices` —
	// trips staticcheck's QF1011, which asks for the type to be dropped and
	// inferred from the right-hand side. An inferred type asserts nothing: it
	// would compile against whatever signature the function happened to have,
	// which is the opposite of what this test is for. A parameter cannot be
	// inferred away.
	acceptWithWebservices := func(func(*cobra.Command, context.Context, chan os.Signal, *logging.Logger, *jsonfile.Querier) error) {
	}
	acceptDaemonOnly := func(func(*cobra.Command, context.Context, chan os.Signal, *logging.Logger, error) error) {}

	acceptWithWebservices(runWithWebservices)
	acceptDaemonOnly(runDaemonOnly)
}

// TestServeStartupErrorCarriesItsPhase asserts the errors are distinguishable.
//
// #270's diagnosis went wrong for months because one function returned an
// identical error from two branches, so the failure was attributed to the wrong
// budget. Fifteen startup paths sharing one exit code is fine; fifteen sharing
// one message is not.
func TestServeStartupErrorCarriesItsPhase(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrServeStartup{Phase: "daemon start", Cause: cause}

	if got := err.Error(); got != "platformd serve: daemon start: connection refused" {
		t.Errorf("Error() = %q, want the phase and the cause", got)
	}
	if !errors.Is(err, cause) {
		t.Error("the cause must stay reachable through errors.Is, or a caller cannot tell " +
			"a port conflict from a bad config")
	}

	// A capability check has no error of its own, and must still read cleanly.
	bare := ErrServeStartup{Phase: "CA key store does not implement XKMSSigner"}
	if got := bare.Error(); got != "platformd serve: CA key store does not implement XKMSSigner" {
		t.Errorf("Error() with no cause = %q, want no trailing separator", got)
	}
	if errors.Unwrap(bare) != nil {
		t.Error("a causeless ErrServeStartup must unwrap to nil, not to a zero error")
	}
}

// TestServeStartupPhasesAreDistinct guards against the copy-paste failure this
// conversion invites: fifteen sites, each needing its own phase, several of
// them adjacent and similar.
func TestServeStartupPhasesAreDistinct(t *testing.T) {
	a := ErrServeStartup{Phase: "platform daemon creation"}
	b := ErrServeStartup{Phase: "platform daemon start"}
	if a.Error() == b.Error() {
		t.Error("two distinct startup phases produce the same message")
	}
}
