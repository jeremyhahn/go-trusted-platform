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

//go:build integration

package helpers

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// AdapterSetupError reports that a transport adapter could not be brought up.
//
// A multi-protocol suite that cannot set an adapter up has not tested that
// transport. Reporting it as an error rather than a skip is the whole point:
// a skipped subtest does not fail its parent, so an unreachable daemon and a
// passing transport produced the same summary line (issue #523).
type AdapterSetupError struct {
	// Suite names the multi-protocol suite, e.g. "device".
	Suite string
	// Adapter names the transport, e.g. "QUIC".
	Adapter string
	// Err is the error the adapter's Setup returned.
	Err error
}

// Error names the transport that is unreachable and where it was dialled, so a
// reader can tell a broken adapter from a broken product without re-running.
func (e *AdapterSetupError) Error() string {
	return fmt.Sprintf(
		"%s suite: the %s transport is unreachable: adapter setup failed: %v (endpoint: %s). "+
			"This is not a skip: the suite did not exercise %s. "+
			"Either the daemon is not serving that transport, or the adapter is broken",
		e.Suite, e.Adapter, e.Err, AdapterEndpoint(e.Adapter), e.Adapter)
}

// Unwrap exposes the underlying setup error to errors.Is/errors.As.
func (e *AdapterSetupError) Unwrap() error { return e.Err }

// ZeroAdaptersError reports that a multi-protocol suite finished without
// executing a single transport.
//
// This is the guard for the class of failure #523 describes: every configured
// adapter degrading at once still leaves a suite that reports no failures.
type ZeroAdaptersError struct {
	// Suite names the multi-protocol suite, e.g. "device".
	Suite string
	// Configured lists the transports the suite intended to exercise.
	Configured []string
}

func (e *ZeroAdaptersError) Error() string {
	configured := "none"
	if len(e.Configured) > 0 {
		configured = strings.Join(e.Configured, ", ")
	}
	return fmt.Sprintf(
		"%s suite executed zero transports (configured: %s). "+
			"A multi-protocol suite that ran no adapter has verified nothing; "+
			"check that platformd is up and that the run was not filtered to a name no adapter matches",
		e.Suite, configured)
}

// unknownTransportEndpoint is the marker AdapterEndpoint returns for a name it
// does not recognise, so that message construction never itself fails.
const unknownTransportEndpoint = "unknown transport"

// cliEndpoint reports the socket platformctl talks to.
func cliEndpoint() string { return GetSocketPath() + " (via platformctl)" }

// transportEndpoints resolves a transport name to the endpoint it dials. The
// values are functions because every endpoint is read from the environment at
// call time, not at package init.
var transportEndpoints = map[string]func() string{
	"rest":        GetRESTEndpoint,
	"https":       GetRESTEndpoint,
	"http":        GetRESTEndpoint,
	"grpc":        GetGRPCEndpoint,
	"quic":        GetQUICEndpoint,
	"mcp":         GetMCPEndpoint,
	"unix":        GetSocketPath,
	"socket":      GetSocketPath,
	"uds":         GetSocketPath,
	"cli":         cliEndpoint,
	"platformctl": cliEndpoint,
}

// AdapterEndpoint returns the endpoint a named transport dials, for use in
// failure messages.
func AdapterEndpoint(adapter string) string {
	endpoint, ok := transportEndpoints[strings.ToLower(adapter)]
	if !ok {
		return unknownTransportEndpoint
	}
	return endpoint()
}

// AdapterSetupFailure wraps a transport adapter's Setup error, or returns nil
// when setup succeeded. It is the testable half of RequireAdapterSetup.
func AdapterSetupFailure(suite, adapter string, err error) error {
	if err == nil {
		return nil
	}
	return &AdapterSetupError{Suite: suite, Adapter: adapter, Err: err}
}

// RequireAdapterSetup fails the current test when a transport adapter's Setup
// returned an error. It replaces the t.Skipf that made an unreachable
// transport indistinguishable from a passing one.
func RequireAdapterSetup(t *testing.T, suite, adapter string, err error) {
	t.Helper()
	if failure := AdapterSetupFailure(suite, adapter, err); failure != nil {
		t.Fatal(failure.Error())
	}
}

// AdapterGate counts the transports a multi-protocol suite actually executed
// and fails the suite if none did.
//
// Construct one per multi-protocol test, before the adapter loop, then call
// RequireSetup inside each subtest. The zero-transport check runs from the
// parent test's cleanup, so it fires after every subtest has finished.
type AdapterGate struct {
	suite      string
	configured []string
	executed   atomic.Int64
}

// NewAdapterGate registers the zero-transport guard on t and returns the gate.
// configured lists the transports the suite intends to exercise; it appears in
// the failure message so a reader knows what was expected to run.
func NewAdapterGate(t *testing.T, suite string, configured ...string) *AdapterGate {
	t.Helper()
	g := &AdapterGate{suite: suite, configured: configured}
	t.Cleanup(func() {
		if err := g.Verify(); err != nil {
			t.Error(err.Error())
		}
	})
	return g
}

// Verify reports a ZeroAdaptersError when the suite executed no transport, and
// nil otherwise. NewAdapterGate calls it from the parent test's cleanup; it is
// exported so the guard itself can be tested.
func (g *AdapterGate) Verify() error {
	if g.executed.Load() > 0 {
		return nil
	}
	return &ZeroAdaptersError{Suite: g.suite, Configured: g.configured}
}

// RequireSetup fails the current subtest when err is non-nil, and otherwise
// records that the named transport executed.
func (g *AdapterGate) RequireSetup(t *testing.T, adapter string, err error) {
	t.Helper()
	RequireAdapterSetup(t, g.suite, adapter, err)
	g.executed.Add(1)
}

// Count reports how many transports have executed so far.
func (g *AdapterGate) Count() int64 { return g.executed.Load() }

// AdapterNames returns the Name() of each adapter, for NewAdapterGate's
// configured list. It takes any slice whose element type has a Name method.
func AdapterNames[T interface{ Name() string }](adapters []T) []string {
	names := make([]string, 0, len(adapters))
	for _, a := range adapters {
		names = append(names, a.Name())
	}
	return names
}
