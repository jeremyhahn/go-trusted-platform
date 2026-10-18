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
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
)

// DeclaredGap is an upstream go-quicbaas defect the pinned SDK still carries.
//
// A subtest that meets one asserts the defect instead of skipping: it checks
// that the call still fails the way the upstream issue records, then returns
// before its success path. When the pin bump that carries the fix lands, the
// assertion fails and names the issue; deleting the gap check makes the
// success path that follows it the assertion again.
type DeclaredGap struct {
	// Issue names the upstream issue that carries the fix, e.g.
	// "go-quicbaas #1533".
	Issue string
	// Service names the embedded-transport service the gap affects, e.g.
	// "quicbaas.Batch".
	Service string
}

// The declared gaps of the pinned go-quicbaas SDK's embedded transport.
var (
	// GapEmbeddedBatch: quicbaas.Batch/Execute has no embedded handler.
	GapEmbeddedBatch = DeclaredGap{Issue: "go-quicbaas #1533", Service: "quicbaas.Batch"}
	// GapEmbeddedTransaction: the Transaction client sends its own TxnRequest,
	// the embedded handler accepts only *service.TransactionRequest.
	GapEmbeddedTransaction = DeclaredGap{Issue: "go-quicbaas #1319", Service: "quicbaas.Transaction"}
	// GapEmbeddedKVListPageSize: the embedded KV List merges every streamed
	// page into one answer, so PageSize does not bound it.
	GapEmbeddedKVListPageSize = DeclaredGap{Issue: "go-quicbaas #1534", Service: "quicbaas.KV"}
	// GapEmbeddedOllama: quicbaas.Ollama has no embedded handler.
	GapEmbeddedOllama = DeclaredGap{Issue: "go-quicbaas #1535", Service: "quicbaas.Ollama"}
	// GapEmbeddedVector: quicbaas.Vector has no embedded handler in the
	// pinned SDK; go-quicbaas main routes it since #1404.
	GapEmbeddedVector = DeclaredGap{Issue: "go-quicbaas #1404", Service: "quicbaas.Vector"}
)

// DeclaredGapClosedError reports that a call did not fail the way its
// declared gap records. Either the pin now carries the upstream fix, and the
// gap check is to be deleted, or the call failed some other way.
type DeclaredGapClosedError struct {
	Gap    DeclaredGap
	Method string
	// Want describes the recorded defect.
	Want string
	// Got describes what the call did instead.
	Got string
}

// Error names the issue, the call and both outcomes.
func (e *DeclaredGapClosedError) Error() string {
	return fmt.Sprintf(
		"declared gap %s on %s/%s: want %s, got %s. "+
			"If the pin now carries the fix, delete this gap check so the success path is asserted again",
		e.Gap.Issue, e.Gap.Service, e.Method, e.Want, e.Got)
}

// CheckUnserved returns nil when err is the embedded transport's
// UnknownMethodError for the gap's service and method.
func (g DeclaredGap) CheckUnserved(method string, err error) error {
	want := fmt.Sprintf("embedded.UnknownMethodError(%s/%s)", g.Service, method)
	var unknown *embedded.UnknownMethodError
	if errors.As(err, &unknown) && unknown.Service == g.Service && unknown.Method == method {
		return nil
	}
	return g.closed(method, want, err)
}

// CheckMistyped returns nil when err is the embedded transport's
// InvalidRequestTypeError for the gap's service and method.
func (g DeclaredGap) CheckMistyped(method string, err error) error {
	want := fmt.Sprintf("embedded.InvalidRequestTypeError(%s/%s)", g.Service, method)
	var mistyped *embedded.InvalidRequestTypeError
	if errors.As(err, &mistyped) && mistyped.Service == g.Service && mistyped.Method == method {
		return nil
	}
	return g.closed(method, want, err)
}

// CheckDefect returns nil when the call still shows the recorded defective
// behaviour. defect describes that behaviour and observed what the call did.
func (g DeclaredGap) CheckDefect(method string, persists bool, defect, observed string) error {
	if persists {
		return nil
	}
	return &DeclaredGapClosedError{Gap: g, Method: method, Want: defect, Got: observed}
}

func (g DeclaredGap) closed(method, want string, err error) error {
	got := "success"
	if err != nil {
		got = fmt.Sprintf("%T: %v", err, err)
	}
	return &DeclaredGapClosedError{Gap: g, Method: method, Want: want, Got: got}
}

// Unserved asserts CheckUnserved and reports whether the gap is still open.
// A false return has already failed t; the caller's success path then runs.
func (g DeclaredGap) Unserved(t testing.TB, method string, err error) bool {
	t.Helper()
	return holds(t, g.CheckUnserved(method, err))
}

// Mistyped asserts CheckMistyped and reports whether the gap is still open.
func (g DeclaredGap) Mistyped(t testing.TB, method string, err error) bool {
	t.Helper()
	return holds(t, g.CheckMistyped(method, err))
}

// Defect asserts CheckDefect and reports whether the gap is still open.
func (g DeclaredGap) Defect(t testing.TB, method string, persists bool, defect, observed string) bool {
	t.Helper()
	return holds(t, g.CheckDefect(method, persists, defect, observed))
}

func holds(t testing.TB, err error) bool {
	t.Helper()
	if err != nil {
		t.Error(err)
		return false
	}
	return true
}
