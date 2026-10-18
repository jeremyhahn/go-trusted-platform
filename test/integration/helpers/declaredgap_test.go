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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
)

// recordingTB records the failures a gap assertion reports instead of failing
// the test that exercises it.
type recordingTB struct {
	testing.TB
	failures []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Error(args ...any) {
	r.failures = append(r.failures, fmt.Sprint(args...))
}

func requireClosedError(t *testing.T, err error, wants ...string) {
	t.Helper()
	var closed *DeclaredGapClosedError
	if !errors.As(err, &closed) {
		t.Fatalf("want *DeclaredGapClosedError, got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("message must name %q; got: %s", want, msg)
		}
	}
}

func TestCheckUnservedAcceptsTheGapsUnknownMethodError(t *testing.T) {
	err := fmt.Errorf("batch: %w", embedded.NewUnknownMethodError("quicbaas.Batch", "Execute"))

	if got := GapEmbeddedBatch.CheckUnserved("Execute", err); got != nil {
		t.Fatalf("a wrapped UnknownMethodError for the gap's call must hold the gap, got %v", got)
	}
}

func TestCheckUnservedRefusesAnythingElse(t *testing.T) {
	cases := map[string]error{
		"success":       nil,
		"other method":  embedded.NewUnknownMethodError("quicbaas.Batch", "Put"),
		"other service": embedded.NewUnknownMethodError("quicbaas.Vector", "Execute"),
		"other error":   errors.New("connection refused"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := GapEmbeddedBatch.CheckUnserved("Execute", err)
			requireClosedError(t, got, "go-quicbaas #1533", "quicbaas.Batch/Execute", "UnknownMethodError")
		})
	}
}

func TestCheckUnservedOverWireAcceptsTheGapsMessage(t *testing.T) {
	// The form a gRPC client sees once the daemon has sent the error.
	wire := embedded.NewUnknownMethodError("quicbaas.Secrets", "Rotate").Error()
	err := fmt.Errorf("gRPC call RotateSecret failed: rpc error: code = Unimplemented desc = rotate secret failed: %s", wire)

	if got := GapEmbeddedSecrets.CheckUnservedOverWire("Rotate", err); got != nil {
		t.Fatalf("the gap's unknown-method text must hold the gap, got %v", got)
	}
}

func TestCheckUnservedOverWireRefusesAnythingElse(t *testing.T) {
	cases := map[string]error{
		"success":      nil,
		"other method": errors.New(embedded.NewUnknownMethodError("quicbaas.Secrets", "Rollback").Error()),
		"other error":  errors.New("secret not found"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := GapEmbeddedSecrets.CheckUnservedOverWire("Rotate", err)
			requireClosedError(t, got, "go-quicbaas #1540", "quicbaas.Secrets/Rotate")
		})
	}
}

func TestCheckMistypedAcceptsTheGapsInvalidRequestTypeError(t *testing.T) {
	err := embedded.NewInvalidRequestTypeError("quicbaas.Transaction", "Execute",
		"*service.TransactionRequest", "*transaction.TxnRequest")

	if got := GapEmbeddedTransaction.CheckMistyped("Execute", err); got != nil {
		t.Fatalf("an InvalidRequestTypeError for the gap's call must hold the gap, got %v", got)
	}
}

func TestCheckMistypedRefusesAnythingElse(t *testing.T) {
	cases := map[string]error{
		"success":        nil,
		"unknown method": embedded.NewUnknownMethodError("quicbaas.Transaction", "Execute"),
		"other method": embedded.NewInvalidRequestTypeError("quicbaas.Transaction", "Get",
			"*service.TransactionRequest", "*transaction.TxnRequest"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := GapEmbeddedTransaction.CheckMistyped("Execute", err)
			requireClosedError(t, got, "go-quicbaas #1319", "quicbaas.Transaction/Execute", "InvalidRequestTypeError")
		})
	}
}

func TestCheckDefectHoldsWhileTheDefectPersists(t *testing.T) {
	if got := GapEmbeddedKVListPageSize.CheckDefect("List", true, "20 entities", "20 entities"); got != nil {
		t.Fatalf("a persisting defect must hold the gap, got %v", got)
	}
}

func TestCheckDefectReportsAFixedDefect(t *testing.T) {
	got := GapEmbeddedKVListPageSize.CheckDefect("List", false, "20 entities", "5 entities")

	requireClosedError(t, got, "go-quicbaas #1534", "quicbaas.KV/List", "want 20 entities", "got 5 entities", "delete this gap check")
}

func TestGapAssertionsReportWhetherTheGapIsOpen(t *testing.T) {
	open := embedded.NewUnknownMethodError("quicbaas.Vector", "Upsert")
	mistyped := embedded.NewInvalidRequestTypeError("quicbaas.Transaction", "Execute", "a", "b")

	rec := &recordingTB{TB: t}
	if !GapEmbeddedVector.Unserved(rec, "Upsert", open) {
		t.Error("Unserved must report an open gap")
	}
	if !GapEmbeddedTransaction.Mistyped(rec, "Execute", mistyped) {
		t.Error("Mistyped must report an open gap")
	}
	if !GapEmbeddedKVListPageSize.Defect(rec, "List", true, "20", "20") {
		t.Error("Defect must report an open gap")
	}
	if len(rec.failures) != 0 {
		t.Errorf("an open gap must not fail the test, got %v", rec.failures)
	}
}

func TestGapAssertionsFailTheTestWhenTheGapCloses(t *testing.T) {
	rec := &recordingTB{TB: t}
	if GapEmbeddedVector.Unserved(rec, "Upsert", nil) {
		t.Error("Unserved must report a closed gap")
	}
	if GapEmbeddedTransaction.Mistyped(rec, "Execute", nil) {
		t.Error("Mistyped must report a closed gap")
	}
	if GapEmbeddedKVListPageSize.Defect(rec, "List", false, "20", "5") {
		t.Error("Defect must report a closed gap")
	}
	if len(rec.failures) != 3 {
		t.Fatalf("each closed gap must fail the test once, got %v", rec.failures)
	}
	if !strings.Contains(rec.failures[0], "go-quicbaas #1404") {
		t.Errorf("the failure must name the upstream issue, got %s", rec.failures[0])
	}
}
