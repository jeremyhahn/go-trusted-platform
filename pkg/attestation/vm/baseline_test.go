// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vm

import (
	"bytes"
	"errors"
	"testing"
)

func pcr(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestComparePCRBaseline_MatchPasses(t *testing.T) {
	baseline := map[int][]byte{0: pcr(0xA0), 7: pcr(0xA7), 14: pcr(0xAE)}
	reported := map[int][]byte{0: pcr(0xA0), 7: pcr(0xA7), 14: pcr(0xAE)}
	if err := ComparePCRBaseline(reported, baseline); err != nil {
		t.Fatalf("identical values must match: %v", err)
	}
}

// TestComparePCRBaseline_NoBaselineIsNotAFailure pins the distinction the
// quarantine safety rule depends on: absence of a baseline is "cannot
// evaluate", a different error from "diverged", and callers must be able to
// tell them apart.
func TestComparePCRBaseline_NoBaselineIsNotAFailure(t *testing.T) {
	err := ComparePCRBaseline(map[int][]byte{0: pcr(1)}, nil)
	var missing ErrBaselineMissing
	if !errors.As(err, &missing) {
		t.Fatalf("empty baseline must be ErrBaselineMissing, got %T: %v", err, err)
	}
	var mismatch ErrBaselineMismatch
	if errors.As(err, &mismatch) {
		t.Fatal("empty baseline must NOT read as a mismatch — that is what would quarantine a healthy node")
	}
}

func TestComparePCRBaseline_ValueDivergenceNamesTheRegister(t *testing.T) {
	baseline := map[int][]byte{0: pcr(1), 7: pcr(2), 14: pcr(3)}
	reported := map[int][]byte{0: pcr(1), 7: pcr(0xFF), 14: pcr(3)}
	err := ComparePCRBaseline(reported, baseline)
	var mismatch ErrBaselineMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrBaselineMismatch, got %T: %v", err, err)
	}
	if mismatch.Index != 7 {
		t.Fatalf("first divergent register is 7, got %d", mismatch.Index)
	}
}

// TestComparePCRBaseline_RegisterSetsMustMatchExactly is the attester-shaped
// attack: report a SUBSET of the baseline's registers (dropping the one that
// diverged) or a SUPERSET (padding with registers nobody vetted). A partial
// match must not be a pass.
func TestComparePCRBaseline_RegisterSetsMustMatchExactly(t *testing.T) {
	baseline := map[int][]byte{0: pcr(1), 7: pcr(2)}
	cases := map[string]map[int][]byte{
		"subset drops a register":  {0: pcr(1)},
		"superset adds a register": {0: pcr(1), 7: pcr(2), 14: pcr(9)},
		"same size, wrong index":   {0: pcr(1), 8: pcr(2)},
		"nothing reported":         {},
	}
	for name, reported := range cases {
		t.Run(name, func(t *testing.T) {
			err := ComparePCRBaseline(reported, baseline)
			var mismatch ErrBaselineMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("expected ErrBaselineMismatch, got %T: %v", err, err)
			}
			if mismatch.Index != -1 {
				t.Fatalf("a set mismatch names no single register, got index %d", mismatch.Index)
			}
		})
	}
}

func TestComparePCRBaseline_LengthDifferenceIsAMismatch(t *testing.T) {
	// A truncated digest must not compare equal to its prefix.
	err := ComparePCRBaseline(map[int][]byte{0: pcr(1)[:16]}, map[int][]byte{0: pcr(1)})
	var mismatch ErrBaselineMismatch
	if !errors.As(err, &mismatch) || mismatch.Index != 0 {
		t.Fatalf("truncated value must mismatch on pcr 0, got %v", err)
	}
}

func TestBaselineErrors_Messages(t *testing.T) {
	if got := (ErrBaselineMissing{Reason: "x"}).Error(); got != "vm: no PCR baseline: x" {
		t.Errorf("unexpected: %q", got)
	}
	if got := (ErrBaselineMismatch{Index: 7, Reason: "y"}).Error(); got != "vm: PCR baseline mismatch: y (pcr 7)" {
		t.Errorf("unexpected: %q", got)
	}
	if got := (ErrBaselineMismatch{Index: -1, Reason: "z"}).Error(); got != "vm: PCR baseline mismatch: z" {
		t.Errorf("unexpected: %q", got)
	}
}
