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

package entities

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validBaseline() *PCRBaseline {
	return &PCRBaseline{
		Values:     map[int][]byte{0: {1, 2, 3}, 7: {4, 5, 6}},
		Source:     BaselineSourceTOFU,
		RecordedAt: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC),
	}
}

func TestPCRBaseline_ValidateAccepts(t *testing.T) {
	for _, src := range []BaselineSource{BaselineSourceSigned, BaselineSourceTOFU} {
		b := validBaseline()
		b.Source = src
		if err := b.Validate(); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
}

func TestPCRBaseline_ValidateRejects(t *testing.T) {
	cases := map[string]struct {
		mutate    func(*PCRBaseline) *PCRBaseline
		wantIndex int
	}{
		"nil":            {func(*PCRBaseline) *PCRBaseline { return nil }, -1},
		"unknown source": {func(b *PCRBaseline) *PCRBaseline { b.Source = "guess"; return b }, -1},
		"no values":      {func(b *PCRBaseline) *PCRBaseline { b.Values = nil; return b }, -1},
		"index too high": {func(b *PCRBaseline) *PCRBaseline { b.Values[24] = []byte{1}; return b }, 24},
		"negative index": {func(b *PCRBaseline) *PCRBaseline { b.Values[-1] = []byte{1}; return b }, -1},
		"empty digest":   {func(b *PCRBaseline) *PCRBaseline { b.Values[7] = nil; return b }, 7},
		"zero time":      {func(b *PCRBaseline) *PCRBaseline { b.RecordedAt = time.Time{}; return b }, -1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.mutate(validBaseline()).Validate()
			var inv ErrInvalidPCRBaseline
			if !errors.As(err, &inv) {
				t.Fatalf("expected ErrInvalidPCRBaseline, got %T: %v", err, err)
			}
			if name != "negative index" && inv.Index != tc.wantIndex {
				t.Fatalf("index: want %d got %d (%v)", tc.wantIndex, inv.Index, err)
			}
		})
	}
}

// TestPCRBaseline_JSONRoundTrip matters because the profile store persists
// entities by JSON round trip (#125): an int-keyed map and byte digests must
// survive it, or a stored baseline silently stops matching anything.
func TestPCRBaseline_JSONRoundTrip(t *testing.T) {
	in := validBaseline()
	in.RecordedFromDeviceID = 42
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out PCRBaseline
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("round-tripped baseline invalid: %v", err)
	}
	if string(out.Values[7]) != string(in.Values[7]) || out.Source != in.Source ||
		!out.RecordedAt.Equal(in.RecordedAt) || out.RecordedFromDeviceID != 42 {
		t.Fatalf("round trip changed the baseline: %+v -> %+v", in, out)
	}
}

func TestErrInvalidPCRBaseline_Message(t *testing.T) {
	if got := (ErrInvalidPCRBaseline{Reason: "empty digest", Index: 7}).Error(); got != "device: invalid PCR baseline: empty digest (pcr 7)" {
		t.Errorf("unexpected: %q", got)
	}
	if got := (ErrInvalidPCRBaseline{Reason: "baseline is nil", Index: -1}).Error(); got != "device: invalid PCR baseline: baseline is nil" {
		t.Errorf("unexpected: %q", got)
	}
}
