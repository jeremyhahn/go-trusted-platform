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

package app

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
)

func stubCurrent(context.Context) (*x509.Certificate, error) { return &x509.Certificate{}, nil }
func stubReissue(context.Context) error                      { return nil }

func validTarget(name string, kind CertKind) *CertTarget {
	return &CertTarget{
		Name:    name,
		Kind:    kind,
		Current: stubCurrent,
		Reissue: stubReissue,
	}
}

// --- CertKind ---

func TestCertKind_IsValid(t *testing.T) {
	cases := []struct {
		k    CertKind
		want bool
	}{
		{CertKindWebservice, true},
		{CertKindBMC, true},
		{CertKind(""), false},
		{CertKind("other"), false},
	}
	for _, tc := range cases {
		if got := tc.k.IsValid(); got != tc.want {
			t.Errorf("CertKind(%q).IsValid() = %v, want %v", string(tc.k), got, tc.want)
		}
	}
}

// --- CertTarget.Validate ---

func TestCertTarget_Validate_Nil(t *testing.T) {
	var t1 *CertTarget
	if err := t1.Validate(); !errors.Is(err, ErrNilCertTarget) {
		t.Errorf("err = %v, want ErrNilCertTarget", err)
	}
}

func TestCertTarget_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		target  *CertTarget
		field   string
	}{
		{"no name", &CertTarget{Kind: CertKindBMC, Current: stubCurrent, Reissue: stubReissue}, "name"},
		{"bad kind", &CertTarget{Name: "x", Kind: CertKind("bad"), Current: stubCurrent, Reissue: stubReissue}, "kind"},
		{"no current", &CertTarget{Name: "x", Kind: CertKindBMC, Reissue: stubReissue}, "current"},
		{"no reissue", &CertTarget{Name: "x", Kind: CertKindBMC, Current: stubCurrent}, "reissue"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.target.Validate()
			var want ErrInvalidCertTarget
			if !errors.As(err, &want) {
				t.Fatalf("err = %v, want ErrInvalidCertTarget", err)
			}
			if want.Field != tc.field {
				t.Errorf("field = %q, want %q", want.Field, tc.field)
			}
		})
	}
}

func TestCertTarget_Validate_OK(t *testing.T) {
	if err := validTarget("x", CertKindBMC).Validate(); err != nil {
		t.Errorf("valid target rejected: %v", err)
	}
}

// --- Registry ---

func TestNewCertTargetRegistry_Empty(t *testing.T) {
	r := NewCertTargetRegistry()
	if r.Len() != 0 {
		t.Errorf("Len() = %d, want 0", r.Len())
	}
	if len(r.Snapshot()) != 0 {
		t.Errorf("Snapshot() not empty")
	}
}

func TestRegistry_Register_AndGet(t *testing.T) {
	r := NewCertTargetRegistry()
	want := validTarget("bmc.device-1", CertKindBMC)
	if err := r.Register(want); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := r.Get("bmc.device-1")
	if !ok {
		t.Fatal("Get returned ok=false")
	}
	if got != want {
		t.Error("Get returned different pointer")
	}
	if r.Len() != 1 {
		t.Errorf("Len() = %d, want 1", r.Len())
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := NewCertTargetRegistry()
	_ = r.Register(validTarget("x", CertKindBMC))
	err := r.Register(validTarget("x", CertKindBMC))
	var want ErrDuplicateCertTarget
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrDuplicateCertTarget", err)
	}
}

func TestRegistry_Register_Invalid(t *testing.T) {
	r := NewCertTargetRegistry()
	err := r.Register(&CertTarget{Kind: CertKindBMC, Current: stubCurrent, Reissue: stubReissue})
	var want ErrInvalidCertTarget
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCertTarget", err)
	}
}

func TestRegistry_Replace_ReplacesExisting(t *testing.T) {
	r := NewCertTargetRegistry()
	first := validTarget("x", CertKindBMC)
	second := validTarget("x", CertKindWebservice)
	_ = r.Register(first)
	if err := r.Replace(second); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, _ := r.Get("x")
	if got != second {
		t.Error("Replace did not overwrite")
	}
}

func TestRegistry_Replace_AddsIfMissing(t *testing.T) {
	r := NewCertTargetRegistry()
	if err := r.Replace(validTarget("x", CertKindBMC)); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, ok := r.Get("x"); !ok {
		t.Error("Replace did not add new entry")
	}
}

func TestRegistry_Replace_Invalid(t *testing.T) {
	r := NewCertTargetRegistry()
	err := r.Replace(&CertTarget{Name: "x"}) // missing kind/current/reissue
	var want ErrInvalidCertTarget
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCertTarget", err)
	}
}

func TestRegistry_Unregister(t *testing.T) {
	r := NewCertTargetRegistry()
	_ = r.Register(validTarget("x", CertKindBMC))
	r.Unregister("x")
	if _, ok := r.Get("x"); ok {
		t.Error("still present after Unregister")
	}
	// idempotent
	r.Unregister("x")
	r.Unregister("never-existed")
}

func TestRegistry_Get_Missing(t *testing.T) {
	r := NewCertTargetRegistry()
	if _, ok := r.Get("nope"); ok {
		t.Error("Get returned ok=true for missing key")
	}
}

func TestRegistry_Snapshot_SortedByName(t *testing.T) {
	r := NewCertTargetRegistry()
	_ = r.Register(validTarget("c.one", CertKindBMC))
	_ = r.Register(validTarget("a.two", CertKindWebservice))
	_ = r.Register(validTarget("b.three", CertKindBMC))
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("len = %d, want 3", len(snap))
	}
	want := []string{"a.two", "b.three", "c.one"}
	for i, name := range want {
		if snap[i].Name != name {
			t.Errorf("snap[%d].Name = %q, want %q", i, snap[i].Name, name)
		}
	}
}

func TestRegistry_Snapshot_IsolatedFromMutation(t *testing.T) {
	r := NewCertTargetRegistry()
	_ = r.Register(validTarget("x", CertKindBMC))
	snap := r.Snapshot()
	r.Unregister("x")
	// snap slice is not affected by the unregister.
	if len(snap) != 1 {
		t.Errorf("snap len changed after Unregister: %d", len(snap))
	}
}

func TestRegistry_ByKind(t *testing.T) {
	r := NewCertTargetRegistry()
	_ = r.Register(validTarget("bmc.a", CertKindBMC))
	_ = r.Register(validTarget("ws.a", CertKindWebservice))
	_ = r.Register(validTarget("bmc.b", CertKindBMC))
	bmcs := r.ByKind(CertKindBMC)
	if len(bmcs) != 2 {
		t.Fatalf("bmcs len = %d, want 2", len(bmcs))
	}
	if bmcs[0].Name != "bmc.a" || bmcs[1].Name != "bmc.b" {
		t.Errorf("unexpected order: %v", []string{bmcs[0].Name, bmcs[1].Name})
	}
	ws := r.ByKind(CertKindWebservice)
	if len(ws) != 1 || ws[0].Name != "ws.a" {
		t.Errorf("ws filter wrong: %v", ws)
	}
	if got := r.ByKind(CertKind("other")); len(got) != 0 {
		t.Errorf("ByKind(other) = %v, want empty", got)
	}
}

// --- errors ---

func TestErrMessages(t *testing.T) {
	cases := []error{
		ErrNilCertTarget,
		ErrInvalidCertTarget{Field: "f", Reason: "r"},
		ErrDuplicateCertTarget{Name: "n"},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
}
