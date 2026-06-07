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
	"reflect"
	"testing"
)

// assertErrorMatches verifies that got is nil when want is nil, and
// that got's concrete type matches want's concrete type when want is
// non-nil. The field values of want are ignored — we only assert on
// type identity so callers can pass a zero-value sentinel of the
// expected error type.
func assertErrorMatches(t *testing.T, got error, want any) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("expected nil error, got %T: %v", got, got)
		}
		return
	}
	if got == nil {
		t.Fatalf("expected error of type %T, got nil", want)
	}
	gotType := reflect.TypeOf(got)
	wantType := reflect.TypeOf(want)
	if gotType != wantType {
		t.Errorf("expected error type %v, got %v: %v", wantType, gotType, got)
	}
}
