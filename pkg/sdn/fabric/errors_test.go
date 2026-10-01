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

package fabric

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrorMessages checks each error names its origin and values, and that
// wrapping errors unwrap to their cause.
func TestErrorMessages(t *testing.T) {
	cause := errors.New("cause")
	tests := []struct {
		err  error
		want []string
	}{
		{ErrUnknownSwitch{ID: "sw"}, []string{"fabric:", `"sw"`}},
		{ErrInvalidPortRef{Reason: "r"}, []string{"port reference", "r"}},
		{ErrDriverConnect{SwitchID: "sw", Cause: cause}, []string{`"sw"`, "cause"}},
		{ErrInvalidFabricConfig{Reason: "r"}, []string{"invalid config", "r"}},
		{ErrDriverNotFound{Vendor: "v"}, []string{`"v"`}},
		{ErrDriverOperation{SwitchID: "sw", Operation: "op", Cause: cause}, []string{"op", `"sw"`, "cause"}},
		{ErrNilConfig{}, []string{"nil config"}},
		{ErrUnknownPortClass{Class: "x"}, []string{`"x"`}},
		{ErrDuplicatePort{SwitchID: "sw", Port: "p"}, []string{`"p"`, `"sw"`}},
		{ErrNilPlan{}, []string{"network plan"}},
		{ErrPortClassPlan{Class: "bmc", Cause: cause}, []string{`"bmc"`, "cause"}},
	}
	for _, tc := range tests {
		for _, w := range tc.want {
			assert.Contains(t, tc.err.Error(), w, "%T", tc.err)
		}
	}
	assert.ErrorIs(t, ErrDriverConnect{Cause: cause}, cause)
	assert.ErrorIs(t, ErrDriverOperation{Cause: cause}, cause)
	assert.ErrorIs(t, ErrPortClassPlan{Cause: cause}, cause)
}
