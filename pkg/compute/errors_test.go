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

package compute

import (
	"errors"
	"testing"
)

func TestErrorEquality(t *testing.T) {
	// Test that errors are sentinel values
	if !errors.Is(ErrInstanceNotFound, ErrInstanceNotFound) {
		t.Error("ErrInstanceNotFound should equal itself")
	}

	if errors.Is(ErrInstanceNotFound, ErrInstanceAlreadyExists) {
		t.Error("Different errors should not be equal")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that our errors can be wrapped
	wrappedErr := errors.Join(ErrInstanceNotFound, errors.New("additional context"))
	if wrappedErr == nil {
		t.Error("Wrapped error should not be nil")
	}

	if !errors.Is(wrappedErr, ErrInstanceNotFound) {
		t.Error("Wrapped error should be detected by errors.Is")
	}
}
