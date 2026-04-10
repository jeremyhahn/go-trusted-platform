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

package auth

import (
	"testing"
)

func TestAuthType(t *testing.T) {
	t.Run("String returns correct value", func(t *testing.T) {
		tests := []struct {
			authType AuthType
			want     string
		}{
			{AuthTypeNone, "none"},
			{AuthTypeToken, "token"},
			{AuthTypeMTLS, "mtls"},
		}

		for _, tc := range tests {
			t.Run(tc.want, func(t *testing.T) {
				if got := tc.authType.String(); got != tc.want {
					t.Errorf("String() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("constants have expected values", func(t *testing.T) {
		if AuthTypeNone != "none" {
			t.Errorf("AuthTypeNone = %v, want 'none'", AuthTypeNone)
		}
		if AuthTypeToken != "token" {
			t.Errorf("AuthTypeToken = %v, want 'token'", AuthTypeToken)
		}
		if AuthTypeMTLS != "mtls" {
			t.Errorf("AuthTypeMTLS = %v, want 'mtls'", AuthTypeMTLS)
		}
	})
}

func TestAuthTypeUniqueness(t *testing.T) {
	t.Run("all auth types are unique", func(t *testing.T) {
		types := []AuthType{AuthTypeNone, AuthTypeToken, AuthTypeMTLS}
		seen := make(map[AuthType]bool)

		for _, at := range types {
			if seen[at] {
				t.Errorf("duplicate auth type: %v", at)
			}
			seen[at] = true
		}
	})
}
