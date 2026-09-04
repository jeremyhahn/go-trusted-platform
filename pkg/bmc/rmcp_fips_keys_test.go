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

package bmc

import (
	"errors"
	"strings"
	"testing"
)

// TestRMCPValidateSessionSecretForMode pins the rule that keeps a short IPMI
// credential from reaching crypto/hmac, which panics rather than erroring under
// FIPS activation (#209). The mode is a parameter because GODEBUG is fixed
// before main runs and cannot be toggled from within a test binary.
func TestRMCPValidateSessionSecretForMode(t *testing.T) {
	const short = "admin_pass"           // 10 bytes — below the 112-bit floor
	const adequate = "admin_password_16" // 17 bytes

	t.Run("non-FIPS accepts a short password", func(t *testing.T) {
		// Existing deployments must not start failing because a binary is
		// FIPS-capable; activation is what changes behaviour, per doc 04
		// ruling 1.
		if err := rmcpValidateSessionSecretForMode(short, nil, false); err != nil {
			t.Errorf("non-FIPS must accept a short password, got %v", err)
		}
	})

	t.Run("non-FIPS accepts a short KG key", func(t *testing.T) {
		if err := rmcpValidateSessionSecretForMode(adequate, []byte("kg"), false); err != nil {
			t.Errorf("non-FIPS must accept a short KG key, got %v", err)
		}
	})

	t.Run("FIPS refuses a short password with a typed error", func(t *testing.T) {
		err := rmcpValidateSessionSecretForMode(short, nil, true)
		if err == nil {
			t.Fatal("FIPS activation must refuse a password below the HMAC key floor")
		}

		var tooShort ErrFIPSKeyTooShort
		if !errors.As(err, &tooShort) {
			t.Fatalf("want ErrFIPSKeyTooShort, got %T: %v", err, err)
		}
		if tooShort.Field != "password" {
			t.Errorf("Field = %q, want \"password\"", tooShort.Field)
		}
		if tooShort.Length != len(short) || tooShort.Minimum != minFIPSHMACKeyBytes {
			t.Errorf("Length/Minimum = %d/%d, want %d/%d",
				tooShort.Length, tooShort.Minimum, len(short), minFIPSHMACKeyBytes)
		}

		// The message must say the mode is the constraint, not that anything
		// is broken — the same requirement doc 04 ruling 7 puts on the LUKS2
		// argon2 refusal.
		msg := err.Error()
		for _, want := range []string{"FIPS", "Redfish", "longer BMC password"} {
			if !strings.Contains(msg, want) {
				t.Errorf("error message must mention %q: %s", want, msg)
			}
		}
	})

	t.Run("FIPS refuses a short KG key even when the password is adequate", func(t *testing.T) {
		err := rmcpValidateSessionSecretForMode(adequate, []byte("kg"), true)
		if err == nil {
			t.Fatal("FIPS activation must refuse a KG key below the HMAC key floor")
		}

		var tooShort ErrFIPSKeyTooShort
		if !errors.As(err, &tooShort) {
			t.Fatalf("want ErrFIPSKeyTooShort, got %T: %v", err, err)
		}
		if tooShort.Field != "KG key" {
			t.Errorf("Field = %q, want \"KG key\"", tooShort.Field)
		}
	})

	t.Run("FIPS accepts adequate credentials", func(t *testing.T) {
		if err := rmcpValidateSessionSecretForMode(adequate, nil, true); err != nil {
			t.Errorf("an adequate password must be accepted under FIPS, got %v", err)
		}
		kg := []byte("0123456789abcdef")
		if err := rmcpValidateSessionSecretForMode(adequate, kg, true); err != nil {
			t.Errorf("an adequate KG key must be accepted under FIPS, got %v", err)
		}
	})

	t.Run("an unset KG key is not measured", func(t *testing.T) {
		// nil KG means "use the password as KG" per IPMI 2.0 13.31, so there
		// is no separate key to reject.
		if err := rmcpValidateSessionSecretForMode(adequate, nil, true); err != nil {
			t.Errorf("an unset KG key must not be rejected, got %v", err)
		}
	})
}
