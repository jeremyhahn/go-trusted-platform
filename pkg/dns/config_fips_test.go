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

package dns

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
)

// fipsActive reports whether this test binary is running FIPS-activated, which
// GODEBUG fixes before main and no test can change.
func fipsActive() bool { return fips140.Enabled() }

// TestDNSSECConfigValidateForMode pins the NSEC3 refusal under FIPS activation
// (#249). The mode is a parameter because GODEBUG is fixed before main runs and
// cannot be toggled from within a test binary.
func TestDNSSECConfigValidateForMode(t *testing.T) {
	t.Run("FIPS refuses NSEC3 with a typed error", func(t *testing.T) {
		cfg := &DNSSECConfig{Enabled: true, NSECMode: "nsec3"}

		err := cfg.validateForMode(true)
		if err == nil {
			t.Fatal("FIPS activation must refuse NSEC3: RFC 5155 defines only a SHA-1 hash")
		}

		var unsupported ErrFIPSNSEC3Unsupported
		if !errors.As(err, &unsupported) {
			t.Fatalf("want ErrFIPSNSEC3Unsupported, got %T: %v", err, err)
		}
		if unsupported.NSECMode != "nsec3" {
			t.Errorf("NSECMode = %q, want the configured value", unsupported.NSECMode)
		}

		// The message must close the question rather than invite a follow-up
		// implementing "the approved variant" — there isn't one — and must
		// name the mode, not the zone or the file, as the constraint.
		msg := err.Error()
		for _, want := range []string{
			"RFC 5155",
			"SHA-1",
			"no approved NSEC3 variant",
			"otherwise valid",
			"FIPS activation",
			"zone enumeration",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("error message must mention %q: %s", want, msg)
			}
		}
	})

	t.Run("FIPS accepts NSEC", func(t *testing.T) {
		// The refusal is scoped to NSEC3. A FIPS deployment signing with NSEC
		// must start normally — failing closed on the mode alone would be a
		// larger outage than the defect.
		cfg := &DNSSECConfig{Enabled: true, NSECMode: "nsec"}
		if err := cfg.validateForMode(true); err != nil {
			t.Errorf("NSEC must be accepted under FIPS, got %v", err)
		}
	})

	t.Run("FIPS accepts an unset mode", func(t *testing.T) {
		// An empty nsec-mode takes the NSEC branch in SignZone, so it is not
		// an NSEC3 configuration and must not be refused.
		cfg := &DNSSECConfig{Enabled: true}
		if err := cfg.validateForMode(true); err != nil {
			t.Errorf("an unset nsec-mode must be accepted under FIPS, got %v", err)
		}
	})

	t.Run("FIPS accepts NSEC3 when DNSSEC is disabled", func(t *testing.T) {
		// Nothing is signed, so nothing hashes. Refusing here would stop a
		// node booting over a setting it never reads.
		cfg := &DNSSECConfig{Enabled: false, NSECMode: "nsec3"}
		if err := cfg.validateForMode(true); err != nil {
			t.Errorf("a disabled DNSSEC config must be accepted under FIPS, got %v", err)
		}
	})

	t.Run("non-FIPS accepts NSEC3", func(t *testing.T) {
		// Existing deployments must not start failing because a binary is
		// FIPS-capable; activation is what changes behaviour (doc 04 ruling 1).
		cfg := &DNSSECConfig{Enabled: true, NSECMode: "nsec3"}
		if err := cfg.validateForMode(false); err != nil {
			t.Errorf("non-FIPS must accept NSEC3, got %v", err)
		}
	})

	t.Run("the mode comparison is case-insensitive", func(t *testing.T) {
		// nsec-mode comes from YAML written by hand.
		cfg := &DNSSECConfig{Enabled: true, NSECMode: "NSEC3"}
		if err := cfg.validateForMode(true); err == nil {
			t.Error("NSEC3 must be refused regardless of case")
		}
	})

	t.Run("a nil config validates", func(t *testing.T) {
		var cfg *DNSSECConfig
		if err := cfg.validateForMode(true); err != nil {
			t.Errorf("a nil DNSSEC config must not error, got %v", err)
		}
	})
}

// TestDNSSECConfigValidate covers the exported wrapper, which reads the process
// mode. It cannot assert the refusal without controlling GODEBUG, so it asserts
// what is true in whichever build runs it: a non-NSEC3 configuration is always
// accepted, and an NSEC3 one is accepted exactly when the process is not
// FIPS-activated.
func TestDNSSECConfigValidate(t *testing.T) {
	if err := (&DNSSECConfig{Enabled: true, NSECMode: "nsec"}).Validate(); err != nil {
		t.Errorf("NSEC must validate in any build, got %v", err)
	}

	err := (&DNSSECConfig{Enabled: true, NSECMode: "nsec3"}).Validate()
	if fipsActive() {
		var unsupported ErrFIPSNSEC3Unsupported
		if !errors.As(err, &unsupported) {
			t.Errorf("a FIPS-activated build must refuse NSEC3, got %v", err)
		}
		return
	}
	if err != nil {
		t.Errorf("a non-FIPS build must accept NSEC3, got %v", err)
	}
}

// TestNewDNSSECService_RefusesNSEC3UnderFIPS covers the constructor guard, which
// catches a configuration that reached the service without going through Run.
func TestNewDNSSECService_RefusesNSEC3UnderFIPS(t *testing.T) {
	if !fipsActive() {
		// Nothing to assert: outside FIPS activation NSEC3 is supported, and
		// the refusal path does not exist. The decision itself is covered
		// exhaustively by TestDNSSECConfigValidateForMode above.
		if _, err := NewDNSSECServiceWithKeyStore(
			&DNSSECConfig{Enabled: true, NSECMode: "nsec3"}, createTestLogger(), NewMockKeyStore(),
		); err != nil {
			t.Errorf("non-FIPS must construct an NSEC3 service, got %v", err)
		}
		return
	}

	_, err := NewDNSSECServiceWithKeyStore(
		&DNSSECConfig{Enabled: true, NSECMode: "nsec3"}, createTestLogger(), NewMockKeyStore(),
	)
	var unsupported ErrFIPSNSEC3Unsupported
	if !errors.As(err, &unsupported) {
		t.Errorf("a FIPS build must refuse to construct an NSEC3 service, got %v", err)
	}
}
