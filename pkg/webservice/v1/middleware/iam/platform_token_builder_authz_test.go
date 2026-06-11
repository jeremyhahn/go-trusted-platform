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

package iam

import (
	"errors"
	"testing"
)

// TestNewPlatformTokenValidator_AuthzModeConfig asserts the HTTP builder applies
// the same fail-closed authz-mode / liveness rules as the daemon adapter: a
// liveness-requiring mode (online/hybrid, including the empty default) without an
// introspection URL fails construction; offline succeeds without one; a bad mode
// string fails.
func TestNewPlatformTokenValidator_AuthzModeConfig(t *testing.T) {
	const (
		issuer  = "https://broker.test"
		jwksURL = "https://broker.test/jwks"
		introsp = "https://broker.test/introspect"
	)

	t.Run("hybrid without introspection URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "hybrid",
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error, got %v", err)
		}
	})

	t.Run("online without introspection URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "online",
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error, got %v", err)
		}
	})

	t.Run("empty mode defaults to hybrid and requires URL", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("empty mode should default to hybrid and require URL, got %v", err)
		}
	})

	t.Run("offline without introspection URL succeeds", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "offline",
		})
		if err != nil {
			t.Fatalf("offline mode must not require an introspection URL: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator")
		}
	})

	t.Run("hybrid with introspection URL succeeds", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "hybrid", IntrospectionURL: introsp,
		})
		if err != nil {
			t.Fatalf("hybrid with URL must succeed: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator")
		}
	})

	t.Run("bad authz-mode string fails", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "occasionally", IntrospectionURL: introsp,
		})
		var modeErr ErrInvalidAuthzMode
		if !errors.As(err, &modeErr) {
			t.Fatalf("expected ErrInvalidAuthzMode, got %T: %v", err, err)
		}
	})

	t.Run("bearer and basic introspection credentials build", func(t *testing.T) {
		// Bearer credential branch.
		if _, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "hybrid", IntrospectionURL: introsp,
			IntrospectionBearerToken: "rs-bearer",
		}); err != nil {
			t.Fatalf("bearer-credential build failed: %v", err)
		}
		// Basic credential branch.
		if _, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "hybrid", IntrospectionURL: introsp,
			IntrospectionClientID: "rs", IntrospectionClientSecret: "pw",
		}); err != nil {
			t.Fatalf("basic-credential build failed: %v", err)
		}
	})
}

func TestErrInvalidAuthzMode_Error(t *testing.T) {
	if (ErrInvalidAuthzMode{Value: "monthly"}).Error() == "" {
		t.Error("ErrInvalidAuthzMode.Error() must not be empty")
	}
}
