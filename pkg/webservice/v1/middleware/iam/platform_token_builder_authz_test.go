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

// TestNewPlatformTokenValidator_ConfigValidation asserts that
// NewPlatformTokenValidator fails closed on missing required fields and
// succeeds with valid inputs. An empty AuthzMode resolves to hybrid, which
// requires an introspection URL — so liveness-requiring modes without one
// fail closed rather than silently downgrading to offline.
func TestNewPlatformTokenValidator_ConfigValidation(t *testing.T) {
	t.Parallel()
	const (
		issuer           = "https://broker.test"
		jwksURL          = "https://broker.test/jwks"
		introspectionURL = "https://broker.test/introspect"
	)

	t.Run("missing issuer fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			JWKSURL: jwksURL,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "issuer" {
			t.Fatalf("expected issuer config error, got %v", err)
		}
	})

	t.Run("missing JWKS URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "jwks-url" {
			t.Fatalf("expected jwks-url config error, got %v", err)
		}
	})

	t.Run("whitespace-only issuer fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: "   ", JWKSURL: jwksURL,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "issuer" {
			t.Fatalf("expected issuer config error for whitespace, got %v", err)
		}
	})

	t.Run("whitespace-only JWKS URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: "   ",
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "jwks-url" {
			t.Fatalf("expected jwks-url config error for whitespace, got %v", err)
		}
	})

	t.Run("default hybrid mode without introspection URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error for hybrid default, got %v", err)
		}
	})

	t.Run("online mode without introspection URL fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "online",
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error for online mode, got %v", err)
		}
	})

	t.Run("unrecognized authz mode fails closed", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "bogus",
		})
		var modeErr ErrInvalidAuthzMode
		if !errors.As(err, &modeErr) || modeErr.Value != "bogus" {
			t.Fatalf("expected ErrInvalidAuthzMode for bogus mode, got %v", err)
		}
	})

	t.Run("offline mode builds a non-nil validator", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "offline",
		})
		if err != nil {
			t.Fatalf("offline mode must not fail: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})

	t.Run("hybrid mode with introspection URL builds a non-nil validator", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL, IntrospectionURL: introspectionURL,
		})
		if err != nil {
			t.Fatalf("hybrid with introspection URL must not fail: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})

	t.Run("explicit audience is accepted", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer:    issuer,
			JWKSURL:   jwksURL,
			AuthzMode: "offline",
			Audience:  "api://my-platform",
		})
		if err != nil {
			t.Fatalf("explicit audience must not fail: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})
}
