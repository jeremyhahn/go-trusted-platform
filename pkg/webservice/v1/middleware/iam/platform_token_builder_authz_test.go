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
// succeeds with valid inputs.  AuthzMode was removed from
// PlatformTokenValidatorParams; the validator now only requires Issuer and
// JWKSURL.
func TestNewPlatformTokenValidator_ConfigValidation(t *testing.T) {
	const (
		issuer  = "https://broker.test"
		jwksURL = "https://broker.test/jwks"
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

	t.Run("valid params build a non-nil validator", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL,
		})
		if err != nil {
			t.Fatalf("valid params must not fail: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})

	t.Run("empty audience defaults without error", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: issuer, JWKSURL: jwksURL,
		})
		if err != nil {
			t.Fatalf("empty audience should default: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})

	t.Run("explicit audience is accepted", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer:   issuer,
			JWKSURL:  jwksURL,
			Audience: "api://my-platform",
		})
		if err != nil {
			t.Fatalf("explicit audience must not fail: %v", err)
		}
		if v == nil {
			t.Fatal("expected non-nil validator")
		}
	})
}
