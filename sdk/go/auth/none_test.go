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
	"context"
	"crypto/tls"
	"testing"
	"time"
)

func TestNewNoneProvider(t *testing.T) {
	t.Run("creates provider with default options", func(t *testing.T) {
		p := NewNoneProvider()

		if p == nil {
			t.Fatal("NewNoneProvider returned nil")
		}
		if p.Type() != AuthTypeNone {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeNone)
		}
	})

	t.Run("creates provider with TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
		p := NewNoneProvider(WithNoneTLSConfig(tlsConfig))

		if p.GetTLSConfig() == nil {
			t.Error("GetTLSConfig() should not be nil")
		}
		if p.GetTLSConfig().MinVersion != tls.VersionTLS13 {
			t.Error("TLS config should have TLS 1.3 minimum")
		}
	})

	t.Run("creates provider with minimal TLS", func(t *testing.T) {
		p := NewNoneProvider(WithMinimalTLS())

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Error("MinVersion should be TLS 1.3")
		}
	})

	t.Run("creates provider with CA PEM TLS", func(t *testing.T) {
		_, _, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p := NewNoneProvider(WithTLSFromCA(caPEM))

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %v, want TLS 1.3 (%v)", tlsConfig.MinVersion, tls.VersionTLS13)
		}
		if tlsConfig.RootCAs == nil {
			t.Error("RootCAs should not be nil")
		}
		if tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must be false")
		}
	})

	t.Run("WithTLSFromCA with invalid PEM does not set config", func(t *testing.T) {
		p := NewNoneProvider(WithTLSFromCA([]byte("not valid pem")))

		if p.GetTLSConfig() != nil {
			t.Error("GetTLSConfig() should be nil for invalid PEM")
		}
	})
}

func TestNoneProvider_GetToken(t *testing.T) {
	t.Run("returns empty string without error", func(t *testing.T) {
		p := NewNoneProvider()

		token, err := p.GetToken(context.Background())
		if err != nil {
			t.Errorf("GetToken() error = %v, want nil", err)
		}
		if token != "" {
			t.Errorf("GetToken() = %v, want empty string", token)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		p := NewNoneProvider()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Even with cancelled context, NoneProvider should succeed
		_, err := p.GetToken(ctx)
		if err != nil {
			t.Errorf("GetToken() error = %v, want nil", err)
		}
	})
}

func TestNoneProvider_GetTLSConfig(t *testing.T) {
	t.Run("returns nil when no config set", func(t *testing.T) {
		p := NewNoneProvider()

		if p.GetTLSConfig() != nil {
			t.Error("GetTLSConfig() should return nil")
		}
	})

	t.Run("returns configured TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "example.com",
		}
		p := NewNoneProvider(WithNoneTLSConfig(tlsConfig))

		got := p.GetTLSConfig()
		if got == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if got.MinVersion != tls.VersionTLS13 {
			t.Error("TLS config MinVersion mismatch")
		}
		if got.ServerName != "example.com" {
			t.Error("TLS config ServerName mismatch")
		}
	})
}

func TestNoneProvider_Refresh(t *testing.T) {
	t.Run("returns nil (no-op)", func(t *testing.T) {
		p := NewNoneProvider()

		err := p.Refresh(context.Background())
		if err != nil {
			t.Errorf("Refresh() error = %v, want nil", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		p := NewNoneProvider()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Even with cancelled context, Refresh should succeed (it's a no-op)
		err := p.Refresh(ctx)
		if err != nil {
			t.Errorf("Refresh() error = %v, want nil", err)
		}
	})
}

func TestNoneProvider_IsExpired(t *testing.T) {
	t.Run("always returns false", func(t *testing.T) {
		p := NewNoneProvider()

		if p.IsExpired() {
			t.Error("IsExpired() should return false")
		}
	})

	t.Run("returns false regardless of options", func(t *testing.T) {
		p := NewNoneProvider(WithMinimalTLS())

		if p.IsExpired() {
			t.Error("IsExpired() should return false")
		}
	})
}

func TestNoneProvider_Type(t *testing.T) {
	t.Run("returns AuthTypeNone", func(t *testing.T) {
		p := NewNoneProvider()

		if p.Type() != AuthTypeNone {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeNone)
		}
	})

	t.Run("returns AuthTypeNone with options", func(t *testing.T) {
		p := NewNoneProvider(WithMinimalTLS())

		if p.Type() != AuthTypeNone {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeNone)
		}
	})
}

func TestNoneProvider_ImplementsInterface(t *testing.T) {
	t.Run("implements Provider interface", func(t *testing.T) {
		var _ Provider = (*NoneProvider)(nil)
	})

	t.Run("can be used as Provider", func(t *testing.T) {
		var p Provider = NewNoneProvider()

		if p.Type() != AuthTypeNone {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeNone)
		}

		token, err := p.GetToken(context.Background())
		if err != nil {
			t.Errorf("GetToken() error = %v", err)
		}
		if token != "" {
			t.Errorf("GetToken() = %v, want empty", token)
		}

		if p.IsExpired() {
			t.Error("IsExpired() should be false")
		}

		if p.GetTLSConfig() != nil {
			t.Error("GetTLSConfig() should be nil for default NoneProvider")
		}

		if err := p.Refresh(context.Background()); err != nil {
			t.Errorf("Refresh() error = %v", err)
		}
	})
}

func TestNoneProvider_UseCases(t *testing.T) {
	t.Run("suitable for Unix socket connections", func(t *testing.T) {
		// Unix sockets use file permissions for security, no auth needed
		p := NewNoneProvider()

		// Should work without any configuration
		_, err := p.GetToken(context.Background())
		if err != nil {
			t.Errorf("GetToken() error = %v", err)
		}

		if p.GetTLSConfig() != nil {
			t.Error("Unix socket shouldn't need TLS")
		}
	})

	t.Run("suitable for local testing with CA cert", func(t *testing.T) {
		// For testing, use proper CA-based verification
		_, _, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))
		p := NewNoneProvider(WithTLSFromCA(caPEM))

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("TLS config should be set")
		}

		if tlsConfig.RootCAs == nil {
			t.Error("RootCAs should be set from CA PEM")
		}
		if tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must be false")
		}
	})

	t.Run("suitable for server-to-server with external auth", func(t *testing.T) {
		// Sometimes auth is handled at a different layer (e.g., service mesh)
		p := NewNoneProvider(WithMinimalTLS())

		// TLS for encryption, but no client auth
		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("TLS config should be set")
		}

		if len(tlsConfig.Certificates) != 0 {
			t.Error("Should not have client certificates")
		}
	})
}
