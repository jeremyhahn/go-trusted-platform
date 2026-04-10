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
	"errors"
	"strings"
	"testing"
)

func TestErrTokenExpired(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		err := ErrTokenExpired{
			ExpiredAt: 1704067200,
		}

		msg := err.Error()
		if !strings.Contains(msg, "expired") {
			t.Error("error message should contain 'expired'")
		}
		if !strings.Contains(msg, "1704067200") {
			t.Error("error message should contain expiration timestamp")
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		err := ErrTokenExpired{
			ExpiredAt: 1704067200,
		}

		var tokenErr ErrTokenExpired
		if !errors.As(err, &tokenErr) {
			t.Error("errors.As should match ErrTokenExpired")
		}
		if tokenErr.ExpiredAt != 1704067200 {
			t.Errorf("ExpiredAt = %v, want %v", tokenErr.ExpiredAt, 1704067200)
		}
	})
}

func TestErrTokenRefreshFailed(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		underlying := errors.New("network timeout")
		err := ErrTokenRefreshFailed{
			Err: underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "refresh") {
			t.Error("error message should contain 'refresh'")
		}
		if !strings.Contains(msg, "network timeout") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("network timeout")
		err := ErrTokenRefreshFailed{
			Err: underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		underlying := errors.New("network timeout")
		err := ErrTokenRefreshFailed{
			Err: underlying,
		}

		var refreshErr ErrTokenRefreshFailed
		if !errors.As(err, &refreshErr) {
			t.Error("errors.As should match ErrTokenRefreshFailed")
		}
	})
}

func TestErrCertificateLoadFailed(t *testing.T) {
	t.Run("error message with path", func(t *testing.T) {
		underlying := errors.New("file not found")
		err := ErrCertificateLoadFailed{
			Path: "/etc/certs/client.crt",
			Err:  underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "certificate") {
			t.Error("error message should contain 'certificate'")
		}
		if !strings.Contains(msg, "/etc/certs/client.crt") {
			t.Error("error message should contain path")
		}
		if !strings.Contains(msg, "file not found") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("error message without path", func(t *testing.T) {
		underlying := errors.New("invalid PEM")
		err := ErrCertificateLoadFailed{
			Err: underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "certificate") {
			t.Error("error message should contain 'certificate'")
		}
		if !strings.Contains(msg, "invalid PEM") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("file not found")
		err := ErrCertificateLoadFailed{
			Path: "/etc/certs/client.crt",
			Err:  underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})
}

func TestErrKeyLoadFailed(t *testing.T) {
	t.Run("error message with path", func(t *testing.T) {
		underlying := errors.New("permission denied")
		err := ErrKeyLoadFailed{
			Path: "/etc/certs/client.key",
			Err:  underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "private key") {
			t.Error("error message should contain 'private key'")
		}
		if !strings.Contains(msg, "/etc/certs/client.key") {
			t.Error("error message should contain path")
		}
		if !strings.Contains(msg, "permission denied") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("error message without path", func(t *testing.T) {
		underlying := errors.New("invalid key format")
		err := ErrKeyLoadFailed{
			Err: underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "private key") {
			t.Error("error message should contain 'private key'")
		}
		if !strings.Contains(msg, "invalid key format") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("permission denied")
		err := ErrKeyLoadFailed{
			Path: "/etc/certs/client.key",
			Err:  underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})
}

func TestErrCALoadFailed(t *testing.T) {
	t.Run("error message with path", func(t *testing.T) {
		underlying := errors.New("file not found")
		err := ErrCALoadFailed{
			Path: "/etc/certs/ca.crt",
			Err:  underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "CA certificate") {
			t.Error("error message should contain 'CA certificate'")
		}
		if !strings.Contains(msg, "/etc/certs/ca.crt") {
			t.Error("error message should contain path")
		}
		if !strings.Contains(msg, "file not found") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("error message without path", func(t *testing.T) {
		underlying := errors.New("invalid CA")
		err := ErrCALoadFailed{
			Err: underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "CA certificate") {
			t.Error("error message should contain 'CA certificate'")
		}
		if !strings.Contains(msg, "invalid CA") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("file not found")
		err := ErrCALoadFailed{
			Path: "/etc/certs/ca.crt",
			Err:  underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})
}

func TestErrInvalidToken(t *testing.T) {
	t.Run("error message with reason", func(t *testing.T) {
		err := ErrInvalidToken{
			Reason: "malformed JWT",
		}

		msg := err.Error()
		if !strings.Contains(msg, "invalid token") {
			t.Error("error message should contain 'invalid token'")
		}
		if !strings.Contains(msg, "malformed JWT") {
			t.Error("error message should contain reason")
		}
	})

	t.Run("error message without reason", func(t *testing.T) {
		err := ErrInvalidToken{}

		msg := err.Error()
		if msg != "invalid token" {
			t.Errorf("error message = %q, want 'invalid token'", msg)
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		err := ErrInvalidToken{
			Reason: "malformed JWT",
		}

		var invalidErr ErrInvalidToken
		if !errors.As(err, &invalidErr) {
			t.Error("errors.As should match ErrInvalidToken")
		}
		if invalidErr.Reason != "malformed JWT" {
			t.Errorf("Reason = %v, want 'malformed JWT'", invalidErr.Reason)
		}
	})
}

func TestErrInvalidCertificate(t *testing.T) {
	t.Run("error message with reason", func(t *testing.T) {
		err := ErrInvalidCertificate{
			Reason: "expired",
		}

		msg := err.Error()
		if !strings.Contains(msg, "invalid certificate") {
			t.Error("error message should contain 'invalid certificate'")
		}
		if !strings.Contains(msg, "expired") {
			t.Error("error message should contain reason")
		}
	})

	t.Run("error message without reason", func(t *testing.T) {
		err := ErrInvalidCertificate{}

		msg := err.Error()
		if msg != "invalid certificate" {
			t.Errorf("error message = %q, want 'invalid certificate'", msg)
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrNoToken", func(t *testing.T) {
		if ErrNoToken == nil {
			t.Error("ErrNoToken should not be nil")
		}
		if ErrNoToken.Error() == "" {
			t.Error("ErrNoToken should have a message")
		}
		if !strings.Contains(ErrNoToken.Error(), "token") {
			t.Error("ErrNoToken should mention token")
		}
	})

	t.Run("ErrNoRefreshCallback", func(t *testing.T) {
		if ErrNoRefreshCallback == nil {
			t.Error("ErrNoRefreshCallback should not be nil")
		}
		if ErrNoRefreshCallback.Error() == "" {
			t.Error("ErrNoRefreshCallback should have a message")
		}
		if !strings.Contains(ErrNoRefreshCallback.Error(), "refresh") {
			t.Error("ErrNoRefreshCallback should mention refresh")
		}
	})

	t.Run("ErrNoCertificate", func(t *testing.T) {
		if ErrNoCertificate == nil {
			t.Error("ErrNoCertificate should not be nil")
		}
		if ErrNoCertificate.Error() == "" {
			t.Error("ErrNoCertificate should have a message")
		}
		if !strings.Contains(ErrNoCertificate.Error(), "certificate") {
			t.Error("ErrNoCertificate should mention certificate")
		}
	})

	t.Run("ErrNoPrivateKey", func(t *testing.T) {
		if ErrNoPrivateKey == nil {
			t.Error("ErrNoPrivateKey should not be nil")
		}
		if ErrNoPrivateKey.Error() == "" {
			t.Error("ErrNoPrivateKey should have a message")
		}
		if !strings.Contains(ErrNoPrivateKey.Error(), "private key") {
			t.Error("ErrNoPrivateKey should mention private key")
		}
	})
}
