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

package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestErrConnectionFailed(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := ErrConnectionFailed{
			Protocol: ProtocolGRPC,
			Target:   "localhost:10443",
			Err:      underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "grpc") {
			t.Error("error message should contain protocol")
		}
		if !strings.Contains(msg, "localhost:10443") {
			t.Error("error message should contain target")
		}
		if !strings.Contains(msg, "connection refused") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := ErrConnectionFailed{
			Protocol: ProtocolGRPC,
			Target:   "localhost:10443",
			Err:      underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := ErrConnectionFailed{
			Protocol: ProtocolGRPC,
			Target:   "localhost:10443",
			Err:      underlying,
		}

		var connErr ErrConnectionFailed
		if !errors.As(err, &connErr) {
			t.Error("errors.As should match ErrConnectionFailed")
		}
		if connErr.Protocol != ProtocolGRPC {
			t.Errorf("Protocol = %v, want %v", connErr.Protocol, ProtocolGRPC)
		}
	})
}

func TestErrDaemonUnavailable(t *testing.T) {
	t.Run("error message with protocols", func(t *testing.T) {
		underlying := errors.New("no route to host")
		err := ErrDaemonUnavailable{
			Attempted: []Protocol{ProtocolUnix, ProtocolGRPC},
			LastErr:   underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "unix") {
			t.Error("error message should contain unix protocol")
		}
		if !strings.Contains(msg, "grpc") {
			t.Error("error message should contain grpc protocol")
		}
		if !strings.Contains(msg, "no route to host") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("error message with no protocols", func(t *testing.T) {
		err := ErrDaemonUnavailable{
			Attempted: []Protocol{},
			LastErr:   nil,
		}

		msg := err.Error()
		if !strings.Contains(msg, "no protocols attempted") {
			t.Error("error message should indicate no protocols attempted")
		}
	})

	t.Run("unwrap returns last error", func(t *testing.T) {
		underlying := errors.New("no route to host")
		err := ErrDaemonUnavailable{
			Attempted: []Protocol{ProtocolGRPC},
			LastErr:   underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})
}

func TestErrProtocolNotSupported(t *testing.T) {
	t.Run("message names the rejected transport", func(t *testing.T) {
		msg := ErrProtocolNotSupported{Transport: "embedded"}.Error()
		if !strings.Contains(msg, "not supported") || !strings.Contains(msg, `"embedded"`) {
			t.Errorf("message %q should say not supported and name the transport", msg)
		}
	})

	t.Run("empty transport is still quoted", func(t *testing.T) {
		msg := ErrProtocolNotSupported{}.Error()
		if !strings.Contains(msg, `""`) {
			t.Errorf("message %q should show the empty name", msg)
		}
	})
}

func TestErrProtocolNotImplemented(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		err := ErrProtocolNotImplemented{
			Protocol: ProtocolREST,
		}

		msg := err.Error()
		if !strings.Contains(msg, "not implemented") {
			t.Error("error message should indicate not implemented")
		}
		if !strings.Contains(msg, "rest") {
			t.Error("error message should contain protocol name")
		}
	})
}

func TestErrTimeout(t *testing.T) {
	t.Run("message names the operation and elapsed time", func(t *testing.T) {
		err := ErrTimeout{Operation: "REST health probe", Elapsed: 5 * time.Second, Err: context.DeadlineExceeded}

		msg := err.Error()
		if !strings.Contains(msg, "REST health probe") || !strings.Contains(msg, "5s") {
			t.Errorf("message %q should contain operation and elapsed time", msg)
		}
	})

	t.Run("unwraps to the deadline error", func(t *testing.T) {
		err := ErrConnectionFailed{
			Protocol: ProtocolREST,
			Err:      ErrTimeout{Operation: "connect", Err: context.DeadlineExceeded},
		}

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("errors.Is should reach context.DeadlineExceeded through ErrTimeout")
		}
		var timeout ErrTimeout
		if !errors.As(err, &timeout) {
			t.Error("errors.As should find ErrTimeout inside ErrConnectionFailed")
		}
	})
}

func TestErrInvalidOptions(t *testing.T) {
	t.Run("error message with field", func(t *testing.T) {
		err := ErrInvalidOptions{
			Field:  "Timeout",
			Reason: "cannot be negative",
		}

		msg := err.Error()
		if !strings.Contains(msg, "Timeout") {
			t.Error("error message should contain field name")
		}
		if !strings.Contains(msg, "cannot be negative") {
			t.Error("error message should contain reason")
		}
	})

	t.Run("error message without field", func(t *testing.T) {
		err := ErrInvalidOptions{
			Reason: "general error",
		}

		msg := err.Error()
		if strings.Contains(msg, ": :") {
			t.Error("error message should not have double colons")
		}
		if !strings.Contains(msg, "general error") {
			t.Error("error message should contain reason")
		}
	})
}

func TestErrServiceUnavailable(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		err := ErrServiceUnavailable{
			Service: "daemon",
		}

		msg := err.Error()
		if !strings.Contains(msg, "daemon") {
			t.Error("error message should contain service name")
		}
		if !strings.Contains(msg, "unavailable") {
			t.Error("error message should indicate unavailable")
		}
	})
}

func TestErrCloseFailed(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		underlying := errors.New("broken pipe")
		err := ErrCloseFailed{
			Protocol: ProtocolGRPC,
			Err:      underlying,
		}

		msg := err.Error()
		if !strings.Contains(msg, "grpc") {
			t.Error("error message should contain protocol")
		}
		if !strings.Contains(msg, "broken pipe") {
			t.Error("error message should contain underlying error")
		}
	})

	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("broken pipe")
		err := ErrCloseFailed{
			Protocol: ProtocolGRPC,
			Err:      underlying,
		}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should match underlying error")
		}
	})
}

func TestErrInsecureTransport(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		err := ErrInsecureTransport{
			Protocol: ProtocolREST,
			Target:   "http://localhost:8443",
			Reason:   "the REST server only offers TLS",
		}

		msg := err.Error()
		if !strings.Contains(msg, "rest") {
			t.Error("error message should contain protocol")
		}
		if !strings.Contains(msg, "http://localhost:8443") {
			t.Error("error message should contain target")
		}
		if !strings.Contains(msg, "only offers TLS") {
			t.Error("error message should contain reason")
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		var err error = ErrInsecureTransport{Protocol: ProtocolMCP}

		var insecureErr ErrInsecureTransport
		if !errors.As(err, &insecureErr) {
			t.Fatal("errors.As should match ErrInsecureTransport")
		}
		if insecureErr.Protocol != ProtocolMCP {
			t.Errorf("Protocol = %v, want %v", insecureErr.Protocol, ProtocolMCP)
		}
	})
}

func TestErrUnsupportedOption(t *testing.T) {
	t.Run("error message formatting", func(t *testing.T) {
		err := ErrUnsupportedOption{
			Protocol: ProtocolUnix,
			Option:   "BearerToken",
			Reason:   "the socket authenticates by peer credentials",
		}

		msg := err.Error()
		if !strings.Contains(msg, "unix") {
			t.Error("error message should contain protocol")
		}
		if !strings.Contains(msg, "BearerToken") {
			t.Error("error message should contain option")
		}
		if !strings.Contains(msg, "peer credentials") {
			t.Error("error message should contain reason")
		}
	})

	t.Run("errors.As works correctly", func(t *testing.T) {
		var err error = ErrUnsupportedOption{Protocol: ProtocolEmbedded, Option: "TLSConfig"}

		var optErr ErrUnsupportedOption
		if !errors.As(err, &optErr) {
			t.Fatal("errors.As should match ErrUnsupportedOption")
		}
		if optErr.Option != "TLSConfig" {
			t.Errorf("Option = %q, want %q", optErr.Option, "TLSConfig")
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrNilOptions", func(t *testing.T) {
		if ErrNilOptions == nil {
			t.Error("ErrNilOptions should not be nil")
		}
		if ErrNilOptions.Error() == "" {
			t.Error("ErrNilOptions should have a message")
		}
	})

	t.Run("ErrEmptyAddress", func(t *testing.T) {
		if ErrEmptyAddress == nil {
			t.Error("ErrEmptyAddress should not be nil")
		}
		if ErrEmptyAddress.Error() == "" {
			t.Error("ErrEmptyAddress should have a message")
		}
	})

	t.Run("ErrNotConnected", func(t *testing.T) {
		if ErrNotConnected == nil {
			t.Error("ErrNotConnected should not be nil")
		}
		if ErrNotConnected.Error() == "" {
			t.Error("ErrNotConnected should have a message")
		}
	})
}
