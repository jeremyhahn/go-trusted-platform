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

package quicwire

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestNewClientNilConfig(t *testing.T) {
	_, err := NewClient(nil)

	if err == nil {
		t.Error("expected error for nil config")
		return
	}

	var invalidConfigErr ErrInvalidConfig
	if !errors.As(err, &invalidConfigErr) {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewClientEmptyServerAddr(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "",
		Timeout:    10 * time.Second,
	}

	_, err := NewClient(config)

	if err == nil {
		t.Error("expected error for empty server address")
		return
	}

	var invalidConfigErr ErrInvalidConfig
	if !errors.As(err, &invalidConfigErr) {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
		return
	}

	if invalidConfigErr.Field != "ServerAddr" {
		t.Errorf("expected error field 'ServerAddr', got '%s'", invalidConfigErr.Field)
	}
}

func TestClientConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *ClientConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: &ClientConfig{
				ServerAddr: "localhost:9444",
				Timeout:    10 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty server addr",
			config: &ClientConfig{
				ServerAddr: "",
				Timeout:    10 * time.Second,
			},
			expectError: true,
			errorField:  "ServerAddr",
		},
		{
			name: "zero timeout defaults",
			config: &ClientConfig{
				ServerAddr: "localhost:9444",
				Timeout:    0,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}

				var invalidConfigErr ErrInvalidConfig
				if !errors.As(err, &invalidConfigErr) {
					t.Errorf("expected ErrInvalidConfig, got %T", err)
					return
				}

				if invalidConfigErr.Field != tt.errorField {
					t.Errorf("expected error field '%s', got '%s'", tt.errorField, invalidConfigErr.Field)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWithClientLoggerOption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opt := WithClientLogger(logger)

	opts := &clientOptions{}
	opt(opts)

	if opts.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestWithTokenOption(t *testing.T) {
	token := "test-token-123"
	opt := WithToken(token)

	opts := &clientOptions{}
	opt(opts)

	if opts.token != token {
		t.Errorf("expected token '%s', got '%s'", token, opts.token)
	}
}

func TestClientOptions(t *testing.T) {
	tests := []struct {
		name          string
		options       []ClientOption
		expectedToken string
		hasLogger     bool
	}{
		{
			name:          "no options",
			options:       nil,
			expectedToken: "",
			hasLogger:     false,
		},
		{
			name: "with token",
			options: []ClientOption{
				WithToken("my-token"),
			},
			expectedToken: "my-token",
			hasLogger:     false,
		},
		{
			name: "with logger",
			options: []ClientOption{
				WithClientLogger(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))),
			},
			expectedToken: "",
			hasLogger:     true,
		},
		{
			name: "with token and logger",
			options: []ClientOption{
				WithToken("bearer-token"),
				WithClientLogger(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))),
			},
			expectedToken: "bearer-token",
			hasLogger:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &clientOptions{}
			for _, opt := range tt.options {
				opt(opts)
			}

			if opts.token != tt.expectedToken {
				t.Errorf("expected token '%s', got '%s'", tt.expectedToken, opts.token)
			}

			if tt.hasLogger && opts.logger == nil {
				t.Error("expected logger to be set")
			}

			if !tt.hasLogger && opts.logger != nil {
				t.Error("expected logger to be nil")
			}
		})
	}
}

func TestDefaultClientConfigValues(t *testing.T) {
	config := DefaultClientConfig("localhost:9444")

	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout 10s, got %v", config.Timeout)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout 30s, got %v", config.MaxIdleTimeout)
	}

	if len(config.NextProtos) != 1 {
		t.Errorf("expected 1 NextProtos, got %d", len(config.NextProtos))
	}

	if config.NextProtos[0] != "platform-quic" {
		t.Errorf("expected NextProtos 'platform-quic', got '%s'", config.NextProtos[0])
	}
}

func TestClientConfigNilTLSConfig(t *testing.T) {
	// When TLSConfig is nil, NewClient should create a default one
	config := &ClientConfig{
		ServerAddr: "localhost:9444",
		Timeout:    10 * time.Second,
		NextProtos: []string{"test-proto"},
	}

	// Validation should pass
	err := config.Validate()
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestClientConfigTimeoutDefaults(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "localhost:9444",
		Timeout:    0,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout to default to 10s, got %v", config.Timeout)
	}
}

func TestClientConfigNegativeTimeoutDefaults(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "localhost:9444",
		Timeout:    -5 * time.Second,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout to default to 10s, got %v", config.Timeout)
	}
}

func TestClientOptionChaining(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	token := "chained-token"

	opts := &clientOptions{}

	// Apply options in sequence
	WithClientLogger(logger)(opts)
	WithToken(token)(opts)

	if opts.logger != logger {
		t.Error("expected logger to be set")
	}

	if opts.token != token {
		t.Errorf("expected token '%s', got '%s'", token, opts.token)
	}
}

func TestClientConfigAddressVariations(t *testing.T) {
	addresses := []struct {
		addr  string
		valid bool
	}{
		{"localhost:9444", true},
		{"127.0.0.1:9444", true},
		{"192.168.1.1:9444", true},
		{"example.com:9444", true},
		{"[::1]:9444", true},
		{"", false},
	}

	for _, tt := range addresses {
		t.Run(tt.addr, func(t *testing.T) {
			config := &ClientConfig{
				ServerAddr: tt.addr,
				Timeout:    10 * time.Second,
			}

			err := config.Validate()

			if tt.valid {
				if err != nil {
					t.Errorf("expected valid address, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error for invalid address")
				}
			}
		})
	}
}
