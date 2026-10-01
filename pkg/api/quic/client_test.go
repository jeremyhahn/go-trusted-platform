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

//go:build codec_msgpack

package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// getAvailablePort finds and returns an available port
func getAvailablePort() (int, error) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port, nil
}

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
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWithClientLoggerOption(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)
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
				WithClientLogger(logging.NewLogger(slog.LevelDebug, io.Discard)),
			},
			expectedToken: "",
			hasLogger:     true,
		},
		{
			name: "with token and logger",
			options: []ClientOption{
				WithToken("bearer-token"),
				WithClientLogger(logging.NewLogger(slog.LevelDebug, io.Discard)),
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

func TestClientConfigWithTLSConfig(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ClientConfig{
		ServerAddr: "localhost:9444",
		Timeout:    10 * time.Second,
		TLSConfig:  tlsConfig,
	}

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
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)
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

// TestNewClientConnectionFailure tests client creation with an unreachable server
func TestNewClientConnectionFailure(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "127.0.0.1:59999", // Unreachable port
		Timeout:    500 * time.Millisecond,
		NextProtos: []string{"trusted-platform"},
	}

	_, err := NewClient(config)

	// Should fail to connect
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

// TestClientServerIntegration tests full client-server communication
func TestClientServerIntegration(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: []byte("pong"),
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	// Create client with TLS config that trusts the server certificate
	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig, WithToken("test-token"))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Test IsConnected
	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}

	// Test ServerAddr
	if client.ServerAddr() != listenAddr {
		t.Errorf("expected server addr '%s', got '%s'", listenAddr, client.ServerAddr())
	}

	// Test SetToken
	client.SetToken("new-token")

	// Test SendRequest
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.SendRequest(ctx, OpHealth, nil)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	if resp.Status != StatusOK {
		t.Errorf("expected status OK, got %d", resp.Status)
	}

	// Test Close
	err = client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Test IsConnected after close
	if client.IsConnected() {
		t.Error("expected client to not be connected after close")
	}

	// Test double close (should be safe)
	err = client.Close()
	if err != nil {
		t.Errorf("double Close failed: %v", err)
	}
}

// TestClientSendMethod tests the Send convenience method
func TestClientSendMethod(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	// Create a handler that echoes back data
	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil, // Empty payload
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with nil request and response data
	err = client.Send(ctx, OpHealth, nil, nil)
	if err != nil {
		t.Errorf("Send failed: %v", err)
	}
}

// TestClientSendRequestWhenClosed tests sending request after close
func TestClientSendRequestWhenClosed(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Close the client
	client.Close()

	// Try to send request after close
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.SendRequest(ctx, OpHealth, nil)
	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

// TestClientHealth tests the Health method
func TestClientHealth(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Health(ctx)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}

// TestNewClientWithTLSConfig tests client creation with custom TLS config
func TestNewClientWithTLSConfig(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	// Create client with custom TLS config that trusts the server cert
	serverCertDER := serverTLSConfig.Certificates[0].Certificate[0]
	serverCertParsed, _ := x509.ParseCertificate(serverCertDER)
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(serverCertParsed)
	clientTLSConfig := &tls.Config{
		RootCAs:    clientCAPool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"trusted-platform"},
	}

	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client with TLS config: %v", err)
	}
	defer client.Close()

	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}
}

// TestNewClientWithTLSConfigEmptyNextProtos tests that NextProtos are set from config
func TestNewClientWithTLSConfigEmptyNextProtos(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	// Create client with TLS config that has empty NextProtos
	serverCertDER := serverTLSConfig.Certificates[0].Certificate[0]
	serverCertParsed, _ := x509.ParseCertificate(serverCertDER)
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(serverCertParsed)
	clientTLSConfig := &tls.Config{
		RootCAs:    clientCAPool,
		MinVersion: tls.VersionTLS13,
	}
	clientTLSConfig.NextProtos = nil // Empty

	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
		NextProtos: []string{"trusted-platform"}, // Should be used
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}
}

// TestNewClientWithClientLogger tests client creation with custom logger
func TestNewClientWithClientLogger(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	logger := logging.NewLogger(slog.LevelDebug, io.Discard)

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig, WithClientLogger(logger))
	if err != nil {
		t.Fatalf("failed to create client with logger: %v", err)
	}
	defer client.Close()

	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}
}

// TestClientSendWithRequestData tests Send with non-nil request data
func TestClientSendWithRequestData(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with non-nil request data
	reqData := map[string]string{"test": "value"}
	err = client.Send(ctx, OpHealth, reqData, nil)
	if err != nil {
		t.Errorf("Send with request data failed: %v", err)
	}
}

// TestClientSendWithResponseData tests Send with non-nil response data
func TestClientSendWithResponseData(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	// Create a handler that returns encoded response data
	respPayload, _ := EncodePayload(map[string]string{"result": "success"})
	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: respPayload,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with non-nil response data
	var respData map[string]string
	err = client.Send(ctx, OpHealth, nil, &respData)
	if err != nil {
		t.Errorf("Send with response data failed: %v", err)
	}

	if respData["result"] != "success" {
		t.Errorf("expected result 'success', got '%s'", respData["result"])
	}
}

// TestClientSendWithBothData tests Send with both request and response data
func TestClientSendWithBothData(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	// Create a handler that returns encoded response data
	respPayload, _ := EncodePayload(map[string]string{"echo": "data"})
	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: respPayload,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with both request and response data
	reqData := map[string]string{"input": "test"}
	var respData map[string]string
	err = client.Send(ctx, OpHealth, reqData, &respData)
	if err != nil {
		t.Errorf("Send with both data failed: %v", err)
	}

	if respData["echo"] != "data" {
		t.Errorf("expected echo 'data', got '%s'", respData["echo"])
	}
}

// TestClientSendEncodeError tests Send when encoding fails
func TestClientSendEncodeError(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: nil,
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with unencodable data (channel is unencodable)
	reqData := make(chan int)
	err = client.Send(ctx, OpHealth, reqData, nil)
	if err == nil {
		t.Error("expected encode error, got nil")
	}
}

// TestClientSendDecodeError tests Send when decoding fails
func TestClientSendDecodeError(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	// Create a handler that returns invalid payload for decoding
	handler := &mockHandler{
		response: &Response{
			Status:  StatusOK,
			Payload: []byte("invalid msgpack data"),
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send with response data that will fail to decode
	var respData map[string]string
	err = client.Send(ctx, OpHealth, nil, &respData)
	if err == nil {
		t.Error("expected decode error, got nil")
	}
}

// TestClientSendRequestError tests Send when SendRequest fails
func TestClientSendRequestError(t *testing.T) {
	// Find an available port
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("failed to get available port: %v", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create and start server
	serverTLSConfig := generateTestTLSConfig()
	serverConfig := &ServerConfig{
		ListenAddr: listenAddr,
		TLSConfig:  serverTLSConfig,
	}

	// Create a handler that returns error status
	handler := &mockHandler{
		response: &Response{
			Status:  StatusInternalError,
			Payload: []byte("internal error"),
		},
	}

	server, err := NewServer(serverConfig, WithHandler(handler))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	clientTLSConfig := generateTestClientTLSConfig(serverTLSConfig)
	clientConfig := &ClientConfig{
		ServerAddr: listenAddr,
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLSConfig,
	}

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test Send when server returns error
	err = client.Send(ctx, OpHealth, nil, nil)
	if err == nil {
		t.Error("expected error from server, got nil")
	}
}
