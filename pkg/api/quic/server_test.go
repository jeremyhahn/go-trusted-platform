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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// generateTestTLSConfig creates a self-signed TLS configuration for testing.
// The certificate includes IP SANs for 127.0.0.1 and ::1 so that clients
// connecting by IP address pass TLS verification without InsecureSkipVerify.
func generateTestTLSConfig() *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"trusted-platform"},
		MinVersion:   tls.VersionTLS13,
	}
}

// generateTestClientTLSConfig creates a client TLS configuration that trusts
// the self-signed certificate from the given server TLS config. This allows
// proper certificate verification without InsecureSkipVerify.
func generateTestClientTLSConfig(serverTLSConfig *tls.Config) *tls.Config {
	serverCertDER := serverTLSConfig.Certificates[0].Certificate[0]
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		panic(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(serverCert)
	return &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"trusted-platform"},
	}
}

func TestNewServerNilConfig(t *testing.T) {
	// NewServer should use DefaultServerConfig when nil is passed
	// This will fail validation because TLSConfig is nil
	_, err := NewServer(nil)

	if err == nil {
		t.Error("expected error for nil TLSConfig")
		return
	}

	// Verify it's a config validation error
	var invalidConfigErr quicwire.ErrInvalidConfig
	if !errors.As(err, &invalidConfigErr) {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestNewServerValidConfig(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server == nil {
		t.Fatal("expected non-nil server")
	}

	// Verify server is not running initially
	if server.IsRunning() {
		t.Error("expected server to not be running initially")
	}
}

func TestNewServerInvalidConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     *ServerConfig
		errorField string
	}{
		{
			name: "empty listen address",
			config: &ServerConfig{
				ListenAddr: "",
				TLSConfig:  generateTestTLSConfig(),
			},
			errorField: "ListenAddr",
		},
		{
			name: "nil TLS config",
			config: &ServerConfig{
				ListenAddr: "127.0.0.1:0",
				TLSConfig:  nil,
			},
			errorField: "TLSConfig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.config)

			if err == nil {
				t.Error("expected error, got nil")
				return
			}

			var invalidConfigErr quicwire.ErrInvalidConfig
			if !errors.As(err, &invalidConfigErr) {
				t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
				return
			}

			if invalidConfigErr.Field != tt.errorField {
				t.Errorf("expected error field '%s', got '%s'", tt.errorField, invalidConfigErr.Field)
			}
		})
	}
}

func TestNewServerWithOptions(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	logger := logging.NewLogger(slog.LevelDebug, io.Discard)

	server, err := NewServer(config, WithLogger(logger))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

// mockHandler implements Handler for testing
type mockHandler struct {
	response *quicwire.Response
}

func (h *mockHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.response != nil {
		return h.response
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: []byte("mock response"),
	}
}

func TestNewServerWithHandler(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	handler := &mockHandler{
		response: &quicwire.Response{
			Status:  quicwire.StatusOK,
			Payload: []byte("test"),
		},
	}

	server, err := NewServer(config, WithHandler(handler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server == nil {
		t.Fatal("expected non-nil server")
	}

	if server.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestServerListenAddr(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:9444",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server.ListenAddr() != "127.0.0.1:9444" {
		t.Errorf("expected listen address '127.0.0.1:9444', got '%s'", server.ListenAddr())
	}
}

// A server configured on port 0 reports the port it bound while it runs,
// so a caller can dial it, and the configured address once it stops.
func TestServerListenAddr_ReportsTheBoundPortWhileRunning(t *testing.T) {
	server, err := NewServer(&ServerConfig{ListenAddr: "127.0.0.1:0", TLSConfig: generateTestTLSConfig()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	host, port, err := net.SplitHostPort(server.ListenAddr())
	if err != nil {
		t.Fatalf("ListenAddr() = %q: %v", server.ListenAddr(), err)
	}
	if host != "127.0.0.1" || port == "0" {
		t.Errorf("ListenAddr() = %q, want 127.0.0.1 with the bound port", server.ListenAddr())
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}
	if server.ListenAddr() != "127.0.0.1:0" {
		t.Errorf("ListenAddr() after Stop = %q, want the configured 127.0.0.1:0", server.ListenAddr())
	}
}

// A server marked running before it has a listener (the health checker's
// tests do this) reports the configured address instead of panicking.
func TestServerListenAddr_RunningWithoutListenerReportsConfiguredAddr(t *testing.T) {
	server, err := NewServer(&ServerConfig{ListenAddr: "127.0.0.1:9999", TLSConfig: generateTestTLSConfig()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server.running.Store(true)

	if got := server.ListenAddr(); got != "127.0.0.1:9999" {
		t.Errorf("ListenAddr() = %q, want the configured 127.0.0.1:9999", got)
	}
}

func TestServerIsRunningInitialState(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server.IsRunning() {
		t.Error("expected server to not be running initially")
	}
}

func TestServerStopNotRunning(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = server.Stop()

	if !errors.Is(err, ErrServerNotRunning) {
		t.Errorf("expected ErrServerNotRunning, got %v", err)
	}
}

func TestServerGetMetricsInitial(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	metrics := server.GetMetrics()

	if metrics == nil {
		t.Fatal("expected non-nil metrics")
	}

	// Verify expected metrics keys
	expectedKeys := []string{
		"active_connections",
		"active_streams",
		"total_requests",
		"total_errors",
		"running",
	}

	for _, key := range expectedKeys {
		if _, ok := metrics[key]; !ok {
			t.Errorf("expected metrics to contain key '%s'", key)
		}
	}

	// Verify initial values
	if metrics["active_connections"].(int64) != 0 {
		t.Errorf("expected active_connections 0, got %d", metrics["active_connections"])
	}

	if metrics["active_streams"].(int64) != 0 {
		t.Errorf("expected active_streams 0, got %d", metrics["active_streams"])
	}

	if metrics["total_requests"].(uint64) != 0 {
		t.Errorf("expected total_requests 0, got %d", metrics["total_requests"])
	}

	if metrics["total_errors"].(uint64) != 0 {
		t.Errorf("expected total_errors 0, got %d", metrics["total_errors"])
	}

	if metrics["running"].(bool) != false {
		t.Error("expected running to be false")
	}
}

func TestWithHandlerOption(t *testing.T) {
	handler := &mockHandler{}
	opt := WithHandler(handler)

	server := &Server{}
	opt(server)

	if server.handler != handler {
		t.Error("expected handler to be set")
	}
}

func TestWithLoggerOption(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)
	opt := WithLogger(logger)

	server := &Server{}
	opt(server)

	if server.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestServerDefaultLogger(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	// Create without providing a logger option
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify a default logger was assigned
	if server.logger == nil {
		t.Error("expected default logger to be assigned")
	}
}

func TestHandlerInterface(t *testing.T) {
	// Verify mockHandler implements Handler interface
	var _ Handler = (*mockHandler)(nil)
}

func TestServerConfigFields(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr:                 "127.0.0.1:9444",
		TLSConfig:                  tlsConfig,
		MaxStreams:                 500,
		MaxIdleTimeout:             60 * time.Second,
		MaxIncomingStreams:         500,
		MaxIncomingUniStreams:      50,
		KeepAlivePeriod:            10 * time.Second,
		HandshakeIdleTimeout:       3 * time.Second,
		MaxReceiveBufferSize:       2 * 1024 * 1024,
		InitialStreamReceiveWindow: 256 * 1024,
		MaxStreamReceiveWindow:     4 * 1024 * 1024,
		EnableMetrics:              false,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server.config.MaxStreams != 500 {
		t.Errorf("expected MaxStreams 500, got %d", server.config.MaxStreams)
	}

	if server.config.MaxIdleTimeout != 60*time.Second {
		t.Errorf("expected MaxIdleTimeout 60s, got %v", server.config.MaxIdleTimeout)
	}
}

func TestServerMultipleStopCalls(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First stop should return ErrServerNotRunning
	err = server.Stop()
	if !errors.Is(err, ErrServerNotRunning) {
		t.Errorf("expected ErrServerNotRunning, got %v", err)
	}

	// Second stop should also return ErrServerNotRunning
	err = server.Stop()
	if !errors.Is(err, ErrServerNotRunning) {
		t.Errorf("expected ErrServerNotRunning, got %v", err)
	}
}

func TestServerStats(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats := server.Stats()

	if stats == nil {
		t.Fatal("expected non-nil stats")
	}

	// Verify initial stats values
	if stats.ActiveConnections != 0 {
		t.Errorf("expected ActiveConnections 0, got %d", stats.ActiveConnections)
	}

	if stats.TotalConnections != 0 {
		t.Errorf("expected TotalConnections 0, got %d", stats.TotalConnections)
	}

	if stats.ActiveStreams != 0 {
		t.Errorf("expected ActiveStreams 0, got %d", stats.ActiveStreams)
	}

	if stats.RequestsHandled != 0 {
		t.Errorf("expected RequestsHandled 0, got %d", stats.RequestsHandled)
	}

	if stats.Errors != 0 {
		t.Errorf("expected Errors 0, got %d", stats.Errors)
	}
}

func TestServerStatsStruct(t *testing.T) {
	stats := &ServerStats{
		ActiveConnections: 5,
		TotalConnections:  100,
		ActiveStreams:     10,
		RequestsHandled:   1000,
		Errors:            5,
	}

	if stats.ActiveConnections != 5 {
		t.Errorf("expected ActiveConnections 5, got %d", stats.ActiveConnections)
	}

	if stats.TotalConnections != 100 {
		t.Errorf("expected TotalConnections 100, got %d", stats.TotalConnections)
	}

	if stats.ActiveStreams != 10 {
		t.Errorf("expected ActiveStreams 10, got %d", stats.ActiveStreams)
	}

	if stats.RequestsHandled != 1000 {
		t.Errorf("expected RequestsHandled 1000, got %d", stats.RequestsHandled)
	}

	if stats.Errors != 5 {
		t.Errorf("expected Errors 5, got %d", stats.Errors)
	}
}

func TestServerWithMultipleOptions(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	logger := logging.NewLogger(slog.LevelDebug, io.Discard)
	handler := &mockHandler{}

	server, err := NewServer(config, WithLogger(logger), WithHandler(handler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if server.logger != logger {
		t.Error("expected logger to be set")
	}

	if server.handler != handler {
		t.Error("expected handler to be set")
	}
}

func TestGetMetricsContainsTotalConnections(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	metrics := server.GetMetrics()

	// Verify total_connections key exists
	if _, ok := metrics["total_connections"]; !ok {
		t.Error("expected metrics to contain key 'total_connections'")
	}

	if metrics["total_connections"].(uint64) != 0 {
		t.Errorf("expected total_connections 0, got %d", metrics["total_connections"])
	}
}

// TestServerStartAndStop tests the server Start and Stop lifecycle
func TestServerStartAndStop(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0", // Use port 0 for dynamic port allocation
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Start the server
	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Verify server is running
	if !server.IsRunning() {
		t.Error("expected server to be running after Start")
	}

	// Try to start again - should return ErrServerRunning
	err = server.Start()
	if !errors.Is(err, ErrServerRunning) {
		t.Errorf("expected ErrServerRunning, got %v", err)
	}

	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}

	// Verify server is not running
	if server.IsRunning() {
		t.Error("expected server to not be running after Stop")
	}
}

// TestServerStartInvalidAddress tests starting server with invalid address
func TestServerStartInvalidAddress(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "invalid-address-format",
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	// Start should fail with invalid address
	err = server.Start()
	if err == nil {
		// If it somehow succeeded, stop it
		server.Stop()
		t.Error("expected error for invalid address, got nil")
	}
}

// TestServerStartPrivilegedPort tests starting server on privileged port
func TestServerStartPrivilegedPort(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:80", // Privileged port requiring root
		TLSConfig:  tlsConfig,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	// Start should fail without root privileges
	err = server.Start()
	if err == nil {
		// If it somehow succeeded (running as root), stop it
		server.Stop()
	}
	// We don't check the specific error since behavior varies by OS and permissions
}

// TestServerConfigValidationMaxStreams tests MaxStreams default value
func TestServerConfigValidationMaxStreams(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
		MaxStreams: 0, // Should default to 1000
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams to default to 1000, got %d", config.MaxStreams)
	}
}

// TestServerConfigValidationMaxIdleTimeout tests MaxIdleTimeout default value
func TestServerConfigValidationMaxIdleTimeout(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSConfig:      tlsConfig,
		MaxIdleTimeout: 0, // Should default to 30 seconds
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout to default to 30s, got %v", config.MaxIdleTimeout)
	}
}

// TestServerConfigValidationNegativeMaxStreams tests negative MaxStreams default
func TestServerConfigValidationNegativeMaxStreams(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
		MaxStreams: -100, // Should default to 1000
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams to default to 1000, got %d", config.MaxStreams)
	}
}

// TestServerConfigValidationNegativeMaxIdleTimeout tests negative MaxIdleTimeout default
func TestServerConfigValidationNegativeMaxIdleTimeout(t *testing.T) {
	tlsConfig := generateTestTLSConfig()
	config := &ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSConfig:      tlsConfig,
		MaxIdleTimeout: -5 * time.Second, // Should default to 30 seconds
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout to default to 30s, got %v", config.MaxIdleTimeout)
	}
}

// TestDefaultServerConfigValues tests DefaultServerConfig function
func TestDefaultServerConfigValues(t *testing.T) {
	config := DefaultServerConfig()

	if config.ListenAddr != "0.0.0.0:9444" {
		t.Errorf("expected ListenAddr '0.0.0.0:9444', got '%s'", config.ListenAddr)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams 1000, got %d", config.MaxStreams)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout 30s, got %v", config.MaxIdleTimeout)
	}

	if config.MaxIncomingStreams != 1000 {
		t.Errorf("expected MaxIncomingStreams 1000, got %d", config.MaxIncomingStreams)
	}

	if config.MaxIncomingUniStreams != 100 {
		t.Errorf("expected MaxIncomingUniStreams 100, got %d", config.MaxIncomingUniStreams)
	}

	if config.KeepAlivePeriod != 15*time.Second {
		t.Errorf("expected KeepAlivePeriod 15s, got %v", config.KeepAlivePeriod)
	}

	if config.HandshakeIdleTimeout != 5*time.Second {
		t.Errorf("expected HandshakeIdleTimeout 5s, got %v", config.HandshakeIdleTimeout)
	}

	if config.EnableMetrics != true {
		t.Error("expected EnableMetrics to be true")
	}
}
