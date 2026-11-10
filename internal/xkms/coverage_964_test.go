package xkms

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// stubServicer satisfies XKMSServicer for the embedded client constructor,
// which only stores the service; no method is called by these tests.
type stubServicer struct {
	XKMSServicer
}

// newRawAdapter builds an adapter around cfg without Validate, so a test can
// reach the per-transport constructors with configurations Validate rejects.
func newRawAdapter(cfg *Config) *Adapter {
	return &Adapter{
		config: cfg,
		logger: logging.NewLogger(slog.LevelError, nil),
	}
}

func TestCoverage964_CreateClient_RemoteTransports(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		address   string
		socket    string
	}{
		{name: "unix", transport: TransportUnix, socket: "/run/test-xkms.sock"},
		{name: "grpc", transport: TransportGRPC, address: "127.0.0.1:10443"},
		{name: "rest", transport: TransportREST, address: "https://127.0.0.1:8443"},
		{name: "quic", transport: TransportQUIC, address: "127.0.0.1:9444"},
		{name: "mcp", transport: TransportMCP, address: "http://127.0.0.1:9445"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newRawAdapter(&Config{
				Transport:  tt.transport,
				Address:    tt.address,
				UnixSocket: tt.socket,
			})
			client, err := a.createClient(nil)
			if err != nil {
				t.Fatalf("createClient(%s) error = %v", tt.transport, err)
			}
			if client == nil {
				t.Fatalf("createClient(%s) returned a nil client", tt.transport)
			}
		})
	}
}

func TestCoverage964_CreateClient_MissingEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		want      error
	}{
		{name: "unix", transport: TransportUnix, want: ErrMissingUnixSocket},
		{name: "grpc", transport: TransportGRPC, want: ErrMissingAddress},
		{name: "rest", transport: TransportREST, want: ErrMissingAddress},
		{name: "quic", transport: TransportQUIC, want: ErrMissingAddress},
		{name: "mcp", transport: TransportMCP, want: ErrMissingAddress},
		{name: "embedded", transport: TransportEmbedded, want: ErrEmbeddedServiceRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newRawAdapter(&Config{Transport: tt.transport})
			client, err := a.createClient(nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("createClient(%s) error = %v, want %v", tt.transport, err, tt.want)
			}
			if client != nil {
				t.Fatalf("createClient(%s) returned a client alongside an error", tt.transport)
			}
		})
	}
}

func TestCoverage964_CreateClient_UnsupportedTransport(t *testing.T) {
	a := newRawAdapter(&Config{Transport: Transport("carrier-pigeon")})
	_, err := a.createClient(nil)
	var unsupported ErrUnsupportedTransport
	if !errors.As(err, &unsupported) {
		t.Fatalf("createClient error = %v, want ErrUnsupportedTransport", err)
	}
	if unsupported.Transport != "carrier-pigeon" {
		t.Fatalf("ErrUnsupportedTransport.Transport = %q, want carrier-pigeon", unsupported.Transport)
	}
}

func TestCoverage964_ApplyTLSConfig(t *testing.T) {
	t.Run("nil TLS leaves the backend config untouched", func(t *testing.T) {
		a := newRawAdapter(&Config{Transport: TransportGRPC})
		cfg := &xkmssdk.BackendConfig{}
		a.applyTLSConfig(cfg)
		if cfg.TLSEnabled || cfg.TLSConfig != nil || cfg.TLSCAFile != "" {
			t.Fatalf("applyTLSConfig without TLS changed the config: %+v", cfg)
		}
	})

	t.Run("TLS settings are copied with a TLS 1.3 floor", func(t *testing.T) {
		a := newRawAdapter(&Config{
			Transport: TransportGRPC,
			TLS: &TLSConfig{
				CACert:     "/etc/xkms/ca.pem",
				ClientCert: "/etc/xkms/client.pem",
				ClientKey:  "/etc/xkms/client.key",
			},
		})
		cfg := &xkmssdk.BackendConfig{}
		a.applyTLSConfig(cfg)
		if !cfg.TLSEnabled {
			t.Fatal("TLSEnabled = false, want true")
		}
		if cfg.TLSCAFile != "/etc/xkms/ca.pem" || cfg.TLSCertFile != "/etc/xkms/client.pem" ||
			cfg.TLSKeyFile != "/etc/xkms/client.key" {
			t.Fatalf("TLS files not copied: ca=%q cert=%q key=%q", cfg.TLSCAFile, cfg.TLSCertFile, cfg.TLSKeyFile)
		}
		if cfg.TLSConfig == nil {
			t.Fatal("TLSConfig = nil, want MinVersion TLS 1.3")
		}
		if cfg.TLSConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("TLSConfig.MinVersion = %#x, want %#x", cfg.TLSConfig.MinVersion, tls.VersionTLS13)
		}
	})
}

func TestCoverage964_Start_EmbeddedSucceeds(t *testing.T) {
	a, err := NewAdapter(&Config{Transport: TransportEmbedded}, logging.NewLogger(slog.LevelError, nil))
	if err != nil {
		t.Fatalf("NewAdapter error = %v", err)
	}
	if err := a.Start(context.Background(), &stubServicer{}); err != nil {
		t.Fatalf("Start error = %v", err)
	}
	if !a.IsStarted() {
		t.Fatal("IsStarted = false after a successful Start")
	}
	if a.Client() == nil {
		t.Fatal("Client = nil after a successful Start")
	}
}

func TestCoverage964_Start_RemoteConnectFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent.sock")
	a, err := NewAdapter(UnixConfig(socket), logging.NewLogger(slog.LevelError, nil))
	if err != nil {
		t.Fatalf("NewAdapter error = %v", err)
	}
	err = a.Start(context.Background(), nil)
	var connErr ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("Start error = %v, want ErrConnectionFailed", err)
	}
	if connErr.Transport != TransportUnix || connErr.Cause == nil {
		t.Fatalf("ErrConnectionFailed = %+v, want unix transport with a cause", connErr)
	}
	if a.IsStarted() {
		t.Fatal("IsStarted = true after a failed connect")
	}
}

func TestCoverage964_Start_CreateClientErrorPropagates(t *testing.T) {
	a := newRawAdapter(&Config{Transport: TransportGRPC})
	err := a.Start(context.Background(), nil)
	if !errors.Is(err, ErrMissingAddress) {
		t.Fatalf("Start error = %v, want ErrMissingAddress", err)
	}
	if a.IsStarted() {
		t.Fatal("IsStarted = true after createClient failed")
	}
}
