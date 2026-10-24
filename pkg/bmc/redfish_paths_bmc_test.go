package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// errRedfishPathsProvider is the failure the TLS provider reports.
var errRedfishPathsProvider = errors.New("trust anchor unavailable")

// redfishPathsTransport serves handler over TLS and returns a transport
// pointed at it, counting the requests that reach the server.
func redfishPathsTransport(t *testing.T, handler http.HandlerFunc) (*redfishTransport, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return newTestRedfishClient(t, server).transport, &hits
}

// failingTLSConfig is a valid Redfish config whose TLS provider fails.
func failingTLSConfig() *Config {
	return &Config{
		Address:  "10.0.0.9",
		Port:     443,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolRedfish,
		TLS:      &fakeTLSProvider{err: errRedfishPathsProvider},
	}
}

func TestRedfishPaths_DoRequestRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   any
	}{
		{"unencodable body", http.MethodPost, map[string]any{"ch": make(chan int)}},
		{"invalid method", "BAD METHOD", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, hits := redfishPathsTransport(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			resp, err := transport.doRequest(context.Background(), tt.method, "/redfish/v1/", tt.body)
			var reqErr ErrRedfishRequest
			if !errors.As(err, &reqErr) || reqErr.Method != tt.method || reqErr.Path != "/redfish/v1/" {
				t.Fatalf("error = %v, want ErrRedfishRequest naming %s /redfish/v1/", err, tt.method)
			}
			if resp != nil {
				t.Error("a rejected request must not return a response")
			}
			if hits.Load() != 0 {
				t.Errorf("a rejected request reached the BMC %d times", hits.Load())
			}
		})
	}
}

func TestRedfishPaths_DoJSONMalformedBody(t *testing.T) {
	transport, _ := redfishPathsTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Members": 5}`))
	})
	var out redfishCollection
	status, err := transport.doJSON(context.Background(), http.MethodGet, "/redfish/v1/Managers", nil, &out)
	var reqErr ErrRedfishRequest
	if !errors.As(err, &reqErr) {
		t.Fatalf("error = %v, want ErrRedfishRequest", err)
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("error = %v, want the JSON decode cause kept", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want the 200 the BMC sent", status)
	}
}

func TestRedfishPaths_TLSProviderFailure(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
	}{
		{"newRedfishTransport", func() error {
			_, err := newRedfishTransport(ctx, failingTLSConfig(), slog.Default())
			return err
		}},
		{"redfishCertManager.GetWebCertificate", func() error {
			_, err := (&redfishCertManager{cfg: failingTLSConfig()}).GetWebCertificate(ctx)
			return err
		}},
		{"AutoCertManager.GetWebCertificate", func() error {
			_, err := (&AutoCertManager{cfg: failingTLSConfig()}).GetWebCertificate(ctx)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			var providerErr ErrTLSProvider
			if !errors.As(err, &providerErr) || !errors.Is(err, errRedfishPathsProvider) {
				t.Fatalf("error = %v, want ErrTLSProvider wrapping the provider failure", err)
			}
			if !strings.Contains(providerErr.Endpoint, "10.0.0.9") {
				t.Errorf("endpoint = %q, want the BMC address", providerErr.Endpoint)
			}
		})
	}
}

func TestRedfishPaths_MaxUsers(t *testing.T) {
	t.Run("clamps past 255 accounts", func(t *testing.T) {
		transport, _ := redfishPathsTransport(t, func(w http.ResponseWriter, _ *http.Request) {
			members := make([]redfishRef, 300)
			for i := range members {
				members[i] = redfishRef{ODataID: redfishAccountsCollection + "/x"}
			}
			writeJSON(w, map[string]any{"Members": members})
		})
		m := &redfishUserManager{transport: transport, logger: slog.Default()}
		if got, err := m.MaxUsers(context.Background()); err != nil || got != 255 {
			t.Fatalf("MaxUsers = %d, %v; want 255", got, err)
		}
	})
	t.Run("collection error", func(t *testing.T) {
		transport, _ := redfishPathsTransport(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		m := &redfishUserManager{transport: transport, logger: slog.Default()}
		got, err := m.MaxUsers(context.Background())
		var reqErr ErrRedfishRequest
		if !errors.As(err, &reqErr) || got != 0 {
			t.Fatalf("MaxUsers = %d, %v; want 0 and ErrRedfishRequest", got, err)
		}
	})
}

func TestRedfishPaths_PathsEmptyBeforeDiscovery(t *testing.T) {
	c := &redfishClient{}
	if got := c.getSystemPath(); got != "" {
		t.Errorf("system path = %q, want empty before discovery", got)
	}
	if got := c.getResetActionPath(); got != "" {
		t.Errorf("reset action path = %q, want empty before discovery", got)
	}
}

func TestRedfishPaths_StandardBackendRejectsNilSpec(t *testing.T) {
	if (&vmediaRedfishStd{}).Supports(nil) {
		t.Error("a nil media spec must not be supported")
	}
}

func TestRedfishPaths_InferProtocol(t *testing.T) {
	tests := []struct {
		name      string
		spec      MediaSpec
		want      MediaProtocol
		badReason string
	}{
		{"explicit protocol kept", MediaSpec{Protocol: MediaProtocolCIFS}, MediaProtocolCIFS, ""},
		{"scheme is case-insensitive", MediaSpec{URL: "HTTPS://10.0.0.5/boot.iso"}, MediaProtocolHTTPS, ""},
		{"empty URL", MediaSpec{}, "", "must not be empty"},
		{"malformed URL", MediaSpec{URL: "http://[::1/boot.iso"}, "", "malformed"},
		{"unknown scheme", MediaSpec{URL: "ftp://10.0.0.5/boot.iso"}, "", "unrecognized scheme: ftp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			err := spec.inferProtocol()
			if tt.badReason == "" {
				if err != nil || spec.Protocol != tt.want {
					t.Fatalf("inferProtocol = %v, protocol %q; want %q", err, spec.Protocol, tt.want)
				}
				return
			}
			var specErr ErrVirtualMediaInvalidSpec
			if !errors.As(err, &specErr) || specErr.Field != "URL" || !strings.Contains(specErr.Reason, tt.badReason) {
				t.Fatalf("error = %v, want an invalid URL naming %q", err, tt.badReason)
			}
		})
	}
}

func TestRedfishPaths_ServiceKeepsTheFirstCachedClient(t *testing.T) {
	const profileID = 7
	winner := NewMockClient()
	loser := NewMockClient()
	loser.CloseErr = errors.New("session already gone")

	var svc *Service
	factory := &MockClientFactory{ClientFn: func(*Config) (Client, error) {
		// A concurrent caller caches its client while this one is built.
		svc.clients.Store(uint64(profileID), winner)
		return loser, nil
	}}
	svc, err := NewService(ServiceParams{
		Factory:  factory,
		Profiles: &mockProfileStore{configs: map[uint64]*Config{profileID: {Address: "10.0.0.7"}}},
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if err := svc.PowerOn(context.Background(), profileID); err != nil {
		t.Fatalf("PowerOn: %v", err)
	}
	if winner.PowerOnCalls() != 1 || loser.PowerOnCalls() != 0 {
		t.Errorf("power-on calls winner=%d loser=%d, want the cached client used", winner.PowerOnCalls(), loser.PowerOnCalls())
	}
	if loser.CloseCalls() != 1 {
		t.Errorf("duplicate client closed %d times, want 1", loser.CloseCalls())
	}
}
