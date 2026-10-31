package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	stepsManagerPath = "/redfish/v1/Managers/1"
	stepsCertPath    = stepsManagerPath + redfishHTTPSCertSuffix
	stepsResetPath   = stepsManagerPath + "/Actions/Manager.Reset"
)

var (
	errFakeBMCRebooting = errors.New("fake BMC: web server restarting")
	errFakeResolverDown = errors.New("fake TLS provider: resolver down")
)

// restoreStepsBMC is a Redfish BMC on which each step RestoreFactoryCertificate
// takes after reading the current certificate can be made to fail: manager
// discovery, the reset, the web server coming back, and the new certificate.
type restoreStepsBMC struct {
	mu     sync.Mutex
	server *httptest.Server

	root    redfishServiceRoot
	members []redfishRef
	manager redfishManagerResource
	// status forces an HTTP status on a path, whatever the method.
	status map[string]int
	// handshakesAfterReset is how many TLS handshakes the BMC completes
	// once it has been reset; a negative value completes every one.
	handshakesAfterReset int
	// factory, when set, is the certificate presented after the reset.
	factory *tls.Certificate

	reset      bool
	afterReset int
	requests   []string
}

func newRestoreStepsBMC(t *testing.T) *restoreStepsBMC {
	t.Helper()
	b := &restoreStepsBMC{
		root:    redfishServiceRoot{Managers: redfishRef{ODataID: "/redfish/v1/Managers"}},
		members: []redfishRef{{ODataID: stepsManagerPath}},
		manager: redfishManagerResource{
			ODataID: stepsManagerPath,
			ID:      "1",
			Actions: redfishManagerActions{Reset: struct {
				Target string `json:"target"`
			}{Target: stepsResetPath}},
		},
		status:               map[string]int{},
		handshakesAfterReset: -1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /redfish/v1/{$}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, b.root)
	})
	mux.HandleFunc("GET /redfish/v1/Managers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: b.members})
	})
	mux.HandleFunc("GET "+stepsManagerPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, b.manager)
	})
	mux.HandleFunc("DELETE "+stepsCertPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST "+stepsResetPath, func(w http.ResponseWriter, _ *http.Request) {
		b.mu.Lock()
		b.reset = true
		b.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	b.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.requests = append(b.requests, r.Method+" "+r.URL.Path)
		status, forced := b.status[r.URL.Path]
		b.mu.Unlock()
		if forced {
			http.Error(w, "forced failure", status)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	b.server.TLS = &tls.Config{GetConfigForClient: b.configForClient}
	// The refused handshakes are the point of the fake; keep them out of
	// the test output.
	b.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	b.server.StartTLS()
	t.Cleanup(b.server.Close)
	return b
}

// configForClient models the web server restart: after the reset it completes
// handshakesAfterReset handshakes, presenting the factory certificate when one
// is set, and refuses the rest.
func (b *restoreStepsBMC) configForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.reset {
		return nil, nil
	}
	b.afterReset++
	if b.handshakesAfterReset >= 0 && b.afterReset > b.handshakesAfterReset {
		return nil, errFakeBMCRebooting
	}
	if b.factory == nil {
		return nil, nil
	}
	return &tls.Config{Certificates: []tls.Certificate{*b.factory}, MinVersion: tls.VersionTLS12}, nil
}

func (b *restoreStepsBMC) sawRequest(req string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Contains(b.requests, req)
}

// cfg points a Config at the BMC through provider, which trusts both the
// server certificate and the factory one.
func (b *restoreStepsBMC) cfg(t *testing.T, provider *countingTLSProvider) *Config {
	t.Helper()
	u, err := url.Parse(b.server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(b.server.Certificate())
	if b.factory != nil {
		pool.AddCert(b.factory.Leaf)
	}
	provider.cfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &Config{
		Address:  u.Hostname(),
		Port:     port,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolRedfish,
		TLS:      provider,
	}
}

// countingTLSProvider hands out its config until call failFrom (1-based),
// then fails every call. A zero failFrom never fails.
type countingTLSProvider struct {
	cfg      *tls.Config
	failFrom int32
	calls    atomic.Int32
}

func (p *countingTLSProvider) TLSConfig(context.Context, string) (*tls.Config, error) {
	n := p.calls.Add(1)
	if p.failFrom > 0 && n >= p.failFrom {
		return nil, errFakeResolverDown
	}
	return p.cfg.Clone(), nil
}

func TestRedfishCert_RestoreFactory_StepFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(b *restoreStepsBMC)
		// failTLSAt, when set, fails the TLS provider on that call after
		// the manager is built: 1 is the first certificate read, 2 the
		// readiness wait.
		failTLSAt int32
		// wantDelete and wantReset are whether the certificate DELETE
		// and the manager reset reached the BMC.
		wantDelete bool
		wantReset  bool
		check      func(t *testing.T, err error)
	}{
		{
			name:  "service root fails",
			setup: func(b *restoreStepsBMC) { b.status["/redfish/v1/"] = http.StatusInternalServerError },
			check: wantDiscoveryErr("service root"),
		},
		{
			name:  "service root has no Managers link",
			setup: func(b *restoreStepsBMC) { b.root = redfishServiceRoot{} },
			check: wantDiscoveryErr("managers"),
		},
		{
			name:  "managers collection fails",
			setup: func(b *restoreStepsBMC) { b.status["/redfish/v1/Managers"] = http.StatusServiceUnavailable },
			check: wantDiscoveryErr("managers collection"),
		},
		{
			name:  "managers collection is empty",
			setup: func(b *restoreStepsBMC) { b.members = nil },
			check: wantDiscoveryErr("managers collection"),
		},
		{
			name:  "manager resource fails",
			setup: func(b *restoreStepsBMC) { b.status[stepsManagerPath] = http.StatusNotFound },
			check: wantDiscoveryErr("manager"),
		},
		{
			name:       "reset is rejected",
			setup:      func(b *restoreStepsBMC) { b.status[stepsResetPath] = http.StatusInternalServerError },
			wantDelete: true,
			wantReset:  true,
			check: func(t *testing.T, err error) {
				var reqErr ErrRedfishRequest
				if !errors.As(err, &reqErr) || reqErr.StatusCode != http.StatusInternalServerError {
					t.Fatalf("error = %v, want ErrRedfishRequest with status 500", err)
				}
			},
		},
		{
			name:       "web server never comes back",
			setup:      func(b *restoreStepsBMC) { b.handshakesAfterReset = 0 },
			wantDelete: true,
			wantReset:  true,
			check: func(t *testing.T, err error) {
				var timeout ErrBMCResetTimeout
				if !errors.As(err, &timeout) {
					t.Fatalf("error = %v, want ErrBMCResetTimeout", err)
				}
				if timeout.Cause == nil {
					t.Error("ErrBMCResetTimeout carries no cause from the last handshake")
				}
			},
		},
		{
			name:       "TLS provider fails before the readiness wait",
			setup:      func(*restoreStepsBMC) {},
			failTLSAt:  2,
			wantDelete: true,
			wantReset:  true,
			check: func(t *testing.T, err error) {
				var provErr ErrTLSProvider
				if !errors.As(err, &provErr) || !errors.Is(err, errFakeResolverDown) {
					t.Fatalf("error = %v, want ErrTLSProvider wrapping the provider failure", err)
				}
			},
		},
		{
			name: "new certificate cannot be read",
			// The readiness wait completes one handshake; the BMC drops
			// again before the certificate is re-read.
			setup:      func(b *restoreStepsBMC) { b.handshakesAfterReset = 1 },
			wantDelete: true,
			wantReset:  true,
			check: func(t *testing.T, err error) {
				var connErr ErrConnectionFailed
				if !errors.As(err, &connErr) {
					t.Fatalf("error = %v, want ErrConnectionFailed", err)
				}
				if connErr.Address == "" || !strings.Contains(err.Error(), "new cert could not be read") {
					t.Errorf("error = %v, want the address and the failed re-read named", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newRestoreStepsBMC(t)
			tt.setup(b)
			provider := &countingTLSProvider{}
			m := newFastCertManager(t, b.cfg(t, provider))
			defer m.Close()
			if tt.failTLSAt > 0 {
				provider.failFrom = provider.calls.Load() + tt.failTLSAt
			}

			got, err := m.RestoreFactoryCertificate(context.Background())
			if got != nil {
				t.Errorf("returned certificate %v on a failed restore", got.Subject)
			}
			tt.check(t, err)
			if deleted := b.sawRequest("DELETE " + stepsCertPath); deleted != tt.wantDelete {
				t.Errorf("certificate DELETE sent = %v, want %v", deleted, tt.wantDelete)
			}
			if reset := b.sawRequest("POST " + stepsResetPath); reset != tt.wantReset {
				t.Errorf("reset POST sent = %v, want %v", reset, tt.wantReset)
			}
		})
	}
}

func wantDiscoveryErr(resource string) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var disc ErrRedfishDiscovery
		if !errors.As(err, &disc) {
			t.Fatalf("error = %v, want ErrRedfishDiscovery", err)
		}
		if disc.Resource != resource {
			t.Errorf("discovery resource = %q, want %q", disc.Resource, resource)
		}
	}
}

// TestRedfishCert_RestoreFactory_DerivesPathsFromCollection pins the fallbacks
// for a manager that names neither itself nor its reset action: the
// certificate and reset paths are built from the collection member.
func TestRedfishCert_RestoreFactory_DerivesPathsFromCollection(t *testing.T) {
	b := newRestoreStepsBMC(t)
	b.manager = redfishManagerResource{ID: "1"}
	factory := selfSignedCert(t, "bmc-factory-default", 7)
	b.factory = &factory
	m := newFastCertManager(t, b.cfg(t, &countingTLSProvider{}))
	defer m.Close()

	got, err := m.RestoreFactoryCertificate(context.Background())
	if err != nil {
		t.Fatalf("RestoreFactoryCertificate: %v", err)
	}
	if !got.Equal(factory.Leaf) {
		t.Errorf("returned certificate %q, want the factory certificate", got.Subject.CommonName)
	}
	for _, req := range []string{"DELETE " + stepsCertPath, "POST " + stepsResetPath} {
		if !b.sawRequest(req) {
			t.Errorf("BMC never received %s", req)
		}
	}
}

// TestRedfishCert_WaitForReady_ContextDeadlineCapsWait pins that a caller's
// deadline earlier than resetMaxWait ends the wait at that deadline.
func TestRedfishCert_WaitForReady_ContextDeadlineCapsWait(t *testing.T) {
	b := newRestoreStepsBMC(t)
	m := newFastCertManager(t, b.cfg(t, &countingTLSProvider{}))
	defer m.Close()
	b.server.Close()
	m.resetMaxWait = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.waitForReady(ctx)
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("waitForReady ran %v, want it bounded by the 100ms context deadline", elapsed)
	}
	var timeout ErrBMCResetTimeout
	if !errors.As(err, &timeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want ErrBMCResetTimeout or context.DeadlineExceeded", err)
	}
}
