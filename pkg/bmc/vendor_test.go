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

package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestVendor_IsValid(t *testing.T) {
	cases := []struct {
		v    Vendor
		want bool
	}{
		{VendorUnknown, true},
		{VendorSupermicro, true},
		{VendorDell, true},
		{VendorHPE, true},
		{VendorLenovo, true},
		{VendorGeneric, true},
		{Vendor(""), false},
		{Vendor("apple"), false},
	}
	for _, tc := range cases {
		if got := tc.v.IsValid(); got != tc.want {
			t.Errorf("Vendor(%q).IsValid() = %v, want %v", string(tc.v), got, tc.want)
		}
	}
}

func TestRecommendCertBackend(t *testing.T) {
	cases := []struct {
		v    Vendor
		want CertBackend
	}{
		{VendorSupermicro, CertBackendSMCCGI},
		{VendorDell, CertBackendRedfish},
		{VendorHPE, CertBackendRedfish},
		{VendorLenovo, CertBackendRedfish},
		{VendorGeneric, CertBackendRedfish},
		{VendorUnknown, CertBackendRedfish},
		{Vendor("nonsense"), CertBackendRedfish},
	}
	for _, tc := range cases {
		if got := RecommendCertBackend(tc.v); got != tc.want {
			t.Errorf("RecommendCertBackend(%q) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestClassifyVendor(t *testing.T) {
	cases := []struct {
		name string
		root vendorProbeRoot
		want Vendor
	}{
		{
			name: "vendor field supermicro",
			root: vendorProbeRoot{Vendor: "Supermicro Computer, Inc."},
			want: VendorSupermicro,
		},
		{
			name: "vendor field dell uppercase",
			root: vendorProbeRoot{Vendor: "DELL Inc."},
			want: VendorDell,
		},
		{
			name: "vendor field hewlett",
			root: vendorProbeRoot{Vendor: "Hewlett Packard Enterprise"},
			want: VendorHPE,
		},
		{
			name: "vendor field lenovo",
			root: vendorProbeRoot{Vendor: "Lenovo"},
			want: VendorLenovo,
		},
		{
			name: "oem fallback supermicro",
			root: vendorProbeRoot{
				RedfishVersion: "1.0.2",
				Oem:            map[string]json.RawMessage{"Supermicro": json.RawMessage(`{}`)},
			},
			want: VendorSupermicro,
		},
		{
			name: "oem fallback hp legacy",
			root: vendorProbeRoot{
				RedfishVersion: "1.4.0",
				Oem:            map[string]json.RawMessage{"Hp": json.RawMessage(`{}`)},
			},
			want: VendorHPE,
		},
		{
			name: "redfish version present, no vendor signal",
			root: vendorProbeRoot{RedfishVersion: "1.6.0"},
			want: VendorGeneric,
		},
		{
			name: "empty",
			root: vendorProbeRoot{},
			want: VendorUnknown,
		},
		{
			name: "vendor name takes precedence over oem mismatch",
			root: vendorProbeRoot{
				Vendor: "Dell",
				Oem:    map[string]json.RawMessage{"Supermicro": json.RawMessage(`{}`)},
			},
			want: VendorDell,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyVendor(tc.root); got != tc.want {
				t.Errorf("classifyVendor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// startVendorProbeServer spins up an httptest TLS server that returns the
// given JSON body for /redfish/v1/. Returns the parsed host/port and a
// TLSProvider that trusts the server's self-signed certificate via its
// certificate pool (no InsecureSkipVerify).
func startVendorProbeServer(t *testing.T, status int, body string) (host string, port int, tlsProv TLSProvider, close func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewTLSServer(mux)
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse server URL: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		srv.Close()
		t.Fatalf("parse server port: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	prov := &fakeTLSProvider{cfg: &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}}
	return u.Hostname(), p, prov, srv.Close
}

func TestVendorProbe_DetectSupermicro(t *testing.T) {
	body := `{"RedfishVersion":"1.0.2","Oem":{"Supermicro":{"VirtualMedia":{}}}}`
	host, port, tlsProv, closeSrv := startVendorProbeServer(t, http.StatusOK, body)
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{
		Address: host, Port: port, TLS: tlsProv,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}

	got, err := probe.Detect(context.Background(), &Config{
		Address: host, Port: port, TLS: tlsProv,
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != VendorSupermicro {
		t.Errorf("Detect = %q, want %q", got, VendorSupermicro)
	}
}

func TestVendorProbe_DetectDellByVendorField(t *testing.T) {
	body := `{"RedfishVersion":"1.8.0","Vendor":"Dell Inc."}`
	host, port, tlsProv, closeSrv := startVendorProbeServer(t, http.StatusOK, body)
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, TLS: tlsProv}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}

	got, err := probe.Detect(context.Background(), &Config{
		Address: host, Port: port, TLS: tlsProv,
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != VendorDell {
		t.Errorf("Detect = %q, want %q", got, VendorDell)
	}
}

func TestVendorProbe_DetectHTTPError(t *testing.T) {
	host, port, tlsProv, closeSrv := startVendorProbeServer(t, http.StatusInternalServerError, "{}")
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, TLS: tlsProv}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	_, err = probe.Detect(context.Background(), &Config{
		Address: host, Port: port, TLS: tlsProv,
	})
	var want ErrConnectionFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrConnectionFailed", err)
	}
}

func TestVendorProbe_DetectMalformedJSON(t *testing.T) {
	host, port, tlsProv, closeSrv := startVendorProbeServer(t, http.StatusOK, "not-json")
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, TLS: tlsProv}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	_, err = probe.Detect(context.Background(), &Config{
		Address: host, Port: port, TLS: tlsProv,
	})
	var want ErrConnectionFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrConnectionFailed", err)
	}
}

func TestVendorProbe_DetectConnectionRefused(t *testing.T) {
	// No TLS provider; system roots used. Port 1 refuses connections.
	probe, err := NewVendorProbe(&Config{Address: "127.0.0.1", Port: 1}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	v, err := probe.Detect(context.Background(), &Config{
		Address: "127.0.0.1", Port: 1,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if v != VendorUnknown {
		t.Errorf("Detect on conn refused returned vendor %q", v)
	}
}

func TestVendorProbe_NilConfig(t *testing.T) {
	if _, err := NewVendorProbe(nil, nil); err == nil {
		t.Fatal("NewVendorProbe(nil) returned nil error")
	}
	probe, err := NewVendorProbe(&Config{Address: "x", Port: 443}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	if _, err := probe.Detect(context.Background(), nil); err == nil {
		t.Fatal("Detect(nil) returned nil error")
	}
}

// TestNewVendorProbe_ProviderError verifies that when the TLSProvider returns
// an error, NewVendorProbe propagates it immediately at construction time.
func TestNewVendorProbe_ProviderError(t *testing.T) {
	cause := errors.New("provider unavailable")
	cfg := &Config{
		Address: "x",
		Port:    443,
		TLS:     &fakeTLSProvider{err: cause},
	}
	_, err := NewVendorProbe(cfg, nil)
	if err == nil {
		t.Fatal("expected error from NewVendorProbe with failing provider")
	}
	if !errors.Is(err, cause) {
		t.Errorf("cause not wrapped: got %v", err)
	}
}
