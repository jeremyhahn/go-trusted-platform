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
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
// given JSON body for /redfish/v1/. Returns the parsed host/port for use
// in a *Config.
func startVendorProbeServer(t *testing.T, status int, body string) (host string, port int, close func()) {
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
	return u.Hostname(), p, srv.Close
}

func TestVendorProbe_DetectSupermicro(t *testing.T) {
	body := `{"RedfishVersion":"1.0.2","Oem":{"Supermicro":{"VirtualMedia":{}}}}`
	host, port, closeSrv := startVendorProbeServer(t, http.StatusOK, body)
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{
		Address: host, Port: port, SkipTLSVerify: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}

	got, err := probe.Detect(context.Background(), &Config{
		Address: host, Port: port, SkipTLSVerify: true,
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
	host, port, closeSrv := startVendorProbeServer(t, http.StatusOK, body)
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, SkipTLSVerify: true}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}

	got, err := probe.Detect(context.Background(), &Config{
		Address: host, Port: port, SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != VendorDell {
		t.Errorf("Detect = %q, want %q", got, VendorDell)
	}
}

func TestVendorProbe_DetectHTTPError(t *testing.T) {
	host, port, closeSrv := startVendorProbeServer(t, http.StatusInternalServerError, "{}")
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, SkipTLSVerify: true}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	_, err = probe.Detect(context.Background(), &Config{
		Address: host, Port: port, SkipTLSVerify: true,
	})
	var want ErrConnectionFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrConnectionFailed", err)
	}
}

func TestVendorProbe_DetectMalformedJSON(t *testing.T) {
	host, port, closeSrv := startVendorProbeServer(t, http.StatusOK, "not-json")
	defer closeSrv()

	probe, err := NewVendorProbe(&Config{Address: host, Port: port, SkipTLSVerify: true}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	_, err = probe.Detect(context.Background(), &Config{
		Address: host, Port: port, SkipTLSVerify: true,
	})
	var want ErrConnectionFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrConnectionFailed", err)
	}
}

func TestVendorProbe_DetectConnectionRefused(t *testing.T) {
	probe, err := NewVendorProbe(&Config{Address: "127.0.0.1", Port: 1, SkipTLSVerify: true}, nil)
	if err != nil {
		t.Fatalf("NewVendorProbe: %v", err)
	}
	v, err := probe.Detect(context.Background(), &Config{
		Address: "127.0.0.1", Port: 1, SkipTLSVerify: true,
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

func TestBuildVendorProbeTLS_WithCAPath(t *testing.T) {
	tmp := t.TempDir()
	pemPath := filepath.Join(tmp, "ca.pem")
	// Reuse the httptest TLS cert so we have valid PEM material.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pem := certPEMOf(t, srv.Certificate())
	if err := os.WriteFile(pemPath, pem, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	cfg := &Config{Address: "x", Port: 443, CACertPath: pemPath}
	got, err := buildVendorProbeTLS(cfg)
	if err != nil {
		t.Fatalf("buildVendorProbeTLS: %v", err)
	}
	if got.RootCAs == nil {
		t.Error("RootCAs not populated")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS12", got.MinVersion)
	}
}

func TestBuildVendorProbeTLS_BadCAPath(t *testing.T) {
	cfg := &Config{Address: "x", Port: 443, CACertPath: "/nonexistent/ca.pem"}
	_, err := buildVendorProbeTLS(cfg)
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestBuildVendorProbeTLS_BadCAContent(t *testing.T) {
	tmp := t.TempDir()
	pemPath := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(pemPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := &Config{Address: "x", Port: 443, CACertPath: pemPath}
	_, err := buildVendorProbeTLS(cfg)
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestNewVendorProbe_RejectsBadCAPath(t *testing.T) {
	cfg := &Config{Address: "x", Port: 443, CACertPath: "/no/such/file"}
	if _, err := NewVendorProbe(cfg, nil); err == nil {
		t.Fatal("expected error from NewVendorProbe with bad CA path")
	}
}

// certPEMOf encodes a single x509 certificate to PEM bytes.
func certPEMOf(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
