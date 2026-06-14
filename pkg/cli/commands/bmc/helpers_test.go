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
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// testCAPEM is a well-formed certificate accepted by x509 CertPool parsing.
const testCAPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

func TestNewBMCHTTPClient_NoCASystemRoots(t *testing.T) {
	t.Setenv(envPlatformCACert, "")
	client, err := newBMCHTTPClient(&bmcFlags{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Transport != nil {
		t.Errorf("expected default transport (system roots), got custom transport")
	}
}

func TestNewBMCHTTPClient_WithCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte(testCAPEM), 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	client, err := newBMCHTTPClient(&bmcFlags{caCert: caPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected RootCAs to be populated from the CA bundle")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must never be set")
	}
}

func TestNewBMCHTTPClient_EnvFallback(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte(testCAPEM), 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	t.Setenv(envPlatformCACert, caPath)

	client, err := newBMCHTTPClient(&bmcFlags{}) // no flag; env supplies CA
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := client.Transport.(*http.Transport); !ok {
		t.Fatalf("expected custom transport from env CA, got %T", client.Transport)
	}
}

func TestNewBMCHTTPClient_MissingFile(t *testing.T) {
	t.Setenv(envPlatformCACert, "")
	_, err := newBMCHTTPClient(&bmcFlags{caCert: "/nonexistent/ca.pem"})
	var target ErrCABundleLoadFailed
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrCABundleLoadFailed, got %T: %v", err, err)
	}
}

func TestNewBMCHTTPClient_InvalidPEM(t *testing.T) {
	t.Setenv(envPlatformCACert, "")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0600); err != nil {
		t.Fatalf("write bad ca: %v", err)
	}
	_, err := newBMCHTTPClient(&bmcFlags{caCert: caPath})
	var target ErrCABundleLoadFailed
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrCABundleLoadFailed, got %T: %v", err, err)
	}
}
