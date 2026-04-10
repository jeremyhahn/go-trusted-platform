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

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

// generateTestCert creates a self-signed TLS certificate for testing purposes.
func generateTestCert(cn string) *tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func TestNewCertReloader_StoresInitial(t *testing.T) {
	cert := generateTestCert("test-initial")
	reloader, err := NewCertReloader(cert)
	if err != nil {
		t.Fatalf("NewCertReloader returned unexpected error: %v", err)
	}
	got := reloader.Current()
	if got != cert {
		t.Fatal("Current() did not return the initial certificate")
	}
}

func TestNewCertReloader_NilCert(t *testing.T) {
	reloader, err := NewCertReloader(nil)
	if reloader != nil {
		t.Fatal("expected nil reloader for nil certificate")
	}
	if err == nil {
		t.Fatal("expected error for nil certificate")
	}
	var reloadErr ErrCertReloadFailed
	if !errors.As(err, &reloadErr) {
		t.Fatalf("expected ErrCertReloadFailed, got %T: %v", err, err)
	}
}

func TestReload_AtomicSwap(t *testing.T) {
	certA := generateTestCert("cert-a")
	certB := generateTestCert("cert-b")

	reloader, err := NewCertReloader(certA)
	if err != nil {
		t.Fatalf("NewCertReloader returned unexpected error: %v", err)
	}

	if err := reloader.Reload(certB); err != nil {
		t.Fatalf("Reload returned unexpected error: %v", err)
	}

	got := reloader.Current()
	if got != certB {
		t.Fatal("Current() did not return the reloaded certificate")
	}
	if got.Leaf.Subject.CommonName != "cert-b" {
		t.Fatalf("expected CN cert-b, got %s", got.Leaf.Subject.CommonName)
	}
}

func TestReload_NilCert(t *testing.T) {
	cert := generateTestCert("test-reload-nil")
	reloader, err := NewCertReloader(cert)
	if err != nil {
		t.Fatalf("NewCertReloader returned unexpected error: %v", err)
	}

	err = reloader.Reload(nil)
	if err == nil {
		t.Fatal("expected error when reloading with nil certificate")
	}
	var reloadErr ErrCertReloadFailed
	if !errors.As(err, &reloadErr) {
		t.Fatalf("expected ErrCertReloadFailed, got %T: %v", err, err)
	}

	// Verify original cert is still in place
	if reloader.Current() != cert {
		t.Fatal("original certificate should remain after failed reload")
	}
}

func TestGetCertificateFunc_ReturnsCurrent(t *testing.T) {
	cert := generateTestCert("test-get-func")
	reloader, err := NewCertReloader(cert)
	if err != nil {
		t.Fatalf("NewCertReloader returned unexpected error: %v", err)
	}

	getCert := reloader.GetCertificateFunc()
	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("GetCertificateFunc closure returned unexpected error: %v", err)
	}
	if got != cert {
		t.Fatal("GetCertificateFunc closure did not return the current certificate")
	}
}

func TestReload_ConcurrentSafety(t *testing.T) {
	initial := generateTestCert("concurrent-initial")
	reloader, err := NewCertReloader(initial)
	if err != nil {
		t.Fatalf("NewCertReloader returned unexpected error: %v", err)
	}

	getCert := reloader.GetCertificateFunc()

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers * 2)

	// 10 goroutines performing reloads
	for i := range workers {
		go func(id int) {
			defer wg.Done()
			cert := generateTestCert("reload-worker")
			for range 100 {
				if err := reloader.Reload(cert); err != nil {
					t.Errorf("worker %d: Reload returned unexpected error: %v", id, err)
					return
				}
			}
		}(i)
	}

	// 10 goroutines reading via GetCertificateFunc
	for i := range workers {
		go func(id int) {
			defer wg.Done()
			for range 100 {
				got, err := getCert(nil)
				if err != nil {
					t.Errorf("reader %d: GetCertificateFunc returned unexpected error: %v", id, err)
					return
				}
				if got == nil {
					t.Errorf("reader %d: GetCertificateFunc returned nil certificate", id)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
