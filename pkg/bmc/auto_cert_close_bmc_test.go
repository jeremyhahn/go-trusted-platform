package bmc

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

var (
	errFakePrimaryClose  = errors.New("fake primary backend: close failed")
	errFakeFallbackClose = errors.New("fake fallback backend: close failed")
	errFakeFactory       = errors.New("fake cert factory: backend unreachable")
)

// closeErrCertManager is a fakeCertManager whose Close fails with err.
type closeErrCertManager struct {
	fakeCertManager
	err error
}

func (c *closeErrCertManager) Close() error {
	if err := c.fakeCertManager.Close(); err != nil {
		return err
	}
	return c.err
}

func TestAutoCertManager_Close_ReportsFirstBackendError(t *testing.T) {
	tests := []struct {
		name        string
		primaryErr  error
		fallbackErr error
		want        error
	}{
		{name: "fallback error when the primary closes cleanly", fallbackErr: errFakeFallbackClose, want: errFakeFallbackClose},
		{name: "primary error when both fail", primaryErr: errFakePrimaryClose, fallbackErr: errFakeFallbackClose, want: errFakePrimaryClose},
		{name: "nil when both close cleanly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := &closeErrCertManager{err: tt.primaryErr}
			fallback := &closeErrCertManager{err: tt.fallbackErr}
			m := &AutoCertManager{primary: primary, fallback: fallback}

			if err := m.Close(); !errors.Is(err, tt.want) {
				t.Fatalf("Close = %v, want %v", err, tt.want)
			}
			if !primary.closed || !fallback.closed {
				t.Errorf("closed primary=%v fallback=%v, want both closed", primary.closed, fallback.closed)
			}
			if m.primary != nil || m.fallback != nil {
				t.Error("backends still held after Close")
			}
		})
	}
}

func TestAutoCertManager_PrimaryFactoryErrorIsReturned(t *testing.T) {
	calls := 0
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) {
			calls++
			return nil, errFakeFactory
		},
	})
	m, err := NewAutoCertManager(baseCfg("x", 443, nil), CertBackendRedfish, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()

	for attempt := 1; attempt <= 2; attempt++ {
		if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); !errors.Is(err, errFakeFactory) {
			t.Fatalf("attempt %d: ReplaceWebCertificate = %v, want the factory error", attempt, err)
		}
	}
	// A failed build is not cached: the next call tries the factory again.
	if calls != 2 {
		t.Errorf("factory called %d times, want 2", calls)
	}
}

func TestAutoCertManager_AutoProbeTLSProviderFailure(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	cfg.TLS = &fakeTLSProvider{err: errFakeTrustStoreDown}
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}
	defer m.Close()

	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()

	err = m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var resolveErr ErrAutoCertResolve
	if !errors.As(err, &resolveErr) {
		t.Fatalf("ReplaceWebCertificate = %v, want ErrAutoCertResolve", err)
	}
	var provErr ErrTLSProvider
	if !errors.As(err, &provErr) || !errors.Is(err, errFakeTrustStoreDown) {
		t.Errorf("error = %v, want ErrTLSProvider wrapping the provider failure", err)
	}
}
