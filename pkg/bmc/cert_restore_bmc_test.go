package bmc

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

// plainCertManager hides every method beyond ManagedCertificateManager,
// so it stands for a backend without factory-restore support.
type plainCertManager struct {
	ManagedCertificateManager
}

func TestAutoMgr_RestoreFactory_DelegatesToPrimary(t *testing.T) {
	f := newFakeCertBMCWithDelete(t)
	defer f.close()
	factory := selfSignedCert(t, "bmc-factory-default", 2)
	f.reissueOnReset(factory)
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(cfg *Config, _ *slog.Logger) (ManagedCertificateManager, error) {
			return newFastCertManager(t, cfg), nil
		},
	})

	m, err := NewAutoCertManager(f.cfg(), CertBackendRedfish, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}
	defer m.Close()

	got, err := m.RestoreFactoryCertificate(context.Background())
	if err != nil {
		t.Fatalf("RestoreFactoryCertificate: %v", err)
	}
	if !got.Equal(factory.Leaf) {
		t.Errorf("returned certificate %q, want the regenerated factory certificate", got.Subject.CommonName)
	}
}

func TestAutoMgr_RestoreFactory_Errors(t *testing.T) {
	tests := []struct {
		name      string
		factories map[CertBackend]CertManagerFactory
		check     func(t *testing.T, err error)
	}{
		{
			name: "backend without factory restore",
			factories: map[CertBackend]CertManagerFactory{
				CertBackendRedfish: func(cfg *Config, _ *slog.Logger) (ManagedCertificateManager, error) {
					return plainCertManager{newFastCertManager(t, cfg)}, nil
				},
			},
			check: func(t *testing.T, err error) {
				var unsupported ErrFactoryRestoreUnsupported
				if !errors.As(err, &unsupported) {
					t.Fatalf("error = %v, want ErrFactoryRestoreUnsupported", err)
				}
				if unsupported.Backend != CertBackendRedfish {
					t.Errorf("backend = %q, want %q", unsupported.Backend, CertBackendRedfish)
				}
			},
		},
		{
			name:      "backend not registered",
			factories: map[CertBackend]CertManagerFactory{},
			check: func(t *testing.T, err error) {
				var unavailable ErrAutoCertBackendUnavailable
				if !errors.As(err, &unavailable) {
					t.Fatalf("error = %v, want ErrAutoCertBackendUnavailable", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeCertBMCWithDelete(t)
			defer f.close()
			withTempRegistry(t, tt.factories)

			m, err := NewAutoCertManager(f.cfg(), CertBackendRedfish, nil)
			if err != nil {
				t.Fatalf("NewAutoCertManager: %v", err)
			}
			defer m.Close()

			got, err := m.RestoreFactoryCertificate(context.Background())
			if got != nil {
				t.Errorf("certificate = %v, want nil on error", got.Subject)
			}
			tt.check(t, err)
		})
	}
}
