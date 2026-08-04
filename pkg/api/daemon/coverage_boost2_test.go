package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// IDevID gRPC Service Tests - Nil TPM Service
// =============================================================================

func TestBoost_IDevIDGRPCService_NewAndSetTPM2Service(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)
	if svc == nil {
		t.Fatal("expected non-nil IDevIDGRPCService")
	}
	// SetTPM2Service with nil should not panic
	svc.SetTPM2Service(nil)
}

func TestBoost_IDevIDGRPCService_NilTPM_AllMethods(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateIDevID", func() error {
			_, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})
			return err
		}},
		{"GetIDevIDInfo", func() error {
			_, err := svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
			return err
		}},
		{"HasIDevID", func() error {
			_, err := svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})
			return err
		}},
		{"DeleteIDevID", func() error {
			_, err := svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
			return err
		}},
		{"GenerateIAK", func() error {
			_, err := svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})
			return err
		}},
		{"GetIAKInfo", func() error {
			_, err := svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
			return err
		}},
		{"HasIAK", func() error {
			_, err := svc.HasIAK(ctx, &platformv1.HasIAKRequest{})
			return err
		}},
		{"DeleteIAK", func() error {
			_, err := svc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
			return err
		}},
		{"CreateIDevIDCSR", func() error {
			_, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})
			return err
		}},
		{"CreateIAKCSR", func() error {
			_, err := svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})
			return err
		}},
		{"InstallIDevIDCertificate", func() error {
			_, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{})
			return err
		}},
		{"InstallIAKCertificate", func() error {
			_, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{})
			return err
		}},
		{"GetIDevIDCertificate", func() error {
			_, err := svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
			return err
		}},
		{"GetIAKCertificate", func() error {
			_, err := svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
			return err
		}},
		{"DeleteIDevIDCertificate", func() error {
			_, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
			return err
		}},
		{"DeleteIAKCertificate", func() error {
			_, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
			return err
		}},
		{"GetDeviceAttributes", func() error {
			_, err := svc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})
			return err
		}},
		{"FlushTransientContexts", func() error {
			_, err := svc.FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})
			return err
		}},
		{"ActivateCredential", func() error {
			_, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error for nil TPM2 service")
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("expected FailedPrecondition, got %v: %v", status.Code(err), err)
			}
		})
	}
}

// =============================================================================
// Daemon Accessor Tests
// =============================================================================

func TestBoost_Daemon_FunctionalOptions(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	// Test WithGRPCServer
	opt := WithGRPCServer(nil)
	opt(d)

	// Test WithQUICServer
	opt2 := WithQUICServer(nil)
	opt2(d)

	// Test WithRESTServer
	opt3 := WithRESTServer(nil)
	opt3(d)

	// Test WithMCPServer
	opt4 := WithMCPServer(nil)
	opt4(d)

	// Test WithGRPCUDSServer
	opt5 := WithGRPCUDSServer(nil)
	opt5(d)
}

func TestBoost_Daemon_ComputeGRPCService_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.ComputeGRPCService() != nil {
		t.Fatal("expected nil compute service initially")
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewComputeGRPCService(logger, nil)
	d.SetComputeGRPCService(svc)
	if d.ComputeGRPCService() != svc {
		t.Fatal("expected compute service to be set")
	}
}

func TestBoost_Daemon_AttestationGRPCService_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.AttestationGRPCService() != nil {
		t.Fatal("expected nil attestation service initially")
	}

	svc := &AttestationServiceServer{}
	d.SetAttestationGRPCService(svc)
	if d.AttestationGRPCService() != svc {
		t.Fatal("expected attestation service to be set")
	}
}

func TestBoost_Daemon_IDevIDGRPCService_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.IDevIDGRPCService() != nil {
		t.Fatal("expected nil IDevID service initially")
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)
	d.SetIDevIDGRPCService(svc)
	if d.IDevIDGRPCService() != svc {
		t.Fatal("expected IDevID service to be set")
	}
}

func TestBoost_Daemon_TPMGRPCService_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.TPMGRPCService() != nil {
		t.Fatal("expected nil TPM service initially")
	}

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewTPMGRPCService(logger)
	d.SetTPMGRPCService(svc)
	if d.TPMGRPCService() != svc {
		t.Fatal("expected TPM service to be set")
	}
}

func TestBoost_Daemon_TPM2Service_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.TPM2Service() != nil {
		t.Fatal("expected nil TPM2 service initially")
	}
}

func TestBoost_Daemon_GRPCUDSServer_Accessor(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	if d.GRPCUDSServer() != nil {
		t.Fatal("expected nil gRPC UDS server initially")
	}
}

func TestBoost_Daemon_GRPCSocketPath_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableGRPCUDS = false
	d := &Daemon{
		config: cfg,
	}

	if d.GRPCSocketPath() != "" {
		t.Fatal("expected empty socket path when gRPC UDS disabled")
	}
}

func TestBoost_Daemon_GRPCSocketPath_Enabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableGRPCUDS = true
	cfg.GRPCSocketPath = "/tmp/test.sock"
	d := &Daemon{
		config: cfg,
	}

	if d.GRPCSocketPath() != "/tmp/test.sock" {
		t.Fatalf("expected /tmp/test.sock, got %s", d.GRPCSocketPath())
	}
}

func TestBoost_Daemon_IsGRPCUDSEnabled_NoServer(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
	}

	// Even though EnableGRPCUDS is true in default config, no server is set
	if d.IsGRPCUDSEnabled() {
		t.Fatal("expected gRPC UDS disabled when no server set")
	}
}

func TestBoost_Daemon_SetTPM2Service_NilService(t *testing.T) {
	d := &Daemon{
		config: DefaultConfig(),
		logger: logging.NewLogger(slog.LevelError, io.Discard),
	}

	// SetTPM2Service with nil should be a no-op (early return)
	d.SetTPM2Service(nil)
	if d.TPM2Service() != nil {
		t.Fatal("expected nil TPM2 service after setting nil")
	}
}
