package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// IDevID gRPC Service Helper Tests
// =============================================================================

func TestBoost_IDevIDGRPCService_CertToProto_NilCert(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)

	result := svc.certToProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestBoost_IDevIDGRPCService_CertToProto_ValidCert(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)

	// Generate a self-signed test certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "test-device",
		},
		Issuer: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	proto := svc.certToProto(cert)
	if proto == nil {
		t.Fatal("expected non-nil proto")
	}
	if proto.SubjectCn != "test-device" {
		t.Fatalf("expected subject CN test-device, got %s", proto.SubjectCn)
	}
	if proto.KeyType != "ECDSA" {
		t.Fatalf("expected key type ECDSA, got %s", proto.KeyType)
	}
	if len(proto.Pem) == 0 {
		t.Fatal("expected non-empty PEM")
	}
	if len(proto.Der) == 0 {
		t.Fatal("expected non-empty DER")
	}
	if proto.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if proto.SerialNumber != "12345" {
		t.Fatalf("expected serial 12345, got %s", proto.SerialNumber)
	}
}

func TestBoost_IDevIDGRPCService_MapTPM2Error_NilError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)

	result := svc.mapTPM2Error(nil, "test")
	if result != nil {
		t.Fatal("expected nil for nil error")
	}
}

func TestBoost_IDevIDGRPCService_MapTPM2Error_Patterns(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewIDevIDGRPCService(logger)

	tests := []struct {
		name     string
		errMsg   string
		expected codes.Code
	}{
		{"not-found", "key not found", codes.NotFound},
		{"does-not-exist", "handle does not exist", codes.NotFound},
		{"no-such", "no such object", codes.NotFound},
		{"already-exists", "key already exists", codes.AlreadyExists},
		{"duplicate", "duplicate entry", codes.AlreadyExists},
		{"invalid", "invalid argument", codes.InvalidArgument},
		{"malformed", "malformed key", codes.InvalidArgument},
		{"permission", "permission denied", codes.PermissionDenied},
		{"unauthorized", "unauthorized access", codes.PermissionDenied},
		{"forbidden", "forbidden operation", codes.PermissionDenied},
		{"timeout", "operation timeout", codes.DeadlineExceeded},
		{"deadline", "deadline exceeded", codes.DeadlineExceeded},
		{"unavailable", "tpm unavailable", codes.Unavailable},
		{"not-ready", "device not ready", codes.Unavailable},
		{"default", "some random error", codes.Internal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.mapTPM2Error(ErrServiceNotAvailable{Service: tc.errMsg}, "op")
			if err == nil {
				t.Fatal("expected non-nil error")
			}
			if status.Code(err) != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, status.Code(err))
			}
		})
	}
}

// =============================================================================
// TPM gRPC Service Helper Tests
// =============================================================================

func TestBoost_TPMGRPCService_MapError_NilError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewTPMGRPCService(logger)

	result := svc.mapError(nil)
	if result != nil {
		t.Fatal("expected nil for nil error")
	}
}

func TestBoost_TPMGRPCService_MapError_Patterns(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	svc := NewTPMGRPCService(logger)

	tests := []struct {
		name     string
		errMsg   string
		expected codes.Code
	}{
		{"not-found", "key not found", codes.NotFound},
		{"does-not-exist", "handle does not exist", codes.NotFound},
		{"no-such", "no such entry", codes.NotFound},
		{"already-exists", "key already exists", codes.AlreadyExists},
		{"duplicate", "duplicate handle", codes.AlreadyExists},
		{"invalid", "invalid parameter", codes.InvalidArgument},
		{"required", "field required", codes.InvalidArgument},
		{"must-be", "value must be positive", codes.InvalidArgument},
		{"cannot-be", "value cannot be zero", codes.InvalidArgument},
		{"permission", "permission denied", codes.PermissionDenied},
		{"denied", "access denied", codes.PermissionDenied},
		{"unauthorized", "unauthorized", codes.PermissionDenied},
		{"forbidden", "forbidden", codes.PermissionDenied},
		{"authorization", "authorization failed", codes.PermissionDenied},
		{"tpm-upper", "TPM error occurred", codes.FailedPrecondition},
		{"tpm-lower", "tpm device busy", codes.FailedPrecondition},
		{"handle", "handle not available", codes.FailedPrecondition},
		{"default", "some random error", codes.Internal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.mapError(ErrServiceNotAvailable{Service: tc.errMsg})
			if err == nil {
				t.Fatal("expected non-nil error")
			}
			if status.Code(err) != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, status.Code(err))
			}
		})
	}
}

func TestBoost_HashAlgToProtoPCRBank(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected platformv1.PCRBank
	}{
		{"sha1-lower", "sha1", platformv1.PCRBank_PCR_BANK_SHA1},
		{"sha1-dash", "SHA-1", platformv1.PCRBank_PCR_BANK_SHA1},
		{"sha1-upper", "SHA1", platformv1.PCRBank_PCR_BANK_SHA1},
		{"sha256-lower", "sha256", platformv1.PCRBank_PCR_BANK_SHA256},
		{"sha256-dash", "SHA-256", platformv1.PCRBank_PCR_BANK_SHA256},
		{"sha256-upper", "SHA256", platformv1.PCRBank_PCR_BANK_SHA256},
		{"sha384-lower", "sha384", platformv1.PCRBank_PCR_BANK_SHA384},
		{"sha384-dash", "SHA-384", platformv1.PCRBank_PCR_BANK_SHA384},
		{"sha384-upper", "SHA384", platformv1.PCRBank_PCR_BANK_SHA384},
		{"sha512-lower", "sha512", platformv1.PCRBank_PCR_BANK_SHA512},
		{"sha512-dash", "SHA-512", platformv1.PCRBank_PCR_BANK_SHA512},
		{"sha512-upper", "SHA512", platformv1.PCRBank_PCR_BANK_SHA512},
		{"sm3-lower", "sm3", platformv1.PCRBank_PCR_BANK_SM3_256},
		{"sm3-upper", "SM3-256", platformv1.PCRBank_PCR_BANK_SM3_256},
		{"default", "unknown", platformv1.PCRBank_PCR_BANK_SHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hashAlgToProtoPCRBank(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestBoost_KeyAlgorithmToProto(t *testing.T) {
	tests := []struct {
		name     string
		input    x509.PublicKeyAlgorithm
		expected platformv1.KeyAlgorithm
	}{
		{"RSA", x509.RSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		{"ECDSA", x509.ECDSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256},
		{"Ed25519", x509.Ed25519, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519},
		{"Unknown", x509.UnknownPublicKeyAlgorithm, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := keyAlgorithmToProto(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
