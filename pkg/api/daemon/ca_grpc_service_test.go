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

package daemon

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewCAGRPCService(t *testing.T) {
	t.Parallel()

	t.Run("creates service with nil CA", func(t *testing.T) {
		svc := NewCAGRPCService(nil, nil, nil)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

func TestCAGRPCService_GetCAInfo_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", st.Code())
	}
}

func TestCAGRPCService_GetCAInfo_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	mockCA := &configurableMockCA{
		isInitialized:   true,
		identity:        "test-ca",
		defaultKeyAlg:   x509.ECDSA,
		defaultValidity: 365,
		trustedRoot:     rootCA.cert,
		trustedInter:    intermediateCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.CaInfo == nil {
		t.Fatal("expected non-nil CA info")
	}
	if !resp.CaInfo.IsInitialized {
		t.Error("expected CA to be initialized")
	}
	if resp.CaInfo.CommonName != "test-ca" {
		t.Errorf("expected CN 'test-ca', got %q", resp.CaInfo.CommonName)
	}
	if resp.CaInfo.DefaultAlgorithm != "ECDSA" {
		t.Errorf("expected algorithm ECDSA, got %q", resp.CaInfo.DefaultAlgorithm)
	}
	if !resp.CaInfo.IsIntermediate {
		t.Error("expected IsIntermediate to be true")
	}
	if len(resp.CaInfo.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate, got %d", len(resp.CaInfo.Intermediates))
	}
}

func TestCAGRPCService_GetCAInfo_NotInitialized(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		isInitialized: false,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.CaInfo.IsInitialized {
		t.Error("expected CA not to be initialized")
	}
}

func TestCAGRPCService_IssueCertificate_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_IssueCertificate_Validation(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &mockCA{}}
	ctx := context.Background()

	t.Run("missing request", func(t *testing.T) {
		resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing subject", func(t *testing.T) {
		resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
			Request: &platformv1.CertificateRequest{},
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing common name", func(t *testing.T) {
		resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
			Request: &platformv1.CertificateRequest{
				Subject: &platformv1.Subject{},
			},
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("invalid key algorithm", func(t *testing.T) {
		resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
			Request: &platformv1.CertificateRequest{
				Subject: &platformv1.Subject{
					CommonName: "test.example.com",
				},
				KeyAlgorithm: platformv1.KeyAlgorithm(999),
			},
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})
}

func TestCAGRPCService_IssueCertificate_Success(t *testing.T) {
	t.Parallel()

	issuedCert := createTestCertificate(t)

	mockCA := &configurableMockCA{
		issuedCert: issuedCert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName:   "test.example.com",
				Organization: "Test Org",
				Country:      "US",
			},
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			ValidDays:    365,
			KeyUsage:     []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"},
			ExtKeyUsage:  []string{"SERVER_AUTH", "CLIENT_AUTH"},
			Sans: &platformv1.SubjectAlternativeNames{
				DnsNames:    []string{"test.example.com", "www.example.com"},
				IpAddresses: []string{"192.168.1.1"},
			},
			StoreType: "software",
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

func TestCAGRPCService_IssueCertificate_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		issueCertErr: errors.New("failed to issue"),
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName: "test.example.com",
			},
		},
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.Internal)
}

// "kms" names no key store. It used to fall back to a new software key and
// certify that, which is not the key the caller meant.
func TestCAGRPCService_IssueCertificate_UnknownStoreType(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &configurableMockCA{issuedCert: createTestCertificate(t)}}
	resp, err := svc.IssueCertificate(context.Background(), &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject:   &platformv1.Subject{CommonName: "rpi/fleet"},
			StoreType: "kms",
		},
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.InvalidArgument)
}

// csrMockCA certifies CSRs for real, so a test can check whose key the
// certificate holds.
type csrMockCA struct {
	mockCA
	signer *issuancetest.CA
}

func (m *csrMockCA) SignCSR(ctx context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	return m.signer.SignCSR(ctx, csrPEM, opts)
}

// rootSocketCtx is the context of root calling over the daemon's Unix
// socket: the platform admin.
func rootSocketCtx() context.Context {
	return peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 0})
}

// The daemon's CA service, on TCP and the Unix socket alike, certifies a
// code-signing key for the platform admin only; ca:write and mTLS-only
// callers are refused before the CA sees the request.
func TestCAGRPCService_SignCSR_OnlyThePlatformAdmin(t *testing.T) {
	t.Parallel()

	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"mTLS, no platform token", context.Background(), codes.PermissionDenied},
		{"ca:write", grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Scopes: []string{"ca:write"}}), codes.PermissionDenied},
		{"Unix socket, not root", peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 1000}), codes.PermissionDenied},
		{"ca:sign-csr", grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Scopes: []string{"ca:sign-csr"}}), codes.OK},
		{"Unix socket, root", rootSocketCtx(), codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{signer: issuancetest.NewCA(t)}
			svc := NewCAGRPCService(nil, ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

			_, err := svc.SignCSR(tc.ctx, &platformv1.SignCSRRequest{CsrPem: csr})
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.code)
			}
			if reached := ca.signer.Opts != nil; reached != (tc.code == codes.OK) {
				t.Errorf("reached the CA = %v", reached)
			}
		})
	}
}

func TestCAGRPCService_SignCSR_CertifiesTheKMSKeyForCodeSigning(t *testing.T) {
	t.Parallel()

	ca := &csrMockCA{signer: issuancetest.NewCA(t)}
	key := issuancetest.RSAKey(t)
	svc := NewCAGRPCService(nil, ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

	resp, err := svc.SignCSR(rootSocketCtx(), &platformv1.SignCSRRequest{
		CsrPem:    string(issuancetest.CSR(t, key, "rpi/fleet")),
		ValidDays: 30,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	block, _ := pem.Decode(resp.GetCertificate().GetPem())
	if block == nil {
		t.Fatal("no certificate PEM in the response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the certificate does not certify the CSR's key")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("EKU = %v, want codeSigning only", cert.ExtKeyUsage)
	}
	if ca.signer.Opts.ValidityDays != 30 {
		t.Errorf("sign options = %+v", ca.signer.Opts)
	}
}

func TestCAGRPCService_SignCSR_Errors(t *testing.T) {
	t.Parallel()

	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	cases := []struct {
		name    string
		csr     string
		noKMS   bool
		caErr   error
		code    codes.Code
		reached bool
	}{
		{"malformed CSR", "not a csr", false, nil, codes.InvalidArgument, false},
		{"names no KMS key", string(issuancetest.CSR(t, key, "admin")), false, nil, codes.InvalidArgument, false},
		{"key is not the KMS key", string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet")), false, nil, codes.InvalidArgument, false},
		{"no KMS", csr, true, nil, codes.Internal, false},
		{"CA failure", csr, false, errors.New("sealed"), codes.Internal, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{signer: issuancetest.NewCA(t)}
			ca.signer.Err = tc.caErr
			svc := NewCAGRPCService(nil, ca, nil)
			if !tc.noKMS {
				svc.WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))
			}
			resp, err := svc.SignCSR(rootSocketCtx(), &platformv1.SignCSRRequest{CsrPem: tc.csr})
			if resp != nil {
				t.Error("expected nil response")
			}
			assertGRPCError(t, err, tc.code)
			if reached := ca.signer.Opts != nil; reached != tc.reached {
				t.Errorf("reached the CA = %v, want %v", reached, tc.reached)
			}
		})
	}
}

func TestCAGRPCService_SignCSR_WithoutACA(t *testing.T) {
	t.Parallel()

	_, err := NewCAGRPCService(nil, nil, nil).SignCSR(rootSocketCtx(), &platformv1.SignCSRRequest{CsrPem: "x"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_GetCertificate_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{Serial: "test"})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_GetCertificate_Validation(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &mockCA{}}
	ctx := context.Background()

	t.Run("missing serial", func(t *testing.T) {
		resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})
}

func TestCAGRPCService_GetCertificate_RootMatch(t *testing.T) {
	t.Parallel()

	rootCert := createTestCACertificate(t, "Test Root CA", nil, nil)
	serial := hex.EncodeToString(rootCert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedRoot: rootCert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Certificate == nil {
		t.Fatal("expected certificate in response")
	}
	if resp.Certificate.Serial != serial {
		t.Errorf("expected serial %q, got %q", serial, resp.Certificate.Serial)
	}
}

func TestCAGRPCService_GetCertificate_IntermediateMatch(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)
	serial := hex.EncodeToString(intermediateCA.cert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedRoot:  rootCA.cert,
		trustedInter: intermediateCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludeDer: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Certificate == nil {
		t.Fatal("expected certificate in response")
	}
}

func TestCAGRPCService_GetCertificate_FromStore(t *testing.T) {
	t.Parallel()

	cert := createTestCertificate(t)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: cert,
		},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: serial,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Certificate == nil {
		t.Fatal("expected certificate in response")
	}
}

func TestCAGRPCService_GetCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: "nonexistent",
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.NotFound)
}

func TestCAGRPCService_ListCertificates_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_ListCertificates_NilCertStore(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		certStore: nil,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_ListCertificates_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{},
	}

	mockCA := &configurableMockCA{
		trustedRoot:  rootCA.cert,
		trustedInter: intermediateCA.cert,
		certStore:    mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(resp.Certificates))
	}
	if resp.Pagination == nil {
		t.Error("expected pagination info")
	}
}

func TestCAGRPCService_ListCertificates_Pagination(t *testing.T) {
	t.Parallel()

	rootCert := createTestCACertificate(t, "Test Root CA", nil, nil)

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{},
	}

	mockCA := &configurableMockCA{
		trustedRoot: rootCert,
		certStore:   mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	t.Run("custom page size", func(t *testing.T) {
		resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
			Pagination: &platformv1.PaginationRequest{
				PageSize: 10,
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Pagination.PageSize != 10 {
			t.Errorf("expected page size 10, got %d", resp.Pagination.PageSize)
		}
	})

	t.Run("max page size limit", func(t *testing.T) {
		resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
			Pagination: &platformv1.PaginationRequest{
				PageSize: 5000, // exceeds max
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Pagination.PageSize != caMaxPageSize {
			t.Errorf("expected page size %d, got %d", caMaxPageSize, resp.Pagination.PageSize)
		}
	})
}

func TestCAGRPCService_RevokeCertificate_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{Serial: "test"})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_RevokeCertificate_Validation(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &mockCA{}}
	ctx := context.Background()

	t.Run("missing serial", func(t *testing.T) {
		resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})
}

func TestCAGRPCService_RevokeCertificate_CertNotFound(t *testing.T) {
	t.Parallel()

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: "nonexistent",
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.NotFound)
}

func TestCAGRPCService_RevokeCertificate_Success(t *testing.T) {
	t.Parallel()

	cert := createTestCertificate(t)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: cert,
		},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		DeleteKeys: false,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if resp.Serial != serial {
		t.Errorf("expected serial %q, got %q", serial, resp.Serial)
	}
	if resp.CertificateStatus != platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		t.Error("expected revoked status")
	}
	// RFC 5280 §5.3.1: keyCompromise is CRLReason 1. The CA must record the
	// caller's reason; MCP and the Unix socket reach the CA through this service.
	if len(mockCA.revokedOpts) != 1 || mockCA.revokedOpts[0].Reason != 1 {
		t.Errorf("expected one RevokeCert with Reason 1, got %+v", mockCA.revokedOpts)
	}
}

// A reason outside RFC 5280 §5.3.1 (7 is unassigned) is InvalidArgument and
// never reaches the CA, which would publish it in the CRL.
func TestCAGRPCService_RevokeCertificate_RejectsUndefinedReason(t *testing.T) {
	t.Parallel()

	for _, reason := range []int32{7, 8, -1, 99} {
		cert := createTestCertificate(t)
		serial := hex.EncodeToString(cert.SerialNumber.Bytes())
		mockCA := &configurableMockCA{
			certStore: &mockCertStore{certs: map[string]*x509.Certificate{serial: cert}},
		}
		svc := &CAGRPCService{ca: mockCA}

		_, err := svc.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{
			Serial: serial,
			Reason: platformv1.RevocationReason(reason),
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("reason %d: expected InvalidArgument, got %v", reason, err)
		}
		if len(mockCA.revokedOpts) != 0 {
			t.Errorf("reason %d: the CA was asked to revoke: %+v", reason, mockCA.revokedOpts)
		}
	}
}

func TestCAGRPCService_RevokeCertificate_WithDeleteKeys(t *testing.T) {
	t.Parallel()

	cert := createTestCertificate(t)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: cert,
		},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		DeleteKeys: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
}

func TestCAGRPCService_RevokeCertificate_Error(t *testing.T) {
	t.Parallel()

	cert := createTestCertificate(t)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: cert,
		},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
		revokeErr: errors.New("revoke failed"),
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: serial,
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.Internal)
}

func TestCAGRPCService_RenewCertificate_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{Serial: "test", ValidDays: 365})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_RenewCertificate_Validation(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &mockCA{}}
	ctx := context.Background()

	t.Run("missing serial", func(t *testing.T) {
		resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
			ValidDays: 365,
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("invalid valid_days", func(t *testing.T) {
		resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
			Serial:    "test",
			ValidDays: 0,
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("negative valid_days", func(t *testing.T) {
		resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
			Serial:    "test",
			ValidDays: -1,
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})
}

func TestCAGRPCService_RenewCertificate_CertNotFound(t *testing.T) {
	t.Parallel()

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{},
	}

	mockCA := &configurableMockCA{
		certStore: mockStore,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    "nonexistent",
		ValidDays: 365,
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.NotFound)
}

func TestCAGRPCService_RenewCertificate_Success(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificateWithSANs(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createTestCertificate(t)

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: existingCert,
		},
	}

	mockCA := &configurableMockCA{
		certStore:  mockStore,
		issuedCert: newCert,
		keyStore:   &rotatingKeyStore{},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:       serial,
		ValidDays:    365,
		PreserveSans: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if resp.OldCertificate == nil {
		t.Error("expected old certificate")
	}
	if resp.NewCertificate == nil {
		t.Error("expected new certificate")
	}
}

func TestCAGRPCService_RenewCertificate_WithNewSANs(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificate(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createTestCertificate(t)

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: existingCert,
		},
	}

	mockCA := &configurableMockCA{
		certStore:  mockStore,
		issuedCert: newCert,
		keyStore:   &rotatingKeyStore{},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
		NewSans: &platformv1.SubjectAlternativeNames{
			DnsNames:    []string{"new.example.com"},
			IpAddresses: []string{"10.0.0.1"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
}

func TestCAGRPCService_RenewCertificate_Error(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificate(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())

	mockStore := &mockCertStore{
		certs: map[string]*x509.Certificate{
			serial: existingCert,
		},
	}

	mockCA := &configurableMockCA{
		certStore:    mockStore,
		issueCertErr: errors.New("failed to renew"),
		keyStore:     &rotatingKeyStore{},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.Internal)
}

// rotatingKeyStore records RotateKey calls. Every other Backend method is the
// nil embedded interface: renewal must not reach them.
type rotatingKeyStore struct {
	xkmsbackend.Backend
	rotated   []*xkmssdk.KeyAttributes
	rotateErr error
}

func (k *rotatingKeyStore) RotateKey(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	k.rotated = append(k.rotated, attrs)
	return nil, k.rotateErr
}

// renewingMockCA records the revocation options and serves a key store.
type renewingMockCA struct {
	configurableMockCA
	noKeyStore  bool
	revokeOpts  []xkmsca.RevokeOptions
	issuedCalls int
}

func (m *renewingMockCA) KeyStore() xkmsbackend.Backend {
	if m.noKeyStore {
		return nil
	}
	return m.configurableMockCA.KeyStore()
}

func (m *renewingMockCA) RevokeCert(ctx context.Context, cert *x509.Certificate, opts xkmsca.RevokeOptions) error {
	m.revokeOpts = append(m.revokeOpts, opts)
	return m.configurableMockCA.RevokeCert(ctx, cert, opts)
}

func (m *renewingMockCA) IssueCertificate(ctx context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	m.issuedCalls++
	return m.configurableMockCA.IssueCertificate(ctx, req)
}

// The SDK KMS keeps a deleted key's name reserved, so renewal must rotate the
// key under its name rather than delete it and generate a new one: a second
// renewal of the same CN failed with already_exists (#973).
func TestCAGRPCService_RenewCertificate_RenewTwiceRotatesKey(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificateWithSANs(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	keyStore := &rotatingKeyStore{}
	mockCA := &renewingMockCA{
		configurableMockCA: configurableMockCA{
			certStore:  &mockCertStore{certs: map[string]*x509.Certificate{serial: existingCert}},
			issuedCert: createTestCertificate(t),
			keyStore:   keyStore,
		},
	}
	svc := &CAGRPCService{ca: mockCA}

	for i := 0; i < 2; i++ {
		resp, err := svc.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{
			Serial:    serial,
			ValidDays: 365,
		})
		if err != nil {
			t.Fatalf("renewal %d: unexpected error: %v", i+1, err)
		}
		if !resp.GetStatus().GetSuccess() {
			t.Fatalf("renewal %d: expected success status", i+1)
		}
	}

	if len(mockCA.revokeOpts) != 2 {
		t.Fatalf("expected 2 revocations, got %d", len(mockCA.revokeOpts))
	}
	for i, opts := range mockCA.revokeOpts {
		if opts.DeleteKeys {
			t.Errorf("revocation %d deleted the key; renewal must keep its name", i+1)
		}
	}
	if len(keyStore.rotated) != 2 {
		t.Fatalf("expected 2 key rotations, got %d", len(keyStore.rotated))
	}
	for i, attrs := range keyStore.rotated {
		if attrs.CN != existingCert.Subject.CommonName || attrs.KeyAlgorithm != existingCert.PublicKeyAlgorithm {
			t.Errorf("rotation %d: got CN %q alg %v, want CN %q alg %v", i+1,
				attrs.CN, attrs.KeyAlgorithm, existingCert.Subject.CommonName, existingCert.PublicKeyAlgorithm)
		}
	}
}

func TestCAGRPCService_RenewCertificate_RotateKeyError(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificate(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	mockCA := &renewingMockCA{
		configurableMockCA: configurableMockCA{
			certStore:  &mockCertStore{certs: map[string]*x509.Certificate{serial: existingCert}},
			issuedCert: createTestCertificate(t),
			keyStore:   &rotatingKeyStore{rotateErr: errors.New("rotation refused")},
		},
	}
	svc := &CAGRPCService{ca: mockCA}

	_, err := svc.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	if mockCA.issuedCalls != 0 {
		t.Error("a failed rotation must not issue a certificate")
	}
}

func TestCAGRPCService_RenewCertificate_NoKeyStore(t *testing.T) {
	t.Parallel()

	existingCert := createTestCertificate(t)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	mockCA := &renewingMockCA{
		configurableMockCA: configurableMockCA{
			certStore: &mockCertStore{certs: map[string]*x509.Certificate{serial: existingCert}},
		},
		noKeyStore: true,
	}
	svc := &CAGRPCService{ca: mockCA}

	_, err := svc.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
	if len(mockCA.revokeOpts) != 0 {
		t.Error("renewal without a key store must not revoke")
	}
}

func TestCAGRPCService_VerifyCertificate_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{CertificatePem: []byte("test")})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_VerifyCertificate_Validation(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{ca: &mockCA{}}
	ctx := context.Background()

	t.Run("missing certificate", func(t *testing.T) {
		resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
			CertificatePem: []byte("not a valid PEM"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("invalid DER", func(t *testing.T) {
		resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
			CertificateDer: []byte("not valid DER"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertGRPCError(t, err, codes.InvalidArgument)
	})
}

func TestCAGRPCService_VerifyCertificate_ValidDER(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificateDer: leafCert.Raw,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestCAGRPCService_VerifyCertificate_ValidPEM(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: pemBlock,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestCAGRPCService_VerifyCertificate_WithIntermediate(t *testing.T) {
	t.Parallel()

	// Create a proper CA chain with keys
	rootCA := createTestCAWithKey(t, "Test Root CA")

	// Create intermediate CA signed by root
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	intermediateDER, _ := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCA.cert, &intermediateKey.PublicKey, rootCA.key)
	intermediateCert, _ := x509.ParseCertificate(intermediateDER)

	// Create leaf cert signed by intermediate
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot:  rootCA.cert,
		trustedInter: intermediateCert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: pemBlock,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestCAGRPCService_VerifyCertificate_ExpiredCert(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	expiredCert := createExpiredCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: expiredCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Valid {
		t.Error("expected invalid certificate for expired cert")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected errors for expired cert")
	}
}

func TestCAGRPCService_VerifyCertificate_NotYetValid(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	futureCert := createFutureCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: futureCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Warnings) == 0 {
		t.Error("expected warnings for not yet valid cert")
	}
}

func TestCAGRPCService_VerifyCertificate_WithTrustedRoots(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "External Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: pemBlock,
		TrustedRoots:   [][]byte{rootCA.cert.Raw},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate with trusted root, errors: %v", resp.Errors)
	}
}
func TestCAGRPCService_GetCRL_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_GetCRL_NotSupported(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	// configurableMockCA.GenerateCRL() returns "not supported" error, which is mapped to Unimplemented
	assertGRPCError(t, err, codes.Unimplemented)
}

func TestCAGRPCService_GetCRL_GenerateError(t *testing.T) {
	t.Parallel()

	mockCA := &mockCAWithCRL{
		configurableMockCA: configurableMockCA{},
		crlErr:             errors.New("CRL generation failed"),
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.Internal)
}

func TestCAGRPCService_GetCRL_Success(t *testing.T) {
	t.Parallel()

	crlDER := createTestCRL(t)

	mockCA := &mockCAWithCRL{
		configurableMockCA: configurableMockCA{},
		crlData:            crlDER,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Crl == nil {
		t.Fatal("expected CRL in response")
	}
	if len(resp.Crl.Data) == 0 {
		t.Error("expected CRL data")
	}
}

func TestCAGRPCService_GetCRL_WithEntries(t *testing.T) {
	t.Parallel()

	crlDER := createTestCRLWithEntries(t)

	mockCA := &mockCAWithCRL{
		configurableMockCA: configurableMockCA{},
		crlData:            crlDER,
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{
		IncludeEntries: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Crl.RevokedCount < 1 {
		t.Error("expected revoked entries in CRL")
	}
}

func TestCAGRPCService_GetCABundle_NilCA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(nil, nil, nil)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestCAGRPCService_GetCABundle_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundleErr: errors.New("bundle error"),
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.Internal)
}

func TestCAGRPCService_GetCABundle_EmptyBundle(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundle: []byte{},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertGRPCError(t, err, codes.NotFound)
}

func TestCAGRPCService_GetCABundle_Success(t *testing.T) {
	t.Parallel()

	rootCert := createTestCACertificate(t, "Test Root CA", nil, nil)

	bundlePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	})

	mockCA := &configurableMockCA{
		bundle:       bundlePEM,
		parsedBundle: []*x509.Certificate{rootCert},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Bundle == nil {
		t.Fatal("expected bundle in response")
	}
	if len(resp.Bundle.Pem) == 0 {
		t.Error("expected PEM data in bundle")
	}
}

// TestCAGRPCService_GetCABundle_UsesUnfilteredPath is a regression test for
// the production bug where GetCABundle called CABundleFiltered(StoreUnknown,
// 0) and the underlying CA returned "no certificates match filter". The gRPC
// service must always take the unfiltered path until the request grows
// store-type/key-algorithm filters.
func TestCAGRPCService_GetCABundle_UsesUnfilteredPath(t *testing.T) {
	t.Parallel()

	rootCert := createTestCACertificate(t, "Test Root CA", nil, nil)
	bundlePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	})

	mockCA := &configurableMockCA{
		bundle:            bundlePEM,
		parsedBundle:      []*x509.Certificate{rootCert},
		bundleFilteredErr: errors.New("ca: invalid certificate chain: no certificates match filter"),
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	if err != nil {
		t.Fatalf("GetCABundle returned %v; expected success via unfiltered CABundle()", err)
	}
	if resp == nil || resp.Bundle == nil || len(resp.Bundle.Pem) == 0 {
		t.Fatal("expected non-empty bundle in response")
	}
	if !mockCA.caBundleCalled {
		t.Error("CABundle() was never called; gRPC service did not take unfiltered path")
	}
	if mockCA.caBundleFilteredCalled {
		t.Error("CABundleFiltered() must not be called by GetCABundle; that path triggers the upstream filter bug")
	}
}

func TestCAGRPCService_GetCABundle_WithIntermediates(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	var bundlePEM []byte
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCA.cert.Raw,
	})...)
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediateCA.cert.Raw,
	})...)

	mockCA := &configurableMockCA{
		bundle:       bundlePEM,
		parsedBundle: []*x509.Certificate{rootCA.cert, intermediateCA.cert},
	}

	svc := &CAGRPCService{ca: mockCA}
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{
		IncludeIntermediates: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Bundle.CertCount < 2 {
		t.Errorf("expected at least 2 certs in bundle, got %d", resp.Bundle.CertCount)
	}
}

func TestCAGRPCService_ProtoKeyAlgorithmToX509(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		input    platformv1.KeyAlgorithm
		expected x509.PublicKeyAlgorithm
		wantErr  bool
	}{
		{"RSA 2048", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, x509.RSA, false},
		{"RSA 3072", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, x509.RSA, false},
		{"RSA 4096", platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, x509.RSA, false},
		{"ECDSA P256", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, x509.ECDSA, false},
		{"ECDSA P384", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, x509.ECDSA, false},
		{"ECDSA P521", platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521, x509.ECDSA, false},
		{"ED25519", platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, x509.Ed25519, false},
		{"Unspecified defaults to ECDSA", platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, x509.ECDSA, false},
		{"Invalid algorithm", platformv1.KeyAlgorithm(999), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := svc.protoKeyAlgorithmToX509(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tc.expected {
					t.Errorf("got %v, want %v", result, tc.expected)
				}
			}
		})
	}
}

func TestCAGRPCService_KeyAlgorithmToString(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		input    x509.PublicKeyAlgorithm
		expected string
	}{
		{x509.RSA, "RSA"},
		{x509.ECDSA, "ECDSA"},
		{x509.Ed25519, "ED25519"},
		{x509.DSA, "UNKNOWN"},
	}

	for _, tc := range tests {
		result := svc.keyAlgorithmToString(tc.input)
		if result != tc.expected {
			t.Errorf("keyAlgorithmToString(%v) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestCAGRPCService_X509KeyAlgorithmToProto(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		input    x509.PublicKeyAlgorithm
		expected platformv1.KeyAlgorithm
	}{
		{x509.RSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		{x509.ECDSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256},
		{x509.Ed25519, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519},
		{x509.DSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
	}

	for _, tc := range tests {
		result := svc.x509KeyAlgorithmToProto(tc.input)
		if result != tc.expected {
			t.Errorf("x509KeyAlgorithmToProto(%v) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

func TestCAGRPCService_CertStatusToProto(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}
	now := time.Now()

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected platformv1.CertificateStatus
	}{
		{
			"valid certificate",
			&x509.Certificate{
				NotBefore: now.Add(-time.Hour),
				NotAfter:  now.Add(time.Hour),
			},
			platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
		},
		{
			"not yet valid certificate",
			&x509.Certificate{
				NotBefore: now.Add(time.Hour),
				NotAfter:  now.Add(2 * time.Hour),
			},
			platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING,
		},
		{
			"expired certificate",
			&x509.Certificate{
				NotBefore: now.Add(-2 * time.Hour),
				NotAfter:  now.Add(-time.Hour),
			},
			platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.certStatusToProto(tc.cert)
			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestCAGRPCService_RevocationReasonToProto(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		input    int
		expected platformv1.RevocationReason
	}{
		{1, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE},
		{2, platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE},
		{3, platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED},
		{4, platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED},
		{5, platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION},
		{6, platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD},
		{8, platformv1.RevocationReason_REVOCATION_REASON_REMOVE_FROM_CRL},
		{9, platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN},
		{10, platformv1.RevocationReason_REVOCATION_REASON_AA_COMPROMISE},
		{0, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
		{99, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
	}

	for _, tc := range tests {
		result := svc.revocationReasonToProto(tc.input)
		if result != tc.expected {
			t.Errorf("revocationReasonToProto(%d) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

func TestCAGRPCService_ParseKeyUsage(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		input    []string
		expected x509.KeyUsage
	}{
		{
			"digital signature",
			[]string{"DIGITALSIGNATURE"},
			x509.KeyUsageDigitalSignature,
		},
		{
			"digital_signature with underscore",
			[]string{"DIGITAL_SIGNATURE"},
			x509.KeyUsageDigitalSignature,
		},
		{
			"multiple usages",
			[]string{"DIGITALSIGNATURE", "KEYENCIPHERMENT", "CERTSIGN"},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		},
		{
			"all usages",
			[]string{
				"DIGITALSIGNATURE", "CONTENTCOMMITMENT", "KEYENCIPHERMENT",
				"DATAENCIPHERMENT", "KEYAGREEMENT", "CERTSIGN",
				"CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY",
			},
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
		},
		{
			"underscore variants",
			[]string{
				"CONTENT_COMMITMENT", "KEY_ENCIPHERMENT", "DATA_ENCIPHERMENT",
				"KEY_AGREEMENT", "CERT_SIGN", "CRL_SIGN",
				"ENCIPHER_ONLY", "DECIPHER_ONLY",
			},
			x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
				x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
				x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
		},
		{
			"empty input",
			[]string{},
			0,
		},
		{
			"unknown usage ignored",
			[]string{"UNKNOWN"},
			0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.parseKeyUsage(tc.input)
			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestCAGRPCService_ParseExtKeyUsage(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		input    []string
		expected []x509.ExtKeyUsage
	}{
		{
			"server auth",
			[]string{"SERVERAUTH"},
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			"server_auth with underscore",
			[]string{"SERVER_AUTH"},
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			"multiple usages",
			[]string{"SERVERAUTH", "CLIENTAUTH", "CODESIGNING"},
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
		},
		{
			"all usages",
			[]string{"ANY", "SERVERAUTH", "CLIENTAUTH", "CODESIGNING", "EMAILPROTECTION", "TIMESTAMPING", "OCSPSIGNING"},
			[]x509.ExtKeyUsage{
				x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
			},
		},
		{
			"underscore variants",
			[]string{"CLIENT_AUTH", "CODE_SIGNING", "EMAIL_PROTECTION", "TIME_STAMPING", "OCSP_SIGNING"},
			[]x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping,
				x509.ExtKeyUsageOCSPSigning,
			},
		},
		{
			"empty input",
			[]string{},
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.parseExtKeyUsage(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("got length %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("index %d: got %v, want %v", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestCAGRPCService_KeyUsageToStrings(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		input    x509.KeyUsage
		expected []string
	}{
		{
			"digital signature",
			x509.KeyUsageDigitalSignature,
			[]string{"DIGITAL_SIGNATURE"},
		},
		{
			"multiple usages",
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"},
		},
		{
			"all usages",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			[]string{
				"DIGITAL_SIGNATURE", "CONTENT_COMMITMENT", "KEY_ENCIPHERMENT",
				"DATA_ENCIPHERMENT", "KEY_AGREEMENT", "CERT_SIGN",
				"CRL_SIGN", "ENCIPHER_ONLY", "DECIPHER_ONLY",
			},
		},
		{
			"no usages",
			0,
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.keyUsageToStrings(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("got length %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("index %d: got %q, want %q", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestCAGRPCService_ExtKeyUsageToStrings(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		input    []x509.ExtKeyUsage
		expected []string
	}{
		{
			"server auth",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			[]string{"SERVER_AUTH"},
		},
		{
			"multiple usages",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			[]string{"SERVER_AUTH", "CLIENT_AUTH"},
		},
		{
			"all usages",
			[]x509.ExtKeyUsage{
				x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
			},
			[]string{"ANY", "SERVER_AUTH", "CLIENT_AUTH", "CODE_SIGNING", "EMAIL_PROTECTION", "TIME_STAMPING", "OCSP_SIGNING"},
		},
		{
			"empty input",
			[]x509.ExtKeyUsage{},
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.extKeyUsageToStrings(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("got length %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("index %d: got %q, want %q", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestCAGRPCService_CertToProto(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	t.Run("nil certificate", func(t *testing.T) {
		result := svc.certToProto(nil, false, false)
		if result != nil {
			t.Error("expected nil")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createTestCertificate(t)
		result := svc.certToProto(cert, false, false)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Subject == nil {
			t.Error("expected subject")
		}
		if result.Subject.CommonName != "test.example.com" {
			t.Errorf("got CN %q, want 'test.example.com'", result.Subject.CommonName)
		}
		if result.IsCa != false {
			t.Error("expected non-CA cert")
		}
	})

	t.Run("with PEM", func(t *testing.T) {
		cert := createTestCertificate(t)
		result := svc.certToProto(cert, true, false)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if len(result.Pem) == 0 {
			t.Error("expected PEM data")
		}
		if len(result.Der) != 0 {
			t.Error("expected no DER data")
		}
	})

	t.Run("with DER", func(t *testing.T) {
		cert := createTestCertificate(t)
		result := svc.certToProto(cert, false, true)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if len(result.Pem) != 0 {
			t.Error("expected no PEM data")
		}
		if len(result.Der) == 0 {
			t.Error("expected DER data")
		}
	})

	t.Run("with SANs", func(t *testing.T) {
		cert := createTestCertificateWithSANs(t)
		result := svc.certToProto(cert, false, false)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Sans == nil {
			t.Fatal("expected SANs")
		}
		if len(result.Sans.DnsNames) == 0 {
			t.Error("expected DNS names")
		}
		if len(result.Sans.IpAddresses) == 0 {
			t.Error("expected IP addresses")
		}
	})
}

func TestCAGRPCService_CertToSummaryProto(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	t.Run("nil certificate", func(t *testing.T) {
		result := svc.certToSummaryProto(nil)
		if result != nil {
			t.Error("expected nil")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createTestCertificate(t)
		result := svc.certToSummaryProto(cert)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.CommonName != "test.example.com" {
			t.Errorf("got CN %q, want 'test.example.com'", result.CommonName)
		}
	})
}

func TestCAGRPCService_BuildVerifyStatusMessage(t *testing.T) {
	t.Parallel()

	svc := &CAGRPCService{}

	tests := []struct {
		name     string
		valid    bool
		errors   []string
		expected string
	}{
		{
			"valid",
			true,
			nil,
			"certificate verification successful",
		},
		{
			"invalid with errors",
			false,
			[]string{"some error"},
			"certificate verification failed: some error",
		},
		{
			"invalid without errors",
			false,
			nil,
			"certificate verification failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.buildVerifyStatusMessage(tc.valid, tc.errors)
			if result != tc.expected {
				t.Errorf("got %q, want %q", result, tc.expected)
			}
		})
	}
}

func TestFirstOrEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{"non-empty slice", []string{"first", "second"}, "first"},
		{"single element", []string{"only"}, "only"},
		{"empty slice", []string{}, ""},
		{"nil slice", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := firstOrEmpty(tc.input)
			if result != tc.expected {
				t.Errorf("got %q, want %q", result, tc.expected)
			}
		})
	}
}

// Helper functions

func assertGRPCError(t *testing.T, err error, expectedCode codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != expectedCode {
		t.Errorf("expected code %v, got %v: %s", expectedCode, st.Code(), st.Message())
	}
}

func createTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// testCA holds certificate and key for testing
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func createTestCertificateWithSANs(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses:        []string{"test@example.com"},
		URIs:                  []*url.URL{{Scheme: "https", Host: "example.com"}},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func createTestCACertificate(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	var certDER []byte
	if parent == nil {
		// Self-signed root
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	} else {
		// Signed by parent
		signingKey := parentKey
		if signingKey == nil {
			signingKey = key
		}
		certDER, err = x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signingKey)
	}
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return cert
}

// createTestCAWithKey creates a self-signed CA certificate and returns both cert and key
func createTestCAWithKey(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createIntermediateCAWithKey creates an intermediate CA signed by the parent CA
func createIntermediateCAWithKey(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createCertSignedByCA creates a certificate signed by the given CA
func createCertSignedByCA(t *testing.T, cn string, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createExpiredCertSignedByCA creates an expired certificate signed by the given CA
func createExpiredCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "expired.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-1 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createFutureCertSignedByCA creates a not-yet-valid certificate signed by the given CA
func createFutureCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "future.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func createTestCRL(t *testing.T) []byte {
	t.Helper()

	ca := createTestCAWithKey(t, "Test CRL CA")

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlDER
}

func createTestCRLWithEntries(t *testing.T) []byte {
	t.Helper()

	ca := createTestCAWithKey(t, "Test CRL CA")

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(12345),
				RevocationTime: time.Now(),
				ReasonCode:     1, // Key Compromise
			},
		},
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlDER
}

// mockCertStore is a simple mock for the cert store interface
type mockCertStore struct {
	certs  map[string]*x509.Certificate
	chains map[string][]*x509.Certificate
	crls   map[string]*x509.RevocationList
}

func (m *mockCertStore) GetCertificate(id string) (*x509.Certificate, error) {
	if cert, ok := m.certs[id]; ok {
		return cert, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	return nil
}

func (m *mockCertStore) DeleteCertificate(id string) error {
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, cert := range m.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}

func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	if chain, ok := m.chains[cn]; ok {
		return chain, nil
	}
	return nil, errors.New("chain not found")
}

func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error {
	return nil
}

func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	if crl, ok := m.crls[issuer]; ok {
		return crl, nil
	}
	return nil, errors.New("CRL not found")
}

func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}

func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}

func (m *mockCertStore) Close() error {
	return nil
}

// configurableMockCA is a mock CA with configurable responses.
// It implements ca.TCGCA by embedding baseMockCA and overriding the
// methods each test case exercises.
type configurableMockCA struct {
	baseMockCA
	// revokedOpts records the options each RevokeCert got.
	revokedOpts            []xkmsca.RevokeOptions
	keyStore               *rotatingKeyStore
	isInitialized          bool
	identity               string
	defaultKeyAlg          x509.PublicKeyAlgorithm
	defaultValidity        int
	trustedRoot            *x509.Certificate
	trustedInter           *x509.Certificate
	issuedCert             *x509.Certificate
	issueCertErr           error
	revokeErr              error
	bundleErr              error
	bundleFilteredErr      error
	bundle                 []byte
	parsedBundle           []*x509.Certificate
	certStore              xkmssdk.CertStore
	caBundleCalled         bool
	caBundleFilteredCalled bool
}

func (m *configurableMockCA) IsInitialized() bool { return m.isInitialized }
func (m *configurableMockCA) Identity() string    { return m.identity }
func (m *configurableMockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	if m.defaultKeyAlg == 0 {
		return x509.ECDSA
	}
	return m.defaultKeyAlg
}
func (m *configurableMockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA256
}
func (m *configurableMockCA) DefaultValidityPeriod() int {
	if m.defaultValidity == 0 {
		return 365
	}
	return m.defaultValidity
}
func (m *configurableMockCA) TrustedRoot() (*x509.Certificate, error) {
	return m.trustedRoot, nil
}
func (m *configurableMockCA) TrustedIntermediate() (*x509.Certificate, error) {
	return m.trustedInter, nil
}
func (m *configurableMockCA) CABundle() ([]byte, error) {
	m.caBundleCalled = true
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	return m.bundle, nil
}
func (m *configurableMockCA) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	m.caBundleFilteredCalled = true
	if m.bundleFilteredErr != nil {
		return nil, m.bundleFilteredErr
	}
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	return m.bundle, nil
}
func (m *configurableMockCA) ParseBundle(_ []byte) ([]*x509.Certificate, error) {
	return m.parsedBundle, nil
}
func (m *configurableMockCA) IssueCertificate(_ context.Context, _ *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	if m.issueCertErr != nil {
		return nil, m.issueCertErr
	}
	if m.issuedCert == nil {
		return nil, nil
	}
	return &xkmsca.IssuedCertificate{Certificate: m.issuedCert}, nil
}
func (m *configurableMockCA) RevokeCert(_ context.Context, _ *x509.Certificate, opts xkmsca.RevokeOptions) error {
	m.revokedOpts = append(m.revokedOpts, opts)
	return m.revokeErr
}
func (m *configurableMockCA) CertStore() xkmssdk.CertStore { return m.certStore }

// KeyStore serves the key store renewal rotates keys in; a throwaway one
// when the test does not inspect rotations.
func (m *configurableMockCA) KeyStore() xkmsbackend.Backend {
	if m.keyStore == nil {
		return &rotatingKeyStore{}
	}
	return m.keyStore
}
func (m *configurableMockCA) GenerateCRL(_ context.Context) ([]byte, error) {
	return nil, errors.New("CRL generation not supported")
}
func (m *configurableMockCA) IsRevoked(serial *big.Int) (bool, error) {
	return false, nil
}

// mockCAWithCRL extends configurableMockCA with CRL generation support
type mockCAWithCRL struct {
	configurableMockCA
	crlData []byte
	crlErr  error
}

func (m *mockCAWithCRL) GenerateCRL(_ context.Context) ([]byte, error) {
	if m.crlErr != nil {
		return nil, m.crlErr
	}
	return m.crlData, nil
}

// mockCA is a minimal CA mock for testing validation paths.
// Implements ca.TCGCA via baseMockCA.
type mockCA struct {
	baseMockCA
}

func (m *mockCA) IsInitialized() bool                                { return true }
func (m *mockCA) Identity() string                                   { return "test-ca" }
func (m *mockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm       { return x509.ECDSA }
func (m *mockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm { return x509.ECDSAWithSHA256 }
func (m *mockCA) DefaultValidityPeriod() int                         { return 365 }
