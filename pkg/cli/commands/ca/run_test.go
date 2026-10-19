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

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

var (
	testNotBefore = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	testNotAfter  = time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
)

// inProcCAServer is a CAService served over a Unix socket so the run*
// functions go through the real CLI base command, SDK client and gRPC
// transport. It records the last request and returns canned responses.
type inProcCAServer struct {
	platformv1.UnimplementedCAServiceServer
	mu   sync.Mutex
	last proto.Message
	fail error

	caInfo    *platformv1.CAInfo
	cert      *platformv1.Certificate
	summaries []*platformv1.CertificateSummary
	page      *platformv1.PaginationResponse
	revoke    *platformv1.RevokeCertificateResponse
	verify    *platformv1.VerifyCertificateResponse
	crl       *platformv1.CRL
	bundle    *platformv1.CABundle
	install   *platformv1.InstallCACertificatesResponse
	uninstall *platformv1.UninstallCACertificatesResponse
}

// record stores req as the last request and returns the configured failure.
func (s *inProcCAServer) record(req proto.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = req
	return s.fail
}

func (s *inProcCAServer) lastRequest() proto.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *inProcCAServer) GetCAInfo(_ context.Context, r *platformv1.GetCAInfoRequest) (*platformv1.GetCAInfoResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.GetCAInfoResponse{CaInfo: s.caInfo}, nil
}

func (s *inProcCAServer) InitCA(_ context.Context, r *platformv1.InitCARequest) (*platformv1.InitCAResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.InitCAResponse{CaInfo: s.caInfo}, nil
}

func (s *inProcCAServer) GetCertificate(_ context.Context, r *platformv1.GetCertificateRequest) (*platformv1.GetCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.GetCertificateResponse{Certificate: s.cert}, nil
}

func (s *inProcCAServer) ListCertificates(_ context.Context, r *platformv1.ListCertificatesRequest) (*platformv1.ListCertificatesResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.ListCertificatesResponse{Certificates: s.summaries, Pagination: s.page}, nil
}

func (s *inProcCAServer) IssueCertificate(_ context.Context, r *platformv1.IssueCertificateRequest) (*platformv1.IssueCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.IssueCertificateResponse{Certificate: s.cert}, nil
}

func (s *inProcCAServer) SignCSR(_ context.Context, r *platformv1.SignCSRRequest) (*platformv1.IssueCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.IssueCertificateResponse{Certificate: s.cert}, nil
}

func (s *inProcCAServer) RevokeCertificate(_ context.Context, r *platformv1.RevokeCertificateRequest) (*platformv1.RevokeCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return s.revoke, nil
}

func (s *inProcCAServer) RenewCertificate(_ context.Context, r *platformv1.RenewCertificateRequest) (*platformv1.RenewCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.RenewCertificateResponse{NewCertificate: s.cert}, nil
}

func (s *inProcCAServer) VerifyCertificate(_ context.Context, r *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return s.verify, nil
}

func (s *inProcCAServer) GetCRL(_ context.Context, r *platformv1.GetCRLRequest) (*platformv1.GetCRLResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.GetCRLResponse{Crl: s.crl}, nil
}

func (s *inProcCAServer) GetCABundle(_ context.Context, r *platformv1.GetCABundleRequest) (*platformv1.GetCABundleResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return &platformv1.GetCABundleResponse{Bundle: s.bundle}, nil
}

func (s *inProcCAServer) InstallCACertificates(_ context.Context, r *platformv1.InstallCACertificatesRequest) (*platformv1.InstallCACertificatesResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return s.install, nil
}

func (s *inProcCAServer) UninstallCACertificates(_ context.Context, r *platformv1.UninstallCACertificatesRequest) (*platformv1.UninstallCACertificatesResponse, error) {
	if err := s.record(r); err != nil {
		return nil, err
	}
	return s.uninstall, nil
}

// testCertificateProto is the certificate every canned response carries.
func testCertificateProto() *platformv1.Certificate {
	return &platformv1.Certificate{
		Serial:             "0A1B2C",
		Subject:            &platformv1.Subject{CommonName: "node-01.example.com", Organization: "Example"},
		Issuer:             "Example Issuing CA",
		NotBefore:          timestamppb.New(testNotBefore),
		NotAfter:           timestamppb.New(testNotAfter),
		Status:             platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
		KeyAlgorithm:       platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		SignatureAlgorithm: "ECDSA-SHA256",
		FingerprintSha256:  "AB:CD",
		Pem:                []byte(testCertPEM),
	}
}

// testCertificateDetails is printCertificateDetails' output for testCertificateProto.
func testCertificateDetails() string {
	cert := casvc.CertificateFromProto(testCertificateProto())
	return "Serial: 0A1B2C\n" +
		"Common Name: node-01.example.com\n" +
		"Organization: Example\n" +
		"Issuer: Example Issuing CA\n" +
		"Not Before: 2026-01-02 03:04:05 UTC\n" +
		"Not After: 2027-01-02 03:04:05 UTC\n" +
		"Status: " + string(cert.Status) + "\n" +
		"Key Algorithm: " + string(cert.KeyAlgorithm) + "\n" +
		"Signature Algorithm: ECDSA-SHA256\n" +
		"Is CA: No\n" +
		"SHA-256 Fingerprint: AB:CD\n"
}

// startCAServer serves an inProcCAServer and returns it with CLI flags,
// for a given output format, that point the CLI at it.
func startCAServer(t *testing.T) (*inProcCAServer, func(cli.OutputFormat) *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &inProcCAServer{cert: testCertificateProto()}
	gs := grpc.NewServer()
	platformv1.RegisterCAServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		require.NoError(t, <-served)
	})

	flags := func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
	return srv, flags
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w

	var buf bytes.Buffer
	copied := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(&buf, r)
		copied <- copyErr
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	require.NoError(t, <-copied)
	require.NoError(t, r.Close())
	return buf.String(), runErr
}

// decodeJSON decodes the JSON the CLI printed into a value of type T.
func decodeJSON[T any](t *testing.T, out string) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal([]byte(out), &v))
	return v
}

func TestRunInfo_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.caInfo = &platformv1.CAInfo{
		IsInitialized:       true,
		CommonName:          "Example Root CA",
		DefaultAlgorithm:    "ECDSA-P256",
		DefaultValidityDays: 365,
		RootCert:            &platformv1.CertificateSummary{Serial: "01", CommonName: "Example Root CA"},
	}

	out, err := captureStdout(t, func() error { return runInfo(flags(cli.OutputFormatTable)) })
	require.NoError(t, err)
	assert.Contains(t, out, "Initialized: Yes\nCommon Name: Example Root CA\nIs Intermediate: No\n"+
		"Default Algorithm: ECDSA-P256\nDefault Validity: 365 days\n")
	assert.Contains(t, out, "[INFO] Root Certificate:\n  Common Name: Example Root CA\n  Serial: 01\n")

	out, err = captureStdout(t, func() error { return runInfo(flags(cli.OutputFormatJSON)) })
	require.NoError(t, err)
	info := decodeJSON[casvc.CAInfo](t, out)
	assert.Equal(t, "Example Root CA", info.CommonName)
	assert.Equal(t, int32(365), info.DefaultValidityDays)
	require.NotNil(t, info.RootCert)
	assert.Equal(t, "01", info.RootCert.Serial)
}

func TestRunInit_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)

	out, err := captureStdout(t, func() error { return runInit(flags(cli.OutputFormatTable), true) })
	require.NoError(t, err)
	assert.Equal(t, "[INFO] CA initialized successfully (no info available)\n", out)
	assert.True(t, srv.lastRequest().(*platformv1.InitCARequest).Force)

	srv.caInfo = &platformv1.CAInfo{
		IsInitialized:       true,
		CommonName:          "Example Root CA",
		IsIntermediate:      true,
		DefaultAlgorithm:    "RSA-2048",
		DefaultValidityDays: 90,
		RootCert:            &platformv1.CertificateSummary{Serial: "01", CommonName: "Example Root CA"},
		Intermediates:       []*platformv1.CertificateSummary{{Serial: "02", CommonName: "Example Issuing CA"}},
	}
	out, err = captureStdout(t, func() error { return runInit(flags(cli.OutputFormatTable), false) })
	require.NoError(t, err)
	assert.Contains(t, out, "[INFO] Certificate Authority initialized successfully\n\n"+
		"Common Name: Example Root CA\nInitialized: Yes\nIs Intermediate: Yes\n"+
		"Default Algorithm: RSA-2048\nDefault Validity: 90 days\n")
	assert.Contains(t, out, "[INFO] Intermediate Certificates:\n  [1]\n    Common Name: Example Issuing CA\n    Serial: 02\n")
	assert.False(t, srv.lastRequest().(*platformv1.InitCARequest).Force)

	out, err = captureStdout(t, func() error { return runInit(flags(cli.OutputFormatYAML), false) })
	require.NoError(t, err)
	assert.Contains(t, out, "Example Root CA")
}

func TestRunCertificate_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)

	out, err := captureStdout(t, func() error { return runCertificate(flags(cli.OutputFormatTable), "0A1B2C", false, false) })
	require.NoError(t, err)
	assert.Equal(t, testCertificateDetails(), out)
	req := srv.lastRequest().(*platformv1.GetCertificateRequest)
	assert.Equal(t, "0A1B2C", req.Serial)
	assert.True(t, req.IncludePem, "table output always asks for the PEM")

	out, err = captureStdout(t, func() error { return runCertificate(flags(cli.OutputFormatTable), "0A1B2C", true, false) })
	require.NoError(t, err)
	assert.Equal(t, testCertPEM+"\n", out)

	out, err = captureStdout(t, func() error { return runCertificate(flags(cli.OutputFormatJSON), "0A1B2C", false, true) })
	require.NoError(t, err)
	req = srv.lastRequest().(*platformv1.GetCertificateRequest)
	assert.False(t, req.IncludePem)
	assert.True(t, req.IncludeDer)
	cert := decodeJSON[casvc.Certificate](t, out)
	assert.Equal(t, "0A1B2C", cert.Serial)
	assert.True(t, testNotAfter.Equal(cert.NotAfter))
}

func TestRunCertificate_NotFound(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.cert = nil

	err := runCertificate(flags(cli.OutputFormatJSON), "FFFF", false, false)

	var notFound ErrCertificateNotFound
	require.True(t, errors.As(err, &notFound))
	assert.Equal(t, "FFFF", notFound.Serial)
}

func TestRunList_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)

	out, err := captureStdout(t, func() error { return runList(flags(cli.OutputFormatTable), "", "", 1, 20) })
	require.NoError(t, err)
	assert.Equal(t, "[INFO] No certificates found\n", out)

	srv.summaries = []*platformv1.CertificateSummary{{
		Serial:       "0123456789ABCDEF0123",
		CommonName:   "node-01.example.com",
		Issuer:       "Example Issuing CA",
		NotAfter:     timestamppb.New(testNotAfter),
		Status:       platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
	}}
	srv.page = &platformv1.PaginationResponse{Page: 2, TotalPages: 3, TotalItems: 41}

	out, err = captureStdout(t, func() error {
		return runList(flags(cli.OutputFormatTable), "revoked", "Example Issuing CA", 2, 20)
	})
	require.NoError(t, err)
	assert.Contains(t, out, "0123456789ABC...")
	assert.Contains(t, out, "node-01.example.com")
	assert.Contains(t, out, "2027-01-02 03:04:05 UTC")
	assert.Contains(t, out, "Page: 2 of 3\nTotal: 41 certificates\n")

	req := srv.lastRequest().(*platformv1.ListCertificatesRequest)
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED, req.StatusFilter)
	assert.Equal(t, "Example Issuing CA", req.IssuerFilter)
	assert.Equal(t, uint32(2), req.Pagination.Page)
	assert.Equal(t, uint32(20), req.Pagination.PageSize)

	out, err = captureStdout(t, func() error { return runList(flags(cli.OutputFormatJSON), "all", "", 2, 20) })
	require.NoError(t, err)
	result := decodeJSON[casvc.ListCertificatesResult](t, out)
	require.Len(t, result.Certificates, 1)
	assert.Equal(t, "0123456789ABCDEF0123", result.Certificates[0].Serial)
	assert.Equal(t, uint64(41), result.TotalItems)
}

func TestRunList_InvalidStatus(t *testing.T) {
	srv, flags := startCAServer(t)

	err := runList(flags(cli.OutputFormatJSON), "bogus", "", 1, 20)

	var invalid ErrInvalidStatus
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "bogus", invalid.Status)
	assert.Nil(t, srv.lastRequest(), "an invalid filter never reaches the CA")
}

func TestRunList_FailureWrapsTheSDKError(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.fail = status.Error(codes.Unavailable, "ca offline")

	err := runList(flags(cli.OutputFormatJSON), "", "", 1, 20)

	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped))
	assert.Equal(t, "failed to list certificates", wrapped.Msg)
	var sdkErr *casvc.ErrListCertificatesFailed
	assert.True(t, errors.As(err, &sdkErr), "the SDK error stays reachable through Unwrap")
	assert.Contains(t, err.Error(), "ca offline")
}

func TestRunIssue_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)

	out, err := captureStdout(t, func() error {
		return runIssue(flags(cli.OutputFormatTable), "node-01.example.com", "pkcs8", "ecdsa-p256", 0, 30,
			"node-01.example.com, node-01", "10.0.0.1", "ops@example.com", "digitalSignature", "serverAuth,clientAuth")
	})
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Certificate issued successfully: 0A1B2C\n\n"+testCertificateDetails(), out)

	req := srv.lastRequest().(*platformv1.IssueCertificateRequest).Request
	assert.Equal(t, "node-01.example.com", req.Subject.CommonName)
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, req.KeyAlgorithm)
	assert.Equal(t, "pkcs8", req.StoreType)
	assert.Equal(t, int32(30), req.ValidDays)
	assert.Equal(t, []string{"node-01.example.com", "node-01"}, req.Sans.DnsNames)
	assert.Equal(t, []string{"10.0.0.1"}, req.Sans.IpAddresses)
	assert.Equal(t, []string{"ops@example.com"}, req.Sans.EmailAddresses)
	assert.Equal(t, []string{"digitalSignature"}, req.KeyUsage)
	assert.Equal(t, []string{"serverAuth", "clientAuth"}, req.ExtKeyUsage)

	out, err = captureStdout(t, func() error {
		return runIssue(flags(cli.OutputFormatJSON), "node-02", "", "rsa-2048", 2048, 90, "", "", "", "", "")
	})
	require.NoError(t, err)
	assert.Nil(t, srv.lastRequest().(*platformv1.IssueCertificateRequest).Request.Sans, "no SAN flags, no SANs")
	result := decodeJSON[casvc.IssueCertificateResult](t, out)
	require.NotNil(t, result.Certificate)
	assert.Equal(t, "0A1B2C", result.Certificate.Serial)

	srv.cert = nil
	out, err = captureStdout(t, func() error {
		return runIssue(flags(cli.OutputFormatTable), "node-03", "", "ed25519", 0, 30, "", "", "", "", "")
	})
	require.NoError(t, err)
	assert.Empty(t, out, "nothing to print when the CA returns no certificate")
}

func TestRunIssue_InvalidAlgorithm(t *testing.T) {
	srv, flags := startCAServer(t)

	err := runIssue(flags(cli.OutputFormatJSON), "node-01", "", "dsa-1024", 0, 30, "", "", "", "", "")

	var invalid ErrInvalidKeyAlgorithm
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "dsa-1024", invalid.Algorithm)
	assert.Nil(t, srv.lastRequest())
}

func TestRunRevoke_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	revokedAt := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	srv.revoke = &platformv1.RevokeCertificateResponse{
		Status:    &platformv1.Status{Success: true},
		Serial:    "0A1B2C",
		RevokedAt: timestamppb.New(revokedAt),
		Reason:    platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	}

	out, err := captureStdout(t, func() error {
		return runRevoke(flags(cli.OutputFormatTable), "0A1B2C", "key-compromise", true)
	})
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Certificate 0A1B2C revoked successfully\n"+
		"Reason: "+string(casvc.RevocationReasonKeyCompromise)+"\n"+
		"Revoked At: 2026-05-06 07:08:09 UTC\n"+
		"[INFO] Associated keys have been deleted\n", out)
	req := srv.lastRequest().(*platformv1.RevokeCertificateRequest)
	assert.Equal(t, "0A1B2C", req.Serial)
	assert.Equal(t, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, req.Reason)
	assert.True(t, req.DeleteKeys)

	out, err = captureStdout(t, func() error { return runRevoke(flags(cli.OutputFormatJSON), "0A1B2C", "superseded", false) })
	require.NoError(t, err)
	result := decodeJSON[casvc.RevokeCertificateResult](t, out)
	assert.True(t, result.Success)
	assert.True(t, revokedAt.Equal(result.RevokedAt))
}

func TestRunRevoke_NotRevoked(t *testing.T) {
	srv, flags := startCAServer(t)
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{"server message", "certificate is a CA", "[ERROR] Failed to revoke certificate: certificate is a CA\n"},
		{"no message", "", "[ERROR] Failed to revoke certificate: unknown error\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv.revoke = &platformv1.RevokeCertificateResponse{Status: &platformv1.Status{Message: tt.message}}
			out, err := captureStdout(t, func() error { return runRevoke(flags(cli.OutputFormatTable), "01", "", false) })
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestRunRevoke_InvalidReason(t *testing.T) {
	srv, flags := startCAServer(t)

	err := runRevoke(flags(cli.OutputFormatJSON), "01", "because", false)

	var invalid ErrInvalidRevocationReason
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "because", invalid.Reason)
	assert.Nil(t, srv.lastRequest())
}

func TestRunRenew_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)

	out, err := captureStdout(t, func() error { return runRenew(flags(cli.OutputFormatTable), "OLD01", 45, false) })
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Certificate renewed successfully\n\n"+
		"Old Serial: OLD01\nNew Serial: 0A1B2C\n"+testCertificateDetails(), out)
	req := srv.lastRequest().(*platformv1.RenewCertificateRequest)
	assert.Equal(t, "OLD01", req.Serial)
	assert.Equal(t, int32(45), req.ValidDays)
	assert.True(t, req.PreserveSans, "without --force the SANs are preserved")

	out, err = captureStdout(t, func() error { return runRenew(flags(cli.OutputFormatJSON), "OLD01", 45, true) })
	require.NoError(t, err)
	assert.False(t, srv.lastRequest().(*platformv1.RenewCertificateRequest).PreserveSans)
	result := decodeJSON[casvc.RenewCertificateResult](t, out)
	require.NotNil(t, result.NewCertificate)
	assert.Equal(t, "0A1B2C", result.NewCertificate.Serial)

	srv.cert = nil
	out, err = captureStdout(t, func() error { return runRenew(flags(cli.OutputFormatTable), "OLD01", 45, false) })
	require.NoError(t, err)
	assert.Equal(t, "[ERROR] Failed to renew certificate\n", out)
}

func TestRunVerify_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	certFile := filepath.Join(t.TempDir(), "node.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(testCertPEM), 0o600))
	srv.verify = &platformv1.VerifyCertificateResponse{
		Valid:    true,
		Chain:    []string{"node-01.example.com", "Example Root CA"},
		Warnings: []string{"expires in 20 days"},
	}

	out, err := captureStdout(t, func() error { return runVerify(flags(cli.OutputFormatTable), certFile, true, false) })
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] Certificate is valid\n\n"+
		"[INFO] Certificate Chain:\n  [0] node-01.example.com\n  [1] Example Root CA\n\n"+
		"[INFO] Warnings:\n  - expires in 20 days\n", out)
	req := srv.lastRequest().(*platformv1.VerifyCertificateRequest)
	assert.Equal(t, []byte(testCertPEM), req.CertificatePem)
	assert.True(t, req.VerifyRevocation)
	assert.False(t, req.VerifyExpiration)

	out, err = captureStdout(t, func() error { return runVerify(flags(cli.OutputFormatJSON), certFile, false, true) })
	require.NoError(t, err)
	result := decodeJSON[casvc.VerifyCertificateResult](t, out)
	assert.True(t, result.Valid)
	assert.Equal(t, []string{"node-01.example.com", "Example Root CA"}, result.Chain)
}

func TestRunVerify_MissingFile(t *testing.T) {
	srv, flags := startCAServer(t)

	err := runVerify(flags(cli.OutputFormatJSON), filepath.Join(t.TempDir(), "absent.pem"), true, true)

	var verifyErr ErrVerifyCertificateFailed
	require.True(t, errors.As(err, &verifyErr))
	assert.Contains(t, verifyErr.Reason, "failed to read certificate")
	assert.Nil(t, srv.lastRequest())
}

func TestRunCRL_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.crl = &platformv1.CRL{
		LastUpdate:   timestamppb.New(testNotBefore),
		NextUpdate:   timestamppb.New(testNotAfter),
		RevokedCount: 1,
		RevokedCerts: []*platformv1.RevokedCertEntry{{
			Serial:         "0A1B2C",
			RevocationTime: timestamppb.New(testNotBefore),
			Reason:         platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED,
		}},
	}

	out, err := captureStdout(t, func() error { return runCRL(flags(cli.OutputFormatTable), true) })
	require.NoError(t, err)
	assert.Equal(t, "Last Update: 2026-01-02 03:04:05 UTC\nNext Update: 2027-01-02 03:04:05 UTC\n"+
		"Revoked Certificates: 1\n\n[INFO] Revoked Certificates:\n"+
		"  Serial: 0A1B2C  Revoked: 2026-01-02 03:04:05 UTC  Reason: "+string(casvc.RevocationReasonSuperseded)+"\n", out)
	assert.True(t, srv.lastRequest().(*platformv1.GetCRLRequest).IncludeEntries)

	out, err = captureStdout(t, func() error { return runCRL(flags(cli.OutputFormatJSON), false) })
	require.NoError(t, err)
	assert.False(t, srv.lastRequest().(*platformv1.GetCRLRequest).IncludeEntries)
	crl := decodeJSON[casvc.CRL](t, out)
	assert.Equal(t, int32(1), crl.RevokedCount)
}

func TestRunCRLExport_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.crl = &platformv1.CRL{Data: []byte("crl-der-bytes")}
	output := filepath.Join(t.TempDir(), "ca.crl")

	out, err := captureStdout(t, func() error { return runCRLExport(flags(cli.OutputFormatTable), output) })
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] CRL exported to "+output+"\n", out)
	written, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, []byte("crl-der-bytes"), written)
	assert.False(t, srv.lastRequest().(*platformv1.GetCRLRequest).IncludeEntries)
}

func TestRunCRLExport_Errors(t *testing.T) {
	srv, flags := startCAServer(t)

	srv.crl = &platformv1.CRL{}
	err := runCRLExport(flags(cli.OutputFormatTable), filepath.Join(t.TempDir(), "ca.crl"))
	assert.True(t, errors.As(err, new(ErrCRLEmpty)))

	srv.crl = &platformv1.CRL{Data: []byte("crl")}
	err = runCRLExport(flags(cli.OutputFormatTable), filepath.Join(t.TempDir(), "missing-dir", "ca.crl"))
	var exportErr ErrCRLExportFailed
	require.True(t, errors.As(err, &exportErr))
	assert.Contains(t, exportErr.Reason, "missing-dir")
}

func TestRunBundle_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.bundle = &platformv1.CABundle{Pem: []byte(testCertPEM), CertCount: 2}

	out, err := captureStdout(t, func() error { return runBundle(flags(cli.OutputFormatTable), "", true) })
	require.NoError(t, err)
	assert.Equal(t, testCertPEM, out, "without --output the bundle is the whole of stdout")
	assert.True(t, srv.lastRequest().(*platformv1.GetCABundleRequest).IncludeIntermediates)

	output := filepath.Join(t.TempDir(), "bundle.pem")
	out, err = captureStdout(t, func() error { return runBundle(flags(cli.OutputFormatTable), output, false) })
	require.NoError(t, err)
	assert.Equal(t, "[SUCCESS] CA bundle written to "+output+"\nCertificates: 2\n", out)
	written, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, []byte(testCertPEM), written)

	out, err = captureStdout(t, func() error { return runBundle(flags(cli.OutputFormatJSON), output, false) })
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"success": true, "output": output, "cert_count": float64(2)},
		decodeJSON[map[string]any](t, out))
}

func TestRunBundle_Errors(t *testing.T) {
	srv, flags := startCAServer(t)

	srv.bundle = &platformv1.CABundle{}
	err := runBundle(flags(cli.OutputFormatTable), "", false)
	assert.True(t, errors.As(err, new(ErrBundleEmpty)))

	srv.bundle = &platformv1.CABundle{Pem: []byte(testCertPEM), CertCount: 1}
	err = runBundle(flags(cli.OutputFormatTable), filepath.Join(t.TempDir(), "missing-dir", "bundle.pem"), false)
	var bundleErr ErrCABundleFailed
	require.True(t, errors.As(err, &bundleErr))
	assert.Contains(t, bundleErr.Reason, "failed to write bundle")
}

func TestRunInstall_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.install = &platformv1.InstallCACertificatesResponse{CertificatesInstalled: 2, InstallPath: "/usr/local/share/ca-certificates"}

	out, err := captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), true) })
	require.NoError(t, err)
	assert.Equal(t, "[INFO] CA certificates installed successfully\n\n"+
		"Certificates Installed: 2\nInstall Path: /usr/local/share/ca-certificates\n", out)
	assert.True(t, srv.lastRequest().(*platformv1.InstallCACertificatesRequest).IncludeIntermediates)

	srv.install = &platformv1.InstallCACertificatesResponse{CertificatesInstalled: 1}
	out, err = captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatTable), false) })
	require.NoError(t, err)
	assert.Equal(t, "[INFO] CA certificates installed successfully\n\nCertificates Installed: 1\n", out,
		"no install path line when the daemon reports none")

	out, err = captureStdout(t, func() error { return runInstall(flags(cli.OutputFormatJSON), false) })
	require.NoError(t, err)
	assert.Equal(t, int32(1), decodeJSON[casvc.InstallResult](t, out).CertificatesInstalled)
}

func TestRunUninstall_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.uninstall = &platformv1.UninstallCACertificatesResponse{CertificatesRemoved: 3}

	out, err := captureStdout(t, func() error { return runUninstall(flags(cli.OutputFormatTable), true) })
	require.NoError(t, err)
	assert.Equal(t, "[INFO] CA certificates uninstalled successfully\n\nCertificates Removed: 3\n", out)
	assert.True(t, srv.lastRequest().(*platformv1.UninstallCACertificatesRequest).IncludeIntermediates)

	out, err = captureStdout(t, func() error { return runUninstall(flags(cli.OutputFormatJSON), false) })
	require.NoError(t, err)
	assert.False(t, srv.lastRequest().(*platformv1.UninstallCACertificatesRequest).IncludeIntermediates)
	assert.Equal(t, int32(3), decodeJSON[casvc.UninstallResult](t, out).CertificatesRemoved)
}

func TestRunSignCSR_InProcess(t *testing.T) {
	srv, flags := startCAServer(t)
	csrFile := filepath.Join(t.TempDir(), "fleet.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr-pem"), 0o600))

	out, err := captureStdout(t, func() error {
		return runSignCSR(flags(cli.OutputFormatTable), csrFile, signCSROptions{validDays: 7})
	})
	require.NoError(t, err)
	assert.Equal(t, testCertPEM, out, "the PEM is trimmed, then printed with one newline")
	req := srv.lastRequest().(*platformv1.SignCSRRequest)
	assert.Equal(t, "csr-pem", req.CsrPem)
	assert.Equal(t, int32(7), req.ValidDays)

	srv.cert = nil
	err = runSignCSR(flags(cli.OutputFormatTable), csrFile, signCSROptions{})
	assert.True(t, errors.As(err, new(ErrNoCertificateIssued)))
}

func TestCommands_FlagsReachTheRequest(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.bundle = &platformv1.CABundle{Pem: []byte(testCertPEM), CertCount: 1}
	csrFile := filepath.Join(t.TempDir(), "fleet.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr-pem"), 0o600))
	getFlags := func() *cli.CommonFlags { return flags(cli.OutputFormatTable) }

	bundle := newBundleCommand(getFlags)
	bundle.SetArgs([]string{"--intermediates=false"})
	_, err := captureStdout(t, bundle.Execute)
	require.NoError(t, err)
	assert.False(t, srv.lastRequest().(*platformv1.GetCABundleRequest).IncludeIntermediates)

	signCSR := newSignCSRCommand(getFlags)
	signCSR.SetArgs([]string{csrFile, "--valid-days", "14"})
	_, err = captureStdout(t, signCSR.Execute)
	require.NoError(t, err)
	assert.Equal(t, int32(14), srv.lastRequest().(*platformv1.SignCSRRequest).ValidDays)
}

// caRunners invokes every daemon-backed run* function with valid arguments.
func caRunners(t *testing.T) map[string]func(*cli.CommonFlags) error {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(testCertPEM), 0o600))
	csrFile := filepath.Join(dir, "fleet.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr-pem"), 0o600))
	output := filepath.Join(dir, "out")

	return map[string]func(*cli.CommonFlags) error{
		"info":        func(f *cli.CommonFlags) error { return runInfo(f) },
		"init":        func(f *cli.CommonFlags) error { return runInit(f, false) },
		"certificate": func(f *cli.CommonFlags) error { return runCertificate(f, "01", false, false) },
		"list":        func(f *cli.CommonFlags) error { return runList(f, "", "", 1, 20) },
		"issue": func(f *cli.CommonFlags) error {
			return runIssue(f, "node", "", "ecdsa-p256", 0, 30, "", "", "", "", "")
		},
		"revoke":     func(f *cli.CommonFlags) error { return runRevoke(f, "01", "", false) },
		"renew":      func(f *cli.CommonFlags) error { return runRenew(f, "01", 30, false) },
		"verify":     func(f *cli.CommonFlags) error { return runVerify(f, certFile, true, true) },
		"crl":        func(f *cli.CommonFlags) error { return runCRL(f, false) },
		"crl-export": func(f *cli.CommonFlags) error { return runCRLExport(f, output) },
		"bundle":     func(f *cli.CommonFlags) error { return runBundle(f, output, false) },
		"install":    func(f *cli.CommonFlags) error { return runInstall(f, false) },
		"uninstall":  func(f *cli.CommonFlags) error { return runUninstall(f, false) },
		"sign-csr":   func(f *cli.CommonFlags) error { return runSignCSR(f, csrFile, signCSROptions{}) },
	}
}

func TestRunCommands_ServerFailure(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.fail = status.Error(codes.Unavailable, "ca offline")

	want := map[string]any{
		"info":        new(ErrGetCAInfoFailed),
		"init":        new(ErrInitCAFailed),
		"certificate": new(ErrGetCertificateFailed),
		"list":        new(*WrappedError),
		"issue":       new(ErrIssueCertificateFailed),
		"revoke":      new(ErrRevokeCertificateFailed),
		"renew":       new(ErrRenewCertificateFailed),
		"verify":      new(ErrVerifyCertificateFailed),
		"crl":         new(ErrGetCRLFailed),
		"crl-export":  new(ErrGetCRLFailed),
		"bundle":      new(ErrCABundleFailed),
		"install":     new(ErrInstallCertificatesFailed),
		"uninstall":   new(ErrUninstallCertificatesFailed),
		"sign-csr":    new(ErrIssueCertificateFailed),
	}
	for name, run := range caRunners(t) {
		t.Run(name, func(t *testing.T) {
			err := run(flags(cli.OutputFormatJSON))
			require.Error(t, err)
			assert.True(t, errors.As(err, want[name]), "got %T: %v", err, err)
			assert.Contains(t, err.Error(), "ca offline")
		})
	}
}

func TestRunCommands_InvalidOutputFormat(t *testing.T) {
	srv, flags := startCAServer(t)
	srv.caInfo = &platformv1.CAInfo{CommonName: "Example Root CA"}
	srv.revoke = &platformv1.RevokeCertificateResponse{Status: &platformv1.Status{Success: true}}
	srv.verify = &platformv1.VerifyCertificateResponse{Valid: true}
	srv.crl = &platformv1.CRL{Data: []byte("crl")}
	srv.bundle = &platformv1.CABundle{Pem: []byte(testCertPEM), CertCount: 1}
	srv.install = &platformv1.InstallCACertificatesResponse{}
	srv.uninstall = &platformv1.UninstallCACertificatesResponse{}

	// crl export and bundle write a file whatever the format, and only
	// choose how to report it; every other command rejects the format.
	accepts := map[string]bool{"crl-export": true, "bundle": true}
	for name, run := range caRunners(t) {
		t.Run(name, func(t *testing.T) {
			_, err := captureStdout(t, func() error { return run(flags(cli.OutputFormat("xml"))) })
			if accepts[name] {
				assert.NoError(t, err)
				return
			}
			var formatErr cli.ErrInvalidOutputFormat
			require.True(t, errors.As(err, &formatErr), "got %T: %v", err, err)
			assert.Equal(t, "xml", formatErr.Format)
		})
	}
}
