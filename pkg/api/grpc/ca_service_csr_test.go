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

package grpc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// csrMockCA certifies CSRs for real, so a test can check whose key the
// certificate holds.
type csrMockCA struct {
	configurableMockCA
	signer *issuancetest.CA
}

func (m *csrMockCA) SignCSR(ctx context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	return m.signer.SignCSR(ctx, csrPEM, opts)
}

// adminCtx is the context of a caller whose platform token grants
// ca:sign-csr.
func adminCtx() context.Context {
	return withScopes("ca:sign-csr")
}

func withScopes(scopes ...string) context.Context {
	return ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Subject: "u", Scopes: scopes})
}

// Signing a CSR certifies a key for code signing, so only the platform
// admin may: a token granting ca:sign-csr, or root on the Unix socket.
// ca:write, and authentication without a platform token (mTLS, a legacy
// validator), are refused before the CA sees the request.
func TestSignCSR_OnlyThePlatformAdmin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"no platform token", context.Background(), codes.PermissionDenied},
		{"ca:write", withScopes("ca:write"), codes.PermissionDenied},
		{"every other ca scope", withScopes("ca:read", "ca:write", "ca:delete", "kms:write"), codes.PermissionDenied},
		{"Unix socket, not root", peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 1000}), codes.PermissionDenied},
		{"ca:sign-csr", withScopes("ca:sign-csr"), codes.OK},
		{"ca:*", withScopes("ca:*"), codes.OK},
		{"Unix socket, root", peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 0}), codes.OK},
	}
	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{signer: issuancetest.NewCA(t)}
			svc := NewCAGRPCService(createTestLogger(), ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

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

// The embedded transport runs no interceptors: the embedder states who is
// calling through the registry's CallerContext, and sign-csr then decides as
// it does on the Unix socket. Without one the call carries no identity and
// is refused.
func TestSignCSR_OverTheEmbeddedTransport(t *testing.T) {
	t.Parallel()

	as := func(creds peercred.UnixCredentials) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			return peercred.ContextWithUnixCredentials(ctx, creds)
		}
	}
	cases := []struct {
		name   string
		caller func(context.Context) context.Context
		ctx    context.Context
		code   codes.Code
	}{
		{"no caller identity", nil, context.Background(), codes.PermissionDenied},
		{"embedder is not root", as(peercred.UnixCredentials{UID: 1000}), context.Background(), codes.PermissionDenied},
		{"embedder is root", as(peercred.UnixCredentials{UID: 0}), context.Background(), codes.OK},
		{"ca:sign-csr token, no caller identity", nil, adminCtx(), codes.OK},
	}
	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{signer: issuancetest.NewCA(t)}
			svc := NewCAGRPCService(createTestLogger(), ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))
			adapter, err := embedded.New(&embedded.ServiceRegistry{CA: svc, CallerContext: tc.caller})
			if err != nil {
				t.Fatalf("embedded.New: %v", err)
			}

			_, err = platformv1.NewCAServiceClient(adapter.Connection()).SignCSR(tc.ctx, &platformv1.SignCSRRequest{CsrPem: csr})
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.code)
			}
			if reached := ca.signer.Opts != nil; reached != (tc.code == codes.OK) {
				t.Errorf("reached the CA = %v", reached)
			}
		})
	}
}

func TestErrSignCSRNotRoot(t *testing.T) {
	t.Parallel()

	err := AuthorizeSignCSR(peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 1000}))
	if want := "signing a CSR over the Unix socket requires root, but the caller is uid 1000"; status.Convert(err).Message() != want {
		t.Errorf("message = %q, want %q", status.Convert(err).Message(), want)
	}
}

func TestSignCSR_CertifiesTheKMSKey(t *testing.T) {
	t.Parallel()

	ca := &csrMockCA{signer: issuancetest.NewCA(t)}
	key := issuancetest.RSAKey(t)
	svc := NewCAGRPCService(createTestLogger(), ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

	resp, err := svc.SignCSR(adminCtx(), &platformv1.SignCSRRequest{
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
	if ca.signer.Opts.ValidityDays != 30 {
		t.Errorf("sign options = %+v", ca.signer.Opts)
	}
}

func TestSignCSR_Errors(t *testing.T) {
	t.Parallel()

	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	other := string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet"))
	cases := []struct {
		name    string
		csr     string
		noKMS   bool
		caErr   error
		code    codes.Code
		reached bool
	}{
		{"malformed CSR", "not a csr", false, nil, codes.InvalidArgument, false},
		{"key is not the KMS key", other, false, nil, codes.InvalidArgument, false},
		{"no KMS", csr, true, nil, codes.Internal, false},
		{"CA failure", csr, false, errors.New("sealed"), codes.Internal, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{signer: issuancetest.NewCA(t)}
			ca.signer.Err = tc.caErr
			svc := NewCAGRPCService(createTestLogger(), ca, nil)
			if !tc.noKMS {
				svc.WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))
			}
			_, err := svc.SignCSR(adminCtx(), &platformv1.SignCSRRequest{CsrPem: tc.csr})
			assertGRPCError(t, err, tc.code)
			if reached := ca.signer.Opts != nil; reached != tc.reached {
				t.Errorf("reached the CA = %v, want %v", reached, tc.reached)
			}
		})
	}
}

func TestSignCSR_WithoutACA(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(createTestLogger(), nil, nil)
	_, err := svc.SignCSR(adminCtx(), &platformv1.SignCSRRequest{CsrPem: "x"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

// "kms" names no key store; it used to fall back to a new software key.
func TestIssueCertificate_UnknownStoreType(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(createTestLogger(), &configurableMockCA{}, nil)
	_, err := svc.IssueCertificate(context.Background(), &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject:   &platformv1.Subject{CommonName: "rpi/fleet"},
			StoreType: "kms",
		},
	})
	assertGRPCError(t, err, codes.InvalidArgument)
}
