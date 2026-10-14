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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restca "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ca"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// The SDK REST transport has one CA wire format: pb proto-JSON. Two servers
// speak it — the daemon's REST routes (pkg/api/rest), bare, and the CA
// webservice (pkg/webservice/v1/rest/ca), inside the WebServiceResponse
// envelope. These tests drive the same SDK client against both real handlers,
// built from their production constructors over one CA, and require the same
// answers from each.

// signingCA is the parity CA with a real CSR signer behind it.
type signingCA struct {
	*recordingCA
	signer *issuancetest.CA
}

func (c *signingCA) SignCSR(ctx context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	return c.signer.SignCSR(ctx, csrPEM, opts)
}

// tokenScopes maps a bearer token to the scopes it was granted. Both servers
// read the same table, so a token means the same thing to each.
type tokenScopes map[string][]string

func (s tokenScopes) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	scopes, ok := s[token]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unknown token")
	}
	return &platformtoken.AuthorizedContext{Subject: token, Scopes: scopes}, nil
}

// authorize stands in for the webservice's IAM middleware: it resolves the
// bearer token and attaches the authorized context the CA handlers read.
func (s tokenScopes) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if authCtx, err := s.AuthorizeToken(r.Context(), token, "", "", "", ""); err == nil {
			r = r.WithContext(iammw.SetAuthorizedContext(r.Context(), authCtx))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope is the webservice's scope check over the authorized context
// authorize attached: 401 without one, 403 when the scope is missing.
func (s tokenScopes) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, ok := iammw.AuthorizedContextFromRequest(r)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !slices.Contains(authCtx.Scopes, scope) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

const (
	signerToken   = "signer"
	readerToken   = "reader"
	renewToken    = "renewer"
	revokeToken   = "revoker"
	verifyToken   = "verifier"
	csrKeyID      = "rpi/fleet"
	unknownSerial = "dead0001"
)

type caWireServer struct {
	name  string
	build func(ca *signingCA, kms issuance.KMS, tokens tokenScopes) http.Handler
}

var caWireServers = []caWireServer{
	{name: "daemon", build: func(ca *signingCA, kms issuance.KMS, tokens tokenScopes) http.Handler {
		router := mux.NewRouter()
		restapi.NewCAHandlers(restapi.NewCAAuthorityAdapter(ca), nil, nil).
			WithKMS(kms).
			WithTokenAuthorizer(tokens).
			RegisterRoutes(router)
		return router
	}},
	{name: "webservice", build: func(ca *signingCA, kms issuance.KMS, tokens tokenScopes) http.Handler {
		router := mux.NewRouter()
		logger := logging.DefaultLogger()
		restca.NewCARouter(logger, ca, response.NewResponseWriter(logger, nil)).
			WithKMS(kms).
			RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
		return tokens.authorize(router)
	}},
}

// caWebServiceServer is the CA webservice as the daemon wires it for the
// certificate item routes: renew and verify call the CA service gRPC serves,
// and renew, revoke and verify each demand their scope.
var caWebServiceServer = caWireServer{name: "webservice", build: func(ca *signingCA, kms issuance.KMS, tokens tokenScopes) http.Handler {
	router := mux.NewRouter()
	logger := logging.DefaultLogger()
	caRouter := restca.NewCARouter(logger, ca, response.NewResponseWriter(logger, nil)).
		WithKMS(kms).
		WithService(NewCAGRPCService(logger, ca, nil))
	caRouter.SetScopeAuthorizer(tokens)
	caRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return tokens.authorize(router)
}}

// caWireClient serves handler over TLS, with the /health/live route the SDK probes
// on Connect, and returns an SDK REST CA client presenting token.
func caWireClient(t *testing.T, f *caParityFixture, handler http.Handler, token string) platformv1.CAServiceClient {
	t.Helper()
	routes := http.NewServeMux()
	routes.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	routes.Handle("/", handler)
	srv := httptest.NewUnstartedServer(routes)
	srv.TLS = f.tls.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(srv.URL),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
		platform.WithBearerToken(token),
	))
	return connect(t, adapter, err)
}

type caWireFixture struct {
	*caParityFixture
	ca     *signingCA
	kms    issuance.KMS
	tokens tokenScopes
	key    *rsa.PrivateKey
}

func newCAWireFixture(t *testing.T) *caWireFixture {
	t.Helper()
	f := newCAParityFixture(t)
	key := issuancetest.RSAKey(t)
	return &caWireFixture{
		caParityFixture: f,
		ca:              &signingCA{recordingCA: f.ca, signer: issuancetest.NewCA(t)},
		kms:             issuancetest.NewKMS(t, csrKeyID, &key.PublicKey),
		tokens: tokenScopes{
			signerToken: {issuance.SignCSRScope},
			readerToken: {"ca:read"},
			renewToken:  {restca.RenewScope},
			revokeToken: {restca.RevokeScope},
			verifyToken: {restca.VerifyScope},
		},
		key: key,
	}
}

func (f *caWireFixture) client(t *testing.T, server caWireServer, token string) platformv1.CAServiceClient {
	t.Helper()
	return caWireClient(t, f.caParityFixture, server.build(f.ca, f.kms, f.tokens), token)
}

func TestCARESTWire_IssueCertificate(t *testing.T) {
	for _, server := range caWireServers {
		t.Run(server.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, server, signerToken)

			resp, err := client.IssueCertificate(context.Background(), &platformv1.IssueCertificateRequest{
				Request: &platformv1.CertificateRequest{
					Subject:      &platformv1.Subject{CommonName: "parity.example", Organization: "Parity Org"},
					KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
					ValidDays:    30,
					Sans:         &platformv1.SubjectAlternativeNames{DnsNames: []string{"parity.example"}},
				},
			})
			require.NoError(t, err)
			assert.True(t, resp.GetStatus().GetSuccess())
			assert.NotNil(t, resp.GetTimestamp())
			cert := resp.GetCertificate()
			assert.Equal(t, f.serial, cert.GetSerial())
			assert.Equal(t, "parity.example", cert.GetSubject().GetCommonName())
			assert.Equal(t, []string{"parity.example"}, cert.GetSans().GetDnsNames())
			assert.Contains(t, string(cert.GetPem()), "BEGIN CERTIFICATE")

			got := f.ca.last.Load()
			require.NotNil(t, got, "the request reached the CA")
			assert.Equal(t, "parity.example", got.Subject.CommonName)
			assert.Equal(t, "Parity Org", got.Subject.Organization)
			assert.Equal(t, 30, got.Valid)
			assert.Equal(t, x509.ECDSA, got.KeyAttributes.KeyAlgorithm)
		})
	}
}

func TestCARESTWire_IssueCertificate_Refused(t *testing.T) {
	for _, server := range caWireServers {
		t.Run(server.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, server, signerToken)

			_, err := client.IssueCertificate(context.Background(), &platformv1.IssueCertificateRequest{
				Request: &platformv1.CertificateRequest{Subject: &platformv1.Subject{}},
			})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "a request without a common name: %v", err)
			assert.Nil(t, f.ca.last.Load(), "a refused request never reaches the CA")
		})
	}
}

func TestCARESTWire_GetCertificate(t *testing.T) {
	for _, server := range caWireServers {
		t.Run(server.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, server, readerToken)

			resp, err := client.GetCertificate(context.Background(), &platformv1.GetCertificateRequest{
				Serial:     f.serial,
				IncludePem: true,
				IncludeDer: true,
			})
			require.NoError(t, err)
			assert.NotNil(t, resp.GetTimestamp())
			cert := resp.GetCertificate()
			assert.Equal(t, f.serial, cert.GetSerial())
			assert.Equal(t, "parity.example", cert.GetSubject().GetCommonName())
			assert.Contains(t, string(cert.GetPem()), "BEGIN CERTIFICATE")
			assert.Equal(t, f.ca.issuedCert.Raw, cert.GetDer())

			bare, err := client.GetCertificate(context.Background(), &platformv1.GetCertificateRequest{Serial: f.serial})
			require.NoError(t, err)
			assert.Empty(t, bare.GetCertificate().GetPem(), "PEM only when asked for")
			assert.Empty(t, bare.GetCertificate().GetDer(), "DER only when asked for")
		})
	}
}

func TestCARESTWire_GetCertificate_NotFound(t *testing.T) {
	for _, server := range caWireServers {
		t.Run(server.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, server, readerToken)

			_, err := client.GetCertificate(context.Background(), &platformv1.GetCertificateRequest{Serial: "deadbeef"})
			assert.Equal(t, codes.NotFound, status.Code(err), "an unknown serial: %v", err)
		})
	}
}

func TestCARESTWire_SignCSR(t *testing.T) {
	for _, server := range caWireServers {
		t.Run(server.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, server, signerToken)

			resp, err := client.SignCSR(context.Background(), &platformv1.SignCSRRequest{
				CsrPem:    string(issuancetest.CSR(t, f.key, csrKeyID)),
				ValidDays: 7,
			})
			require.NoError(t, err)
			assert.True(t, resp.GetStatus().GetSuccess())
			block, _ := pem.Decode(resp.GetCertificate().GetPem())
			require.NotNil(t, block, "the response carries the certificate PEM")
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, csrKeyID, cert.Subject.CommonName)
			assert.True(t, f.key.PublicKey.Equal(cert.PublicKey), "the certificate certifies the KMS key")
			assert.Equal(t, f.ca.signer.Root.Subject, cert.Issuer)
		})
	}
}

func TestCARESTWire_SignCSR_Refused(t *testing.T) {
	cases := []struct {
		name  string
		token string
		csr   func(f *caWireFixture) string
		want  codes.Code
	}{
		{"without the sign-csr scope", readerToken, func(f *caWireFixture) string {
			return string(issuancetest.CSR(t, f.key, csrKeyID))
		}, codes.PermissionDenied},
		{"a key that is not the KMS key", signerToken, func(*caWireFixture) string {
			return string(issuancetest.CSR(t, issuancetest.RSAKey(t), csrKeyID))
		}, codes.InvalidArgument},
		{"not a CSR", signerToken, func(*caWireFixture) string {
			return "not a csr"
		}, codes.InvalidArgument},
	}
	for _, server := range caWireServers {
		for _, tc := range cases {
			t.Run(server.name+"/"+tc.name, func(t *testing.T) {
				f := newCAWireFixture(t)
				client := f.client(t, server, tc.token)

				_, err := client.SignCSR(context.Background(), &platformv1.SignCSRRequest{CsrPem: tc.csr(f)})
				assert.Equal(t, tc.want, status.Code(err), "%v", err)
			})
		}
	}
}

// The certificate item operations — revoke, renew and verify — are claimed
// by the SDK on the web service's routes, so they are driven against it.

func TestCARESTWire_RevokeCertificate(t *testing.T) {
	f := newCAWireFixture(t)
	client := f.client(t, caWebServiceServer, revokeToken)

	resp, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{
		Serial: f.serial,
		Reason: platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, f.serial, resp.GetSerial())
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED, resp.GetCertificateStatus())
	assert.Equal(t, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, resp.GetReason())
	assert.NotNil(t, resp.GetRevokedAt())
}

func TestCARESTWire_RenewCertificate(t *testing.T) {
	f := newCAWireFixture(t)
	client := f.client(t, caWebServiceServer, renewToken)

	resp, err := client.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{
		Serial:    f.serial,
		ValidDays: 30,
	})
	require.NoError(t, err)
	assert.Equal(t, f.serial, resp.GetOldCertificate().GetSerial())
	assert.Equal(t, "parity.example", resp.GetNewCertificate().GetSubject().GetCommonName())

	got := f.ca.last.Load()
	require.NotNil(t, got, "the renewal reached the CA")
	assert.Equal(t, "parity.example", got.Subject.CommonName)
	assert.Equal(t, 30, got.Valid)
}

func TestCARESTWire_VerifyCertificate(t *testing.T) {
	f := newCAWireFixture(t)
	client := f.client(t, caWebServiceServer, verifyToken)

	resp, err := client.VerifyCertificate(context.Background(), &platformv1.VerifyCertificateRequest{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.issuedCert.Raw}),
	})
	require.NoError(t, err)
	assert.True(t, resp.GetValid(), "the leaf chains to the CA root: %v", resp.GetErrors())
	assert.False(t, resp.GetRevoked())
}

func TestCARESTWire_CertificateItemOperations_Refused(t *testing.T) {
	cases := []struct {
		name  string
		token string
		call  func(client platformv1.CAServiceClient, f *caWireFixture) error
		want  codes.Code
	}{
		{"revoke without the revoke scope", renewToken, func(client platformv1.CAServiceClient, f *caWireFixture) error {
			_, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{Serial: f.serial})
			return err
		}, codes.PermissionDenied},
		{"revoke an unknown serial", revokeToken, func(client platformv1.CAServiceClient, _ *caWireFixture) error {
			_, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{Serial: unknownSerial})
			return err
		}, codes.NotFound},
		{"renew without the renew scope", revokeToken, func(client platformv1.CAServiceClient, f *caWireFixture) error {
			_, err := client.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{Serial: f.serial, ValidDays: 30})
			return err
		}, codes.PermissionDenied},
		{"renew an unknown serial", renewToken, func(client platformv1.CAServiceClient, _ *caWireFixture) error {
			_, err := client.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{Serial: unknownSerial, ValidDays: 30})
			return err
		}, codes.NotFound},
		{"renew a serial that is not hex", renewToken, func(client platformv1.CAServiceClient, _ *caWireFixture) error {
			_, err := client.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{Serial: "not-a-serial", ValidDays: 30})
			return err
		}, codes.InvalidArgument},
		{"verify without the read scope", readerToken, func(client platformv1.CAServiceClient, f *caWireFixture) error {
			_, err := client.VerifyCertificate(context.Background(), &platformv1.VerifyCertificateRequest{CertificateDer: f.ca.issuedCert.Raw})
			return err
		}, codes.PermissionDenied},
		{"verify a PEM that does not decode", verifyToken, func(client platformv1.CAServiceClient, _ *caWireFixture) error {
			_, err := client.VerifyCertificate(context.Background(), &platformv1.VerifyCertificateRequest{CertificatePem: []byte("not a certificate")})
			return err
		}, codes.InvalidArgument},
		{"an unknown token", "stranger", func(client platformv1.CAServiceClient, f *caWireFixture) error {
			_, err := client.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{Serial: f.serial})
			return err
		}, codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCAWireFixture(t)
			client := f.client(t, caWebServiceServer, tc.token)

			err := tc.call(client, f)
			assert.Equal(t, tc.want, status.Code(err), "%v", err)
			assert.Nil(t, f.ca.last.Load(), "a refused call never issues a certificate")
		})
	}
}
