package daemon

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRESTCA exposes the xkmsca.TCGCA surface SetCAHandlers needs. It lives
// in an untagged file so the shared s6 fixture builds under every tag set.
type fakeRESTCA struct {
	xkmsca.TCGCA // embed for any methods we don't override
}

func (f *fakeRESTCA) Identity() string                                { return "Test CA" }
func (f *fakeRESTCA) IsInitialized() bool                             { return true }
func (f *fakeRESTCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm    { return x509.ECDSA }
func (f *fakeRESTCA) DefaultValidityPeriod() int                      { return 365 }
func (f *fakeRESTCA) TrustedRoot() (*x509.Certificate, error)         { return nil, nil }
func (f *fakeRESTCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) IssueCertificate(_ context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	return nil, nil
}
func (f *fakeRESTCA) RevokeCert(_ context.Context, _ *x509.Certificate, _ xkmsca.RevokeOptions) error {
	return nil
}
func (f *fakeRESTCA) CABundle() ([]byte, error) { return []byte{}, nil }
func (f *fakeRESTCA) CABundleFiltered(xkmssdk.StoreType, x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte{}, nil
}
func (f *fakeRESTCA) ParseBundle([]byte) ([]*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) CertStore() xkmssdk.CertStore                    { return nil }

// s11RouteScopes lists every CA certificate route with a concrete request
// path and the scope the gRPC catalog gives its CAService rpc.
var s11RouteScopes = []struct {
	method, route, path, scope string
}{
	{http.MethodPost, "/api/v1/ca/certificates", "/api/v1/ca/certificates", "certs:generate"},
	{http.MethodGet, "/api/v1/ca/certificates", "/api/v1/ca/certificates", "certs:list"},
	{http.MethodGet, "/api/v1/ca/certificates/{serial}", "/api/v1/ca/certificates/1", "certs:read"},
	{http.MethodPost, "/api/v1/ca/certificates/{serial}/revoke", "/api/v1/ca/certificates/1/revoke", "certs:revoke"},
	{http.MethodPost, "/api/v1/ca/certificates/{serial}/renew", "/api/v1/ca/certificates/1/renew", "certs:generate"},
	{http.MethodPost, "/api/v1/ca/certificates/verify", "/api/v1/ca/certificates/verify", "certs:read"},
}

func TestS11REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS6(t)
	for _, tc := range s11RouteScopes {
		name := tc.method + " " + tc.route
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, name)
		assert.Equal(t, tc.scope, scope, name)

		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		// Every other scope is not enough: the route needs the action the
		// catalog gives its rpc, not the one its HTTP method suggests.
		recorder = serveIAM(s, tc.method, tc.path, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "only:"+tc.scope)
		assertReachedHandler(t, recorder, name, recorder.Body.String())
	}
}

// s11CRLCA is fakeRESTCA with an empty CRL, so GET /api/v1/ca/crl has a CA
// to ask.
type s11CRLCA struct {
	fakeRESTCA
}

func (c *s11CRLCA) GenerateCRL(context.Context) ([]byte, error) { return []byte{}, nil }

// The CA's own routes mount as before: info, CRL and bundle answer without a
// credential, and sign-csr still refuses a request without a token.
func TestS11SetCAHandlers_AuthorityRoutesAsBefore(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetCAHandlers(&s11CRLCA{}, s6RESTGuard()))

	for _, path := range []string{"/api/v1/ca/info", "/api/v1/ca/crl", "/api/v1/ca/bundle"} {
		recorder := serveIAM(s, http.MethodGet, path, "")
		assertReachedHandler(t, recorder, path, recorder.Body.String())
	}
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodPost, "/api/v1/ca/sign-csr", "").Code)
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/ca/certificates", "").Code)
}

func TestS11SetCAHandlers_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}

	err := s.SetCAHandlers(&fakeRESTCA{}, nil)
	assert.Equal(t, ErrCARESTUnavailable{Reason: "no REST scope guard"}, err)
	assert.Empty(t, testWalkHandlers(t, s.router), "a refused mount leaves no route")
}
