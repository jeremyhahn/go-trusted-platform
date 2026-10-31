package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// caTestKey is a key and certificate pair a test can sign with.
type caTestKey struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newCATestCert builds a certificate from tmpl, signed by parent (or
// self-signed when parent is nil).
func newCATestCert(t *testing.T, tmpl *x509.Certificate, parent *caTestKey) caTestKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	tmpl.BasicConstraintsValid = true
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return caTestKey{cert: cert, key: key}
}

func caSerial(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.SerialNumber.Bytes())
}

func caPEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return buf.Bytes()
}

func caErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp CAErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Error
}

func caServe(router *mux.Router, method, path string, body []byte) *httptest.ResponseRecorder {
	req := caAdminRequest(method, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// storeOverrideCA replaces the certificate store of the wrapped mock, so a
// test can present no store at all.
type storeOverrideCA struct {
	*mockCAService
	store xkmssdk.CertStore
}

func (c *storeOverrideCA) CertificateStore() xkmssdk.CertStore { return c.store }

// revocationCheckingCA answers IsRevoked, the optional capability the
// verify handler probes for.
type revocationCheckingCA struct {
	*mockCAService
	revoked bool
}

func (c *revocationCheckingCA) IsRevoked(*big.Int) (bool, error) { return c.revoked, nil }

// noCRLCA hides the mock's GenerateCRL so the CA lacks CRL support.
type noCRLCA struct {
	CAServiceInterface
}

// objectNotFoundError is what the fake object store returns for a key it
// does not hold.
type objectNotFoundError struct{ key string }

func (e objectNotFoundError) Error() string { return "object not found: " + e.key }

// revocationObjects is an object store holding only the listed keys.
type revocationObjects struct {
	objectstorage.Client
	keys      map[string]bool
	requested []string
}

func (o *revocationObjects) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	o.requested = append(o.requested, req.Key)
	if !o.keys[req.Key] {
		return nil, objectNotFoundError{key: req.Key}
	}
	return &objectstorage.GetObjectResponse{}, nil
}

// failWriteRecorder records the status but fails every body write.
type failWriteRecorder struct {
	*httptest.ResponseRecorder
}

func (f failWriteRecorder) Write([]byte) (int, error) {
	return 0, objectNotFoundError{key: "write"}
}

// Every handler refuses with 503 and ErrCAServiceNotAvailable when no CA
// is wired in.
func TestCAAPIRest_NoCAService(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	handlers := map[string]http.HandlerFunc{
		"list":   h.handleListCertificates,
		"revoke": h.handleRevokeCertificate,
		"renew":  h.handleRenewCertificate,
		"verify": h.handleVerifyCertificate,
		"crl":    h.handleGetCRL,
		"bundle": h.handleGetCABundle,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handle(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
			require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Equal(t, ErrCAServiceNotAvailable{}.Error(), caErrorMessage(t, rec))
		})
	}
}

// The router never yields an empty {serial}, so the serial-scoped
// handlers are driven directly to prove they refuse it.
func TestCAAPIRest_EmptySerial(t *testing.T) {
	h := NewCAHandlers(newMockCAService(), nil, nil)
	handlers := map[string]http.HandlerFunc{
		"revoke": h.handleRevokeCertificate,
		"renew":  h.handleRenewCertificate,
	}
	want := ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"}.Error()
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), map[string]string{"serial": ""})
			rec := httptest.NewRecorder()
			handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, want, caErrorMessage(t, rec))
		})
	}
}

func TestCAAPIRest_ListCertificates(t *testing.T) {
	ca := newMockCAService()
	leaf := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "leaf.test"}}, nil).cert
	// The store also holds the intermediate; the list must not repeat it.
	ca.certStore.certs[caSerial(ca.intermediateCert)] = ca.intermediateCert
	ca.certStore.certs[caSerial(leaf)] = leaf
	_, router := setupCAHandlers(ca)

	t.Run("dedupes root and intermediate", func(t *testing.T) {
		rec := caServe(router, http.MethodGet, "/api/v1/ca/certificates", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp CACertificateListResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, 3, resp.TotalItems)
		names := make([]string, 0, len(resp.Certificates))
		for _, c := range resp.Certificates {
			names = append(names, c.CommonName)
		}
		assert.ElementsMatch(t, []string{"Test Root CA", "Test Intermediate CA", "leaf.test"}, names)
	})

	t.Run("non-positive page and size fall back to defaults", func(t *testing.T) {
		rec := caServe(router, http.MethodGet, "/api/v1/ca/certificates?page=0&page_size=-5", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp CACertificateListResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, int(caDefaultPageSize), resp.PageSize)
		assert.Len(t, resp.Certificates, 3)
	})

	t.Run("page past the end is empty", func(t *testing.T) {
		rec := caServe(router, http.MethodGet, "/api/v1/ca/certificates?page=5&page_size=2", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp CACertificateListResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Empty(t, resp.Certificates)
		assert.Equal(t, 2, resp.TotalPages)
	})
}

// A renewal whose superseding revoke fails answers 500 and never issues.
func TestCAAPIRest_RenewRevokeFails(t *testing.T) {
	ca := newMockCAService()
	ca.revokeErr = objectNotFoundError{key: "revoke"}
	leaf := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "renew.test"}}, nil).cert
	ca.certStore.certs[caSerial(leaf)] = leaf
	_, router := setupCAHandlers(ca)

	rec := caServe(router, http.MethodPost, "/api/v1/ca/certificates/"+caSerial(leaf)+"/renew", []byte(`{"valid_days":30}`))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	want := ErrCertificateRenewFailed{Serial: caSerial(leaf), Err: ca.revokeErr}.Error()
	assert.Equal(t, want, caErrorMessage(t, rec))
	assert.Empty(t, ca.issuedCerts)
}

func TestCAAPIRest_RenewMalformedBody(t *testing.T) {
	_, router := setupCAHandlers(newMockCAService())

	rec := caServe(router, http.MethodPost, "/api/v1/ca/certificates/abc/renew", []byte(`{`))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, caErrorMessage(t, rec), "unexpected EOF")
}

// PreserveSANs carries IP and URI SANs of the old certificate into the
// renewal request.
func TestCAAPIRest_RenewPreservesIPAndURISANs(t *testing.T) {
	ca := newMockCAService()
	spiffe, err := url.Parse("spiffe://platform/node")
	require.NoError(t, err)
	leaf := newCATestCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "sans.test"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.7")},
		URIs:        []*url.URL{spiffe},
	}, nil).cert
	ca.certStore.certs[caSerial(leaf)] = leaf
	_, router := setupCAHandlers(ca)

	rec := caServe(router, http.MethodPost, "/api/v1/ca/certificates/"+caSerial(leaf)+"/renew",
		[]byte(`{"valid_days":30,"preserve_sans":true}`))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, ca.renewals, 1)
	assert.Equal(t, issuance.RenewOptions{ValidDays: 30, PreserveSANs: true}, ca.renewals[0])
	var resp CARenewCertificateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, []string{"10.0.0.7"}, resp.OldCertificate.IPAddresses)
	assert.Equal(t, []string{"spiffe://platform/node"}, resp.OldCertificate.URIs)
}

func TestCAAPIRest_VerifyCertificate(t *testing.T) {
	root := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "verify root"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "verify leaf"}}, &root)
	expired := newCATestCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "expired"},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}, &root)
	future := newCATestCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "future"},
		NotBefore: time.Now().Add(24 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	}, &root)

	newCA := func() *mockCAService {
		ca := newMockCAService()
		ca.rootCert = root.cert
		ca.intermediateCert = nil
		return ca
	}
	verify := func(t *testing.T, ca CAServiceInterface, objects objectstorage.Client, req CertificateVerifyRequest) CAVerifyCertificateResponse {
		t.Helper()
		router := mux.NewRouter()
		NewCAHandlers(ca, nil, objects).WithScopeGuard(caAdminGuard()).RegisterRoutes(router)
		body, err := json.Marshal(req)
		require.NoError(t, err)
		rec := caServe(router, http.MethodPost, "/api/v1/ca/certificates/verify", body)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp CAVerifyCertificateResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp
	}

	t.Run("chain to the CA root is valid", func(t *testing.T) {
		resp := verify(t, newCA(), nil, CertificateVerifyRequest{CertificateDER: leaf.cert.Raw, VerifyExpiration: true})
		assert.True(t, resp.Valid)
		assert.Equal(t, "certificate verification successful", resp.Message)
		assert.Equal(t, []string{caSerial(leaf.cert), caSerial(root.cert)}, resp.Chain)
	})

	t.Run("expired certificate fails with the reason", func(t *testing.T) {
		resp := verify(t, newCA(), nil, CertificateVerifyRequest{CertificateDER: expired.cert.Raw, VerifyExpiration: true})
		assert.False(t, resp.Valid)
		assert.Contains(t, resp.Errors, "certificate has expired")
		assert.True(t, strings.HasPrefix(resp.Message, "certificate verification failed: "))
	})

	t.Run("not yet valid certificate warns", func(t *testing.T) {
		resp := verify(t, newCA(), nil, CertificateVerifyRequest{CertificateDER: future.cert.Raw, VerifyExpiration: true})
		assert.False(t, resp.Valid)
		assert.Equal(t, []string{"certificate is not yet valid"}, resp.Warnings)
	})

	t.Run("CA revocation check marks the certificate revoked", func(t *testing.T) {
		ca := &revocationCheckingCA{mockCAService: newCA(), revoked: true}
		resp := verify(t, ca, nil, CertificateVerifyRequest{CertificateDER: leaf.cert.Raw, VerifyRevocation: true})
		assert.True(t, resp.Revoked)
		assert.False(t, resp.Valid)
		assert.Equal(t, []string{"certificate has been revoked"}, resp.Errors)
	})

	t.Run("revocation record in the object store marks the certificate revoked", func(t *testing.T) {
		key := "revocations/" + leaf.cert.SerialNumber.Text(10) + ".json"
		objects := &revocationObjects{keys: map[string]bool{key: true}}
		ca := &revocationCheckingCA{mockCAService: newCA(), revoked: false}
		resp := verify(t, ca, objects, CertificateVerifyRequest{CertificateDER: leaf.cert.Raw, VerifyRevocation: true})
		assert.True(t, resp.Revoked)
		assert.Equal(t, []string{key}, objects.requested)
	})

	t.Run("no revocation record leaves the certificate valid", func(t *testing.T) {
		objects := &revocationObjects{keys: map[string]bool{}}
		resp := verify(t, newCA(), objects, CertificateVerifyRequest{CertificateDER: leaf.cert.Raw, VerifyRevocation: true})
		assert.False(t, resp.Revoked)
		assert.True(t, resp.Valid)
		assert.Len(t, objects.requested, 1)
	})

	t.Run("no object store and no checker is not revoked", func(t *testing.T) {
		resp := verify(t, newCA(), nil, CertificateVerifyRequest{CertificateDER: leaf.cert.Raw, VerifyRevocation: true})
		assert.False(t, resp.Revoked)
		assert.True(t, resp.Valid)
	})

	t.Run("untrusted chain reports the verifier error", func(t *testing.T) {
		stranger := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "stranger"}}, nil)
		resp := verify(t, newCA(), nil, CertificateVerifyRequest{CertificateDER: stranger.cert.Raw})
		assert.False(t, resp.Valid)
		require.Len(t, resp.Errors, 1)
		assert.Equal(t, "certificate verification failed: "+resp.Errors[0], resp.Message)
		assert.Empty(t, resp.Chain)
	})
}

func TestCAAPIRest_VerifyMalformedBody(t *testing.T) {
	_, router := setupCAHandlers(newMockCAService())

	rec := caServe(router, http.MethodPost, "/api/v1/ca/certificates/verify", []byte(`not json`))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.True(t, strings.HasPrefix(caErrorMessage(t, rec), ErrInvalidRequestBody{}.Error()))
}

func TestCAAPIRest_GetCRL(t *testing.T) {
	t.Run("entries are listed on request", func(t *testing.T) {
		issuer := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "crl issuer"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, nil)
		revokedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
		crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(7),
			ThisUpdate: time.Now().Add(-time.Minute),
			NextUpdate: time.Now().Add(time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(0xbeef), RevocationTime: revokedAt, ReasonCode: 1},
			},
		}, issuer.cert, issuer.key)
		require.NoError(t, err)
		ca := newMockCAService()
		ca.generateCRLSupport = true
		ca.crlData = crl
		_, router := setupCAHandlers(ca)

		rec := caServe(router, http.MethodGet, "/api/v1/ca/crl?include_entries=true", nil)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp CACRLResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, 1, resp.RevokedCount)
		assert.Equal(t, []CARevokedCertEntry{{Serial: "beef", RevocationTime: revokedAt.Unix(), Reason: 1}}, resp.RevokedCerts)
	})

	t.Run("unparseable CRL is a generation failure", func(t *testing.T) {
		ca := newMockCAService()
		ca.generateCRLSupport = true
		ca.crlData = []byte("not a crl")
		_, router := setupCAHandlers(ca)

		rec := caServe(router, http.MethodGet, "/api/v1/ca/crl", nil)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.True(t, strings.HasPrefix(caErrorMessage(t, rec), ErrCRLGenerationFailed{}.Error()))
	})

	t.Run("CA without CRL generation answers 501", func(t *testing.T) {
		_, router := setupCAHandlers(noCRLCA{CAServiceInterface: newMockCAService()})

		rec := caServe(router, http.MethodGet, "/api/v1/ca/crl", nil)

		require.Equal(t, http.StatusNotImplemented, rec.Code)
		assert.Equal(t, ErrCRLNotFound{}.Error(), caErrorMessage(t, rec))
	})
}

func TestCAAPIRest_GetCABundle(t *testing.T) {
	root := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "bundle root"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "bundle leaf"}}, &root)
	ca := newMockCAService()
	ca.bundle = caPEM(root.cert, leaf.cert)
	_, router := setupCAHandlers(ca)

	t.Run("excluding intermediates keeps only CA certificates", func(t *testing.T) {
		rec := caServe(router, http.MethodGet, "/api/v1/ca/bundle?include_intermediates=false", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp CABundleResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Equal(t, 1, resp.CertCount)
		assert.Equal(t, "bundle root", resp.Certificates[0].CommonName)
	})

	for _, accept := range []string{"application/x-pem-file", "application/pem-certificate-chain"} {
		t.Run("raw PEM for "+accept, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
			req.Header.Set("Accept", accept)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "application/x-pem-file", rec.Header().Get("Content-Type"))
			assert.Equal(t, `attachment; filename="ca-bundle.pem"`, rec.Header().Get("Content-Disposition"))
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, ca.bundle, rec.Body.Bytes())
		})
	}

	t.Run("raw PEM write failure keeps the status", func(t *testing.T) {
		h := NewCAHandlers(ca, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		req.Header.Set("Accept", "application/x-pem-file")
		rec := failWriteRecorder{httptest.NewRecorder()}
		h.handleGetCABundle(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Body.Bytes())
	})
}

func TestCAAPIRest_FindCertificateBySerial(t *testing.T) {
	ca := newMockCAService()
	listed := newCATestCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Listed.Test"}}, nil).cert
	ca.certStore.certs[caSerial(listed)] = listed
	h := NewCAHandlers(ca, nil, nil)

	tests := []struct {
		name       string
		identifier string
		want       *x509.Certificate
	}{
		{"root by common name, any case", "test root ca", ca.rootCert},
		{"intermediate by serial", caSerial(ca.intermediateCert), ca.intermediateCert},
		{"intermediate by common name", "Test Intermediate CA", ca.intermediateCert},
		{"store entry found by listing on its common name", "listed.test", listed},
		{"unknown identifier", "nobody", nil},
		{"empty identifier", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Same(t, tt.want, h.findCertificateBySerial(tt.identifier))
		})
	}

	t.Run("list failure finds nothing", func(t *testing.T) {
		ca.certStore.listErr = objectNotFoundError{key: "list"}
		defer func() { ca.certStore.listErr = nil }()
		assert.Nil(t, h.findCertificateBySerial("listed.test"))
	})

	t.Run("no certificate store finds nothing past the CA pair", func(t *testing.T) {
		bare := NewCAHandlers(&storeOverrideCA{mockCAService: ca}, nil, nil)
		assert.Nil(t, bare.findCertificateBySerial(caSerial(listed)))
		assert.Same(t, ca.rootCert, bare.findCertificateBySerial(caSerial(ca.rootCert)))
	})
}

func TestCAAPIRest_CertMatchesIdentifierNilCert(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	assert.False(t, h.certMatchesIdentifier(nil, "anything"))
}

func TestCAAPIRest_CertToProtoSANs(t *testing.T) {
	spiffe, err := url.Parse("spiffe://platform/svc")
	require.NoError(t, err)
	cert := newCATestCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "proto.test"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		URIs:        []*url.URL{spiffe},
	}, nil).cert
	h := NewCAHandlers(nil, nil, nil)

	out := h.certToProto(cert, false, false)

	require.NotNil(t, out.Sans)
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::1"}, out.Sans.IpAddresses)
	assert.Equal(t, []string{"spiffe://platform/svc"}, out.Sans.Uris)
	assert.Empty(t, out.Pem)
	assert.Empty(t, out.Der)
}

func TestCAAPIRest_WriteProtoWriteFailure(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	rec := failWriteRecorder{httptest.NewRecorder()}

	h.writeProto(rec, http.StatusCreated, &emptypb.Empty{})

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestCAAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestCAAPIRest_CertStatusToString(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	now := time.Now()
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"valid", &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "VALID"},
		{"not yet valid", &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}, "NOT_YET_VALID"},
		{"expired", &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}, "EXPIRED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, h.certStatusToString(tt.cert))
		})
	}
}

// Every key usage name, in both spellings, maps to its bit, and the bits
// map back to the canonical names; unknown names are ignored.
func TestCAAPIRest_KeyUsageRoundTrip(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	usages := []struct {
		compact, canonical string
		bit                x509.KeyUsage
	}{
		{"DIGITALSIGNATURE", "DIGITAL_SIGNATURE", x509.KeyUsageDigitalSignature},
		{"CONTENTCOMMITMENT", "CONTENT_COMMITMENT", x509.KeyUsageContentCommitment},
		{"KEYENCIPHERMENT", "KEY_ENCIPHERMENT", x509.KeyUsageKeyEncipherment},
		{"DATAENCIPHERMENT", "DATA_ENCIPHERMENT", x509.KeyUsageDataEncipherment},
		{"KEYAGREEMENT", "KEY_AGREEMENT", x509.KeyUsageKeyAgreement},
		{"CERTSIGN", "CERT_SIGN", x509.KeyUsageCertSign},
		{"CRLSIGN", "CRL_SIGN", x509.KeyUsageCRLSign},
		{"ENCIPHERONLY", "ENCIPHER_ONLY", x509.KeyUsageEncipherOnly},
		{"DECIPHERONLY", "DECIPHER_ONLY", x509.KeyUsageDecipherOnly},
	}
	var all x509.KeyUsage
	var canonical []string
	for _, u := range usages {
		for _, name := range []string{strings.ToLower(u.compact), u.canonical} {
			got, err := issuance.ParseKeyUsages([]string{name})
			require.NoError(t, err, name)
			assert.Equal(t, u.bit, got, name)
		}
		all |= u.bit
		canonical = append(canonical, u.canonical)
	}
	assert.Equal(t, canonical, h.keyUsageToStrings(all))
	parsed, err := issuance.ParseKeyUsages(h.keyUsageToStrings(all))
	require.NoError(t, err)
	assert.Equal(t, all, parsed, "the names the handler writes parse back to the same mask")
	assert.Nil(t, h.keyUsageToStrings(0))
}

func TestCAAPIRest_ExtKeyUsageRoundTrip(t *testing.T) {
	h := NewCAHandlers(nil, nil, nil)
	usages := []struct {
		compact, canonical string
		value              x509.ExtKeyUsage
	}{
		{"ANY", "ANY", x509.ExtKeyUsageAny},
		{"SERVERAUTH", "SERVER_AUTH", x509.ExtKeyUsageServerAuth},
		{"CLIENTAUTH", "CLIENT_AUTH", x509.ExtKeyUsageClientAuth},
		{"CODESIGNING", "CODE_SIGNING", x509.ExtKeyUsageCodeSigning},
		{"EMAILPROTECTION", "EMAIL_PROTECTION", x509.ExtKeyUsageEmailProtection},
		{"TIMESTAMPING", "TIME_STAMPING", x509.ExtKeyUsageTimeStamping},
		{"OCSPSIGNING", "OCSP_SIGNING", x509.ExtKeyUsageOCSPSigning},
	}
	var values []x509.ExtKeyUsage
	var canonical []string
	for _, u := range usages {
		for _, name := range []string{strings.ToLower(u.compact), u.canonical} {
			got, err := issuance.ParseExtKeyUsages([]string{name})
			require.NoError(t, err, name)
			assert.Equal(t, []x509.ExtKeyUsage{u.value}, got, name)
		}
		values = append(values, u.value)
		canonical = append(canonical, u.canonical)
	}
	assert.Equal(t, canonical, h.extKeyUsageToStrings(values))
	parsed, err := issuance.ParseExtKeyUsages(h.extKeyUsageToStrings(values))
	require.NoError(t, err)
	assert.Equal(t, values, parsed, "the names the handler writes parse back to the same usages")
	assert.Nil(t, h.extKeyUsageToStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}))
}
