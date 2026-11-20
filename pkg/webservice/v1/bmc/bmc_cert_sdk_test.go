package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// certSDKEnroller is the fake enrollment backend: it records what the real
// EnrollBMC handler hands it and returns a fixed result.
type certSDKEnroller struct {
	gotID   uint64
	gotOpts *EnrollOptions
	result  *EnrollResult
}

func (e *certSDKEnroller) EnrollBMC(_ context.Context, deviceID uint64, _ *bmcpkg.Config,
	opts *EnrollOptions) (*EnrollResult, error) {
	e.gotID, e.gotOpts = deviceID, opts
	return e.result, nil
}

func (e *certSDKEnroller) BMCTLSProvider() bmcpkg.TLSProvider { return nil }

// certSDKRestorer is the fake restore backend.
type certSDKRestorer struct {
	gotID  uint64
	result *RestoreResult
}

func (r *certSDKRestorer) RestoreBMC(_ context.Context, deviceID uint64, _ *bmcpkg.Config) (*RestoreResult, error) {
	r.gotID = deviceID
	return r.result, nil
}

func (r *certSDKRestorer) BMCTLSProvider() bmcpkg.TLSProvider { return nil }

// certSDKServer serves the real BMC handlers, with the real response
// writer, under the daemon's /api/v1 prefix over TLS.
func certSDKServer(t *testing.T, svc *mockBMCService, enroller *certSDKEnroller,
	restorer *certSDKRestorer) *httptest.Server {
	t.Helper()
	logger := newTestLogger()
	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		BMCService:     svc,
		ResponseWriter: response.NewResponseWriter(logger, nil),
	})
	require.NoError(t, err)
	lookup := &fakeProfileLookup{cfg: &bmcpkg.Config{}}
	if enroller != nil {
		h.SetEnroller(enroller, lookup)
	}
	if restorer != nil {
		h.SetRestorer(restorer, lookup)
	}
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	// sdkrest.Connect probes /health/live before handing out the adapter.
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID}/cert", h.ReplaceWebCertificate).Methods(http.MethodPut)
	api.HandleFunc("/bmc/{profileID}/enroll", h.EnrollBMC).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID}/cert/restore", h.RestoreBMC).Methods(http.MethodPost)
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	return server
}

func certSDKClient(t *testing.T, server *httptest.Server) platformv1.BMCServiceClient {
	t.Helper()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	cc := conn.(*sdkrest.Adapter).Connection()
	return platformv1.NewBMCServiceClient(cc)
}

func TestBMCCertSDK_ReplaceWebCertificate(t *testing.T) {
	var gotID uint64
	var gotCert, gotKey []byte
	svc := &mockBMCService{replaceWebCertFn: func(_ context.Context, id uint64, certPEM, keyPEM []byte) error {
		gotID, gotCert, gotKey = id, certPEM, keyPEM
		return nil
	}}
	client := certSDKClient(t, certSDKServer(t, svc, nil, nil))

	resp, err := client.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 9, CertPem: []byte("CERT"), KeyPem: []byte("KEY"),
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.GetMessage())
	assert.Equal(t, uint64(9), gotID)
	assert.Equal(t, "CERT", string(gotCert))
	assert.Equal(t, "KEY", string(gotKey))
}

func TestBMCCertSDK_ReplaceWebCertificateServiceError(t *testing.T) {
	svc := &mockBMCService{replaceWebCertFn: func(context.Context, uint64, []byte, []byte) error {
		return errFakeBMC{}
	}}
	client := certSDKClient(t, certSDKServer(t, svc, nil, nil))

	_, err := client.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 9, CertPem: []byte("CERT"), KeyPem: []byte("KEY"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestBMCCertSDK_EnrollBMC(t *testing.T) {
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	enroller := &certSDKEnroller{result: &EnrollResult{
		DeviceID:      42,
		Endpoint:      "bmc.example.test:443",
		Hostname:      "bmc.example.test",
		PinSPKISHA256: "sha256/pin",
		FactoryCertMeta: FactoryCertMeta{
			Subject: "CN=bmc", Issuer: "CN=factory", NotBefore: notBefore, NotAfter: notAfter,
			CapturedAt: notBefore,
		},
		FactoryCertPEM: []byte("FACTORY"),
		NewCertPEM:     []byte("NEW"),
		Steps:          []EnrollStep{{Name: "trust", OK: true}, {Name: "factory_cert", OK: true}},
	}}
	client := certSDKClient(t, certSDKServer(t, &mockBMCService{}, enroller, nil))

	replace, rotate := true, false
	resp, err := client.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{
		ProfileId: 42, ReplaceCertificate: &replace, RotatePassword: &rotate,
	})
	require.NoError(t, err)

	assert.Equal(t, uint64(42), enroller.gotID)
	require.NotNil(t, enroller.gotOpts)
	require.NotNil(t, enroller.gotOpts.ReplaceCertificate)
	assert.True(t, *enroller.gotOpts.ReplaceCertificate)
	require.NotNil(t, enroller.gotOpts.RotatePassword)
	assert.False(t, *enroller.gotOpts.RotatePassword)
	assert.Nil(t, enroller.gotOpts.DNSRegister)

	assert.Equal(t, uint64(42), resp.GetDeviceId())
	assert.Equal(t, "bmc.example.test:443", resp.GetEndpoint())
	assert.Equal(t, "bmc.example.test", resp.GetHostname())
	assert.Equal(t, "sha256/pin", resp.GetPinSpkiSha256())
	assert.Equal(t, "FACTORY", string(resp.GetFactoryCertPem()))
	assert.Equal(t, "NEW", string(resp.GetNewCertPem()))
	meta := resp.GetFactoryCertMeta()
	require.NotNil(t, meta)
	assert.Equal(t, "CN=bmc", meta.GetSubject())
	assert.Equal(t, "CN=factory", meta.GetIssuer())
	assert.True(t, meta.GetNotBefore().AsTime().Equal(notBefore))
	assert.True(t, meta.GetNotAfter().AsTime().Equal(notAfter))
	require.Len(t, resp.GetSteps(), 2)
	assert.Equal(t, "trust", resp.GetSteps()[0].GetName())
	assert.True(t, resp.GetSteps()[1].GetOk())
}

func TestBMCCertSDK_RestoreFactoryCert(t *testing.T) {
	notBefore := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	restorer := &certSDKRestorer{result: &RestoreResult{
		DeviceID: 7,
		Endpoint: "bmc.example.test:443",
		Hostname: "bmc.example.test",
		NewCertMeta: FactoryCertMeta{
			Subject: "CN=bmc", Issuer: "CN=factory", NotBefore: notBefore, NotAfter: notBefore.Add(time.Hour),
		},
		NewCertPEM: []byte("RESTORED"),
		Steps:      []EnrollStep{{Name: "restore", OK: true}},
	}}
	client := certSDKClient(t, certSDKServer(t, &mockBMCService{}, nil, restorer))

	resp, err := client.RestoreFactoryCert(context.Background(), &platformv1.BMCRestoreRequest{ProfileId: 7})
	require.NoError(t, err)

	assert.Equal(t, uint64(7), restorer.gotID)
	assert.Equal(t, uint64(7), resp.GetDeviceId())
	assert.Equal(t, "bmc.example.test:443", resp.GetEndpoint())
	assert.Equal(t, "bmc.example.test", resp.GetHostname())
	assert.Equal(t, "RESTORED", string(resp.GetNewCertPem()))
	require.NotNil(t, resp.GetNewCertMeta())
	assert.Equal(t, "CN=bmc", resp.GetNewCertMeta().GetSubject())
	assert.True(t, resp.GetNewCertMeta().GetNotBefore().AsTime().Equal(notBefore))
	require.Len(t, resp.GetSteps(), 1)
	assert.Equal(t, "restore", resp.GetSteps()[0].GetName())
}

// TestBMCCertSDK_RestoreRefusedWithoutRestorer drives the handler's 503
// refusal (no restorer wired) through the SDK.
func TestBMCCertSDK_RestoreRefusedWithoutRestorer(t *testing.T) {
	client := certSDKClient(t, certSDKServer(t, &mockBMCService{}, nil, nil))

	_, err := client.RestoreFactoryCert(context.Background(), &platformv1.BMCRestoreRequest{ProfileId: 7})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
