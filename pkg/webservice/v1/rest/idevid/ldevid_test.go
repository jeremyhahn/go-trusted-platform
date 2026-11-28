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

package idevid

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// fakeIDevIDServer is the service layer behind the router. It records what
// each call received and answers with fixed replies, or with err when set.
type fakeIDevIDServer struct {
	platformv1.UnimplementedIDevIDServiceServer

	err error

	csrReq     *platformv1.CreateIDevIDCSRRequest
	installReq *platformv1.InstallIDevIDCertificateRequest
	ldevidReq  *platformv1.CreateLDevIDRequest
}

func (f *fakeIDevIDServer) CreateIDevIDCSR(_ context.Context, req *platformv1.CreateIDevIDCSRRequest) (*platformv1.CreateIDevIDCSRResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.csrReq = req
	return &platformv1.CreateIDevIDCSRResponse{CsrPem: []byte("idevid-csr")}, nil
}

func (f *fakeIDevIDServer) InstallIDevIDCertificate(_ context.Context, req *platformv1.InstallIDevIDCertificateRequest) (*platformv1.InstallIDevIDCertificateResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.installReq = req
	return &platformv1.InstallIDevIDCertificateResponse{
		Status: &platformv1.Status{Success: true, Message: "installed"},
	}, nil
}

func (f *fakeIDevIDServer) GetIDevIDCertificate(_ context.Context, _ *platformv1.GetIDevIDCertificateRequest) (*platformv1.GetIDevIDCertificateResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetIDevIDCertificateResponse{
		Certificate: &platformv1.DeviceIdentityCertificate{Pem: []byte("idevid-cert"), SubjectCn: "device-1"},
	}, nil
}

func (f *fakeIDevIDServer) CreateLDevID(_ context.Context, req *platformv1.CreateLDevIDRequest) (*platformv1.CreateLDevIDResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.ldevidReq = req
	return &platformv1.CreateLDevIDResponse{
		CsrPem:         []byte("ldevid-csr"),
		CertificatePem: []byte("ldevid-cert"),
		Certificate:    &platformv1.DeviceIdentityCertificate{KeyType: "LDevID", TpmHandle: req.GetHandle()},
	}, nil
}

// newRouterWith mounts the real IDevID router under /api/v1, the prefix the
// webservice gives it, backed by server.
func newRouterWith(server platformv1.IDevIDServiceServer) *mux.Router {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewIDevIDRouter(logging.NewLogger(slog.LevelError, io.Discard), server, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

func postLDevID(t *testing.T, router http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/idevid/ldevid", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestCreateLDevID_CreatesTheKeyAndAnswers201(t *testing.T) {
	fake := &fakeIDevIDServer{}
	rec := postLDevID(t, newRouterWith(fake),
		`{"handle": 2164326402, "profile": "tls", "validity_days": 30, "template": {"common_name": "node-1"}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NotNil(t, fake.ldevidReq)
	assert.Equal(t, uint32(2164326402), fake.ldevidReq.GetHandle())
	assert.Equal(t, "tls", fake.ldevidReq.GetProfile())
	assert.Equal(t, uint32(30), fake.ldevidReq.GetValidityDays())
	assert.Equal(t, "node-1", fake.ldevidReq.GetTemplate().GetCommonName())

	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Contains(t, envelope.Payload, "certificatePem")
}

func TestCreateLDevID_RejectsAMalformedBody(t *testing.T) {
	fake := &fakeIDevIDServer{}
	rec := postLDevID(t, newRouterWith(fake), `{`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, fake.ldevidReq, "a malformed body must not reach the service layer")
}

// The SDK must send DeviceKeyAlgorithm as its protobuf enum name: the
// decoder runs with DiscardUnknown, so a bare value such as "ECDSA_P384"
// is dropped and the request falls back to UNSPECIFIED (the default key).
func TestCreateLDevID_DecodesTheAlgorithmEnumName(t *testing.T) {
	fake := &fakeIDevIDServer{}
	rec := postLDevID(t, newRouterWith(fake), `{"algorithm": "DEVICE_KEY_ALGORITHM_ECDSA_P384"}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NotNil(t, fake.ldevidReq)
	assert.Equal(t, platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384, fake.ldevidReq.GetAlgorithm())

	fake = &fakeIDevIDServer{}
	postLDevID(t, newRouterWith(fake), `{"algorithm": "ECDSA_P384"}`)

	require.NotNil(t, fake.ldevidReq)
	assert.Equal(t, platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED, fake.ldevidReq.GetAlgorithm())
}

func TestCreateLDevID_NoServiceWiredIs503(t *testing.T) {
	rec := postLDevID(t, newRouterWith(nil), `{}`)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCreateLDevID_MapsTheServiceErrorCode(t *testing.T) {
	fake := &fakeIDevIDServer{err: status.Error(codes.NotFound, "no platform CA")}
	rec := postLDevID(t, newRouterWith(fake), `{}`)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// connectSDK serves the IDevID router in-process and returns the Go SDK's
// IDevID client over its REST transport, so a test drives the exact paths the
// SDK route table names.
func connectSDK(t *testing.T, server platformv1.IDevIDServiceServer) platformv1.IDevIDServiceClient {
	t.Helper()
	root := newRouterWith(server)
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(httpServer.URL),
		platform.WithTLSConfig(tlsConfig),
	))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return platformv1.NewIDevIDServiceClient(adapter.Connection())
}

func TestSDKREST_CreateIDevIDCSR_RoundTrip(t *testing.T) {
	fake := &fakeIDevIDServer{}
	client := connectSDK(t, fake)

	resp, err := client.CreateIDevIDCSR(context.Background(), &platformv1.CreateIDevIDCSRRequest{
		Template: &platformv1.CSRTemplate{CommonName: "device-1", DnsNames: []string{"device-1.local"}},
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("idevid-csr"), resp.GetCsrPem())
	require.NotNil(t, fake.csrReq)
	assert.Equal(t, "device-1", fake.csrReq.GetTemplate().GetCommonName())
	assert.Equal(t, []string{"device-1.local"}, fake.csrReq.GetTemplate().GetDnsNames())
}

func TestSDKREST_InstallIDevIDCertificate_RoundTrip(t *testing.T) {
	fake := &fakeIDevIDServer{}
	client := connectSDK(t, fake)

	resp, err := client.InstallIDevIDCertificate(context.Background(), &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: []byte("issued-cert"),
	})

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	require.NotNil(t, fake.installReq)
	assert.Equal(t, []byte("issued-cert"), fake.installReq.GetCertificatePem())
}

func TestSDKREST_GetIDevIDCertificate_RoundTrip(t *testing.T) {
	client := connectSDK(t, &fakeIDevIDServer{})

	resp, err := client.GetIDevIDCertificate(context.Background(), &platformv1.GetIDevIDCertificateRequest{})

	require.NoError(t, err)
	assert.Equal(t, []byte("idevid-cert"), resp.GetCertificate().GetPem())
	assert.Equal(t, "device-1", resp.GetCertificate().GetSubjectCn())
}

func TestSDKREST_CreateLDevID_RoundTrip(t *testing.T) {
	fake := &fakeIDevIDServer{}
	client := connectSDK(t, fake)

	resp, err := client.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{
		Handle:       0x81010002,
		Profile:      "tls",
		ValidityDays: 30,
		Template:     &platformv1.CSRTemplate{CommonName: "node-1"},
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("ldevid-cert"), resp.GetCertificatePem())
	assert.Equal(t, uint32(0x81010002), resp.GetCertificate().GetTpmHandle())
	require.NotNil(t, fake.ldevidReq)
	assert.Equal(t, "tls", fake.ldevidReq.GetProfile())
	assert.Equal(t, "node-1", fake.ldevidReq.GetTemplate().GetCommonName())
}

func TestSDKREST_ServiceErrorKeepsItsCode(t *testing.T) {
	client := connectSDK(t, &fakeIDevIDServer{err: status.Error(codes.NotFound, "no idevid")})

	_, err := client.GetIDevIDCertificate(context.Background(), &platformv1.GetIDevIDCertificateRequest{})

	assert.Equal(t, codes.NotFound, status.Code(err))
}
