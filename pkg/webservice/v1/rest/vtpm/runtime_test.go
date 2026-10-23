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

package vtpm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// runtimeRoute is one runtime handler with a request body it accepts.
type runtimeRoute struct {
	name    string
	method  string
	path    string
	body    interface{}
	handler func(h *VTPMHandlers) http.HandlerFunc
}

var runtimeRoutes = []runtimeRoute{
	{"start", http.MethodPost, "/start", nil, func(h *VTPMHandlers) http.HandlerFunc { return h.StartVTPM }},
	{"stop", http.MethodPost, "/stop", nil, func(h *VTPMHandlers) http.HandlerFunc { return h.StopVTPM }},
	{"state", http.MethodGet, "/state", nil, func(h *VTPMHandlers) http.HandlerFunc { return h.GetVTPMState }},
	{"quote", http.MethodPost, "/quote", QuoteRequest{Nonce: []byte("n")}, func(h *VTPMHandlers) http.HandlerFunc { return h.QuoteVTPM }},
	{"seal", http.MethodPost, "/seal", SealRequest{Data: []byte("d")}, func(h *VTPMHandlers) http.HandlerFunc { return h.SealVTPM }},
	{"unseal", http.MethodPost, "/unseal", UnsealRequest{SealedData: []byte("s")}, func(h *VTPMHandlers) http.HandlerFunc { return h.UnsealVTPM }},
	{"extend", http.MethodPost, "/pcrs/extend", ExtendPCRRequest{PCRIndex: 16, Data: []byte("d")}, func(h *VTPMHandlers) http.HandlerFunc { return h.ExtendVTPMPCR }},
	{"read", http.MethodGet, "/pcrs", nil, func(h *VTPMHandlers) http.HandlerFunc { return h.ReadVTPMPCR }},
}

// failingRuntimeService answers every runtime call, and the bundle lookup,
// with err.
func failingRuntimeService(err error) *mockVTPMService {
	return &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) { return nil, err },
		startFn:     func(ctx context.Context, id string) error { return err },
		stopFn:      func(ctx context.Context, id string) error { return err },
		quoteFn: func(ctx context.Context, id string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
			return nil, err
		},
		sealFn: func(ctx context.Context, id string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
			return nil, err
		},
		unsealFn: func(ctx context.Context, id string, sealed []byte, auth string) ([]byte, error) {
			return nil, err
		},
		extendPCRFn: func(ctx context.Context, id string, index int, data []byte) error { return err },
		readPCRFn:   func(ctx context.Context, id string, index int) ([]byte, error) { return nil, err },
	}
}

func TestRuntimeHandlers_MissingBundleID(t *testing.T) {
	for _, route := range runtimeRoutes {
		t.Run(route.name, func(t *testing.T) {
			handlers, writer := newTestHandlers(failingRuntimeService(errors.New("must not be called")))
			req := createRequestWithVars(route.method, "/api/v1/vtpm/bundles/"+route.path, route.body, nil)

			route.handler(handlers)(httptest.NewRecorder(), req)

			assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
			assert.IsType(t, ErrMissingBundleID{}, writer.lastError)
		})
	}
}

func TestRuntimeHandlers_BundleNotFound(t *testing.T) {
	for _, route := range runtimeRoutes {
		t.Run(route.name, func(t *testing.T) {
			handlers, writer := newTestHandlers(failingRuntimeService(vtpm.ErrBundleNotFound{ID: "ghost"}))
			req := createRequestWithVars(route.method, "/api/v1/vtpm/bundles/ghost"+route.path, route.body,
				map[string]string{"id": "ghost"})
			rec := httptest.NewRecorder()

			route.handler(handlers)(rec, req)

			assert.Equal(t, http.StatusNotFound, writer.lastStatus)
			assert.Contains(t, rec.Body.String(), "ghost")
		})
	}
}

func TestRuntimeHandlers_RejectUnknownBodyField(t *testing.T) {
	for _, route := range runtimeRoutes {
		if route.body == nil {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			handlers, writer := newTestHandlers(failingRuntimeService(errors.New("must not be called")))
			req := createRequestWithVars(route.method, "/api/v1/vtpm/bundles/b1"+route.path,
				map[string]string{"bogus": "x"}, map[string]string{"id": "b1"})

			route.handler(handlers)(httptest.NewRecorder(), req)

			assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
			assert.IsType(t, ErrInvalidRequestBody{}, writer.lastError)
		})
	}
}

func TestStartVTPM_Success(t *testing.T) {
	var started string
	service := &mockVTPMService{
		startFn:     func(ctx context.Context, id string) error { started = id; return nil },
		isRunningFn: func(id string) bool { return true },
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/start", nil, map[string]string{"id": "b1"})

	handlers.StartVTPM(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, "b1", started)
	payload, ok := writer.lastPayload.(StartResponse)
	require.True(t, ok)
	assert.True(t, payload.Status.Success)
	assert.Equal(t, "b1", payload.BundleID)
	assert.True(t, payload.Running)
	assert.Equal(t, "/bundles/b1/tpm/swtpm.sock", payload.SocketPath)
}

func TestStopVTPM_Success(t *testing.T) {
	var stopped string
	service := &mockVTPMService{
		stopFn: func(ctx context.Context, id string) error { stopped = id; return nil },
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/stop", nil, map[string]string{"id": "b1"})

	handlers.StopVTPM(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, "b1", stopped)
	payload, ok := writer.lastPayload.(StopResponse)
	require.True(t, ok)
	assert.Equal(t, "b1", payload.BundleID)
	assert.True(t, payload.Stopped)
}

func TestGetVTPMState_Success(t *testing.T) {
	service := &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) { return createTestBundle(id), nil },
		isRunningFn: func(id string) bool { return id == "b1" },
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/b1/state", nil, map[string]string{"id": "b1"})

	handlers.GetVTPMState(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(StateResponse)
	require.True(t, ok)
	assert.Equal(t, StateResponse{BundleID: "b1", Running: true, SocketPath: "/bundles/b1/tpm/swtpm.sock"}, payload)
}

func TestQuoteVTPM_Success(t *testing.T) {
	var gotNonce []byte
	var gotPCRs []int
	service := &mockVTPMService{
		quoteFn: func(ctx context.Context, id string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
			gotNonce, gotPCRs = nonce, pcrs
			return &vtpm.QuoteResult{
				Quote:         []byte("attest"),
				Signature:     []byte("sig"),
				PCRValues:     map[int][]byte{0: []byte("pcr0")},
				HashAlgorithm: "SHA256",
			}, nil
		},
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/quote",
		QuoteRequest{Nonce: []byte("nonce"), PCRs: []int{0, 7}}, map[string]string{"id": "b1"})

	handlers.QuoteVTPM(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, []byte("nonce"), gotNonce)
	assert.Equal(t, []int{0, 7}, gotPCRs)
	payload, ok := writer.lastPayload.(QuoteResponse)
	require.True(t, ok)
	assert.Equal(t, "b1", payload.BundleID)
	assert.Equal(t, []byte("attest"), payload.Quote)
	assert.Equal(t, []byte("sig"), payload.Signature)
	assert.Equal(t, []byte("pcr0"), payload.PCRValues[0])
	assert.Equal(t, "SHA256", payload.HashAlgorithm)
}

func TestSealVTPM_Success(t *testing.T) {
	var gotData []byte
	var gotOpts *vtpm.SealOptions
	service := &mockVTPMService{
		sealFn: func(ctx context.Context, id string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
			gotData, gotOpts = data, opts
			return []byte("sealed"), nil
		},
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/seal",
		SealRequest{Data: []byte("secret"), PCRs: []int{7}, AuthValue: "pw"}, map[string]string{"id": "b1"})

	handlers.SealVTPM(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, []byte("secret"), gotData)
	assert.Equal(t, &vtpm.SealOptions{PCRs: []int{7}, AuthValue: "pw"}, gotOpts)
	payload, ok := writer.lastPayload.(SealResponse)
	require.True(t, ok)
	assert.Equal(t, []byte("sealed"), payload.SealedData)
}

func TestUnsealVTPM_Success(t *testing.T) {
	var gotSealed []byte
	var gotAuth string
	service := &mockVTPMService{
		unsealFn: func(ctx context.Context, id string, sealed []byte, auth string) ([]byte, error) {
			gotSealed, gotAuth = sealed, auth
			return []byte("secret"), nil
		},
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/unseal",
		UnsealRequest{SealedData: []byte("sealed"), AuthValue: "pw"}, map[string]string{"id": "b1"})

	handlers.UnsealVTPM(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, []byte("sealed"), gotSealed)
	assert.Equal(t, "pw", gotAuth)
	payload, ok := writer.lastPayload.(UnsealResponse)
	require.True(t, ok)
	assert.Equal(t, []byte("secret"), payload.Data)
}

func TestExtendVTPMPCR_Success(t *testing.T) {
	var gotIndex int
	var gotData []byte
	service := &mockVTPMService{
		extendPCRFn: func(ctx context.Context, id string, index int, data []byte) error {
			gotIndex, gotData = index, data
			return nil
		},
	}
	handlers, writer := newTestHandlers(service)
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/b1/pcrs/extend",
		ExtendPCRRequest{PCRIndex: 16, Data: []byte("measure")}, map[string]string{"id": "b1"})

	handlers.ExtendVTPMPCR(httptest.NewRecorder(), req)

	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, 16, gotIndex)
	assert.Equal(t, []byte("measure"), gotData)
	payload, ok := writer.lastPayload.(ExtendPCRResponse)
	require.True(t, ok)
	assert.Equal(t, 16, payload.PCRIndex)
	assert.True(t, payload.Extended)
}

func TestReadVTPMPCR_Success(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"index from query", "?pcr_index=7", 7},
		{"absent index reads PCR 0", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIndex := -1
			service := &mockVTPMService{
				readPCRFn: func(ctx context.Context, id string, index int) ([]byte, error) {
					gotIndex = index
					return []byte("value"), nil
				},
			}
			handlers, writer := newTestHandlers(service)
			req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/b1/pcrs"+tt.query, nil,
				map[string]string{"id": "b1"})

			handlers.ReadVTPMPCR(httptest.NewRecorder(), req)

			require.Equal(t, http.StatusOK, writer.lastStatus)
			assert.Equal(t, tt.want, gotIndex)
			payload, ok := writer.lastPayload.(ReadPCRResponse)
			require.True(t, ok)
			assert.Equal(t, tt.want, payload.PCRIndex)
			assert.Equal(t, []byte("value"), payload.Value)
		})
	}
}

func TestReadVTPMPCR_InvalidIndexQuery(t *testing.T) {
	handlers, writer := newTestHandlers(failingRuntimeService(errors.New("must not be called")))
	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/b1/pcrs?pcr_index=seven", nil,
		map[string]string{"id": "b1"})

	handlers.ReadVTPMPCR(httptest.NewRecorder(), req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	assert.Equal(t, ErrInvalidPCRIndexQuery{Value: "seven"}, writer.lastError)
}

func TestHandleRuntimeError_MapsTypedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"bundle not found", vtpm.ErrBundleNotFound{ID: "b1"}, http.StatusNotFound},
		{"wrapped bundle not found", fmt.Errorf("start: %w", vtpm.ErrBundleNotFound{ID: "b1"}), http.StatusNotFound},
		{"not running", vtpm.ErrVTPMNotRunning{BundleID: "b1"}, http.StatusConflict},
		{"already running", vtpm.ErrVTPMAlreadyRunning{BundleID: "b1"}, http.StatusConflict},
		{"invalid nonce", vtpm.ErrInvalidNonce{Reason: "empty"}, http.StatusBadRequest},
		{"invalid PCR index", vtpm.ErrInvalidPCRIndex{PCRIndex: 99}, http.StatusBadRequest},
		{"swtpm socket unavailable", vtpm.ErrSwtpmSocketUnavailable{Socket: "/s", Cause: errors.New("refused")}, http.StatusServiceUnavailable},
		{"untyped error", errors.New("swtpm crashed"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, writer := newTestHandlers(&mockVTPMService{})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/b1/start", nil)
			rec := httptest.NewRecorder()

			handlers.handleRuntimeError(rec, req, tt.err)

			assert.Equal(t, tt.want, writer.lastStatus)
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

// TestRuntimeRoutes_BindPathID drives each runtime route through the
// registered router so the {id} segment reaches the service.
func TestRuntimeRoutes_BindPathID(t *testing.T) {
	var got []string
	record := func(id string) { got = append(got, id) }
	service := &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			record(id)
			return createTestBundle(id), nil
		},
		startFn: func(ctx context.Context, id string) error { record(id); return nil },
		stopFn:  func(ctx context.Context, id string) error { record(id); return nil },
		quoteFn: func(ctx context.Context, id string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
			record(id)
			return &vtpm.QuoteResult{}, nil
		},
		sealFn: func(ctx context.Context, id string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
			record(id)
			return nil, nil
		},
		unsealFn: func(ctx context.Context, id string, sealed []byte, auth string) ([]byte, error) {
			record(id)
			return nil, nil
		},
		extendPCRFn: func(ctx context.Context, id string, index int, data []byte) error { record(id); return nil },
		readPCRFn:   func(ctx context.Context, id string, index int) ([]byte, error) { record(id); return nil, nil },
	}
	writer := &mockHttpWriter{}
	muxRouter := mux.NewRouter()
	NewVTPMRouter(newTestLogger(), service, writer).RegisterRoutes(muxRouter.PathPrefix("/api/v1").Subrouter())

	for _, route := range runtimeRoutes {
		t.Run(route.name, func(t *testing.T) {
			got = nil
			req := createRequestWithVars(route.method, "/api/v1/vtpm/bundles/bundle-42"+route.path, route.body, nil)
			rec := httptest.NewRecorder()

			muxRouter.ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code, strings.TrimSpace(rec.Body.String()))
			assert.Equal(t, []string{"bundle-42"}, got)
		})
	}
}
