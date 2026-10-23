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

//go:build integration

package fido2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const defaultRESTTimeout = 30 * time.Second

// RESTAdapter drives FIDO2 operations over HTTPS REST.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter returns an unconfigured REST adapter.
func NewRESTAdapter() *RESTAdapter { return &RESTAdapter{} }

// Name returns "REST".
func (r *RESTAdapter) Name() string { return "REST" }

// Setup constructs the HTTPS client.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}
	r.baseURL = endpoint
	r.httpClient = helpers.NewAdminHTTPClient(defaultRESTTimeout)
	return nil
}

// Teardown releases idle connections.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// doJSON sends an HTTP request and unmarshals the JSON response.
func (r *RESTAdapter) doJSON(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("REST %s %s failed: status %d body %s", method, path, resp.StatusCode, string(respBody))
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

// ListDevices calls GET /api/v1/fido2/devices.
func (r *RESTAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	_ = req
	resp := &fido2sdk.ListDevicesResponse{}
	if err := r.doJSON(ctx, http.MethodGet, "/api/v1/fido2/devices", nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET /api/v1/fido2/devices", Err: err}
	}
	return resp, nil
}

// WaitDevice calls GET /api/v1/fido2/devices/wait?timeout_seconds=N; the
// daemon answers with the bare device that appeared.
func (r *RESTAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	if req == nil {
		req = &fido2sdk.WaitDeviceRequest{}
	}
	path := "/api/v1/fido2/devices/wait?timeout_seconds=" + strconv.Itoa(int(req.TimeoutSeconds))
	resp := &fido2sdk.WaitDeviceResponse{}
	if err := r.doJSON(ctx, http.MethodGet, path, nil, &resp.Device); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET " + path, Err: err}
	}
	return resp, nil
}

// Info calls GET /api/v1/fido2/devices/{device}.
func (r *RESTAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	if req == nil {
		req = &fido2sdk.InfoRequest{}
	}
	path := "/api/v1/fido2/devices/" + req.Device
	resp := &fido2sdk.InfoResponse{}
	if err := r.doJSON(ctx, http.MethodGet, path, nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET " + path, Err: err}
	}
	return resp, nil
}

// Register calls POST /api/v1/fido2/register.
func (r *RESTAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	resp := &fido2sdk.RegisterResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/fido2/register", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/fido2/register", Err: err}
	}
	return resp, nil
}

// Authenticate calls POST /api/v1/fido2/authenticate.
func (r *RESTAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	resp := &fido2sdk.AuthenticateResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/fido2/authenticate", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/fido2/authenticate", Err: err}
	}
	return resp, nil
}

var _ FIDO2Commands = (*RESTAdapter)(nil)
