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

package piv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const defaultRESTTimeout = 30 * time.Second

// RESTAdapter drives PIV operations over HTTPS REST through the SDK REST
// transport. A daemon without a PIV backend answers 503 with
// ErrPIVNotConfigured, the same surface as Unavailable on other transports.
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

// ListDevices calls GET /api/v1/piv/devices.
func (r *RESTAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	_ = req
	resp := &pivsdk.ListDevicesResponse{}
	if err := r.doJSON(ctx, http.MethodGet, "/api/v1/piv/devices", nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET /api/v1/piv/devices", Err: err}
	}
	return resp, nil
}

// ListSlots calls GET /api/v1/piv/devices/{device}/slots.
func (r *RESTAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	if req == nil {
		req = &pivsdk.ListSlotsRequest{}
	}
	path := "/api/v1/piv/devices/" + req.Device + "/slots"
	resp := &pivsdk.ListSlotsResponse{}
	if err := r.doJSON(ctx, http.MethodGet, path, nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET " + path, Err: err}
	}
	return resp, nil
}

// SlotInfo calls GET /api/v1/piv/slots/{slot}.
func (r *RESTAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	if req == nil {
		req = &pivsdk.SlotInfoRequest{}
	}
	path := "/api/v1/piv/slots/" + req.Slot
	if req.Device != "" {
		path += "?device=" + req.Device
	}
	resp := &pivsdk.SlotInfoResponse{}
	if err := r.doJSON(ctx, http.MethodGet, path, nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET " + path, Err: err}
	}
	return resp, nil
}

// Generate calls POST /api/v1/piv/slots/{slot}/generate.
func (r *RESTAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	if req == nil {
		req = &pivsdk.GenerateRequest{}
	}
	path := "/api/v1/piv/slots/" + req.Slot + "/generate"
	resp := &pivsdk.GenerateResponse{}
	if err := r.doJSON(ctx, http.MethodPost, path, req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST " + path, Err: err}
	}
	return resp, nil
}

// Import calls POST /api/v1/piv/slots/{slot}/import.
func (r *RESTAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	if req == nil {
		req = &pivsdk.ImportRequest{}
	}
	path := "/api/v1/piv/slots/" + req.Slot + "/import"
	resp := &pivsdk.ImportResponse{}
	if err := r.doJSON(ctx, http.MethodPost, path, req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST " + path, Err: err}
	}
	return resp, nil
}

// Sign calls POST /api/v1/piv/slots/{slot}/sign.
func (r *RESTAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	if req == nil {
		req = &pivsdk.SignRequest{}
	}
	path := "/api/v1/piv/slots/" + req.Slot + "/sign"
	resp := &pivsdk.SignResponse{}
	if err := r.doJSON(ctx, http.MethodPost, path, req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST " + path, Err: err}
	}
	return resp, nil
}

// Attest calls POST /api/v1/piv/slots/{slot}/attest.
func (r *RESTAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	if req == nil {
		req = &pivsdk.AttestRequest{}
	}
	path := "/api/v1/piv/slots/" + req.Slot + "/attest"
	resp := &pivsdk.AttestResponse{}
	if err := r.doJSON(ctx, http.MethodPost, path, nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST " + path, Err: err}
	}
	return resp, nil
}

// Reset calls POST /api/v1/piv/devices/{device}/reset.
func (r *RESTAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	if req == nil {
		req = &pivsdk.ResetRequest{}
	}
	path := "/api/v1/piv/devices/" + req.Device + "/reset"
	resp := &pivsdk.ResetResponse{}
	if err := r.doJSON(ctx, http.MethodPost, path, nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST " + path, Err: err}
	}
	return resp, nil
}

var _ PIVCommands = (*RESTAdapter)(nil)
