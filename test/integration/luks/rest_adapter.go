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

package luks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const defaultRESTTimeout = 30 * time.Second

// RESTAdapter drives LUKS operations over HTTPS REST.
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
	r.httpClient = helpers.NewHTTPClient(defaultRESTTimeout)
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

// Status calls GET /api/v1/luks/status.
func (r *RESTAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	resp := &lukssdk.StatusResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/status", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/status", Err: err}
	}
	return resp, nil
}

// ListSlots calls POST /api/v1/luks/list-slots.
func (r *RESTAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	resp := &lukssdk.ListSlotsResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/list-slots", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/list-slots", Err: err}
	}
	return resp, nil
}

// Info calls POST /api/v1/luks/info.
func (r *RESTAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	resp := &lukssdk.InfoResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/info", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/info", Err: err}
	}
	return resp, nil
}

// EnrollPassphrase calls POST /api/v1/luks/enroll-passphrase.
func (r *RESTAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	resp := &lukssdk.EnrollPassphraseResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/enroll-passphrase", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/enroll-passphrase", Err: err}
	}
	return resp, nil
}

// EnrollFIDO2 calls POST /api/v1/luks/enroll-fido2.
func (r *RESTAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	resp := &lukssdk.EnrollFIDO2Response{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/enroll-fido2", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/enroll-fido2", Err: err}
	}
	return resp, nil
}

// EnrollTPM calls POST /api/v1/luks/enroll-tpm.
func (r *RESTAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	resp := &lukssdk.EnrollTPMResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/enroll-tpm", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/enroll-tpm", Err: err}
	}
	return resp, nil
}

// EnrollRecovery calls POST /api/v1/luks/enroll-recovery.
func (r *RESTAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	resp := &lukssdk.EnrollRecoveryResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/enroll-recovery", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/enroll-recovery", Err: err}
	}
	return resp, nil
}

// RemoveKey calls POST /api/v1/luks/remove-key.
func (r *RESTAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	resp := &lukssdk.RemoveKeyResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/remove-key", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/remove-key", Err: err}
	}
	return resp, nil
}

// TestUnlock calls POST /api/v1/luks/test-unlock.
func (r *RESTAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	resp := &lukssdk.TestUnlockResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/test-unlock", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/test-unlock", Err: err}
	}
	return resp, nil
}

// ChangePassphrase calls POST /api/v1/luks/change-passphrase.
func (r *RESTAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	resp := &lukssdk.ChangePassphraseResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/luks/change-passphrase", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/luks/change-passphrase", Err: err}
	}
	return resp, nil
}

var _ LUKSCommands = (*RESTAdapter)(nil)
