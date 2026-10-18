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

package ceremony

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const defaultRESTTimeout = 30 * time.Second

// RESTAdapter drives ceremony operations over HTTPS REST through the SDK REST
// transport. A daemon without a ceremony backend answers 503 with
// ErrCeremonyNotConfigured, the same error the other transports report.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter returns an unconfigured REST adapter.
func NewRESTAdapter() *RESTAdapter { return &RESTAdapter{} }

// Name returns "REST".
func (r *RESTAdapter) Name() string { return "REST" }

// Setup constructs the HTTPS client and records the base URL.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}
	r.baseURL = endpoint
	r.httpClient = helpers.NewHTTPClient(defaultRESTTimeout)
	return nil
}

// Teardown releases the HTTP client's idle connections.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// doJSON sends an HTTP request with optional body and decodes the response.
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

// Init invokes POST /api/v1/ceremony/init.
func (r *RESTAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	resp := &ceremonysdk.InitResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/init", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/init", Err: err}
	}
	return resp, nil
}

// Status invokes GET /api/v1/ceremony/status.
func (r *RESTAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	resp := &ceremonysdk.StatusResponse{}
	if err := r.doJSON(ctx, http.MethodGet, "/api/v1/ceremony/status", nil, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GET /api/v1/ceremony/status", Err: err}
	}
	return resp, nil
}

// ClaimCertBegin invokes POST /api/v1/ceremony/claim-cert/begin.
func (r *RESTAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	resp := &ceremonysdk.ClaimCertBeginResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/claim-cert/begin", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/claim-cert/begin", Err: err}
	}
	return resp, nil
}

// ClaimCertComplete invokes POST /api/v1/ceremony/claim-cert/complete.
func (r *RESTAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	var wire restCertificateResponse
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/claim-cert/complete", req, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/claim-cert/complete", Err: err}
	}
	return &ceremonysdk.ClaimCertCompleteResponse{Certificate: wire.CertificatePEM, Chain: wire.ChainPEM}, nil
}

// ClaimShareBegin invokes POST /api/v1/ceremony/claim-share/begin.
func (r *RESTAdapter) ClaimShareBegin(ctx context.Context, req *ceremonysdk.ClaimShareBeginRequest) (*ceremonysdk.ClaimShareBeginResponse, error) {
	resp := &ceremonysdk.ClaimShareBeginResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/claim-share/begin", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/claim-share/begin", Err: err}
	}
	return resp, nil
}

// ClaimShareComplete invokes POST /api/v1/ceremony/claim-share/complete.
func (r *RESTAdapter) ClaimShareComplete(ctx context.Context, req *ceremonysdk.ClaimShareCompleteRequest) (*ceremonysdk.ClaimShareCompleteResponse, error) {
	resp := &ceremonysdk.ClaimShareCompleteResponse{}
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/claim-share/complete", req, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/claim-share/complete", Err: err}
	}
	return resp, nil
}

// SignCSR invokes POST /api/v1/ceremony/sign-csr.
func (r *RESTAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	var wire restCertificateResponse
	if err := r.doJSON(ctx, http.MethodPost, "/api/v1/ceremony/sign-csr", req, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "POST /api/v1/ceremony/sign-csr", Err: err}
	}
	return &ceremonysdk.SignCSRResponse{Certificate: wire.CertificatePEM, Chain: wire.ChainPEM}, nil
}

// restCertificateResponse is the REST body of claim-cert/complete and
// sign-csr: the platform.v1 CeremonyClaimCertCompleteResponse and
// CeremonySignCSRResponse field names (pkg/api/grpc/proto/ceremony.proto).
type restCertificateResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
}

var _ CeremonyCommands = (*RESTAdapter)(nil)
