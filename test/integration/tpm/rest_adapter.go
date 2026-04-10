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

package tpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements TPMCommands using REST API calls to platformd.
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST protocol adapter instance.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}

	return &RESTAdapter{
		endpoint: endpoint,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST adapter by verifying connectivity.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+"/health", nil)
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.endpoint, Err: err}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.endpoint, Err: err}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown performs cleanup.
func (r *RESTAdapter) Teardown() error {
	return nil
}

// doRequest performs an HTTP request and returns the response body.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, ErrCallFailed{Protocol: "REST", Method: method + " " + path, Err: err}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.endpoint+path, reqBody)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: method + " " + path, Err: err}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: method + " " + path, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: method + " " + path, Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrCallFailed{
			Protocol: "REST",
			Method:   method + " " + path,
			Err:      fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	return respBody, nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via REST.
func (r *RESTAdapter) Info(ctx context.Context) (*InfoResult, error) {
	body, err := r.doRequest(ctx, http.MethodGet, "/api/v1/tpm/info", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Info         string `json:"info"`
		Manufacturer *struct {
			Name            string `json:"name"`
			Model           string `json:"model"`
			FirmwareVersion string `json:"firmware_version"`
		} `json:"manufacturer"`
		IsSimulator  bool   `json:"is_simulator"`
		FIPSMode     bool   `json:"fips_mode"`
		MaxNVRAMSize uint32 `json:"max_nvram_size"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Info", Err: err}
	}

	result := &InfoResult{
		Version:      "2.0",
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FIPSMode,
		MaxNVRAMSize: resp.MaxNVRAMSize,
	}

	if resp.Manufacturer != nil {
		result.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer.Name,
			Model:           resp.Manufacturer.Model,
			FirmwareVersion: resp.Manufacturer.FirmwareVersion,
		}
	}

	return result, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via REST.
func (r *RESTAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	reqBody := map[string]interface{}{
		"owner_password": opts.OwnerPassword,
	}

	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/provision", reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Provision", Err: err}
	}

	return &ProvisionResult{
		Success:    resp.Success,
		Message:    resp.Message,
		EKCreated:  resp.Success,
		SRKCreated: resp.Success,
		AKCreated:  resp.Success,
	}, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via REST.
func (r *RESTAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	reqBody := map[string]interface{}{
		"owner_password": opts.OwnerPassword,
	}

	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/clear", reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Clear", Err: err}
	}

	return &ClearResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via REST.
func (r *RESTAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/ek", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EKCreate", Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &EKCreateResult{
		Success:   true,
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via REST.
func (r *RESTAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	body, err := r.doRequest(ctx, http.MethodGet, "/api/v1/tpm/ek", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EKInfo", Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &EKInfoResult{
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
	}, nil
}

// EKCertificate retrieves the EK certificate via REST.
func (r *RESTAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	body, err := r.doRequest(ctx, http.MethodGet, "/api/v1/tpm/ek/certificate", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Certificate string `json:"certificate"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EKCertificate", Err: err}
	}

	cert, decErr := base64.StdEncoding.DecodeString(resp.Certificate)
	if decErr != nil {
		cert = []byte(resp.Certificate)
	}

	return &EKCertificateResult{
		Format:      "DER",
		Certificate: cert,
	}, nil
}

// EKDelete deletes the EK via REST.
func (r *RESTAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	body, err := r.doRequest(ctx, http.MethodDelete, "/api/v1/tpm/ek", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EKDelete", Err: err}
	}

	return &EKDeleteResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via REST.
func (r *RESTAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/srk", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "SRKCreate", Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &SRKCreateResult{
		Success:   true,
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via REST.
func (r *RESTAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	body, err := r.doRequest(ctx, http.MethodGet, "/api/v1/tpm/srk", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "SRKInfo", Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &SRKInfoResult{
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
	}, nil
}

// SRKDelete deletes the SRK via REST.
func (r *RESTAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	body, err := r.doRequest(ctx, http.MethodDelete, "/api/v1/tpm/srk", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "SRKDelete", Err: err}
	}

	return &SRKDeleteResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via REST.
func (r *RESTAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	reqBody := map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(opts.Data),
	}

	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/seal", reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		SealedData string `json:"sealed_data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Seal", Err: err}
	}

	return &SealResult{
		Success: true,
		Message: "data sealed successfully",
	}, nil
}

// Unseal unseals data from the TPM via REST.
func (r *RESTAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	reqBody := map[string]interface{}{
		"cn": opts.CN,
	}

	body, err := r.doRequest(ctx, http.MethodPost, "/api/v1/tpm/unseal", reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data string `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Unseal", Err: err}
	}

	data, decErr := base64.StdEncoding.DecodeString(resp.Data)
	if decErr != nil {
		data = []byte(resp.Data)
	}

	return &UnsealResult{
		Success: true,
		Data:    data,
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via REST.
func (r *RESTAdapter) EventLog(ctx context.Context, path string) (*EventLogResult, error) {
	body, err := r.doRequest(ctx, http.MethodGet, "/api/v1/tpm/eventlog", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		EventLog   string `json:"event_log"`
		Format     string `json:"format"`
		EventCount uint64 `json:"event_count"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EventLog", Err: err}
	}

	result := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	if resp.EventLog != "" {
		eventData, decErr := base64.StdEncoding.DecodeString(resp.EventLog)
		if decErr != nil {
			eventData = []byte(resp.EventLog)
		}
		result.Events = append(result.Events, EventLogEntry{
			EventData: eventData,
		})
	}

	return result, nil
}

// Ensure RESTAdapter implements TPMCommands interface.
var _ TPMCommands = (*RESTAdapter)(nil)
