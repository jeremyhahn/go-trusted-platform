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

// Package daemon provides integration test adapters for daemon services.
// This file implements the DaemonCommands interface using REST HTTP calls.

//go:build integration

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// REST Adapter Constants
// =============================================================================

const (
	// DefaultRESTTimeout is the default timeout for REST requests.
	DefaultRESTTimeout = 30 * time.Second
)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements DaemonCommands using REST HTTP calls.
type RESTAdapter struct {
	endpoint   string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}

	return &RESTAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewAdminHTTPClient(DefaultRESTTimeout),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST connection and verifies connectivity.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	// Verify connectivity with a health check
	_, err := r.Health(ctx)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.endpoint, Err: err}
	}
	return nil
}

// Teardown performs cleanup.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, result interface{}) error {
	url := r.endpoint + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{URL: url, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Err: err}
	}

	if resp.StatusCode >= 400 {
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return ErrRESTRequestFailed{Err: err}
		}
	}

	return nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via REST.
func (r *RESTAdapter) Health(ctx context.Context) (*HealthResult, error) {
	var resp restHealthResponse
	if err := r.doRequest(ctx, http.MethodGet, "/api/v1/health", &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via REST.
func (r *RESTAdapter) Status(ctx context.Context) (*StatusResult, error) {
	var resp restStatusResponse
	if err := r.doRequest(ctx, http.MethodGet, "/api/v1/status", &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via REST.
func (r *RESTAdapter) Version(ctx context.Context) (*VersionResult, error) {
	var resp restVersionResponse
	if err := r.doRequest(ctx, http.MethodGet, "/api/v1/version", &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ListServices lists all services via REST.
func (r *RESTAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	var resp restListServicesResponse
	if err := r.doRequest(ctx, http.MethodGet, "/api/v1/services", &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// GetService retrieves a single service's information via REST.
func (r *RESTAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	var resp restServiceInfoResponse
	if err := r.doRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/services/%s", serviceName), &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// StartService starts a service via REST.
func (r *RESTAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	var resp restServiceActionResponse
	if err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/services/%s/start", serviceName), &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// StopService stops a service via REST.
func (r *RESTAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	var resp restServiceActionResponse
	if err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/services/%s/stop", serviceName), &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// RestartService restarts a service via REST.
func (r *RESTAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	var resp restServiceActionResponse
	if err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/services/%s/restart", serviceName), &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// =============================================================================
// Protocol Operations
// =============================================================================

// ListProtocols lists all protocols via REST.
func (r *RESTAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	var resp restListProtocolsResponse
	if err := r.doRequest(ctx, http.MethodGet, "/api/v1/protocols", &resp); err != nil {
		return nil, err
	}
	return resp.toResult(), nil
}

// =============================================================================
// REST Response Types and Conversion
// =============================================================================

type restHealthResponse struct {
	Status     string                        `json:"status"`
	Components []restComponentHealthResponse `json:"components,omitempty"`
	Timestamp  time.Time                     `json:"timestamp"`
}

type restComponentHealthResponse struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check"`
}

func (r *restHealthResponse) toResult() *HealthResult {
	result := &HealthResult{
		Status:    r.Status,
		Timestamp: r.Timestamp,
	}

	for _, c := range r.Components {
		result.Components = append(result.Components, ComponentHealth{
			Name:      c.Name,
			Status:    c.Status,
			Message:   c.Message,
			LastCheck: c.LastCheck,
		})
	}

	return result
}

type restStatusResponse struct {
	Status    string                `json:"status"`
	Version   string                `json:"version"`
	BuildTime string                `json:"build_time"`
	GitCommit string                `json:"git_commit"`
	GoVersion string                `json:"go_version"`
	System    restSystemInfoReponse `json:"system"`
	Timestamp time.Time             `json:"timestamp"`
}

type restSystemInfoReponse struct {
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	NumCPUs           int    `json:"num_cpus"`
	TotalMemoryMB     uint64 `json:"total_memory_mb"`
	AvailableMemoryMB uint64 `json:"available_memory_mb"`
	Uptime            string `json:"uptime"`
}

func (r *restStatusResponse) toResult() *StatusResult {
	return &StatusResult{
		Status:    r.Status,
		Version:   r.Version,
		BuildTime: r.BuildTime,
		GitCommit: r.GitCommit,
		GoVersion: r.GoVersion,
		System: SystemInfo{
			OS:                r.System.OS,
			Arch:              r.System.Arch,
			NumCPUs:           r.System.NumCPUs,
			TotalMemoryMB:     r.System.TotalMemoryMB,
			AvailableMemoryMB: r.System.AvailableMemoryMB,
			Uptime:            r.System.Uptime,
		},
		Timestamp: r.Timestamp,
	}
}

type restVersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
}

func (r *restVersionResponse) toResult() *VersionResult {
	return &VersionResult{
		Version:   r.Version,
		BuildTime: r.BuildTime,
		GitCommit: r.GitCommit,
		GoVersion: r.GoVersion,
	}
}

type restListServicesResponse struct {
	Services  []restServiceInfoResponse `json:"services"`
	Count     int                       `json:"count"`
	Timestamp time.Time                 `json:"timestamp"`
}

func (r *restListServicesResponse) toResult() *ListServicesResult {
	result := &ListServicesResult{
		Count:     r.Count,
		Timestamp: r.Timestamp,
	}

	for _, s := range r.Services {
		result.Services = append(result.Services, *s.toResult())
	}

	return result
}

type restServiceInfoResponse struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	Uptime     string    `json:"uptime,omitempty"`
	StartCount uint64    `json:"start_count"`
	StopCount  uint64    `json:"stop_count"`
	LastError  string    `json:"last_error,omitempty"`
}

func (r *restServiceInfoResponse) toResult() *ServiceInfoResult {
	return &ServiceInfoResult{
		Name:       r.Name,
		Status:     r.Status,
		StartedAt:  r.StartedAt,
		Uptime:     r.Uptime,
		StartCount: r.StartCount,
		StopCount:  r.StopCount,
		LastError:  r.LastError,
	}
}

type restServiceActionResponse struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (r *restServiceActionResponse) toResult() *ServiceActionResult {
	return &ServiceActionResult{
		Service: r.Service,
		Action:  r.Action,
		Success: r.Success,
		Message: r.Message,
	}
}

type restListProtocolsResponse struct {
	Protocols []restProtocolInfoResponse `json:"protocols"`
	Timestamp time.Time                  `json:"timestamp"`
}

type restProtocolInfoResponse struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	TLS     bool   `json:"tls"`
}

func (r *restListProtocolsResponse) toResult() *ListProtocolsResult {
	result := &ListProtocolsResult{
		Timestamp: r.Timestamp,
	}

	for _, p := range r.Protocols {
		result.Protocols = append(result.Protocols, ProtocolInfo{
			Name:    p.Name,
			Enabled: p.Enabled,
			Address: p.Address,
			Port:    p.Port,
			Status:  p.Status,
			TLS:     p.TLS,
		})
	}

	return result
}

// Ensure RESTAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*RESTAdapter)(nil)
