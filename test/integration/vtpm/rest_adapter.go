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

package vtpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	// restEnvEndpoint is the environment variable for the REST endpoint.
	restEnvEndpoint = "PLATFORM_REST_ENDPOINT"
	// restDefaultEndpoint is the default REST endpoint.
	restDefaultEndpoint = "http://localhost:8443"
)

// RESTAdapterError represents an error from the REST adapter.
type RESTAdapterError struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e *RESTAdapterError) Error() string {
	return fmt.Sprintf("REST adapter error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// RESTAdapter implements VTPMCommands using REST API.
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter.
func NewRESTAdapter() *RESTAdapter {
	endpoint := restDefaultEndpoint
	if env := os.Getenv(restEnvEndpoint); env != "" {
		endpoint = env
	}

	return &RESTAdapter{
		endpoint: endpoint,
		client:   helpers.NewAdminHTTPClient(0),
	}
}

// Setup prepares the adapter for testing.
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing.
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request and returns the response body.
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &RESTAdapterError{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// doStreamRequest performs an HTTP request that returns a streaming response.
func (a *RESTAdapter) doStreamRequest(ctx context.Context, method, path string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/gzip")
	}
	req.Header.Set("Accept", "application/gzip")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return resp.Body, nil
}

// ============================================================================
// Bundle CRUD Operations
// ============================================================================

// CreateBundle creates a new vTPM bundle.
func (a *RESTAdapter) CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error) {
	path := "/api/v1/vtpm/bundles"

	reqBody := createBundleRequest{
		Mode:              string(opts.Mode),
		Hostname:          opts.Hostname,
		EKAlgorithm:       string(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
		Labels:            opts.Labels,
		TemplateID:        opts.TemplateID,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp bundleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateBundle",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	bundle := a.bundleFromResponse(&resp)
	return &CreateBundleResult{Bundle: bundle}, nil
}

// GetBundle retrieves a bundle by its ID.
func (a *RESTAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp bundleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetBundle",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	bundle := a.bundleFromResponse(&resp)
	return &GetBundleResult{Bundle: bundle}, nil
}

// DeleteBundle removes a bundle.
func (a *RESTAdapter) DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s", url.PathEscape(opts.ID))

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteBundleResult{Success: true}, nil
}

// ListBundles lists all bundles with optional filtering.
func (a *RESTAdapter) ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error) {
	path := "/api/v1/vtpm/bundles"

	params := url.Values{}
	if opts.Mode != "" {
		params.Add("mode", string(opts.Mode))
	}
	if opts.Limit > 0 {
		params.Add("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		params.Add("offset", strconv.Itoa(opts.Offset))
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp listBundlesAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ListBundles",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	bundles := make([]*vtpm.Bundle, len(resp.Bundles))
	for i := range resp.Bundles {
		bundles[i] = a.bundleFromResponse(&resp.Bundles[i])
	}

	return &ListBundlesResult{
		Bundles: bundles,
		Total:   resp.Total,
	}, nil
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

// CreateTemplate creates a new vTPM template.
func (a *RESTAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	path := "/api/v1/vtpm/templates"

	reqBody := createTemplateRequest{
		ID:                opts.ID,
		Description:       opts.Description,
		EKAlgorithm:       string(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp templateAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	template := a.templateFromResponse(&resp)
	return &CreateTemplateResult{Template: template}, nil
}

// GetTemplate retrieves a template by its ID.
func (a *RESTAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/templates/%s", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp templateAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	template := a.templateFromResponse(&resp)
	return &GetTemplateResult{Template: template}, nil
}

// DeleteTemplate removes a template.
func (a *RESTAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/templates/%s", url.PathEscape(opts.ID))

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteTemplateResult{Success: true}, nil
}

// ListTemplates lists all templates.
func (a *RESTAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	path := "/api/v1/vtpm/templates"

	params := url.Values{}
	if opts.Limit > 0 {
		params.Add("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		params.Add("offset", strconv.Itoa(opts.Offset))
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp listTemplatesAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ListTemplates",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	templates := make([]*vtpm.Template, len(resp.Templates))
	for i := range resp.Templates {
		templates[i] = a.templateFromResponse(&resp.Templates[i])
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     len(templates),
	}, nil
}

// CloneTemplate clones a template to create a new bundle.
func (a *RESTAdapter) CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/templates/%s/clone", url.PathEscape(opts.TemplateID))

	reqBody := cloneTemplateRequest{
		Hostname: opts.Hostname,
		Labels:   opts.Labels,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp bundleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CloneTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	bundle := a.bundleFromResponse(&resp)
	return &CloneTemplateResult{Bundle: bundle}, nil
}

// ============================================================================
// Export/Import Operations
// ============================================================================

// ExportBundle exports a bundle as a tar.gz archive.
func (a *RESTAdapter) ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/export", url.PathEscape(opts.ID))

	respBody, err := a.doStreamRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer respBody.Close()

	data, err := io.ReadAll(respBody)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "ExportBundle",
			Message:   "failed to read export data: " + err.Error(),
		}
	}

	// Calculate checksum
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	// Write to specified path or generate a temp file
	archivePath := opts.OutputPath
	if archivePath == "" {
		tmpFile, tmpErr := os.CreateTemp("", "vtpm-export-*.tar.gz")
		if tmpErr != nil {
			return nil, &RESTAdapterError{
				Operation: "ExportBundle",
				Message:   "failed to create temp file: " + tmpErr.Error(),
			}
		}
		archivePath = tmpFile.Name()
		tmpFile.Close()
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0755); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ExportBundle",
			Message:   "failed to create output directory: " + err.Error(),
		}
	}
	if err := os.WriteFile(archivePath, data, 0600); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ExportBundle",
			Message:   "failed to write archive file: " + err.Error(),
		}
	}

	return &ExportBundleResult{
		ArchivePath: archivePath,
		Size:        int64(len(data)),
		Checksum:    checksum,
	}, nil
}

// ImportBundle imports a bundle from a tar.gz archive.
func (a *RESTAdapter) ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error) {
	path := "/api/v1/vtpm/bundles/import"

	var data []byte
	var err error

	// Get archive data from path or direct data
	if opts.ArchivePath != "" {
		data, err = os.ReadFile(opts.ArchivePath)
		if err != nil {
			return nil, &RESTAdapterError{
				Operation: "ImportBundle",
				Message:   "failed to read archive file: " + err.Error(),
			}
		}
	} else if opts.ArchiveData != nil {
		data = opts.ArchiveData
	} else {
		return nil, &RESTAdapterError{
			Operation: "ImportBundle",
			Message:   "either ArchivePath or ArchiveData must be provided",
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+path, bytes.NewReader(data))
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "ImportBundle",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "ImportBundle",
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation:  "ImportBundle",
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RESTAdapterError{
			Operation:  "ImportBundle",
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(body),
		}
	}

	// The REST server returns ImportBundleResponse{Bundle: BundleResponse{...}, Timestamp: ...}
	// which wraps the bundle data under a "bundle" key. Try the wrapped format first,
	// then fall back to direct parsing for compatibility.
	var importResp importBundleAPIResponse
	if err := json.Unmarshal(body, &importResp); err == nil && importResp.Bundle.ID != "" {
		bundle := a.bundleFromResponse(&importResp.Bundle)
		return &ImportBundleResult{Bundle: bundle}, nil
	}

	// Fall back to direct bundleAPIResponse parsing
	var bundleResp bundleAPIResponse
	if err := json.Unmarshal(body, &bundleResp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ImportBundle",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	bundle := a.bundleFromResponse(&bundleResp)
	return &ImportBundleResult{Bundle: bundle}, nil
}

// ============================================================================
// Validation Operations
// ============================================================================

// ValidateBundle validates a bundle's integrity.
func (a *RESTAdapter) ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/validate", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp validateBundleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ValidateBundle",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &ValidateBundleResult{
		Valid:            resp.Valid,
		Errors:           resp.Errors,
		ChecksumVerified: resp.Valid && len(resp.Errors) == 0,
	}, nil
}

// ============================================================================
// Path Helper Operations
// ============================================================================

// GetBundlePath returns the filesystem path to a bundle.
func (a *RESTAdapter) GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/path", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pathAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetBundlePath",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetBundlePathResult{Path: resp.Path}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (a *RESTAdapter) GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/tpm-socket", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pathAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetTPMSocketPath",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetTPMSocketPathResult{Path: resp.Path}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (a *RESTAdapter) GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/nvram", url.PathEscape(opts.ID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pathAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetNVRAMPath",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetNVRAMPathResult{Path: resp.Path}, nil
}

// ============================================================================
// Runtime TPM Operations
// ============================================================================

// Start starts the swtpm daemon for a bundle.
func (a *RESTAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/start", url.PathEscape(opts.BundleID))

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp startBundleAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "Start",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &StartResult{
		BundleID:   resp.BundleID,
		Running:    resp.Running,
		SocketPath: resp.SocketPath,
	}, nil
}

// Stop stops the swtpm daemon for a bundle.
func (a *RESTAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/stop", url.PathEscape(opts.BundleID))

	body, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp bundleActionAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "Stop",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &StopResult{
		BundleID: resp.BundleID,
		Stopped:  resp.Success,
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running.
func (a *RESTAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/state", url.PathEscape(opts.BundleID))

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp bundleStateAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "IsRunning",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &IsRunningResult{
		BundleID: resp.ID,
		Running:  resp.Running,
	}, nil
}

// Quote generates a TPM quote over specified PCRs.
func (a *RESTAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/quote", url.PathEscape(opts.BundleID))

	reqBody := quoteAPIRequest{
		Nonce: base64.StdEncoding.EncodeToString(opts.Nonce),
		PCRs:  opts.PCRs,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp quoteAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "Quote",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	quoteBytes, err := base64.StdEncoding.DecodeString(resp.Quote)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "Quote",
			Message:   "failed to decode quote base64: " + err.Error(),
		}
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "Quote",
			Message:   "failed to decode signature base64: " + err.Error(),
		}
	}

	pcrValues := make(map[int][]byte, len(resp.PCRValues))
	for idx, val := range resp.PCRValues {
		decoded, decodeErr := base64.StdEncoding.DecodeString(val)
		if decodeErr != nil {
			return nil, &RESTAdapterError{
				Operation: "Quote",
				Message:   fmt.Sprintf("failed to decode PCR %d base64: %s", idx, decodeErr.Error()),
			}
		}
		pcrValues[idx] = decoded
	}

	return &QuoteResult{
		BundleID:      resp.BundleID,
		Quote:         quoteBytes,
		Signature:     signatureBytes,
		PCRValues:     pcrValues,
		HashAlgorithm: resp.HashAlgorithm,
	}, nil
}

// Seal encrypts data to the TPM, optionally binding to PCR values.
func (a *RESTAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/seal", url.PathEscape(opts.BundleID))

	reqBody := sealAPIRequest{
		Data:      base64.StdEncoding.EncodeToString(opts.Data),
		PCRs:      opts.PCRs,
		AuthValue: opts.AuthValue,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp sealAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "Seal",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	sealedData, err := base64.StdEncoding.DecodeString(resp.SealedData)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "Seal",
			Message:   "failed to decode sealed_data base64: " + err.Error(),
		}
	}

	return &SealResult{
		BundleID:   resp.BundleID,
		SealedData: sealedData,
	}, nil
}

// Unseal decrypts data that was previously sealed to the TPM.
func (a *RESTAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/unseal", url.PathEscape(opts.BundleID))

	reqBody := unsealAPIRequest{
		SealedData: base64.StdEncoding.EncodeToString(opts.SealedData),
		AuthValue:  opts.AuthValue,
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp unsealAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "Unseal",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "Unseal",
			Message:   "failed to decode data base64: " + err.Error(),
		}
	}

	return &UnsealResult{
		BundleID: resp.BundleID,
		Data:     data,
	}, nil
}

// ExtendPCR extends a PCR with the provided data.
func (a *RESTAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/pcr/%d/extend",
		url.PathEscape(opts.BundleID), opts.PCRIndex)

	reqBody := pcrExtendAPIRequest{
		Data: base64.StdEncoding.EncodeToString(opts.Data),
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp bundleActionAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ExtendPCR",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &ExtendPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: opts.PCRIndex,
		Extended: resp.Success,
	}, nil
}

// ReadPCR reads the current value of a PCR.
func (a *RESTAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	path := fmt.Sprintf("/api/v1/vtpm/bundles/%s/pcr/%d",
		url.PathEscape(opts.BundleID), opts.PCRIndex)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp pcrReadAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ReadPCR",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	value, err := base64.StdEncoding.DecodeString(resp.Value)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: "ReadPCR",
			Message:   "failed to decode value base64: " + err.Error(),
		}
	}

	return &ReadPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: resp.PCRIndex,
		Value:    value,
	}, nil
}

// ============================================================================
// Response Type Converters
// ============================================================================

// bundleFromResponse converts a bundleAPIResponse to a vtpm.Bundle.
func (a *RESTAdapter) bundleFromResponse(resp *bundleAPIResponse) *vtpm.Bundle {
	if resp == nil {
		return nil
	}

	bundle := &vtpm.Bundle{
		ID:         resp.ID,
		Mode:       vtpm.BundleMode(resp.Mode),
		ClonedFrom: resp.ClonedFrom,
	}

	if resp.CreatedAt != nil {
		bundle.CreatedAt = *resp.CreatedAt
	}

	if resp.Manifest != nil {
		bundle.Manifest = a.manifestFromResponse(resp.Manifest)
	}

	if resp.TPMState != nil {
		bundle.TPMState = &vtpm.TPMState{
			StateDir:     resp.TPMState.StateDir,
			PermallFile:  resp.TPMState.PermallFile,
			VolatileFile: resp.TPMState.VolatileFile,
		}
	}

	if resp.OVMFState != nil {
		bundle.OVMFState = &vtpm.OVMFState{
			NVRAMFile: resp.OVMFState.NVRAMFile,
		}
	}

	if resp.SecureBootKeys != nil {
		bundle.SecureBootKeys = &vtpm.SecureBootKeyPaths{
			Dir:     resp.SecureBootKeys.Dir,
			PKKey:   resp.SecureBootKeys.PKKey,
			PKCert:  resp.SecureBootKeys.PKCert,
			KEKKey:  resp.SecureBootKeys.KEKKey,
			KEKCert: resp.SecureBootKeys.KEKCert,
			DBKey:   resp.SecureBootKeys.DBKey,
			DBCert:  resp.SecureBootKeys.DBCert,
		}
	}

	return bundle
}

// manifestFromResponse converts a manifestAPIResponse to a vtpm.Manifest.
func (a *RESTAdapter) manifestFromResponse(resp *manifestAPIResponse) *vtpm.Manifest {
	if resp == nil {
		return nil
	}

	manifest := &vtpm.Manifest{
		Version:           resp.Version,
		ID:                resp.ID,
		Mode:              vtpm.BundleMode(resp.Mode),
		Hostname:          resp.Hostname,
		EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
		EKHandle:          resp.EKHandle,
		SecureBootEnabled: resp.SecureBootEnabled,
		Checksums:         resp.Checksums,
		Labels:            resp.Labels,
		ClonedFrom:        resp.ClonedFrom,
	}

	if resp.CreatedAt != nil {
		manifest.CreatedAt = *resp.CreatedAt
	}

	if resp.EKCertificate != nil {
		manifest.EKCertificate = &vtpm.EKCertInfo{
			Subject:      resp.EKCertificate.Subject,
			Issuer:       resp.EKCertificate.Issuer,
			SerialNumber: resp.EKCertificate.SerialNumber,
			Fingerprint:  resp.EKCertificate.Fingerprint,
		}
		if resp.EKCertificate.NotBefore != nil {
			manifest.EKCertificate.NotBefore = *resp.EKCertificate.NotBefore
		}
		if resp.EKCertificate.NotAfter != nil {
			manifest.EKCertificate.NotAfter = *resp.EKCertificate.NotAfter
		}
	}

	if resp.SecureBootKeys != nil {
		manifest.SecureBootKeys = &vtpm.SecureBootKeyInfo{
			PKFingerprint:  resp.SecureBootKeys.PKFingerprint,
			KEKFingerprint: resp.SecureBootKeys.KEKFingerprint,
			DBFingerprint:  resp.SecureBootKeys.DBFingerprint,
			OwnerGUID:      resp.SecureBootKeys.OwnerGUID,
		}
	}

	return manifest
}

// templateFromResponse converts a templateAPIResponse to a vtpm.Template.
func (a *RESTAdapter) templateFromResponse(resp *templateAPIResponse) *vtpm.Template {
	if resp == nil {
		return nil
	}

	template := &vtpm.Template{
		ID:                resp.ID,
		Description:       resp.Description,
		TPMStateDir:       resp.TPMStateDir,
		NVRAMPath:         resp.NVRAMPath,
		SecureBootKeysDir: resp.SecureBootKeysDir,
		EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
		SecureBootEnabled: resp.SecureBootEnabled,
	}

	if resp.CreatedAt != nil {
		template.CreatedAt = *resp.CreatedAt
	}

	return template
}

// ============================================================================
// Internal API Request/Response Types
// ============================================================================

type createBundleRequest struct {
	Mode              string            `json:"mode"`
	Hostname          string            `json:"hostname,omitempty"`
	EKAlgorithm       string            `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool              `json:"secure_boot_enabled"`
	Labels            map[string]string `json:"labels,omitempty"`
	TemplateID        string            `json:"template_id,omitempty"`
}

type createTemplateRequest struct {
	ID                string `json:"id"`
	Description       string `json:"description,omitempty"`
	EKAlgorithm       string `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool   `json:"secure_boot_enabled"`
}

type cloneTemplateRequest struct {
	Hostname string            `json:"hostname"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type bundleAPIResponse struct {
	ID             string                         `json:"id"`
	Mode           string                         `json:"mode"`
	Manifest       *manifestAPIResponse           `json:"manifest,omitempty"`
	TPMState       *tpmStateAPIResponse           `json:"tpm_state,omitempty"`
	OVMFState      *ovmfStateAPIResponse          `json:"ovmf_state,omitempty"`
	SecureBootKeys *secureBootKeyPathsAPIResponse `json:"secure_boot_keys,omitempty"`
	CreatedAt      *time.Time                     `json:"created_at,omitempty"`
	ClonedFrom     string                         `json:"cloned_from,omitempty"`
}

type manifestAPIResponse struct {
	Version           string                        `json:"version"`
	ID                string                        `json:"id"`
	Mode              string                        `json:"mode"`
	Hostname          string                        `json:"hostname,omitempty"`
	CreatedAt         *time.Time                    `json:"created_at,omitempty"`
	EKCertificate     *ekCertInfoAPIResponse        `json:"ek_certificate,omitempty"`
	EKAlgorithm       string                        `json:"ek_algorithm"`
	EKHandle          uint32                        `json:"ek_handle"`
	SecureBootEnabled bool                          `json:"secure_boot_enabled"`
	SecureBootKeys    *secureBootKeyInfoAPIResponse `json:"secure_boot_keys,omitempty"`
	Checksums         map[string]string             `json:"checksums,omitempty"`
	Labels            map[string]string             `json:"labels,omitempty"`
	ClonedFrom        string                        `json:"cloned_from,omitempty"`
}

type ekCertInfoAPIResponse struct {
	Subject      string     `json:"subject"`
	Issuer       string     `json:"issuer"`
	SerialNumber string     `json:"serial_number"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
}

type secureBootKeyInfoAPIResponse struct {
	PKFingerprint  string `json:"pk_fingerprint"`
	KEKFingerprint string `json:"kek_fingerprint"`
	DBFingerprint  string `json:"db_fingerprint"`
	OwnerGUID      string `json:"owner_guid"`
}

type secureBootKeyPathsAPIResponse struct {
	Dir     string `json:"dir"`
	PKKey   string `json:"pk_key"`
	PKCert  string `json:"pk_crt"`
	KEKKey  string `json:"kek_key"`
	KEKCert string `json:"kek_crt"`
	DBKey   string `json:"db_key"`
	DBCert  string `json:"db_crt"`
}

type tpmStateAPIResponse struct {
	StateDir     string `json:"state_dir"`
	PermallFile  string `json:"permall_file"`
	VolatileFile string `json:"volatile_file,omitempty"`
}

type ovmfStateAPIResponse struct {
	NVRAMFile string `json:"nvram_file"`
}

type templateAPIResponse struct {
	ID                string     `json:"id"`
	Description       string     `json:"description,omitempty"`
	TPMStateDir       string     `json:"tpm_state_dir"`
	NVRAMPath         string     `json:"nvram_path"`
	SecureBootKeysDir string     `json:"secure_boot_keys_dir,omitempty"`
	EKAlgorithm       string     `json:"ek_algorithm"`
	SecureBootEnabled bool       `json:"secure_boot_enabled"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
}

type listBundlesAPIResponse struct {
	Bundles []bundleAPIResponse `json:"bundles"`
	Total   int                 `json:"total"`
}

type listTemplatesAPIResponse struct {
	Templates []templateAPIResponse `json:"templates"`
}

type validateBundleAPIResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

type pathAPIResponse struct {
	Path string `json:"path"`
}

// importBundleAPIResponse matches the REST server's ImportBundleResponse
// which wraps the bundle data under a "bundle" key.
type importBundleAPIResponse struct {
	Bundle    bundleAPIResponse `json:"bundle"`
	Timestamp *time.Time        `json:"timestamp,omitempty"`
}

// Runtime TPM API request/response types

type bundleActionAPIResponse struct {
	BundleID string `json:"bundle_id"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

// startBundleAPIResponse is the start reply: the action result plus the
// running state and the swtpm socket path.
type startBundleAPIResponse struct {
	bundleActionAPIResponse
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path"`
}

type bundleStateAPIResponse struct {
	ID         string     `json:"id"`
	Running    bool       `json:"running"`
	SocketPath string     `json:"socket_path"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

type quoteAPIRequest struct {
	Nonce string `json:"nonce"`
	PCRs  []int  `json:"pcrs,omitempty"`
}

type quoteAPIResponse struct {
	BundleID      string         `json:"bundle_id"`
	Quote         string         `json:"quote"`
	Signature     string         `json:"signature"`
	PCRValues     map[int]string `json:"pcr_values"`
	HashAlgorithm string         `json:"hash_algorithm"`
	Timestamp     *time.Time     `json:"timestamp,omitempty"`
}

type sealAPIRequest struct {
	Data      string `json:"data"`
	PCRs      []int  `json:"pcrs,omitempty"`
	AuthValue string `json:"auth_value,omitempty"`
}

type sealAPIResponse struct {
	BundleID   string     `json:"bundle_id"`
	SealedData string     `json:"sealed_data"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

type unsealAPIRequest struct {
	SealedData string `json:"sealed_data"`
	AuthValue  string `json:"auth_value,omitempty"`
}

type unsealAPIResponse struct {
	BundleID  string     `json:"bundle_id"`
	Data      string     `json:"data"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

type pcrExtendAPIRequest struct {
	Data string `json:"data"`
}

type pcrReadAPIResponse struct {
	BundleID  string     `json:"bundle_id"`
	PCRIndex  int        `json:"pcr_index"`
	Value     string     `json:"value"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// Verify RESTAdapter implements VTPMCommands
var _ VTPMCommands = (*RESTAdapter)(nil)
