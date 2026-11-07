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

package ca

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// MCP Protocol Adapter Constants
// =============================================================================

const (
	// DefaultMCPTimeoutCA is the default timeout for MCP CA operations.
	// Kept at 10s per project convention to avoid slow test skips when the
	// MCP server is unavailable.
	DefaultMCPTimeoutCA = 10 * time.Second

	// mcpCAProtocolVersion is the MCP protocol version.
	mcpCAProtocolVersion = "2024-11-05"

	// mcpCAClientName is the name of this MCP test client.
	mcpCAClientName = "ca-integration-test"

	// mcpCAClientVersion is the version of this MCP test client.
	mcpCAClientVersion = "1.0.0"
)

// MCP Tool names for CA operations.
const (
	MCPToolCAInfo    = "ca_info"
	MCPToolCAIssue   = "ca_issue"
	MCPToolCASignCSR = "ca_sign_csr"
	MCPToolCAGet     = "ca_get"
	MCPToolCAList    = "ca_list"
	MCPToolCARevoke  = "ca_revoke"
	MCPToolCARenew   = "ca_renew"
	MCPToolCAVerify  = "ca_verify"
	MCPToolCACRL     = "ca_crl"
	MCPToolCABundle  = "ca_bundle"
)

// =============================================================================
// MCP Error Types
// =============================================================================

// ErrMCPCAConnectionFailed indicates an MCP connection failure.
type ErrMCPCAConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPCAConnectionFailed) Error() string {
	return fmt.Sprintf("MCP CA connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPCAConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPCAInitializeFailed indicates MCP initialization failure.
type ErrMCPCAInitializeFailed struct {
	Err error
}

func (e ErrMCPCAInitializeFailed) Error() string {
	return fmt.Sprintf("MCP CA initialization failed: %v", e.Err)
}

func (e ErrMCPCAInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPCAToolCallFailed indicates an MCP tool call failure.
type ErrMCPCAToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPCAToolCallFailed) Error() string {
	return fmt.Sprintf("MCP CA tool call %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPCAResponseParseFailed indicates MCP response parsing failure.
type ErrMCPCAResponseParseFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPCAResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP CA response parse failed for %s: %v", e.Tool, e.Err)
}

func (e ErrMCPCAResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPCARequestFailed indicates an MCP HTTP request failure.
type ErrMCPCARequestFailed struct {
	Err error
}

func (e ErrMCPCARequestFailed) Error() string {
	return fmt.Sprintf("MCP CA request failed: %v", e.Err)
}

func (e ErrMCPCARequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP JSON-RPC Types
// =============================================================================

type mcpCARequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type mcpCAResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpCAError     `json:"error,omitempty"`
}

type mcpCAError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpCACallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type mcpCACallToolResult struct {
	Content []mcpCAContent `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type mcpCAContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type mcpCAInitializeRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      mcpCAClientInfo        `json:"clientInfo"`
}

type mcpCAClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// =============================================================================
// MCP Protocol Adapter
// =============================================================================

// MCPAdapter implements CACommands using MCP (Model Context Protocol) calls to platformd.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP protocol adapter instance.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection by performing the JSON-RPC initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint, err := helpers.RequireEndpoint(EnvPlatformMCPEndpoint)
	if err != nil {
		return err
	}
	m.endpoint = helpers.MCPBaseURL(endpoint)
	m.httpClient = helpers.NewHTTPClient(DefaultMCPTimeoutCA)

	initReq := mcpCAInitializeRequest{
		ProtocolVersion: mcpCAProtocolVersion,
		Capabilities:    map[string]interface{}{},
		ClientInfo: mcpCAClientInfo{
			Name:    mcpCAClientName,
			Version: mcpCAClientVersion,
		},
	}

	var result json.RawMessage
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPCAInitializeFailed{Err: err}
	}

	m.initialized = true
	return nil
}

// Teardown performs cleanup.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	m.initialized = false
	return nil
}

// =============================================================================
// HTTP Transport Layer
// =============================================================================

// nextRequestID returns a monotonically increasing request ID.
func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC request over HTTP and decodes the response.
func (m *MCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpCARequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return ErrMCPCARequestFailed{Err: err}
	}

	mcpURL := m.endpoint + "/mcp"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, bytes.NewReader(reqBody))
	if err != nil {
		return ErrMCPCARequestFailed{Err: err}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return ErrMCPCAConnectionFailed{Endpoint: m.endpoint, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrMCPCARequestFailed{Err: err}
	}

	var rpcResp mcpCAResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return ErrMCPCAResponseParseFailed{Tool: method, Err: err}
	}

	if rpcResp.Error != nil {
		return ErrMCPCAToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return ErrMCPCAResponseParseFailed{Tool: method, Err: err}
		}
	}

	return nil
}

// callTool calls an MCP tool via the tools/call JSON-RPC method.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}) (*mcpCACallToolResult, error) {
	params := mcpCACallToolParams{
		Name:      name,
		Arguments: args,
	}

	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", params, &rawResult); err != nil {
		return nil, ErrMCPCAToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}

	// The tool output is JSON in the CallToolResult's text block.
	output, err := mcpwire.ToolOutputJSON(rawResult)
	if err != nil {
		return nil, ErrMCPCAToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}
	return &mcpCACallToolResult{
		Content: []mcpCAContent{{Type: "text", Text: string(output)}},
	}, nil
}

// parseToolResult parses the tool result content into the target struct.
func (m *MCPAdapter) parseToolResult(result *mcpCACallToolResult, tool string, v interface{}) error {
	if len(result.Content) == 0 {
		return ErrMCPCAResponseParseFailed{Tool: tool, Err: fmt.Errorf("no content")}
	}

	for _, content := range result.Content {
		if content.Type == "text" && content.Text != "" {
			if err := json.Unmarshal([]byte(content.Text), v); err != nil {
				return ErrMCPCAResponseParseFailed{Tool: tool, Err: err}
			}
			return nil
		}
	}

	return ErrMCPCAResponseParseFailed{Tool: tool, Err: fmt.Errorf("no text content")}
}

// =============================================================================
// MCP Response Types
//
// The MCP service returns protobuf response objects serialized via encoding/json
// through marshalResult(). Timestamps are {seconds, nanos}, enums are integers,
// and nested messages are JSON objects.
// =============================================================================

// mcpCAInfoResp matches the JSON shape of GetCAInfoResponse -> ca_info (CAInfo).
type mcpCAInfoResp struct {
	CAInfo *struct {
		CommonName          string               `json:"common_name"`
		IsInitialized       bool                 `json:"is_initialized"`
		IsIntermediate      bool                 `json:"is_intermediate"`
		DefaultAlgorithm    string               `json:"default_algorithm"`
		DefaultValidityDays int32                `json:"default_validity_days"`
		RootCert            *protoCertSummary    `json:"root_cert"`
		Intermediates       []*protoCertSummary  `json:"intermediates"`
		KeyStores           []*protoKeyStoreInfo `json:"key_stores"`
	} `json:"ca_info"`
}

// mcpCACertResp matches the JSON shape of IssueCertificateResponse or GetCertificateResponse.
type mcpCACertResp struct {
	Status      *protoStatus      `json:"status"`
	Certificate *protoCertificate `json:"certificate"`
}

// mcpCAListResp matches the JSON shape of ListCertificatesResponse.
type mcpCAListResp struct {
	Certificates []*protoCertSummary `json:"certificates"`
	Pagination   *struct {
		TotalItems uint64 `json:"total_items"`
	} `json:"pagination"`
}

// mcpCARevokeResp matches the JSON shape of RevokeCertificateResponse.
type mcpCARevokeResp struct {
	Status            *protoStatus    `json:"status"`
	Serial            string          `json:"serial"`
	CertificateStatus int32           `json:"certificate_status"`
	RevokedAt         *protoTimestamp `json:"revoked_at"`
	Reason            int32           `json:"reason"`
}

// mcpCARenewResp matches the JSON shape of RenewCertificateResponse.
type mcpCARenewResp struct {
	Status         *protoStatus      `json:"status"`
	OldCertificate *protoCertificate `json:"old_certificate"`
	NewCertificate *protoCertificate `json:"new_certificate"`
}

// mcpCAVerifyResp matches the JSON shape of VerifyCertificateResponse.
type mcpCAVerifyResp struct {
	Status   *protoStatus `json:"status"`
	Valid    bool         `json:"valid"`
	Revoked  bool         `json:"revoked"`
	Chain    []string     `json:"chain"`
	Errors   []string     `json:"errors"`
	Warnings []string     `json:"warnings"`
}

// mcpCACRLResp matches the JSON shape of GetCRLResponse -> crl (CRL).
type mcpCACRLResp struct {
	CRL *struct {
		LastUpdate   *protoTimestamp `json:"last_update"`
		NextUpdate   *protoTimestamp `json:"next_update"`
		RevokedCount int32           `json:"revoked_count"`
		RevokedCerts []struct {
			Serial         string          `json:"serial"`
			RevocationTime *protoTimestamp `json:"revocation_time"`
			Reason         int32           `json:"reason"`
		} `json:"revoked_certs"`
		Data []byte `json:"data"`
	} `json:"crl"`
}

// mcpCABundleResp matches the JSON shape of GetCABundleResponse -> bundle (CABundle).
type mcpCABundleResp struct {
	Bundle *struct {
		CertCount    int32               `json:"cert_count"`
		Pem          string              `json:"pem"`
		Certificates []*protoCertSummary `json:"certificates"`
	} `json:"bundle"`
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via MCP.
func (m *MCPAdapter) Info(ctx context.Context) (*InfoResult, error) {
	result, err := m.callTool(ctx, MCPToolCAInfo, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_info", Err: err}
	}

	var resp mcpCAInfoResp
	if err := m.parseToolResult(result, MCPToolCAInfo, &resp); err != nil {
		return nil, err
	}

	if resp.CAInfo == nil {
		return &InfoResult{}, nil
	}

	infoResult := &InfoResult{
		CommonName:          resp.CAInfo.CommonName,
		IsInitialized:       resp.CAInfo.IsInitialized,
		IsIntermediate:      resp.CAInfo.IsIntermediate,
		DefaultAlgorithm:    resp.CAInfo.DefaultAlgorithm,
		DefaultValidityDays: resp.CAInfo.DefaultValidityDays,
	}

	if resp.CAInfo.RootCert != nil {
		rc := resp.CAInfo.RootCert
		infoResult.RootCertificate = &CertificateSummary{
			Serial:       rc.Serial,
			CommonName:   rc.CommonName,
			Issuer:       rc.Issuer,
			KeyAlgorithm: parseKeyAlgorithmEnum(rc.KeyAlgorithm),
			Status:       parseCertStatusEnum(rc.Status),
			NotBefore:    rc.NotBefore.toTime(),
			NotAfter:     rc.NotAfter.toTime(),
		}
	}

	for _, inter := range resp.CAInfo.Intermediates {
		if inter == nil {
			continue
		}
		infoResult.Intermediates = append(infoResult.Intermediates, CertificateSummary{
			Serial:       inter.Serial,
			CommonName:   inter.CommonName,
			Issuer:       inter.Issuer,
			KeyAlgorithm: parseKeyAlgorithmEnum(inter.KeyAlgorithm),
			Status:       parseCertStatusEnum(inter.Status),
			NotBefore:    inter.NotBefore.toTime(),
			NotAfter:     inter.NotAfter.toTime(),
		})
	}

	return infoResult, nil
}

// =============================================================================
// CA Init Operations
// =============================================================================

// Init initializes the CA via MCP.
// Note: CA initialization is done during daemon startup, not via MCP.
func (m *MCPAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "CA init"}
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via MCP.
func (m *MCPAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
	args := map[string]interface{}{
		"common_name": opts.CommonName,
	}
	if opts.Algorithm != "" {
		args["algorithm"] = opts.Algorithm
	}
	if opts.ValidDays > 0 {
		args["valid_days"] = opts.ValidDays
	}
	if opts.StoreType != "" {
		args["store_type"] = opts.StoreType
	}
	if opts.IsCA {
		args["is_ca"] = true
	}
	if len(opts.SANsDNS) > 0 {
		args["dns_names"] = opts.SANsDNS
	}
	if len(opts.SANsIPs) > 0 {
		args["ip_addresses"] = opts.SANsIPs
	}
	if len(opts.SANsEmail) > 0 {
		args["email_addresses"] = opts.SANsEmail
	}

	result, err := m.callTool(ctx, MCPToolCAIssue, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_issue", Err: err}
	}

	var resp mcpCACertResp
	if err := m.parseToolResult(result, MCPToolCAIssue, &resp); err != nil {
		return nil, err
	}

	return mcpIssueResult(&resp), nil
}

// SignCSR certifies a KMS key's CSR via the ca_sign_csr tool.
func (m *MCPAdapter) SignCSR(ctx context.Context, opts SignCSROptions) (*IssueCertificateResult, error) {
	args := map[string]interface{}{
		"csr_pem": opts.CSRPEM,
	}
	if opts.ValidDays > 0 {
		args["valid_days"] = opts.ValidDays
	}

	result, err := m.callTool(ctx, MCPToolCASignCSR, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: MCPToolCASignCSR, Err: err}
	}

	var resp mcpCACertResp
	if err := m.parseToolResult(result, MCPToolCASignCSR, &resp); err != nil {
		return nil, err
	}

	return mcpIssueResult(&resp), nil
}

// mcpIssueResult converts an issued-certificate response into the shared result.
func mcpIssueResult(resp *mcpCACertResp) *IssueCertificateResult {
	issueResult := &IssueCertificateResult{}

	if resp.Status != nil {
		issueResult.Success = resp.Status.Success
	}

	if resp.Certificate != nil {
		issueResult.Certificate = convertProtoCertificate(resp.Certificate)
		if resp.Status == nil {
			issueResult.Success = issueResult.Certificate.Serial != ""
		}
	}

	return issueResult
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via MCP.
func (m *MCPAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	// Determine the identifier to send: prefer Serial, fall back to CommonName
	identifier := opts.Serial
	if identifier == "" && opts.CommonName != "" {
		identifier = opts.CommonName
	}

	args := map[string]interface{}{
		"serial": identifier,
	}
	if opts.IncludePEM {
		args["include_pem"] = true
	}

	result, err := m.callTool(ctx, MCPToolCAGet, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_get", Err: err}
	}

	var resp mcpCACertResp
	if err := m.parseToolResult(result, MCPToolCAGet, &resp); err != nil {
		return nil, err
	}

	if resp.Certificate == nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_get", Err: ErrCertificateNotFound{Identifier: opts.Serial}}
	}

	return &GetCertificateResult{
		Certificate: convertProtoCertificate(resp.Certificate),
	}, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via MCP.
func (m *MCPAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}

	result, err := m.callTool(ctx, MCPToolCAList, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_list", Err: err}
	}

	var resp mcpCAListResp
	if err := m.parseToolResult(result, MCPToolCAList, &resp); err != nil {
		return nil, err
	}

	listResult := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(resp.Certificates)),
	}

	if resp.Pagination != nil {
		listResult.Total = int32(resp.Pagination.TotalItems)
	}

	for _, c := range resp.Certificates {
		if c == nil {
			continue
		}
		listResult.Certificates = append(listResult.Certificates, CertificateSummary{
			Serial:       c.Serial,
			CommonName:   c.CommonName,
			Issuer:       c.Issuer,
			NotBefore:    c.NotBefore.toTime(),
			NotAfter:     c.NotAfter.toTime(),
			Status:       parseCertStatusEnum(c.Status),
			KeyAlgorithm: parseKeyAlgorithmEnum(c.KeyAlgorithm),
		})
	}

	return listResult, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via MCP.
func (m *MCPAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	args := map[string]interface{}{}
	if len(opts.CertificatePEM) > 0 {
		args["certificate_pem"] = string(opts.CertificatePEM)
	}
	if opts.CheckCRL {
		args["check_revoked"] = true
	}

	result, err := m.callTool(ctx, MCPToolCAVerify, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_verify", Err: err}
	}

	var resp mcpCAVerifyResp
	if err := m.parseToolResult(result, MCPToolCAVerify, &resp); err != nil {
		return nil, err
	}

	return &VerifyCertificateResult{
		Valid:         resp.Valid,
		Revoked:       resp.Revoked,
		ChainValid:    resp.Valid && len(resp.Errors) == 0,
		ChainLength:   len(resp.Chain),
		ChainSubjects: resp.Chain,
		Errors:        resp.Errors,
		Warnings:      resp.Warnings,
	}, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via MCP.
func (m *MCPAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	args := map[string]interface{}{
		"serial": opts.Serial,
	}
	if opts.Reason != RevocationReasonUnspecified {
		args["reason"] = int(opts.Reason)
	}
	if opts.DeleteKeys {
		args["delete_keys"] = true
	}

	result, err := m.callTool(ctx, MCPToolCARevoke, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_revoke", Err: err}
	}

	var resp mcpCARevokeResp
	if err := m.parseToolResult(result, MCPToolCARevoke, &resp); err != nil {
		return nil, err
	}

	revokeResult := &RevokeCertificateResult{
		Serial: resp.Serial,
		Status: parseCertStatusEnum(resp.CertificateStatus),
		Reason: parseRevocationReasonEnum(resp.Reason),
	}

	if resp.Status != nil {
		revokeResult.Success = resp.Status.Success
		revokeResult.Message = resp.Status.Message
	}

	if resp.RevokedAt != nil {
		revokeResult.RevokedAt = resp.RevokedAt.toTime()
	}

	return revokeResult, nil
}

// =============================================================================
// Certificate Renew Operations
// =============================================================================

// RenewCertificate renews a certificate via MCP.
func (m *MCPAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
	args := map[string]interface{}{
		"serial":      opts.Serial,
		"extend_days": opts.ValidDays,
	}
	if opts.PreserveSANs {
		args["preserve_attrs"] = true
	}

	result, err := m.callTool(ctx, MCPToolCARenew, args)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_renew", Err: err}
	}

	var resp mcpCARenewResp
	if err := m.parseToolResult(result, MCPToolCARenew, &resp); err != nil {
		return nil, err
	}

	renewResult := &RenewCertificateResult{}

	if resp.Status != nil {
		renewResult.Success = resp.Status.Success
		renewResult.Message = resp.Status.Message
	}

	if resp.OldCertificate != nil {
		renewResult.OldCertificate = convertProtoCertificate(resp.OldCertificate)
	}

	if resp.NewCertificate != nil {
		renewResult.NewCertificate = convertProtoCertificate(resp.NewCertificate)
		if resp.Status == nil {
			renewResult.Success = renewResult.NewCertificate.Serial != ""
		}
	}

	return renewResult, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via MCP.
func (m *MCPAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	result, err := m.callTool(ctx, MCPToolCACRL, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_crl", Err: err}
	}

	var resp mcpCACRLResp
	if err := m.parseToolResult(result, MCPToolCACRL, &resp); err != nil {
		return nil, err
	}

	crlResult := &GetCRLResult{}

	if resp.CRL != nil {
		crlResult.Data = resp.CRL.Data
		crlResult.RevokedCount = resp.CRL.RevokedCount
		if resp.CRL.LastUpdate != nil {
			crlResult.ThisUpdate = resp.CRL.LastUpdate.toTime()
		}
		if resp.CRL.NextUpdate != nil {
			crlResult.NextUpdate = resp.CRL.NextUpdate.toTime()
		}

		for _, entry := range resp.CRL.RevokedCerts {
			rce := RevokedCertEntry{
				Serial: entry.Serial,
				Reason: parseRevocationReasonEnum(entry.Reason),
			}
			if entry.RevocationTime != nil {
				rce.RevocationTime = entry.RevocationTime.toTime()
			}
			crlResult.RevokedCerts = append(crlResult.RevokedCerts, rce)
		}
	}

	if err := crlResult.setIssuerFromData("MCP"); err != nil {
		return nil, err
	}

	return crlResult, nil
}

// GenerateCRL generates a new CRL via MCP.
func (m *MCPAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	toolResult, err := m.callTool(ctx, MCPToolCACRL, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_crl", Err: err}
	}

	var resp mcpCACRLResp
	if err := m.parseToolResult(toolResult, MCPToolCACRL, &resp); err != nil {
		return nil, err
	}

	result := &GenerateCRLResult{Success: true}
	if resp.CRL != nil {
		if resp.CRL.LastUpdate != nil {
			result.ThisUpdate = resp.CRL.LastUpdate.toTime()
		}
		if resp.CRL.NextUpdate != nil {
			result.NextUpdate = resp.CRL.NextUpdate.toTime()
		}
	}

	return result, nil
}

// ExportCRL exports the CRL via MCP.
// Note: CRL export to file is a CLI operation, not exposed via MCP.
func (m *MCPAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "CRL export"}
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via MCP.
func (m *MCPAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	result, err := m.callTool(ctx, MCPToolCABundle, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: "ca_bundle", Err: err}
	}
	var resp mcpCABundleResp
	if err := m.parseToolResult(result, MCPToolCABundle, &resp); err != nil {
		return nil, err
	}
	bundleResult := &ExportBundleResult{}
	if resp.Bundle != nil {
		bundleResult.CertCount = resp.Bundle.CertCount
		bundleResult.Success = resp.Bundle.CertCount > 0
		// Decode PEM data from base64 (protobuf bytes field)
		var pemData []byte
		if resp.Bundle.Pem != "" {
			pemData, err = base64.StdEncoding.DecodeString(resp.Bundle.Pem)
			if err != nil {
				// Try raw string as PEM
				pemData = []byte(resp.Bundle.Pem)
			}
			bundleResult.Size = int64(len(pemData))
		}
		// Write bundle to file if output path specified
		if output != "" && len(pemData) > 0 {
			if writeErr := os.WriteFile(output, pemData, 0644); writeErr != nil {
				return nil, ErrExportFailed{Type: "CA bundle", Path: output, Reason: writeErr.Error()}
			}
			bundleResult.FilePath = output
		}
	}
	return bundleResult, nil
}

// =============================================================================
// Install/Uninstall Operations
// =============================================================================

// InstallCACertificates installs CA certificates via MCP.
// Note: CA certificate installation is a local OS operation, not exposed via MCP.
func (m *MCPAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "install CA certificates"}
}

// UninstallCACertificates uninstalls CA certificates via MCP.
// Note: CA certificate uninstallation is a local OS operation, not exposed via MCP.
func (m *MCPAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "uninstall CA certificates"}
}

// Ensure MCPAdapter implements CACommands interface.
var _ CACommands = (*MCPAdapter)(nil)
