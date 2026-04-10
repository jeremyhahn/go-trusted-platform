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

// Package rest provides the REST transport adapter for the platform SDK.
// It wraps HTTP/HTTPS communication with the REST API and provides a
// gRPC-compatible interface for service clients.
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolREST, Connect)
}

// Adapter implements the transport.Adapter interface for REST over HTTP/HTTPS.
type Adapter struct {
	httpClient *http.Client
	baseURL    string
	connected  atomic.Bool
	closed     atomic.Bool
	tlsConfig  *tls.Config
	token      atomic.Value // stores auth token as string
}

// Connect establishes a REST connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.RESTAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	timeout := opts.GetTimeout()

	// Build base URL - always use HTTPS
	baseURL := opts.RESTAddr
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Configure TLS - TLS is mandatory for REST transport
	var tlsConfig *tls.Config
	if opts.TLSConfig != nil {
		tlsConfig = opts.TLSConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Create HTTP transport with TLS
	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
	}

	a := &Adapter{
		httpClient: httpClient,
		baseURL:    baseURL,
		tlsConfig:  tlsConfig,
	}
	a.connected.Store(true)

	// Optionally verify connectivity with a health check
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, baseURL+"/health", nil)
	if err != nil {
		closeErr := a.Close()
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolREST,
			Target:   opts.RESTAddr,
			Err:      errors.Join(err, closeErr),
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection test failed, but we still return the adapter
		// as REST may not have a /health endpoint
		// The adapter is still usable for other endpoints
	} else {
		resp.Body.Close()
	}

	return a, nil
}

// Connection returns a gRPC-compatible client connection interface.
// This wraps the REST adapter to provide a unified interface for service clients.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return &restClientConn{adapter: a}
}

// Close closes the REST client connection.
func (a *Adapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	a.connected.Store(false)

	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}

	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	return a.connected.Load() && !a.closed.Load()
}

// Target returns the REST API base URL.
func (a *Adapter) Target() string {
	return a.baseURL
}

// SetToken sets the authentication token for requests.
func (a *Adapter) SetToken(token string) {
	a.token.Store(token)
}

// GetToken returns the current authentication token.
func (a *Adapter) GetToken() string {
	if v := a.token.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// DoRequest performs an HTTP request to the REST API.
func (a *Adapter) DoRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	if a.closed.Load() {
		return ErrClientClosed{}
	}

	url := a.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return ErrMarshalFailed{Err: err}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if token := a.GetToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrHTTPStatus{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(respBody),
		}
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
	}

	return nil
}

// restClientConn implements grpc.ClientConnInterface for REST transport.
// This allows using REST as a drop-in replacement for gRPC connections.
type restClientConn struct {
	adapter *Adapter
}

// Invoke performs a unary RPC call by translating to REST HTTP requests.
func (c *restClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	if c.adapter.closed.Load() {
		return status.Error(codes.Unavailable, "connection closed")
	}

	// Map gRPC method to REST endpoint
	path, httpMethod := mapGRPCMethodToREST(method)

	err := c.adapter.DoRequest(ctx, httpMethod, path, args, reply)
	if err != nil {
		return translateErrorToGRPC(err)
	}

	return nil
}

// NewStream creates a new stream (not fully supported for REST).
func (c *restClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not supported over REST transport")
}

// grpcMethodToRESTMap provides O(1) lookup for gRPC to REST endpoint mapping.
var grpcMethodToRESTMap = map[string]struct {
	path   string
	method string
}{
	// Platform Daemon
	"/platformv1.PlatformDaemon/GetVersion": {"/api/v1/version", http.MethodGet},
	"/platformv1.PlatformDaemon/GetStatus":  {"/api/v1/status", http.MethodGet},

	// Health endpoints
	"/platformv1.PlatformDaemon/Health":    {"/health", http.MethodGet},
	"/platformv1.PlatformDaemon/Liveness":  {"/health/live", http.MethodGet},
	"/platformv1.PlatformDaemon/Readiness": {"/health/ready", http.MethodGet},

	// CA Service
	"/platformv1.CAService/GetInfo":      {"/api/v1/ca/info", http.MethodGet},
	"/platformv1.CAService/Issue":        {"/api/v1/ca/certificates", http.MethodPost},
	"/platformv1.CAService/Get":          {"/api/v1/ca/certificates", http.MethodGet},
	"/platformv1.CAService/List":         {"/api/v1/ca/certificates", http.MethodGet},
	"/platformv1.CAService/Revoke":       {"/api/v1/ca/certificates/revoke", http.MethodPost},
	"/platformv1.CAService/Renew":        {"/api/v1/ca/certificates/renew", http.MethodPost},
	"/platformv1.CAService/Verify":       {"/api/v1/ca/certificates/verify", http.MethodPost},
	"/platformv1.CAService/GetCRL":       {"/api/v1/ca/crl", http.MethodGet},
	"/platformv1.CAService/GetBundle":    {"/api/v1/ca/bundle", http.MethodGet},
	"/platformv1.CAService/GetTrustRoot": {"/api/v1/ca/trust-root", http.MethodGet},

	// IAM Service
	"/platformv1.PlatformIAMService/CreateUser": {"/api/v1/iam/users", http.MethodPost},
	"/platformv1.PlatformIAMService/DeleteUser": {"/api/v1/iam/users", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetUser":    {"/api/v1/iam/users", http.MethodGet},
	"/platformv1.PlatformIAMService/ListUsers":  {"/api/v1/iam/users", http.MethodGet},

	"/platformv1.PlatformIAMService/CreateRole": {"/api/v1/iam/roles", http.MethodPost},
	"/platformv1.PlatformIAMService/DeleteRole": {"/api/v1/iam/roles", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetRole":    {"/api/v1/iam/roles", http.MethodGet},
	"/platformv1.PlatformIAMService/ListRoles":  {"/api/v1/iam/roles", http.MethodGet},
	"/platformv1.PlatformIAMService/AssignRole": {"/api/v1/iam/roles/assign", http.MethodPost},
	"/platformv1.PlatformIAMService/RevokeRole": {"/api/v1/iam/roles/revoke", http.MethodPost},

	"/platformv1.PlatformIAMService/CreateGroup":       {"/api/v1/iam/groups", http.MethodPost},
	"/platformv1.PlatformIAMService/DeleteGroup":       {"/api/v1/iam/groups", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetGroup":          {"/api/v1/iam/groups", http.MethodGet},
	"/platformv1.PlatformIAMService/ListGroups":        {"/api/v1/iam/groups", http.MethodGet},
	"/platformv1.PlatformIAMService/AddGroupMember":    {"/api/v1/iam/groups/members", http.MethodPost},
	"/platformv1.PlatformIAMService/RemoveGroupMember": {"/api/v1/iam/groups/members", http.MethodDelete},

	"/platformv1.PlatformIAMService/CreateTenant": {"/api/v1/iam/tenants", http.MethodPost},
	"/platformv1.PlatformIAMService/DeleteTenant": {"/api/v1/iam/tenants", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetTenant":    {"/api/v1/iam/tenants", http.MethodGet},
	"/platformv1.PlatformIAMService/ListTenants":  {"/api/v1/iam/tenants", http.MethodGet},

	"/platformv1.PlatformIAMService/Authenticate":     {"/api/v1/iam/authenticate", http.MethodPost},
	"/platformv1.PlatformIAMService/CheckPermission":  {"/api/v1/iam/permissions/check", http.MethodPost},
	"/platformv1.PlatformIAMService/CreateToken":      {"/api/v1/iam/tokens", http.MethodPost},
	"/platformv1.PlatformIAMService/RevokeToken":      {"/api/v1/iam/tokens/revoke", http.MethodPost},
	"/platformv1.PlatformIAMService/VerifyToken":      {"/api/v1/iam/tokens/verify", http.MethodPost},
	"/platformv1.PlatformIAMService/RefreshToken":     {"/api/v1/iam/tokens/refresh", http.MethodPost},
	"/platformv1.PlatformIAMService/GetCurrentUser":   {"/api/v1/iam/users/current", http.MethodGet},
	"/platformv1.PlatformIAMService/ChangePassword":   {"/api/v1/iam/users/password", http.MethodPost},
	"/platformv1.PlatformIAMService/ResetPassword":    {"/api/v1/iam/users/password/reset", http.MethodPost},
	"/platformv1.PlatformIAMService/SetupTOTP":        {"/api/v1/iam/mfa/totp/setup", http.MethodPost},
	"/platformv1.PlatformIAMService/VerifyTOTP":       {"/api/v1/iam/mfa/totp/verify", http.MethodPost},
	"/platformv1.PlatformIAMService/DisableTOTP":      {"/api/v1/iam/mfa/totp", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetTOTPStatus":    {"/api/v1/iam/mfa/totp/status", http.MethodGet},
	"/platformv1.PlatformIAMService/ListActiveSesss":  {"/api/v1/iam/sessions", http.MethodGet},
	"/platformv1.PlatformIAMService/RevokeSession":    {"/api/v1/iam/sessions/revoke", http.MethodPost},
	"/platformv1.PlatformIAMService/RevokeAllSesss":   {"/api/v1/iam/sessions/revoke-all", http.MethodPost},
	"/platformv1.PlatformIAMService/GetAPIKeys":       {"/api/v1/iam/api-keys", http.MethodGet},
	"/platformv1.PlatformIAMService/CreateAPIKey":     {"/api/v1/iam/api-keys", http.MethodPost},
	"/platformv1.PlatformIAMService/RevokeAPIKey":     {"/api/v1/iam/api-keys/revoke", http.MethodPost},
	"/platformv1.PlatformIAMService/GetAuditLogs":     {"/api/v1/iam/audit-logs", http.MethodGet},
	"/platformv1.PlatformIAMService/CreatePermission": {"/api/v1/iam/permissions", http.MethodPost},
	"/platformv1.PlatformIAMService/DeletePermission": {"/api/v1/iam/permissions", http.MethodDelete},
	"/platformv1.PlatformIAMService/GetPermission":    {"/api/v1/iam/permissions", http.MethodGet},
	"/platformv1.PlatformIAMService/ListPermissions":  {"/api/v1/iam/permissions", http.MethodGet},

	// KMS Service
	"/platformv1.KeyManagementService/CreateKey":              {"/api/v1/kms/keys", http.MethodPost},
	"/platformv1.KeyManagementService/DeleteKey":              {"/api/v1/kms/keys", http.MethodDelete},
	"/platformv1.KeyManagementService/GetKey":                 {"/api/v1/kms/keys", http.MethodGet},
	"/platformv1.KeyManagementService/ListKeys":               {"/api/v1/kms/keys", http.MethodGet},
	"/platformv1.KeyManagementService/RotateKey":              {"/api/v1/kms/keys/rotate", http.MethodPost},
	"/platformv1.KeyManagementService/Encrypt":                {"/api/v1/kms/encrypt", http.MethodPost},
	"/platformv1.KeyManagementService/Decrypt":                {"/api/v1/kms/decrypt", http.MethodPost},
	"/platformv1.KeyManagementService/Sign":                   {"/api/v1/kms/sign", http.MethodPost},
	"/platformv1.KeyManagementService/Verify":                 {"/api/v1/kms/verify", http.MethodPost},
	"/platformv1.KeyManagementService/GenerateRandom":         {"/api/v1/kms/random", http.MethodPost},
	"/platformv1.KeyManagementService/GenerateDataKey":        {"/api/v1/kms/data-keys", http.MethodPost},
	"/platformv1.KeyManagementService/GenerateWrappedDataKey": {"/api/v1/kms/data-keys/wrapped", http.MethodPost},

	// VTPM Service
	"/platformv1.VTPMService/Create":    {"/api/v1/vtpm/instances", http.MethodPost},
	"/platformv1.VTPMService/Delete":    {"/api/v1/vtpm/instances", http.MethodDelete},
	"/platformv1.VTPMService/Start":     {"/api/v1/vtpm/instances/start", http.MethodPost},
	"/platformv1.VTPMService/Stop":      {"/api/v1/vtpm/instances/stop", http.MethodPost},
	"/platformv1.VTPMService/List":      {"/api/v1/vtpm/instances", http.MethodGet},
	"/platformv1.VTPMService/GetState":  {"/api/v1/vtpm/instances/state", http.MethodGet},
	"/platformv1.VTPMService/Quote":     {"/api/v1/vtpm/quote", http.MethodPost},
	"/platformv1.VTPMService/Seal":      {"/api/v1/vtpm/seal", http.MethodPost},
	"/platformv1.VTPMService/Unseal":    {"/api/v1/vtpm/unseal", http.MethodPost},
	"/platformv1.VTPMService/ExtendPCR": {"/api/v1/vtpm/pcrs/extend", http.MethodPost},
	"/platformv1.VTPMService/ReadPCR":   {"/api/v1/vtpm/pcrs", http.MethodGet},

	// Device Service
	"/platformv1.DeviceService/Register": {"/api/v1/devices", http.MethodPost},
	"/platformv1.DeviceService/Delete":   {"/api/v1/devices", http.MethodDelete},
	"/platformv1.DeviceService/Get":      {"/api/v1/devices", http.MethodGet},
	"/platformv1.DeviceService/List":     {"/api/v1/devices", http.MethodGet},
	"/platformv1.DeviceService/Update":   {"/api/v1/devices", http.MethodPut},
	"/platformv1.DeviceService/Attest":   {"/api/v1/devices/attest", http.MethodPost},

	// SDN Service
	"/platformv1.SDNService/CreateBridge":     {"/api/v1/sdn/bridges", http.MethodPost},
	"/platformv1.SDNService/DeleteBridge":     {"/api/v1/sdn/bridges", http.MethodDelete},
	"/platformv1.SDNService/ListBridges":      {"/api/v1/sdn/bridges", http.MethodGet},
	"/platformv1.SDNService/GetPortState":     {"/api/v1/sdn/ports/state", http.MethodGet},
	"/platformv1.SDNService/SetPortState":     {"/api/v1/sdn/ports/state", http.MethodPost},
	"/platformv1.SDNService/AddPort":          {"/api/v1/sdn/ports", http.MethodPost},
	"/platformv1.SDNService/DeletePort":       {"/api/v1/sdn/ports", http.MethodDelete},
	"/platformv1.SDNService/AddFlow":          {"/api/v1/sdn/flows", http.MethodPost},
	"/platformv1.SDNService/DeleteFlow":       {"/api/v1/sdn/flows", http.MethodDelete},
	"/platformv1.SDNService/ListFlows":        {"/api/v1/sdn/flows", http.MethodGet},
	"/platformv1.SDNService/ApplyPolicy":      {"/api/v1/sdn/policies/apply", http.MethodPost},
	"/platformv1.SDNService/GetPolicy":        {"/api/v1/sdn/policies", http.MethodGet},
	"/platformv1.SDNService/ListPolicies":     {"/api/v1/sdn/policies", http.MethodGet},
	"/platformv1.SDNService/AuthenticatePort": {"/api/v1/sdn/ports/auth", http.MethodPost},
	"/platformv1.SDNService/RevokePortAuth":   {"/api/v1/sdn/ports/auth", http.MethodDelete},

	// DNS Service
	"/platformv1.DNSService/AddRecord":    {"/api/v1/dns/records", http.MethodPost},
	"/platformv1.DNSService/DeleteRecord": {"/api/v1/dns/records", http.MethodDelete},
	"/platformv1.DNSService/GetRecord":    {"/api/v1/dns/records", http.MethodGet},
	"/platformv1.DNSService/ListRecords":  {"/api/v1/dns/records", http.MethodGet},
	"/platformv1.DNSService/Resolve":      {"/api/v1/dns/resolve", http.MethodGet},
	"/platformv1.DNSService/CreateZone":   {"/api/v1/dns/zones", http.MethodPost},
	"/platformv1.DNSService/DeleteZone":   {"/api/v1/dns/zones", http.MethodDelete},
	"/platformv1.DNSService/ListZones":    {"/api/v1/dns/zones", http.MethodGet},

	// Attestation Service
	"/platformv1.AttestationService/GetQuote":       {"/api/v1/attestation/quote", http.MethodPost},
	"/platformv1.AttestationService/VerifyQuote":    {"/api/v1/attestation/verify", http.MethodPost},
	"/platformv1.AttestationService/GetEK":          {"/api/v1/attestation/ek", http.MethodGet},
	"/platformv1.AttestationService/GetAK":          {"/api/v1/attestation/ak", http.MethodGet},
	"/platformv1.AttestationService/CreateAK":       {"/api/v1/attestation/ak", http.MethodPost},
	"/platformv1.AttestationService/ChallengeAK":    {"/api/v1/attestation/challenge", http.MethodPost},
	"/platformv1.AttestationService/VerifyChalleng": {"/api/v1/attestation/challenge/verify", http.MethodPost},

	// IDevID Service
	"/platformv1.IDevIDService/Generate":    {"/api/v1/idevid", http.MethodPost},
	"/platformv1.IDevIDService/GetInfo":     {"/api/v1/idevid/info", http.MethodGet},
	"/platformv1.IDevIDService/Delete":      {"/api/v1/idevid", http.MethodDelete},
	"/platformv1.IDevIDService/GetCSR":      {"/api/v1/idevid/csr", http.MethodGet},
	"/platformv1.IDevIDService/InstallCert": {"/api/v1/idevid/cert", http.MethodPost},
	"/platformv1.IDevIDService/GetCert":     {"/api/v1/idevid/cert", http.MethodGet},
	"/platformv1.IDevIDService/Exists":      {"/api/v1/idevid/exists", http.MethodGet},

	// Tenant Service
	"/platformv1.TenantService/Create":  {"/api/v1/tenants", http.MethodPost},
	"/platformv1.TenantService/Delete":  {"/api/v1/tenants", http.MethodDelete},
	"/platformv1.TenantService/Get":     {"/api/v1/tenants", http.MethodGet},
	"/platformv1.TenantService/List":    {"/api/v1/tenants", http.MethodGet},
	"/platformv1.TenantService/Update":  {"/api/v1/tenants", http.MethodPut},
	"/platformv1.TenantService/Suspend": {"/api/v1/tenants/suspend", http.MethodPost},
	"/platformv1.TenantService/Resume":  {"/api/v1/tenants/resume", http.MethodPost},

	// PXE Service
	"/platformv1.PXEService/ListDevices":    {"/api/v1/pxe/devices", http.MethodGet},
	"/platformv1.PXEService/GetDevice":      {"/api/v1/pxe/devices", http.MethodGet},
	"/platformv1.PXEService/RegisterDevice": {"/api/v1/pxe/devices", http.MethodPost},
	"/platformv1.PXEService/UpdateState":    {"/api/v1/pxe/devices/state", http.MethodPut},
	"/platformv1.PXEService/Authorize":      {"/api/v1/pxe/devices/authorize", http.MethodPost},
	"/platformv1.PXEService/Quarantine":     {"/api/v1/pxe/devices/quarantine", http.MethodPost},
	"/platformv1.PXEService/GetStatus":      {"/api/v1/pxe/status", http.MethodGet},

	// Compute Service
	"/platformv1.ComputeService/CreateContainer":  {"/api/v1/compute/containers", http.MethodPost},
	"/platformv1.ComputeService/DeleteContainer":  {"/api/v1/compute/containers", http.MethodDelete},
	"/platformv1.ComputeService/StartContainer":   {"/api/v1/compute/containers/start", http.MethodPost},
	"/platformv1.ComputeService/StopContainer":    {"/api/v1/compute/containers/stop", http.MethodPost},
	"/platformv1.ComputeService/ListContainers":   {"/api/v1/compute/containers", http.MethodGet},
	"/platformv1.ComputeService/GetContainer":     {"/api/v1/compute/containers", http.MethodGet},
	"/platformv1.ComputeService/AttestContainer":  {"/api/v1/compute/containers/attest", http.MethodPost},
	"/platformv1.ComputeService/GetContainerLogs": {"/api/v1/compute/containers/logs", http.MethodGet},
}

// mapGRPCMethodToREST maps a gRPC method to REST endpoint and HTTP method.
// Uses O(1) map lookup for efficient dispatching.
func mapGRPCMethodToREST(grpcMethod string) (path string, httpMethod string) {
	if mapping, ok := grpcMethodToRESTMap[grpcMethod]; ok {
		return mapping.path, mapping.method
	}

	// Fallback: derive REST path from gRPC method
	// /package.Service/Method -> /api/v1/service/method
	parts := strings.Split(grpcMethod, "/")
	if len(parts) >= 3 {
		serviceParts := strings.Split(parts[1], ".")
		service := strings.ToLower(serviceParts[len(serviceParts)-1])
		service = strings.TrimSuffix(service, "service")
		method := strings.ToLower(parts[2])
		return "/api/v1/" + service + "/" + method, http.MethodPost
	}

	return "/api/v1/unknown", http.MethodPost
}

// httpStatusToGRPCMap provides O(1) lookup for HTTP to gRPC status code mapping.
var httpStatusToGRPCMap = map[int]codes.Code{
	http.StatusOK:                  codes.OK,
	http.StatusCreated:             codes.OK,
	http.StatusNoContent:           codes.OK,
	http.StatusBadRequest:          codes.InvalidArgument,
	http.StatusUnauthorized:        codes.Unauthenticated,
	http.StatusForbidden:           codes.PermissionDenied,
	http.StatusNotFound:            codes.NotFound,
	http.StatusConflict:            codes.AlreadyExists,
	http.StatusTooManyRequests:     codes.ResourceExhausted,
	http.StatusInternalServerError: codes.Internal,
	http.StatusNotImplemented:      codes.Unimplemented,
	http.StatusBadGateway:          codes.Unavailable,
	http.StatusServiceUnavailable:  codes.Unavailable,
	http.StatusGatewayTimeout:      codes.DeadlineExceeded,
}

// translateErrorToGRPC translates REST errors to gRPC status errors.
func translateErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case ErrHTTPStatus:
		code, ok := httpStatusToGRPCMap[e.StatusCode]
		if !ok {
			code = codes.Unknown
		}
		return status.Error(code, e.Body)

	case ErrClientClosed:
		return status.Error(codes.Unavailable, e.Error())

	case ErrRequestFailed:
		return status.Error(codes.Unavailable, e.Error())

	case ErrMarshalFailed:
		return status.Error(codes.InvalidArgument, e.Error())

	case ErrUnmarshalFailed:
		return status.Error(codes.Internal, e.Error())

	default:
		return status.Error(codes.Unknown, err.Error())
	}
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
