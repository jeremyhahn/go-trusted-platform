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

package daemon

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrDaemonNotRunning is returned when attempting operations on a stopped daemon
type ErrDaemonNotRunning struct{}

func (e ErrDaemonNotRunning) Error() string {
	return "daemon is not running"
}

// ErrMCPAuthorizationBackendRequired is returned when the MCP server would
// start with neither the platform-token validator nor the QuicBaaS auth
// adapter available. Until #440 this state was a Warn ("MCP server running
// without QuicBaaS authorization") and the server started anyway, with
// AuthorizeTool allowing every tool; the transport is now refused instead.
// SkipIAMValidation (testing only) is the explicit opt-out.
type ErrMCPAuthorizationBackendRequired struct{}

func (e ErrMCPAuthorizationBackendRequired) Error() string {
	return "mcp: no authorization backend is configured (neither the platform-token validator nor the QuicBaaS auth adapter is available); refusing to start the MCP server without one"
}

// ErrTransportAuthRequired is returned when a network transport (gRPC TCP,
// QUIC or REST) would start with no way to authenticate its callers. Until
// #550 the gRPC and QUIC interceptors were installed with
// WithRequireAuth(tokenValidator != nil), so a node whose IAM wiring failed
// served its whole daemon API anonymously; the transport is now refused
// instead. SkipIAMValidation (testing only) is the explicit opt-out.
type ErrTransportAuthRequired struct {
	Transport string
	Reason    string
}

func (e ErrTransportAuthRequired) Error() string {
	msg := e.Transport + ": no authentication backend is configured"
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg + "; refusing to start the transport without one"
}

// ErrEmbeddedPEPUnavailable is returned by New when gRPC TCP
// would authorize every scoped call through the IAM policy enforcement point
// and that point is the embedded quicbaas SDK, which does not implement it:
// go-quicbaas sdk/go transport/embedded handleIAMPEPCheck answers every Check
// with ServiceNotConfigured. The listener would start and then answer every
// scoped call Unavailable. Platform tokens carry their own scope claims and
// mTLS authorizes by certificate, so either one keeps the PEP off the path.
type ErrEmbeddedPEPUnavailable struct {
	Transport string
}

func (e ErrEmbeddedPEPUnavailable) Error() string {
	return e.Transport + ": tokens without scope claims are authorized by the IAM policy enforcement point, " +
		"which the embedded quicbaas SDK does not implement (IAM.PEP Check is not configured); " +
		"enable platform tokens (webservice jwt.platform-token.enabled) or enable mTLS (--enable-mtls)"
}

// ErrTransportConstructionFailed is returned by New when an enabled transport
// (QUIC, REST or MCP) cannot be constructed. Until #444 New logged a Warn and
// continued, so a daemon reported healthy without a transport its
// configuration enabled. A transport that is not enabled is never constructed
// and never produces this error.
type ErrTransportConstructionFailed struct {
	Transport string
	Cause     error
}

func (e ErrTransportConstructionFailed) Error() string {
	return fmt.Sprintf("%s: server could not be constructed: %v; refusing to run without the enabled transport", e.Transport, e.Cause)
}

func (e ErrTransportConstructionFailed) Unwrap() error {
	return e.Cause
}

// ErrDaemonAlreadyRunning is returned when attempting to start an already running daemon
type ErrDaemonAlreadyRunning struct{}

func (e ErrDaemonAlreadyRunning) Error() string {
	return "daemon is already running"
}

// ErrServiceNotFound is returned when a requested service does not exist
type ErrServiceNotFound struct {
	ServiceName string
}

func (e ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceName)
}

// ErrServiceAlreadyRunning is returned when attempting to start an already running service
type ErrServiceAlreadyRunning struct {
	ServiceName string
}

func (e ErrServiceAlreadyRunning) Error() string {
	return fmt.Sprintf("service already running: %s", e.ServiceName)
}

// ErrServiceNotRunning is returned when attempting operations on a stopped service
type ErrServiceNotRunning struct {
	ServiceName string
}

func (e ErrServiceNotRunning) Error() string {
	return fmt.Sprintf("service is not running: %s", e.ServiceName)
}

// ErrServiceStartFailed is returned when a service fails to start
type ErrServiceStartFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStartFailed) Error() string {
	return fmt.Sprintf("service %s failed to start: %s", e.ServiceName, e.Reason)
}

// ErrServiceStopFailed is returned when a service fails to stop
type ErrServiceStopFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStopFailed) Error() string {
	return fmt.Sprintf("service %s failed to stop: %s", e.ServiceName, e.Reason)
}

// ErrServiceNotControllable is returned when start, stop or restart names a
// service whose lifecycle belongs to the platformd process, not to the
// daemon's service registry: it comes up with the process and goes down with
// it, and driving it at runtime is refused rather than faked.
type ErrServiceNotControllable struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceNotControllable) Error() string {
	return fmt.Sprintf("service %s cannot be started or stopped at runtime: %s", e.ServiceName, e.Reason)
}

// GRPCStatus classifies the refusal as FailedPrecondition: the RPC is
// implemented, and the named service's state (owned by the process) does not
// allow it. Unimplemented would mark a missing capability instead.
func (e ErrServiceNotControllable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrConfigNotFound is returned when requested configuration does not exist
type ErrConfigNotFound struct {
	ConfigKey string
}

func (e ErrConfigNotFound) Error() string {
	return fmt.Sprintf("configuration not found: %s", e.ConfigKey)
}

// ErrInvalidConfig is returned when configuration validation fails
type ErrInvalidConfig struct {
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s", e.Reason)
}

// ErrProvisionFailed is returned when platform provisioning fails
type ErrProvisionFailed struct {
	Reason string
}

func (e ErrProvisionFailed) Error() string {
	return fmt.Sprintf("provisioning failed: %s", e.Reason)
}

// ErrShutdownFailed is returned when graceful shutdown fails
type ErrShutdownFailed struct {
	Reason string
}

func (e ErrShutdownFailed) Error() string {
	return fmt.Sprintf("shutdown failed: %s", e.Reason)
}

// ErrInvalidServiceType is returned when an unknown service type is specified
type ErrInvalidServiceType struct {
	Type string
}

func (e ErrInvalidServiceType) Error() string {
	return fmt.Sprintf("invalid service type: %s", e.Type)
}

// ErrHealthRegistryNotConfigured is returned when health check operations
// are attempted but the health registry is not configured
type ErrHealthRegistryNotConfigured struct{}

func (e ErrHealthRegistryNotConfigured) Error() string {
	return "health registry not configured"
}

// ErrHealthCheckFailed is returned when a health check operation fails
type ErrHealthCheckFailed struct {
	Component string
	Reason    string
}

func (e ErrHealthCheckFailed) Error() string {
	return fmt.Sprintf("health check failed for %s: %s", e.Component, e.Reason)
}

// ErrDatabaseNotAvailable is returned when the database is not available for operations
type ErrDatabaseNotAvailable struct {
	Reason string
}

func (e ErrDatabaseNotAvailable) Error() string {
	return fmt.Sprintf("database not available: %s", e.Reason)
}

// ErrUnsupportedRecordType is returned when an unsupported DNS record type is specified
type ErrUnsupportedRecordType struct{}

func (e ErrUnsupportedRecordType) Error() string {
	return "unsupported DNS record type"
}

// ErrDNSServiceNotAvailable is returned when DNS service is not configured
type ErrDNSServiceNotAvailable struct{}

func (e ErrDNSServiceNotAvailable) Error() string {
	return "DNS service not available"
}

// GRPCStatus classifies the error as the canonical not-configured answer for
// service "dns" (codes.Unavailable, SERVICE_NOT_CONFIGURED), so gRPC, Unix,
// QUIC and MCP agree with REST's 503.
func (e ErrDNSServiceNotAvailable) GRPCStatus() *status.Status {
	return ErrServiceNotConfigured{Service: "dns", Detail: e.Error()}.GRPCStatus()
}

// ErrDNSInvalidParameter is returned when a DNS operation receives an invalid parameter
type ErrDNSInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrDNSInvalidParameter) Error() string {
	return fmt.Sprintf("invalid DNS parameter %s: %s", e.Parameter, e.Reason)
}

// ErrDaemonUnhealthy is returned by the aggregate gRPC health checker when
// the platform health registry reports the node unhealthy. It carries the
// component count only -- component names are deliberately withheld, since
// this error drives an unauthenticated health response.
type ErrDaemonUnhealthy struct {
	UnhealthyCount int
}

func (e ErrDaemonUnhealthy) Error() string {
	return fmt.Sprintf("daemon unhealthy: %d component(s) failing", e.UnhealthyCount)
}

// ErrServiceNotAvailable is returned when a service is not configured or available
type ErrServiceNotAvailable struct {
	Service string
}

func (e ErrServiceNotAvailable) Error() string {
	return fmt.Sprintf("service not available: %s", e.Service)
}

// GRPCStatus classifies a missing service as Unavailable, so every
// transport (MCP included, via its JSON-RPC code) reports the same class.
func (e ErrServiceNotAvailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrServiceUnavailable is returned when a service is temporarily unavailable
// or not initialized yet. This is used by gRPC service adapters when the
// underlying SDK client is nil.
type ErrServiceUnavailable struct {
	Service string
}

func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("service unavailable: %s", e.Service)
}

// =============================================================================
// TLS Configuration Errors
// =============================================================================

// ErrTLSConfigFailed indicates a TLS configuration error during server setup.
type ErrTLSConfigFailed struct {
	Reason string
}

func (e ErrTLSConfigFailed) Error() string {
	return "tls config failed: " + e.Reason
}

// ErrUnusableServingCertificate is returned when a certificate offered to a
// ServingCertificate could not complete a handshake: no chain or no private
// key. The certificate already being served stays in place (#36).
type ErrUnusableServingCertificate struct{}

func (e ErrUnusableServingCertificate) Error() string {
	return "serving certificate unusable: it needs a certificate chain and a private key"
}

// ErrNoServingCertificate is returned by ServingCertificate.GetCertificate
// when no certificate has been stored, so the handshake fails instead of
// presenting nothing.
type ErrNoServingCertificate struct{}

func (e ErrNoServingCertificate) Error() string {
	return "no serving certificate stored"
}

// =============================================================================
// gRPC Server Errors
// =============================================================================

// ErrGRPCServerNotConfigured is returned when the gRPC server is not configured
type ErrGRPCServerNotConfigured struct{}

func (e ErrGRPCServerNotConfigured) Error() string {
	return "gRPC server not configured"
}

// =============================================================================
// REST Service Errors
// =============================================================================

// ErrRESTServerNotRunning is returned when attempting operations on a stopped REST server
type ErrRESTServerNotRunning struct{}

func (e ErrRESTServerNotRunning) Error() string {
	return "REST server is not running"
}

// ErrRESTRoutesUnavailable is returned by Daemon.MountRESTRoutes when the
// daemon built no REST route table (EnableREST and RESTRoutesOnly both off),
// or when it is given no router to mount on.
type ErrRESTRoutesUnavailable struct{}

func (e ErrRESTRoutesUnavailable) Error() string {
	return "daemon REST routes are unavailable: no route table or no target router"
}

// ErrOwnedRouteNotReplayable is returned by MountOwnedRoutes when a daemon
// REST route has no path below /api/v1, so it cannot be registered on the
// router the webservice hands it.
type ErrOwnedRouteNotReplayable struct {
	Template string
	Cause    error
}

func (e ErrOwnedRouteNotReplayable) Error() string {
	if e.Cause != nil {
		return "daemon REST route " + e.Template + " cannot be replayed: " + e.Cause.Error()
	}
	return "daemon REST route " + e.Template + " is not below " + restBasePath
}

func (e ErrOwnedRouteNotReplayable) Unwrap() error { return e.Cause }

// ErrRESTServerAlreadyRunning is returned when attempting to start an already running REST server
type ErrRESTServerAlreadyRunning struct{}

func (e ErrRESTServerAlreadyRunning) Error() string {
	return "REST server is already running"
}

// ErrRESTServerStartFailed is returned when the REST server fails to start
type ErrRESTServerStartFailed struct {
	Reason string
}

func (e ErrRESTServerStartFailed) Error() string {
	return fmt.Sprintf("REST server failed to start: %s", e.Reason)
}

// MCPServerStartError is returned when Daemon.Start cannot start the MCP
// server. Start fails rather than run without the configured transport.
type MCPServerStartError struct {
	Err error
}

func (e *MCPServerStartError) Error() string {
	return "daemon: MCP server failed to start: " + e.Err.Error()
}

func (e *MCPServerStartError) Unwrap() error {
	return e.Err
}

// ErrRESTServerStopFailed is returned when the REST server fails to stop gracefully
type ErrRESTServerStopFailed struct {
	Reason string
}

func (e ErrRESTServerStopFailed) Error() string {
	return fmt.Sprintf("REST server failed to stop: %s", e.Reason)
}

// ErrRESTInvalidRequest is returned when a REST request is invalid
type ErrRESTInvalidRequest struct {
	Reason string
}

func (e ErrRESTInvalidRequest) Error() string {
	return fmt.Sprintf("invalid REST request: %s", e.Reason)
}

// ErrRESTEncodingFailed is returned when JSON encoding fails
type ErrRESTEncodingFailed struct {
	Cause error
}

func (e ErrRESTEncodingFailed) Error() string {
	return fmt.Sprintf("REST response encoding failed: %v", e.Cause)
}

func (e ErrRESTEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrRESTDecodingFailed is returned when JSON decoding fails
type ErrRESTDecodingFailed struct {
	Cause error
}

func (e ErrRESTDecodingFailed) Error() string {
	return fmt.Sprintf("REST request decoding failed: %v", e.Cause)
}

func (e ErrRESTDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidRequestBody is returned when the request body is invalid or malformed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingRequiredField is returned when a required field is missing from a request
type ErrMissingRequiredField struct {
	Field string
}

func (e ErrMissingRequiredField) Error() string {
	return fmt.Sprintf("missing required field: %s", e.Field)
}

// =============================================================================
// QUIC Service Errors
// =============================================================================

// ErrQUICNilRequest is returned when a nil request is passed to the QUIC handler
type ErrQUICNilRequest struct{}

func (e ErrQUICNilRequest) Error() string {
	return "QUIC request cannot be nil"
}

// ErrClientCertRequired is returned when a request needing a verified client
// certificate arrives on a connection without one. The listener verifies a
// certificate only if given, so the request is where it is enforced.
type ErrClientCertRequired struct {
	Operation string
}

func (e ErrClientCertRequired) Error() string {
	return "a verified client certificate is required for " + e.Operation
}

// ErrQUICHandlerPanic is returned when a handler sub-function panics.
// The recover() guard in QUICServiceHandler.HandleRequest catches the panic,
// logs a stack trace, and converts it to a StatusInternalError response so the
// QUIC stream is never closed without a valid response frame.
type ErrQUICHandlerPanic struct {
	Cause interface{}
}

func (e ErrQUICHandlerPanic) Error() string {
	return fmt.Sprintf("QUIC handler panic: %v", e.Cause)
}

// ErrQUICUnknownOpcode is returned when an unknown opcode is received
type ErrQUICUnknownOpcode struct {
	Opcode byte
}

func (e ErrQUICUnknownOpcode) Error() string {
	return fmt.Sprintf("unknown QUIC opcode: 0x%02X", e.Opcode)
}

// ErrQUICAuthMiddlewareRequired is returned by NewQUICServiceHandler when no
// auth middleware is configured: the QUIC dispatcher authorizes every request,
// so a handler without one cannot be built.
type ErrQUICAuthMiddlewareRequired struct{}

func (e ErrQUICAuthMiddlewareRequired) Error() string {
	return "QUIC service handler requires an auth middleware (WithQUICAuthMiddleware)"
}

// ErrQUICServiceUnavailable is returned when a required service is not available
type ErrQUICServiceUnavailable struct {
	Service string
}

func (e ErrQUICServiceUnavailable) Error() string {
	return fmt.Sprintf("QUIC service unavailable: %s", e.Service)
}

// ErrQUICDecodingFailed is returned when payload decoding fails
type ErrQUICDecodingFailed struct {
	Cause error
}

func (e ErrQUICDecodingFailed) Error() string {
	return fmt.Sprintf("QUIC payload decoding failed: %v", e.Cause)
}

func (e ErrQUICDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICEncodingFailed is returned when payload encoding fails
type ErrQUICEncodingFailed struct {
	Cause error
}

func (e ErrQUICEncodingFailed) Error() string {
	return fmt.Sprintf("QUIC payload encoding failed: %v", e.Cause)
}

func (e ErrQUICEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICMissingField is returned when a required field is missing
type ErrQUICMissingField struct {
	Field string
}

func (e ErrQUICMissingField) Error() string {
	return fmt.Sprintf("QUIC request missing required field: %s", e.Field)
}

// ErrQUICOperationFailed is returned when a QUIC operation fails
type ErrQUICOperationFailed struct {
	Op    string
	Cause error
}

func (e ErrQUICOperationFailed) Error() string {
	return fmt.Sprintf("QUIC operation %s failed: %v", e.Op, e.Cause)
}

func (e ErrQUICOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICAttestationRefused carries a refusal from the shared attestation
// gRPC servicer to the daemon-native QUIC attestation handler. QUICStatus
// gives it the status the daemon's quote opcodes (0x70-0x72) give the same
// gRPC class, so one refusal reads the same on every attestation opcode.
type ErrQUICAttestationRefused struct {
	Op    string
	Cause error
}

func (e ErrQUICAttestationRefused) Error() string {
	return fmt.Sprintf("attestation %s refused: %v", e.Op, e.Cause)
}

func (e ErrQUICAttestationRefused) Unwrap() error {
	return e.Cause
}

// QUICStatus is the QUIC status for the refusal's gRPC class.
func (e ErrQUICAttestationRefused) QUICStatus() byte {
	return grpcCodeToQUICStatus(e.Cause)
}

// ErrQUICAttestationNoService refuses a daemon-native QUIC attestation
// operation that no transport serves (device workload attestation, reports,
// policies: docs/attestation/api.md §2, docs/13 G7).
type ErrQUICAttestationNoService struct {
	Op string
}

func (e ErrQUICAttestationNoService) Error() string {
	return fmt.Sprintf("attestation %s is not served by any transport (docs/13 G7)", e.Op)
}

// QUICStatus is StatusNotImplemented: the opcode is in range, nothing serves it.
func (e ErrQUICAttestationNoService) QUICStatus() byte {
	return quicwire.StatusNotImplemented
}

// ErrQUICServerNotConfigured is returned when QUIC server is not configured
type ErrQUICServerNotConfigured struct{}

func (e ErrQUICServerNotConfigured) Error() string {
	return "QUIC server not configured"
}

// ErrQUICServerStartFailed is returned when the QUIC server fails to start
type ErrQUICServerStartFailed struct {
	Cause error
}

func (e ErrQUICServerStartFailed) Error() string {
	return fmt.Sprintf("QUIC server failed to start: %v", e.Cause)
}

func (e ErrQUICServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICServerStopFailed is returned when the QUIC server fails to stop gracefully
type ErrQUICServerStopFailed struct {
	Cause error
}

func (e ErrQUICServerStopFailed) Error() string {
	return fmt.Sprintf("QUIC server failed to stop: %v", e.Cause)
}

func (e ErrQUICServerStopFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// MCP Service Errors
// =============================================================================

// ErrMCPServerNotRunning is returned when attempting operations on a stopped MCP server
type ErrMCPServerNotRunning struct{}

func (e ErrMCPServerNotRunning) Error() string {
	return "MCP server is not running"
}

// ErrMCPServerAlreadyRunning is returned when attempting to start an already running MCP server
type ErrMCPServerAlreadyRunning struct{}

func (e ErrMCPServerAlreadyRunning) Error() string {
	return "MCP server is already running"
}

// ErrMCPServerStartFailed is returned when the MCP server fails to start
type ErrMCPServerStartFailed struct {
	Cause error
}

func (e ErrMCPServerStartFailed) Error() string {
	return fmt.Sprintf("MCP server failed to start: %v", e.Cause)
}

func (e ErrMCPServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrMCPServerStopFailed is returned when the MCP server fails to stop gracefully
type ErrMCPServerStopFailed struct {
	Cause error
}

func (e ErrMCPServerStopFailed) Error() string {
	return fmt.Sprintf("MCP server failed to stop: %v", e.Cause)
}

func (e ErrMCPServerStopFailed) Unwrap() error {
	return e.Cause
}

// ErrMCPServerNotConfigured is returned when MCP server is not configured
type ErrMCPServerNotConfigured struct{}

func (e ErrMCPServerNotConfigured) Error() string {
	return "MCP server not configured"
}

// =============================================================================
// vTPM Service Errors
// =============================================================================

// ErrVTPMOperationNotImplemented is returned when a vTPM operation is not yet implemented
type ErrVTPMOperationNotImplemented struct {
	Operation string
}

func (e ErrVTPMOperationNotImplemented) Error() string {
	return fmt.Sprintf("vTPM operation not implemented: %s", e.Operation)
}

// =============================================================================
// Device Service Errors
// =============================================================================

// ErrDeviceConfigFinderUnavailable is returned by FindConfigForDevice when the
// daemon's profile service cannot resolve a booting machine's config.
type ErrDeviceConfigFinderUnavailable struct{}

func (ErrDeviceConfigFinderUnavailable) Error() string {
	return "device config lookup is not available: the profile service does not resolve configs by EK serial or MAC"
}

// ErrInvalidDeviceID is returned when a device ID is invalid
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// GRPCStatus classifies a malformed device ID as InvalidArgument.
func (e ErrInvalidDeviceID) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrInvalidPortType is returned when an MCP port type names no PortType.
type ErrInvalidPortType struct {
	Type string
}

func (e ErrInvalidPortType) Error() string {
	return fmt.Sprintf("invalid port type: %s", e.Type)
}

// GRPCStatus classifies an unknown port type as InvalidArgument.
func (e ErrInvalidPortType) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrInvalidFlowConfig is returned when an MCP flow body does not decode into
// a FlowConfig: an unknown field, a wrong type or an unknown enum name.
type ErrInvalidFlowConfig struct {
	Cause error
}

func (e ErrInvalidFlowConfig) Error() string {
	return fmt.Sprintf("invalid flow config: %v", e.Cause)
}

// ErrUnencodableFlow reports a FlowConfig field the OVS flow grammar cannot
// install exactly as written (sdn_flow_codec.go).
type ErrUnencodableFlow struct {
	Field  string
	Reason string
}

func (e ErrUnencodableFlow) Error() string {
	return fmt.Sprintf("invalid flow %s: %s", e.Field, e.Reason)
}

func (e ErrInvalidFlowConfig) Unwrap() error {
	return e.Cause
}

// GRPCStatus classifies an undecodable flow body as InvalidArgument.
func (e ErrInvalidFlowConfig) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrAttestationFailed is returned when device attestation fails
type ErrAttestationFailed struct {
	Reason string
	// Err is the underlying cause, when there is one: a context error or a
	// typed upstream verifier error stays matchable through errors.Is/As.
	Err error
}

func (e ErrAttestationFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attestation failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("attestation failed: %s", e.Reason)
}

func (e ErrAttestationFailed) Unwrap() error {
	return e.Err
}

// ErrDeviceProfileLookupFailed is returned when the profile store could not
// answer which profile holds a device's PCR baseline. It is distinct from a
// device with no profile (device.ErrNoProfileForDevice), which is a verdict:
// a lookup failure decides nothing, so the verification fails closed.
type ErrDeviceProfileLookupFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrDeviceProfileLookupFailed) Error() string {
	return fmt.Sprintf("device profile lookup failed for device %s: %v", e.DeviceID, e.Cause)
}

func (e ErrDeviceProfileLookupFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceNotFound is returned when a device is not found
type ErrDeviceNotFound struct {
	DeviceID string
}

func (e ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %s", e.DeviceID)
}

// ErrProvisioningFailed is returned when device provisioning fails
type ErrProvisioningFailed struct {
	Reason string
}

func (e ErrProvisioningFailed) Error() string {
	return fmt.Sprintf("device provisioning failed: %s", e.Reason)
}

// ErrProfileNotFound is returned when a device profile is not found
type ErrProfileNotFound struct {
	Profile string
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("device profile not found: %s", e.Profile)
}

// ErrInvalidAttestationEvidence is returned when attestation evidence is malformed
type ErrInvalidAttestationEvidence struct {
	Reason string
}

func (e ErrInvalidAttestationEvidence) Error() string {
	return fmt.Sprintf("invalid attestation evidence: %s", e.Reason)
}

// ErrDeviceOperationFailed is returned when a device operation fails
type ErrDeviceOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDeviceOperationFailed) Error() string {
	return fmt.Sprintf("device operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDeviceOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceProfileServiceNotAvailable is returned when the device profile service is not configured
type ErrDeviceProfileServiceNotAvailable struct{}

func (e ErrDeviceProfileServiceNotAvailable) Error() string {
	return "device: profile service not available"
}

// =============================================================================
// SDN Service Errors
// =============================================================================

// ErrSDNOperationNotImplemented is returned when an SDN operation is not yet implemented
type ErrSDNOperationNotImplemented struct {
	Operation string
}

func (e ErrSDNOperationNotImplemented) Error() string {
	return fmt.Sprintf("SDN operation not implemented: %s", e.Operation)
}

// ErrSDNPolicyNotFound is returned when a policy is not found
type ErrSDNPolicyNotFound struct {
	PolicyID string
}

func (e ErrSDNPolicyNotFound) Error() string {
	return fmt.Sprintf("SDN policy not found: %s", e.PolicyID)
}

// ErrSDNInvalidPolicy is returned when a policy specification is invalid
type ErrSDNInvalidPolicy struct {
	Reason string
}

func (e ErrSDNInvalidPolicy) Error() string {
	return fmt.Sprintf("invalid SDN policy: %s", e.Reason)
}

// ErrSDNSetPortStateFailed is returned when setting port state fails
type ErrSDNSetPortStateFailed struct {
	PortID string
	Cause  error
}

func (e ErrSDNSetPortStateFailed) Error() string {
	return fmt.Sprintf("failed to set port state for %s: %v", e.PortID, e.Cause)
}

func (e ErrSDNSetPortStateFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNApplyPolicyFailed is returned when applying a policy fails
type ErrSDNApplyPolicyFailed struct {
	PolicyID string
	Cause    error
}

func (e ErrSDNApplyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to apply policy %s: %v", e.PolicyID, e.Cause)
}

func (e ErrSDNApplyPolicyFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNBridgeNotFound is returned when a bridge is not found
type ErrSDNBridgeNotFound struct {
	BridgeName string
}

func (e ErrSDNBridgeNotFound) Error() string {
	return fmt.Sprintf("SDN bridge not found: %s", e.BridgeName)
}

// ErrSDNPortNotFound is returned when a port is not found
type ErrSDNPortNotFound struct {
	BridgeName string
	PortName   string
}

func (e ErrSDNPortNotFound) Error() string {
	return fmt.Sprintf("SDN port not found: %s on bridge %s", e.PortName, e.BridgeName)
}

// ErrSDNMissingParameter is returned when a required parameter is missing
type ErrSDNMissingParameter struct {
	Parameter string
}

func (e ErrSDNMissingParameter) Error() string {
	return fmt.Sprintf("missing required parameter: %s", e.Parameter)
}

// ErrOVSNotConfigured is returned when an OVS connection operation is attempted
// but no OVS client has been configured (e.g. when running in zone-only stub mode).
type ErrOVSNotConfigured struct{}

func (ErrOVSNotConfigured) Error() string {
	return "OVS client not configured"
}

// =============================================================================
// DNS Service Errors
// =============================================================================

// ErrDNSZoneNotFound is returned when a DNS zone is not found
type ErrDNSZoneNotFound struct {
	Zone string
}

func (e ErrDNSZoneNotFound) Error() string {
	return fmt.Sprintf("DNS zone not found: %s", e.Zone)
}

// ErrDNSRecordNotFound is returned when a DNS record is not found
type ErrDNSRecordNotFound struct {
	Name       string
	RecordType string
}

func (e ErrDNSRecordNotFound) Error() string {
	return fmt.Sprintf("DNS record not found: %s %s", e.Name, e.RecordType)
}

// ErrDNSOperationFailed is returned when a DNS operation fails
type ErrDNSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDNSOperationFailed) Error() string {
	return fmt.Sprintf("DNS operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDNSOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// IAM Service Errors
// =============================================================================

// ErrIAMServiceNotAvailable is returned when IAM service is not configured
type ErrIAMServiceNotAvailable struct{}

func (e ErrIAMServiceNotAvailable) Error() string {
	return "IAM service not available"
}

// GRPCStatus classifies the error as FailedPrecondition on every transport:
// the request is well formed, but this daemon has no IAM backend to serve it.
func (e ErrIAMServiceNotAvailable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrIAMMissingParameter is returned when a required IAM parameter is missing
type ErrIAMMissingParameter struct {
	Parameter string
}

func (e ErrIAMMissingParameter) Error() string {
	return fmt.Sprintf("missing required IAM parameter: %s", e.Parameter)
}

// ErrIAMUserNotFound is returned when a user is not found
type ErrIAMUserNotFound struct {
	TenantID string
	UserID   string
}

func (e ErrIAMUserNotFound) Error() string {
	return fmt.Sprintf("IAM user not found: %s in tenant %s", e.UserID, e.TenantID)
}

// ErrIAMUserAlreadyExists is returned when attempting to create a user that already exists
type ErrIAMUserAlreadyExists struct {
	TenantID string
	Email    string
}

func (e ErrIAMUserAlreadyExists) Error() string {
	return fmt.Sprintf("IAM user already exists: %s in tenant %s", e.Email, e.TenantID)
}

// ErrIAMRoleNotFound is returned when a role is not found
type ErrIAMRoleNotFound struct {
	TenantID string
	RoleID   string
}

func (e ErrIAMRoleNotFound) Error() string {
	return fmt.Sprintf("IAM role not found: %s in tenant %s", e.RoleID, e.TenantID)
}

// ErrIAMRoleAlreadyExists is returned when attempting to create a role that already exists
type ErrIAMRoleAlreadyExists struct {
	TenantID string
	RoleID   string
}

func (e ErrIAMRoleAlreadyExists) Error() string {
	return fmt.Sprintf("IAM role already exists: %s in tenant %s", e.RoleID, e.TenantID)
}

// ErrIAMGroupNotFound is returned when a group is not found
type ErrIAMGroupNotFound struct {
	TenantID string
	GroupID  string
}

func (e ErrIAMGroupNotFound) Error() string {
	return fmt.Sprintf("IAM group not found: %s in tenant %s", e.GroupID, e.TenantID)
}

// ErrIAMGroupAlreadyExists is returned when attempting to create a group that already exists
type ErrIAMGroupAlreadyExists struct {
	TenantID string
	GroupID  string
}

func (e ErrIAMGroupAlreadyExists) Error() string {
	return fmt.Sprintf("IAM group already exists: %s in tenant %s", e.GroupID, e.TenantID)
}

// ErrIAMTenantNotFound is returned when a tenant is not found
type ErrIAMTenantNotFound struct {
	TenantID string
}

func (e ErrIAMTenantNotFound) Error() string {
	return fmt.Sprintf("IAM tenant not found: %s", e.TenantID)
}

// ErrIAMTenantAlreadyExists is returned when attempting to create a tenant that already exists
type ErrIAMTenantAlreadyExists struct {
	TenantID string
}

func (e ErrIAMTenantAlreadyExists) Error() string {
	return fmt.Sprintf("IAM tenant already exists: %s", e.TenantID)
}

// ErrIAMPolicyNotFound is returned when a policy is not found
type ErrIAMPolicyNotFound struct {
	TenantID   string
	PolicyName string
}

func (e ErrIAMPolicyNotFound) Error() string {
	return fmt.Sprintf("IAM policy not found: %s in tenant %s", e.PolicyName, e.TenantID)
}

// ErrIAMPolicyAlreadyExists is returned when attempting to create a policy that already exists
type ErrIAMPolicyAlreadyExists struct {
	TenantID   string
	PolicyName string
}

func (e ErrIAMPolicyAlreadyExists) Error() string {
	return fmt.Sprintf("IAM policy already exists: %s in tenant %s", e.PolicyName, e.TenantID)
}

// ErrIAMPolicyValidationFailed is returned when policy validation fails
type ErrIAMPolicyValidationFailed struct {
	Reason string
}

func (e ErrIAMPolicyValidationFailed) Error() string {
	return fmt.Sprintf("IAM policy validation failed: %s", e.Reason)
}

// ErrIAMAppNotFound is returned when an application is not found
type ErrIAMAppNotFound struct {
	TenantID string
	ClientID string
}

func (e ErrIAMAppNotFound) Error() string {
	return fmt.Sprintf("IAM application not found: %s in tenant %s", e.ClientID, e.TenantID)
}

// ErrIAMAppAlreadyExists is returned when attempting to create an application that already exists
type ErrIAMAppAlreadyExists struct {
	TenantID string
	Name     string
}

func (e ErrIAMAppAlreadyExists) Error() string {
	return fmt.Sprintf("IAM application already exists: %s in tenant %s", e.Name, e.TenantID)
}

// ErrIAMAuthenticationViaOIDC refuses the MCP iam_authenticate tool. The IAM
// service holds no credentials to check and the platform has no Authenticate
// RPC: users sign in through the broker's OIDC flows, which issue the
// platform token.
type ErrIAMAuthenticationViaOIDC struct{}

func (e ErrIAMAuthenticationViaOIDC) Error() string {
	return "iam authentication is handled via OIDC flows, not the IAM service"
}

// GRPCStatus classifies the refusal as Unimplemented, the class the token
// create and revoke refusals carry.
func (e ErrIAMAuthenticationViaOIDC) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}

// ErrIAMPermissionDenied is returned when a permission check fails
type ErrIAMPermissionDenied struct {
	Subject  string
	Resource string
	Action   string
}

func (e ErrIAMPermissionDenied) Error() string {
	return fmt.Sprintf("IAM permission denied: subject %s cannot perform %s on %s", e.Subject, e.Action, e.Resource)
}

// ErrIAMTenantForbidden is returned when an IAM request names a tenant other
// than the one the authenticated caller is bound to. It is the gRPC twin of
// the REST guard's 403 "caller may not act on another tenant".
type ErrIAMTenantForbidden struct {
	Requested string
}

func (e ErrIAMTenantForbidden) Error() string {
	return fmt.Sprintf("IAM request names tenant %q: caller may not act on another tenant", e.Requested)
}

// ErrOrchestratorTenantForbidden is returned when an orchestrator request
// names a tenant other than the one the authenticated caller is bound to. It
// is the gRPC, QUIC, MCP and Unix twin of the webservice REST tenant rule.
type ErrOrchestratorTenantForbidden struct {
	Requested string
}

func (e ErrOrchestratorTenantForbidden) Error() string {
	return fmt.Sprintf("orchestrator request names tenant %q: caller may not act on another tenant", e.Requested)
}

// ErrTenantBarrierShamirUnsupported is returned when InitTenantBarrier asks
// for Shamir sharing. The per-tenant barrier initializes with its
// deterministic credential only, and the init returns no shares, so
// honouring the request would leave a barrier nobody could unseal.
type ErrTenantBarrierShamirUnsupported struct {
	Threshold int32
	Shares    int32
}

func (e ErrTenantBarrierShamirUnsupported) Error() string {
	return fmt.Sprintf("tenant barrier init with Shamir threshold %d of %d shares is not supported: "+
		"the per-tenant barrier initializes with its deterministic credential and returns no shares; send threshold and shares 0",
		e.Threshold, e.Shares)
}

// ErrIAMInvalidCredentials is returned when credentials are invalid
type ErrIAMInvalidCredentials struct{}

func (e ErrIAMInvalidCredentials) Error() string {
	return "IAM invalid credentials"
}

// ErrIAMRoleAssignmentFailed is returned when role assignment fails
type ErrIAMRoleAssignmentFailed struct {
	UserID string
	RoleID string
	Reason string
}

func (e ErrIAMRoleAssignmentFailed) Error() string {
	return fmt.Sprintf("IAM failed to assign role %s to user %s: %s", e.RoleID, e.UserID, e.Reason)
}

// ErrIAMRoleRevocationFailed is returned when role revocation fails
type ErrIAMRoleRevocationFailed struct {
	UserID string
	RoleID string
	Reason string
}

func (e ErrIAMRoleRevocationFailed) Error() string {
	return fmt.Sprintf("IAM failed to revoke role %s from user %s: %s", e.RoleID, e.UserID, e.Reason)
}

// ErrIAMGroupMembershipFailed is returned when group membership operation fails
type ErrIAMGroupMembershipFailed struct {
	GroupID string
	UserID  string
	Reason  string
}

func (e ErrIAMGroupMembershipFailed) Error() string {
	return fmt.Sprintf("IAM group membership operation failed for user %s in group %s: %s", e.UserID, e.GroupID, e.Reason)
}

// ErrIAMTokenNotFound is returned when a token is not found
type ErrIAMTokenNotFound struct {
	TokenID string
}

func (e ErrIAMTokenNotFound) Error() string {
	return fmt.Sprintf("IAM token not found: %s", e.TokenID)
}

// ErrIAMTokenExpired is returned when a token has expired
type ErrIAMTokenExpired struct {
	TokenID string
}

func (e ErrIAMTokenExpired) Error() string {
	return fmt.Sprintf("IAM token expired: %s", e.TokenID)
}

// ErrIAMTokenRevoked is returned when a token has been revoked
type ErrIAMTokenRevoked struct {
	TokenID string
}

func (e ErrIAMTokenRevoked) Error() string {
	return fmt.Sprintf("IAM token revoked: %s", e.TokenID)
}

// ErrIAMTokenInvalid is returned when a token is invalid
type ErrIAMTokenInvalid struct {
	Reason string
}

func (e ErrIAMTokenInvalid) Error() string {
	return fmt.Sprintf("IAM token invalid: %s", e.Reason)
}

// ErrIAMTokenVerifierNotConfigured is returned when a token is submitted for
// verification but the daemon has no token validator wired. It is never an
// answer about the token: without a validator no token is valid.
type ErrIAMTokenVerifierNotConfigured struct{}

func (e ErrIAMTokenVerifierNotConfigured) Error() string {
	return "IAM token verification is not configured: no token validator is wired"
}

// ErrNoPlatformJWTVerifier is returned when a platform JWT is checked but no
// platform JWT verifier is attached to the validator.
type ErrNoPlatformJWTVerifier struct{}

func (e ErrNoPlatformJWTVerifier) Error() string {
	return "no platform JWT verifier is configured"
}

// ErrPlatformJWTRejected is returned when every platform JWT verifier
// rejected a token. Cause joins each verifier's rejection so callers can
// classify it with errors.Is.
type ErrPlatformJWTRejected struct {
	Cause error
}

func (e ErrPlatformJWTRejected) Error() string {
	return "platform JWT rejected: " + e.Cause.Error()
}

func (e ErrPlatformJWTRejected) Unwrap() error {
	return e.Cause
}

// =============================================================================
// KMS Service Errors
// =============================================================================

// ErrKMSKeyNotFound is returned when a key is not found in the KMS
type ErrKMSKeyNotFound struct {
	KeyID string
}

func (e ErrKMSKeyNotFound) Error() string {
	return fmt.Sprintf("KMS key not found: %s", e.KeyID)
}

// GRPCStatus classifies the error as NotFound, the code the gRPC KMS
// adapter returns for the same lookup.
func (e ErrKMSKeyNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrKMSKeyAlreadyExists is returned when attempting to create a key that already exists
type ErrKMSKeyAlreadyExists struct {
	KeyID string
}

func (e ErrKMSKeyAlreadyExists) Error() string {
	return fmt.Sprintf("KMS key already exists: %s", e.KeyID)
}

// ErrKMSKeyDisabled is returned when attempting to use a disabled key
type ErrKMSKeyDisabled struct {
	KeyID string
}

func (e ErrKMSKeyDisabled) Error() string {
	return fmt.Sprintf("KMS key is disabled: %s", e.KeyID)
}

// ErrKMSInvalidParameter is returned when a KMS operation receives an invalid parameter
type ErrKMSInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrKMSInvalidParameter) Error() string {
	return fmt.Sprintf("invalid KMS parameter %s: %s", e.Parameter, e.Reason)
}

// GRPCStatus classifies the error as InvalidArgument, the code the gRPC
// KMS and secrets adapters return for the same bad input.
func (e ErrKMSInvalidParameter) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSInvalidAlgorithm is returned when an unsupported algorithm is specified
type ErrKMSInvalidAlgorithm struct {
	Algorithm string
}

func (e ErrKMSInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid KMS algorithm: %s", e.Algorithm)
}

// ErrCAInvalidKeyAlgorithm is returned when a certificate request names a
// key algorithm the CA does not issue.
type ErrCAInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrCAInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid certificate key algorithm: %s", e.Algorithm)
}

// ErrEmbeddedHostFailed is returned when platformd cannot be hosted inside
// the calling process for the SDK's embedded transport.
type ErrEmbeddedHostFailed struct {
	Op  string
	Err error
}

func (e ErrEmbeddedHostFailed) Error() string {
	return fmt.Sprintf("embedded platformd %s failed: %v", e.Op, e.Err)
}

func (e ErrEmbeddedHostFailed) Unwrap() error {
	return e.Err
}

// ErrKMSInvalidKeyUsage is returned when an invalid key usage is specified
type ErrKMSInvalidKeyUsage struct {
	Usage string
}

func (e ErrKMSInvalidKeyUsage) Error() string {
	return fmt.Sprintf("invalid KMS key usage: %s", e.Usage)
}

// ErrKMSOperationFailed is returned when a KMS operation fails
type ErrKMSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrKMSOperationFailed) Error() string {
	return fmt.Sprintf("KMS operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrKMSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSEncryptionFailed is returned when encryption fails
type ErrKMSEncryptionFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSEncryptionFailed) Error() string {
	return fmt.Sprintf("KMS encryption failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSEncryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSDecryptionFailed is returned when decryption fails
type ErrKMSDecryptionFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSDecryptionFailed) Error() string {
	return fmt.Sprintf("KMS decryption failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSDecryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSSigningFailed is returned when signing fails
type ErrKMSSigningFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSSigningFailed) Error() string {
	return fmt.Sprintf("KMS signing failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSSigningFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSVerificationFailed is returned when signature verification fails
type ErrKMSVerificationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSVerificationFailed) Error() string {
	return fmt.Sprintf("KMS signature verification failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSKeyRotationFailed is returned when key rotation fails
type ErrKMSKeyRotationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSKeyRotationFailed) Error() string {
	return fmt.Sprintf("KMS key rotation failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSKeyRotationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSRandomGenerationFailed is returned when random byte generation fails
type ErrKMSRandomGenerationFailed struct {
	Cause error
}

func (e ErrKMSRandomGenerationFailed) Error() string {
	return fmt.Sprintf("KMS random generation failed: %v", e.Cause)
}

func (e ErrKMSRandomGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSKeyDeletionProtected is returned when attempting to delete a protected key
type ErrKMSKeyDeletionProtected struct {
	KeyID string
}

func (e ErrKMSKeyDeletionProtected) Error() string {
	return fmt.Sprintf("KMS key %s has deletion protection enabled", e.KeyID)
}

// ErrKMSDataKeyGenerationFailed is returned when data key generation fails
type ErrKMSDataKeyGenerationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSDataKeyGenerationFailed) Error() string {
	return fmt.Sprintf("KMS data key generation failed for KEK %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSDataKeyGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSOperationNotImplemented is returned when a KMS operation is not yet
// implemented in the backend adapter. This allows partial KMS service wiring
// where implemented operations work while unimplemented ones return a clear error.
type ErrKMSOperationNotImplemented struct {
	Operation string
}

func (e ErrKMSOperationNotImplemented) Error() string {
	return fmt.Sprintf("KMS operation not implemented: %s", e.Operation)
}

// =============================================================================
// TPM2/IDevID Service Errors
// =============================================================================

// ErrInvalidCertificatePEM is returned when a PEM-encoded certificate is invalid
type ErrInvalidCertificatePEM struct{}

func (e ErrInvalidCertificatePEM) Error() string {
	return "invalid PEM-encoded certificate"
}

// ErrTPM2ServiceNotAvailable is returned when TPM2 service is not configured
type ErrTPM2ServiceNotAvailable struct{}

func (e ErrTPM2ServiceNotAvailable) Error() string {
	return "TPM2 service not available"
}

// ErrIDevIDNotFound is returned when IDevID is not found in TPM
type ErrIDevIDNotFound struct{}

func (e ErrIDevIDNotFound) Error() string {
	return "IDevID not found in TPM"
}

// ErrIAKNotFound is returned when IAK is not found in TPM
type ErrIAKNotFound struct{}

func (e ErrIAKNotFound) Error() string {
	return "IAK not found in TPM"
}

// ErrIDevIDCertificateNotFound is returned when IDevID certificate is not installed
type ErrIDevIDCertificateNotFound struct{}

func (e ErrIDevIDCertificateNotFound) Error() string {
	return "IDevID certificate not installed"
}

// ErrIAKCertificateNotFound is returned when IAK certificate is not installed
type ErrIAKCertificateNotFound struct{}

func (e ErrIAKCertificateNotFound) Error() string {
	return "IAK certificate not installed"
}

// ErrTPM2OperationFailed is returned when a TPM2 operation fails
type ErrTPM2OperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTPM2OperationFailed) Error() string {
	return fmt.Sprintf("TPM2 operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTPM2OperationFailed) Unwrap() error {
	return e.Cause
}

// ErrActivateCredentialFieldRequired is returned when a credential
// activation arrives without its credential blob or its encrypted
// secret. The request is refused before the TPM is touched: an empty
// blob cannot be a TPM2_ActivateCredential challenge, and the session
// HMAC go-tpm computes over it panics under GODEBUG=fips140=only.
type ErrActivateCredentialFieldRequired struct {
	// Field names the missing request field.
	Field string
}

// Error implements the error interface.
func (e ErrActivateCredentialFieldRequired) Error() string {
	return e.Field + " is required"
}

// GRPCStatus classifies the refusal as InvalidArgument.
func (e ErrActivateCredentialFieldRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// =============================================================================
// Container Service Errors
// =============================================================================

// ErrContainerServiceNotAvailable is returned when container service is not configured
type ErrContainerServiceNotAvailable struct{}

func (e ErrContainerServiceNotAvailable) Error() string {
	return "container service not available"
}

// ErrContainerNotFound is returned when a container is not found
type ErrContainerNotFound struct {
	ContainerID string
}

func (e ErrContainerNotFound) Error() string {
	return fmt.Sprintf("container not found: %s", e.ContainerID)
}

// ErrContainerOperationFailed is returned when a container operation fails
type ErrContainerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrContainerOperationFailed) Error() string {
	return fmt.Sprintf("container operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrContainerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerLogsNotSupported is returned when container log retrieval is not supported
type ErrContainerLogsNotSupported struct{}

func (e ErrContainerLogsNotSupported) Error() string {
	return "container logs not supported via orchestrator"
}

// ErrContainerAttestNotSupported is returned when container attestation is not supported
type ErrContainerAttestNotSupported struct{}

func (e ErrContainerAttestNotSupported) Error() string {
	return "container attestation not implemented"
}

// ErrContainerCreateNoInstance is returned when the orchestrator reports a
// container created but answers no instance for it.
type ErrContainerCreateNoInstance struct{}

func (e ErrContainerCreateNoInstance) Error() string {
	return "the orchestrator answered no container instance"
}

// ErrContainerInvalidParameter is returned when a container operation receives an invalid parameter
type ErrContainerInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrContainerInvalidParameter) Error() string {
	return fmt.Sprintf("invalid container parameter %s: %s", e.Parameter, e.Reason)
}

// =============================================================================
// Authentication/Token Validation Errors
// =============================================================================

// ErrQuicBaaSServiceUnavailable is returned when QuicBaaS service is not available
// for authentication operations
type ErrQuicBaaSServiceUnavailable struct{}

func (e ErrQuicBaaSServiceUnavailable) Error() string {
	return "QuicBaaS service not available for authentication"
}

// ErrTokenValidationFailed is returned when token validation fails
type ErrTokenValidationFailed struct {
	Cause error
}

func (e ErrTokenValidationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("token validation failed: %v", e.Cause)
	}
	return "token validation failed"
}

func (e ErrTokenValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrIAMPermissionCheckFailed is returned when the IAM policy enforcement
// point cannot decide a transport's permission check.
type ErrIAMPermissionCheckFailed struct {
	Cause error
}

func (e ErrIAMPermissionCheckFailed) Error() string {
	return fmt.Sprintf("IAM permission check failed: %v", e.Cause)
}

func (e ErrIAMPermissionCheckFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Overlay Network Service Errors
// =============================================================================

// ErrOverlayServiceNotAvailable is returned when the overlay network service is not configured
type ErrOverlayServiceNotAvailable struct{}

func (e ErrOverlayServiceNotAvailable) Error() string {
	return "overlay network service not available"
}

// =============================================================================
// Gateway Service Errors
// =============================================================================

// ErrGatewayServiceNotAvailable is returned when the gateway service is not configured
type ErrGatewayServiceNotAvailable struct{}

func (e ErrGatewayServiceNotAvailable) Error() string {
	return "gateway service not available"
}

// ErrBGPAttributeUnsupported is returned when a prefix announcement asks
// for a BGP path attribute the gateway service does not announce with.
type ErrBGPAttributeUnsupported struct {
	Attribute string
}

func (e ErrBGPAttributeUnsupported) Error() string {
	return fmt.Sprintf("BGP path attribute not supported on announce: %s", e.Attribute)
}

// GRPCStatus classifies the refused attribute as an invalid argument, so
// the QUIC handler answers it as one.
func (e ErrBGPAttributeUnsupported) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// =============================================================================
// TPM Service Errors
// =============================================================================

// ErrTPMInvalidSize is returned when a requested size exceeds the maximum.
type ErrTPMInvalidSize struct {
	Max       int
	Requested int
}

func (e ErrTPMInvalidSize) Error() string {
	return fmt.Sprintf("requested size %d exceeds maximum %d bytes", e.Requested, e.Max)
}

// GRPCStatus classes an oversized request as InvalidArgument, the class
// gRPC GetRandom gives the same request.
func (e ErrTPMInvalidSize) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrVTPMIDRequired is returned when a vTPM call names no bundle or template.
// Field is the name the gRPC VTPMService uses in the same refusal.
type ErrVTPMIDRequired struct {
	Field string
}

func (e ErrVTPMIDRequired) Error() string {
	return e.Field + " is required"
}

// GRPCStatus classes a missing id as InvalidArgument, as gRPC VTPMService does.
func (e ErrVTPMIDRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrNVOffsetOutOfRange is returned when an NV request's offset exceeds
// the 16-bit offset TPM2_NV_Read / TPM2_NV_Write carry.
type ErrNVOffsetOutOfRange struct {
	Offset uint32
}

func (e ErrNVOffsetOutOfRange) Error() string {
	return fmt.Sprintf("NV offset %d exceeds maximum %d", e.Offset, math.MaxUint16)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrNVOffsetOutOfRange) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrTenantDEKProvision is returned when DEK provisioning fails during tenant creation.
type ErrTenantDEKProvision struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDEKProvision) Error() string {
	return fmt.Sprintf("daemon: failed to provision DEK for tenant %s: %v", e.TenantID, e.Cause)
}

func (e ErrTenantDEKProvision) Unwrap() error {
	return e.Cause
}

// ErrTenantDEKDeprovision is returned when DEK cleanup fails during tenant deletion.
type ErrTenantDEKDeprovision struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDEKDeprovision) Error() string {
	return fmt.Sprintf("daemon: failed to deprovision DEK for tenant %s: %v", e.TenantID, e.Cause)
}

func (e ErrTenantDEKDeprovision) Unwrap() error {
	return e.Cause
}

// ErrConfigReloadFailed wraps a failure during runtime reload of the
// platformd configuration from disk. The cause exposes the underlying
// viper / unmarshal error for log analysis.
type ErrConfigReloadFailed struct {
	Cause error
}

func (e ErrConfigReloadFailed) Error() string {
	return fmt.Sprintf("daemon: config reload failed: %v", e.Cause)
}

func (e ErrConfigReloadFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigInvalid is returned by validation paths when a YAML body
// fails to parse or fails schema checks.
type ErrConfigInvalid struct {
	Issues []string
}

func (e ErrConfigInvalid) Error() string {
	return fmt.Sprintf("daemon: invalid config: %v", e.Issues)
}

// ErrAttestationManifestIDRequired is returned by AttestationService
// operations that need a non-empty manifest ID.
type ErrAttestationManifestIDRequired struct{}

func (ErrAttestationManifestIDRequired) Error() string {
	return "daemon: attestation manifest id is required"
}

// ErrAttestationManifestSignatureUnchecked is returned by
// AttestationService.VerifyManifest when the caller supplies a public
// key: the service cannot check a manifest signature against it, so it
// refuses rather than report the signature valid unchecked.
type ErrAttestationManifestSignatureUnchecked struct{}

func (ErrAttestationManifestSignatureUnchecked) Error() string {
	return "daemon: manifest verification cannot check a signature against a supplied public key"
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// ErrConfigDeliveryServiceNotAvailable is returned when the pre-enrollment
// config delivery service is not configured on this daemon.
type ErrConfigDeliveryServiceNotAvailable struct{}

// Error implements the error interface.
func (e ErrConfigDeliveryServiceNotAvailable) Error() string {
	return "config delivery service is not available"
}

// GRPCStatus classifies the error as Unavailable, the code the gRPC
// ConfigDeliveryService answers with when no service is wired, so MCP
// reports the same error class.
func (e ErrConfigDeliveryServiceNotAvailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrConfigDeliveryClassified carries a config delivery error over MCP with
// the gRPC code the ConfigDeliveryService answers the same error with, so
// both transports report one error class. Unwrap keeps the typed cause
// reachable through errors.As.
type ErrConfigDeliveryClassified struct {
	Code codes.Code
	Err  error
}

// Error implements the error interface.
func (e ErrConfigDeliveryClassified) Error() string {
	return e.Err.Error()
}

// Unwrap returns the config delivery error.
func (e ErrConfigDeliveryClassified) Unwrap() error {
	return e.Err
}

// GRPCStatus returns the gRPC status for the classified error.
func (e ErrConfigDeliveryClassified) GRPCStatus() *status.Status {
	return status.New(e.Code, e.Err.Error())
}

// ErrConfigSerializationFailed is returned when a resolved device
// configuration could not be serialized to JSON for wire delivery.
type ErrConfigSerializationFailed struct {
	Cause error
}

// Error implements the error interface.
func (e ErrConfigSerializationFailed) Error() string {
	return "config delivery: config serialization failed: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause.
func (e ErrConfigSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrEABUnsupportedSortField is returned when an EAB list request asks
// for a sort_by field the service does not support.
type ErrEABUnsupportedSortField struct {
	Field string
}

// Error implements the error interface.
func (e ErrEABUnsupportedSortField) Error() string {
	return "eab: unsupported sort field: " + e.Field
}

// ErrEABInvalidQRCodeSize is returned when an EAB QR code request asks
// for a negative pixel size.
type ErrEABInvalidQRCodeSize struct {
	Size int
}

// Error implements the error interface.
func (e ErrEABInvalidQRCodeSize) Error() string {
	return fmt.Sprintf("eab: invalid QR code size: %d", e.Size)
}

// ErrEABUnsupportedStatusFilter is returned when an EAB list request over
// MCP names a status other than active, revoked, expired or used.
type ErrEABUnsupportedStatusFilter struct {
	Status string
}

// Error implements the error interface.
func (e ErrEABUnsupportedStatusFilter) Error() string {
	return "eab: unsupported status filter: " + e.Status
}

// ErrVMListUnknownState is returned when a ListVMs request filters on a state
// value the VMState enum does not define.
type ErrVMListUnknownState struct {
	State int32
}

func (e ErrVMListUnknownState) Error() string {
	return fmt.Sprintf("list VMs: unknown VM state %d", e.State)
}

// GRPCStatus classifies an unknown state filter as InvalidArgument.
func (e ErrVMListUnknownState) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrVMListSelectorExpression is returned when a ListVMs selector carries a
// match_expressions entry. The API defines no expression syntax, so the
// service refuses the entry rather than ignore it.
type ErrVMListSelectorExpression struct {
	Expression string
}

func (e ErrVMListSelectorExpression) Error() string {
	return fmt.Sprintf("list VMs: selector match_expressions are not supported: %q", e.Expression)
}

// GRPCStatus classifies a selector expression as InvalidArgument.
func (e ErrVMListSelectorExpression) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrVMCreateUnsupportedField is returned when a CreateVM config sets a
// field the compute backend cannot honour. The service refuses the request
// rather than create a VM that differs from it.
type ErrVMCreateUnsupportedField struct {
	Field  string
	Reason string
}

func (e ErrVMCreateUnsupportedField) Error() string {
	return "create VM: config." + e.Field + " is not supported: " + e.Reason
}

// GRPCStatus classifies an unsupported config field as InvalidArgument.
func (e ErrVMCreateUnsupportedField) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrVMListUnsupportedSortField is returned when a ListVMs request asks for a
// sort_by field the service does not support.
type ErrVMListUnsupportedSortField struct {
	Field string
}

func (e ErrVMListUnsupportedSortField) Error() string {
	return "list VMs: unsupported sort field: " + e.Field
}

// GRPCStatus classifies an unsupported sort field as InvalidArgument.
func (e ErrVMListUnsupportedSortField) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrProfileConfigInvalid is returned when a device profile create or
// update request carries config bytes that are not valid JSON, so the
// full platform config cannot be decoded onto the profile entity.
type ErrProfileConfigInvalid struct {
	Cause error
}

// Error implements the error interface.
func (e ErrProfileConfigInvalid) Error() string {
	return "device: profile config is not valid JSON: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause.
func (e ErrProfileConfigInvalid) Unwrap() error {
	return e.Cause
}

// ErrDaemonRetryUnsafe is returned by Start when a prior failed startup had
// to stop a gRPC server that had already served. grpc.Server.Stop is
// permanent, so retrying on the same Daemon instance would report success
// with a dead gRPC transport; construct a new Daemon instead.
type ErrDaemonRetryUnsafe struct{}

func (ErrDaemonRetryUnsafe) Error() string {
	return "daemon startup previously failed after a gRPC server had served: retry on this instance is unsafe, construct a new Daemon"
}
