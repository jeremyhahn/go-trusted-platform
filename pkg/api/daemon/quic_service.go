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
	"context"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// QUICServiceHandler implements quic.Handler interface and delegates to daemon services.
// It provides a unified request handler that routes QUIC protocol operations to the
// appropriate service implementations (CA, vTPM, Device, DNS, SDN, KMS, TPM2, Container,
// Attestation, VM, PXE, Tenant, etc.).
type QUICServiceHandler struct {
	logger             *logging.Logger
	authMiddleware     *quic.AuthMiddleware
	caHandler          *quic.CAHandler
	vtpmService        vtpm.VTPMService
	deviceService      device.DeviceService
	profileService     device.DeviceProfileService
	dnsService         DNSService
	healthRegistry     health.Registry
	sdnService         *SDNService
	iamService         QUICIAMService
	kmsService         KMSServiceInterface
	cryptoService      CryptoServiceInterface
	tpm2Service        xkmssdk.TrustedPlatformModule
	containerHandler   *quic.ContainerHandler
	attestationHandler *quic.AttestationHandler
	vmHandler          *quic.VMHandler
	pxeService         pxe.Service
	tenantManager      TenantManagerInterface
	daemonService      *Service
	overlayHandler     *quic.OverlayHandler
	gatewayHandler     *quic.GatewayHandler
}

// QUICServiceHandlerOption is a functional option for configuring QUICServiceHandler
type QUICServiceHandlerOption func(*QUICServiceHandler)

// WithQUICCAService sets the CA service for the QUIC handler
func WithQUICCAService(ca goca.CACertificateAuthority) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		if ca != nil {
			h.caHandler = quic.NewCAHandler(h.logger, ca)
		}
	}
}

// WithQUICVTPMService sets the vTPM service for the QUIC handler
func WithQUICVTPMService(svc vtpm.VTPMService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.vtpmService = svc
	}
}

// WithQUICDeviceService sets the Device service for the QUIC handler
func WithQUICDeviceService(svc device.DeviceService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.deviceService = svc
	}
}

// WithQUICDeviceProfileService sets the Device Profile service for the QUIC handler
func WithQUICDeviceProfileService(svc device.DeviceProfileService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.profileService = svc
	}
}

// WithQUICDNSService sets the DNS service for the QUIC handler
func WithQUICDNSService(svc DNSService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.dnsService = svc
	}
}

// WithQUICHealthRegistry sets the health registry for the QUIC handler
func WithQUICHealthRegistry(reg health.Registry) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.healthRegistry = reg
	}
}

// WithQUICAuthMiddleware sets the authentication middleware for the QUIC handler.
// When set, all requests (except health checks) will be authenticated via OIDC.
func WithQUICAuthMiddleware(m *quic.AuthMiddleware) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.authMiddleware = m
	}
}

// WithQUICSDNService sets the SDN service for the QUIC handler
func WithQUICSDNService(svc *SDNService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.sdnService = svc
	}
}

// WithQUICIAMService sets the IAM service for the QUIC handler
func WithQUICIAMService(svc QUICIAMService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.iamService = svc
	}
}

// WithQUICKMSService sets the KMS service for the QUIC handler
func WithQUICKMSService(svc KMSServiceInterface) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.kmsService = svc
	}
}

// WithQUICCryptoService sets the Crypto service for the QUIC handler
func WithQUICCryptoService(svc CryptoServiceInterface) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.cryptoService = svc
	}
}

// WithQUICTPM2Service sets the TPM2 service for the QUIC handler
func WithQUICTPM2Service(svc xkmssdk.TrustedPlatformModule) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.tpm2Service = svc
	}
}

// WithQUICContainerService sets the Container orchestrator for the QUIC handler
func WithQUICContainerService(orchestrator container.ContainerOrchestrator) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		if orchestrator != nil {
			h.containerHandler = quic.NewContainerHandler(h.logger, orchestrator)
		}
	}
}

// WithQUICAttestationService sets the Attestation service for the QUIC handler
func WithQUICAttestationService(svc quic.AttestationServiceInterface) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		if svc != nil {
			h.attestationHandler = quic.NewAttestationHandler(h.logger, svc)
		}
	}
}

// WithQUICVMService sets the VM orchestrator for the QUIC handler
func WithQUICVMService(orchestrator quic.VMOrchestrator) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		if orchestrator != nil {
			h.vmHandler = quic.NewVMHandler(h.logger, orchestrator)
		}
	}
}

// WithQUICDaemonService sets the daemon service for the QUIC handler
func WithQUICDaemonService(svc *Service) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.daemonService = svc
	}
}

// WithQUICOverlayHandler sets the overlay handler for the QUIC handler
func WithQUICOverlayHandler(handler *quic.OverlayHandler) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.overlayHandler = handler
	}
}

// WithQUICGatewayHandler sets the gateway handler for the QUIC handler
func WithQUICGatewayHandler(handler *quic.GatewayHandler) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.gatewayHandler = handler
	}
}

// NewQUICServiceHandler creates a new QUIC service handler that delegates to daemon services
func NewQUICServiceHandler(logger *logging.Logger, opts ...QUICServiceHandlerOption) *QUICServiceHandler {
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	h := &QUICServiceHandler{
		logger: logger,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// SetCAHandler sets the CA handler after construction
func (h *QUICServiceHandler) SetCAHandler(handler *quic.CAHandler) {
	h.caHandler = handler
}

// SetVTPMService sets the vTPM service after construction
func (h *QUICServiceHandler) SetVTPMService(svc vtpm.VTPMService) {
	h.vtpmService = svc
}

// SetDeviceService sets the Device service after construction
func (h *QUICServiceHandler) SetDeviceService(svc device.DeviceService) {
	h.deviceService = svc
}

// SetDNSService sets the DNS service after construction
func (h *QUICServiceHandler) SetDNSService(svc DNSService) {
	h.dnsService = svc
}

// SetSDNService sets the SDN service after construction
func (h *QUICServiceHandler) SetSDNService(svc *SDNService) {
	h.sdnService = svc
}

// SetIAMService sets the IAM service after construction
func (h *QUICServiceHandler) SetIAMService(svc QUICIAMService) {
	h.iamService = svc
}

// SetKMSService sets the KMS service after construction
func (h *QUICServiceHandler) SetKMSService(svc KMSServiceInterface) {
	h.kmsService = svc
}

// SetCryptoService sets the Crypto service after construction
func (h *QUICServiceHandler) SetCryptoService(svc CryptoServiceInterface) {
	h.cryptoService = svc
}

// SetTPM2Service sets the TPM2 service after construction
func (h *QUICServiceHandler) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	h.tpm2Service = svc
}

// SetContainerHandler sets the Container handler after construction
func (h *QUICServiceHandler) SetContainerHandler(handler *quic.ContainerHandler) {
	h.containerHandler = handler
}

// SetContainerOrchestrator sets the Container orchestrator and creates a handler
func (h *QUICServiceHandler) SetContainerOrchestrator(orchestrator container.ContainerOrchestrator) {
	if orchestrator != nil {
		h.containerHandler = quic.NewContainerHandler(h.logger, orchestrator)
	}
}

// SetAttestationHandler sets the Attestation handler after construction
func (h *QUICServiceHandler) SetAttestationHandler(handler *quic.AttestationHandler) {
	h.attestationHandler = handler
}

// SetAttestationService sets the Attestation service and creates a handler
func (h *QUICServiceHandler) SetAttestationService(svc quic.AttestationServiceInterface) {
	if svc != nil {
		h.attestationHandler = quic.NewAttestationHandler(h.logger, svc)
	}
}

// SetVMHandler sets the VM handler after construction
func (h *QUICServiceHandler) SetVMHandler(handler *quic.VMHandler) {
	h.vmHandler = handler
}

// SetVMOrchestrator sets the VM orchestrator and creates a handler
func (h *QUICServiceHandler) SetVMOrchestrator(orchestrator quic.VMOrchestrator) {
	if orchestrator != nil {
		h.vmHandler = quic.NewVMHandler(h.logger, orchestrator)
	}
}

// SetDaemonService sets the daemon service after construction
func (h *QUICServiceHandler) SetDaemonService(svc *Service) {
	h.daemonService = svc
}

// SetOverlayHandler sets the overlay handler after construction
func (h *QUICServiceHandler) SetOverlayHandler(handler *quic.OverlayHandler) {
	h.overlayHandler = handler
}

// SetGatewayHandler sets the gateway handler after construction
func (h *QUICServiceHandler) SetGatewayHandler(handler *quic.GatewayHandler) {
	h.gatewayHandler = handler
}

// errorResponse creates an error response with the given status and error
func (h *QUICServiceHandler) errorResponse(status byte, err error) *quic.Response {
	return &quic.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// HandleRequest processes a QUIC request and returns a response.
// It routes the request to the appropriate service handler based on the opcode.
func (h *QUICServiceHandler) HandleRequest(ctx context.Context, req *quic.Request) *quic.Response {
	if req == nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICNilRequest{})
	}

	// Authenticate request if auth middleware is configured
	if h.authMiddleware != nil {
		authCtx, authResp := h.authMiddleware.AuthenticateRequest(ctx, req)
		if authResp != nil {
			return authResp // Authentication failed
		}
		ctx = authCtx // Use authenticated context with token
	}

	// Route based on opcode ranges
	switch {
	// Health Operations (0x00-0x02)
	case req.Opcode >= quic.OpHealth && req.Opcode <= quic.OpReadiness:
		return h.handleHealth(ctx, req)

	// vTPM Extended Operations (0x03-0x0F) - Template and Bundle Management
	case req.Opcode >= quic.OpVTPMCreateTemplate && req.Opcode <= quic.OpVTPMIsRunning:
		return h.handleVTPMOperation(ctx, req)

	// vTPM Operations (0x10-0x1F)
	case req.Opcode >= quic.OpVTPMCreate && req.Opcode <= quic.OpVTPMGetRandom:
		return h.handleVTPM(ctx, req)

	// DNS Operations (0x20-0x2F)
	case req.Opcode >= quic.OpDNSAddRecord && req.Opcode <= quic.OpDNSFlushCache:
		return h.handleDNS(ctx, req)

	// Overlay Category Opcode (0x2E) - multiplexes overlay sub-operations
	case req.Opcode == quic.OpOverlayCategory:
		return h.handleOverlayCategory(ctx, req)

	// Gateway Category Opcode (0x2F) - multiplexes gateway sub-operations
	case req.Opcode == quic.OpGatewayCategory:
		return h.handleGatewayCategory(ctx, req)

	// Device Operations (0x30-0x3F)
	case req.Opcode >= quic.OpDeviceRegister && req.Opcode <= quic.OpDeviceGetMetrics:
		return h.handleDevice(ctx, req)

	// IPAM Category Opcode (0x3F) - multiplexes IPAM sub-operations
	case req.Opcode == quic.OpIPAMCategory:
		return h.handleIPAMCategory(ctx, req)

	// SDN Operations (0x40-0x4F) - Full range from GetPortState to GetPort
	case req.Opcode >= quic.OpSDNGetPortState && req.Opcode <= quic.OpSDNGetPort:
		return h.handleSDNOperation(ctx, req)

	// IDevID/IAK Device Identity Operations (0x56-0x5F)
	case req.Opcode >= quic.OpIDevIDGenerate && req.Opcode <= quic.OpIAKCSR:
		return h.handleIDevIDOperation(ctx, req)

	// Compute/VM Operations (0x60-0x6A)
	case req.Opcode >= quic.OpVMCreate && req.Opcode <= quic.OpVMGetState:
		return h.handleVMServiceOperation(ctx, req)

	// IAK Extended Operations (0x6B-0x6E)
	case req.Opcode >= quic.OpIAKInstallCert && req.Opcode <= quic.OpActivateCredential:
		return h.handleIDevIDOperation(ctx, req)

	// Container Get (0x6F - reused reserved code)
	case req.Opcode == quic.OpContainerGet:
		return h.handleContainerOperation(ctx, req)

	// Attestation Operations (0x70-0x77)
	case req.Opcode >= quic.OpAttestQuote && req.Opcode <= quic.OpAttestGetReportByID:
		return h.handleAttestationOperation(ctx, req)

	// IDevID Extended Operations (0x78-0x7B) - HasIDevID, HasIAK, IDevIDDeleteCert, IAKDeleteCert
	case req.Opcode >= quic.OpHasIDevID && req.Opcode <= quic.OpIAKDeleteCert:
		return h.handleIDevIDOperation(ctx, req)

	// PXE Service Control Operations (0x7C-0x7E) - Start, Stop, WebhookComplete
	case req.Opcode >= OpPXEStart && req.Opcode <= OpPXEWebhookComplete:
		return h.handlePXEOperation(ctx, req)

	// Attestation Extended Operations (0x7F)
	case req.Opcode == quic.OpAttestVMWorkload:
		return h.handleAttestationOperation(ctx, req)

	// Certificate/PKI Operations (0x80-0x88)
	case req.Opcode >= quic.OpCertIssue && req.Opcode <= quic.OpCertGetOCSP:
		return h.handleCertificate(ctx, req)

	// Daemon Management Operations (0x89-0x8F)
	case req.Opcode >= quic.OpDaemonStatus && req.Opcode <= quic.OpDaemonRestartService:
		return h.handleDaemonOperation(ctx, req)

	// Daemon ListProtocols (0x98)
	case req.Opcode == quic.OpDaemonListProtocols:
		return h.handleDaemonOperation(ctx, req)

	// CA Operations (0xA0-0xA8)
	case req.Opcode >= quic.OpCAInfo && req.Opcode <= quic.OpCABundle:
		return h.handleCA(ctx, req)

	// IAM User Operations (0xA9-0xAD)
	case req.Opcode >= quic.OpIAMUserCreate && req.Opcode <= quic.OpIAMUserUpdate:
		return h.handleIAMOperation(ctx, req)

	// Container List (0xAE) and Container Logs (0xAF)
	case req.Opcode == quic.OpContainerList || req.Opcode == quic.OpContainerLogs:
		return h.handleContainerOperation(ctx, req)

	// Attestation Policy Operations (0xAA-0xAB)
	case req.Opcode == quic.OpAttestCreatePolicy || req.Opcode == quic.OpAttestListPolicies:
		return h.handleAttestationOperation(ctx, req)

	// SDN Extended Operations (0xB0-0xB4) - CreateBridge to DeletePolicy
	case req.Opcode >= quic.OpSDNCreateBridge && req.Opcode <= quic.OpSDNDeletePolicy:
		return h.handleSDNOperation(ctx, req)

	// IAM Role Operations (0xB5-0xBA)
	case req.Opcode >= quic.OpIAMRoleCreate && req.Opcode <= quic.OpIAMRoleRevoke:
		return h.handleIAMOperation(ctx, req)

	// IAM Group Operations (0xBB-0xBF)
	case req.Opcode >= quic.OpIAMGroupCreate && req.Opcode <= quic.OpIAMGroupAddMember:
		return h.handleIAMOperation(ctx, req)

	// VM Extended Operations (0xB6-0xBE)
	case req.Opcode >= quic.OpVMRestart && req.Opcode <= quic.OpVMSnapshotList:
		return h.handleVMServiceOperation(ctx, req)

	// KMS Key Management Operations (0xC0-0xCF)
	case req.Opcode >= quic.OpKMSGenerateKey && req.Opcode <= quic.OpKMSBackendStatus:
		return h.handleKMSOperation(ctx, req)

	// KMS Crypto Operations (0xD0-0xDA) - Includes GenerateDataKey and GenerateWrappedDataKey
	case req.Opcode >= quic.OpKMSEncrypt && req.Opcode <= quic.OpKMSGenerateWrappedDataKey:
		return h.handleKMSOperation(ctx, req)

	// Tenant Operations (0xDB-0xE9)
	case quic.IsTenantOpcode(req.Opcode):
		return h.handleTenantOperation(ctx, req)

	// PXE Operations (0xEC-0xEF) - ListDevices, GetDevice, RegisterDevice, UpdateState
	case req.Opcode >= OpPXEListDevices && req.Opcode <= OpPXEUpdateState:
		return h.handlePXEOperation(ctx, req)

	// IAM Extended Operations (0xF6-0xFB) - GroupRemoveMember through TokenVerify
	case req.Opcode >= quic.OpIAMGroupRemoveMember && req.Opcode <= quic.OpIAMTokenVerify:
		return h.handleIAMOperation(ctx, req)

	// PXE Extended Operations (0xFC-0xFF) - Authorize, Quarantine, Retry, RemoveDevice
	case req.Opcode >= OpPXEAuthorize && req.Opcode <= OpPXERemoveDevice:
		return h.handlePXEOperation(ctx, req)

	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleHealth handles health-related operations
func (h *QUICServiceHandler) handleHealth(ctx context.Context, req *quic.Request) *quic.Response {
	switch req.Opcode {
	case quic.OpHealth:
		return h.handleHealthCheck(ctx, req)
	case quic.OpLiveness:
		return h.handleLiveness(ctx, req)
	case quic.OpReadiness:
		return h.handleReadiness(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDNS handles DNS-related operations
func (h *QUICServiceHandler) handleDNS(ctx context.Context, req *quic.Request) *quic.Response {
	return h.handleDNSOperation(ctx, req)
}

// handleVTPM handles vTPM-related operations
func (h *QUICServiceHandler) handleVTPM(ctx context.Context, req *quic.Request) *quic.Response {
	return h.handleVTPMOperation(ctx, req)
}

// handleDevice handles Device-related operations
func (h *QUICServiceHandler) handleDevice(ctx context.Context, req *quic.Request) *quic.Response {
	if h.deviceService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "device"})
	}
	return h.handleDeviceOperation(ctx, req)
}

// handleCertificate handles Certificate/PKI-related operations
func (h *QUICServiceHandler) handleCertificate(ctx context.Context, req *quic.Request) *quic.Response {
	if h.caHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "ca"})
	}
	return h.caHandler.HandleRequest(ctx, req)
}

// handleCA handles CA-related operations
func (h *QUICServiceHandler) handleCA(ctx context.Context, req *quic.Request) *quic.Response {
	if h.caHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "ca"})
	}
	return h.caHandler.HandleRequest(ctx, req)
}

// handleOverlayCategory handles overlay category opcode (0x2E).
// The first byte of the payload is the sub-opcode that maps to an overlay operation.
// The remaining payload bytes are the actual request payload for the sub-operation.
func (h *QUICServiceHandler) handleOverlayCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.overlayHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "overlay"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to overlay handler with the sub-opcode as the request opcode
	subReq := &quic.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	return h.overlayHandler.HandleRequest(ctx, subReq)
}

// handleGatewayCategory handles gateway category opcode (0x2F).
// The first byte of the payload is the sub-opcode that maps to a gateway operation.
// The remaining payload bytes are the actual request payload for the sub-operation.
func (h *QUICServiceHandler) handleGatewayCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.gatewayHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "gateway"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to gateway handler with the sub-opcode as the request opcode
	subReq := &quic.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	return h.gatewayHandler.HandleRequest(ctx, subReq)
}

// handleIPAMCategory handles IPAM category opcode (0x3F).
// The first byte of the payload is the sub-opcode that maps to an IPAM operation
// within the gateway handler. The remaining payload bytes are the actual request payload.
func (h *QUICServiceHandler) handleIPAMCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.gatewayHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "ipam"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to gateway handler with the sub-opcode as the request opcode
	// IPAM operations use the gateway handler's IPAM sub-opcodes
	subReq := &quic.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	return h.gatewayHandler.HandleRequest(ctx, subReq)
}

// handleHealthCheck handles the health check operation
func (h *QUICServiceHandler) handleHealthCheck(ctx context.Context, req *quic.Request) *quic.Response {
	resp := &HealthCheckResponse{
		Healthy:    true,
		Status:     "healthy",
		Components: make(map[string]string),
		Timestamp:  time.Now().Unix(),
	}

	if h.healthRegistry != nil {
		systemHealth := h.healthRegistry.Check(ctx)
		if systemHealth.Status != health.StatusHealthy {
			resp.Healthy = false
			resp.Status = "unhealthy"
		}
		// Components is a slice of ComponentHealth
		for _, component := range systemHealth.Components {
			if component.Status == health.StatusHealthy {
				resp.Components[component.Name] = "healthy"
			} else {
				resp.Components[component.Name] = "unhealthy"
			}
		}
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleLiveness handles the liveness probe operation
func (h *QUICServiceHandler) handleLiveness(ctx context.Context, req *quic.Request) *quic.Response {
	resp := &HealthCheckResponse{
		Healthy:   true,
		Status:    "alive",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleReadiness handles the readiness probe operation
func (h *QUICServiceHandler) handleReadiness(ctx context.Context, req *quic.Request) *quic.Response {
	resp := &HealthCheckResponse{
		Healthy:    true,
		Status:     "ready",
		Components: make(map[string]string),
		Timestamp:  time.Now().Unix(),
	}

	// Check if required services are available
	if h.caHandler != nil {
		resp.Components["ca"] = "ready"
	}
	if h.vtpmService != nil {
		resp.Components["vtpm"] = "ready"
	}
	if h.deviceService != nil {
		resp.Components["device"] = "ready"
	}
	if h.dnsService != nil {
		resp.Components["dns"] = "ready"
	}
	if h.sdnService != nil {
		resp.Components["sdn"] = "ready"
	}
	if h.iamService != nil {
		resp.Components["iam"] = "ready"
	}
	if h.kmsService != nil {
		resp.Components["kms"] = "ready"
	}
	if h.tpm2Service != nil {
		resp.Components["tpm2"] = "ready"
	}
	if h.containerHandler != nil {
		resp.Components["container"] = "ready"
	}
	if h.attestationHandler != nil {
		resp.Components["attestation"] = "ready"
	}
	if h.vmHandler != nil {
		resp.Components["vm"] = "ready"
	}
	if h.pxeService != nil {
		resp.Components["pxe"] = "ready"
	}
	if h.tenantManager != nil {
		resp.Components["tenant"] = "ready"
	}
	if h.overlayHandler != nil {
		resp.Components["overlay"] = "ready"
	}
	if h.gatewayHandler != nil {
		resp.Components["gateway"] = "ready"
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// HealthCheckRequest represents a health check request
type HealthCheckRequest struct {
	Component string `codec:"component"`
}

// HealthCheckResponse represents a health check response
type HealthCheckResponse struct {
	Healthy    bool              `codec:"healthy"`
	Status     string            `codec:"status"`
	Components map[string]string `codec:"components"`
	Timestamp  int64             `codec:"timestamp"`
}

// =============================================================================
// QUIC Daemon Response Types
// =============================================================================

// QUICDaemonStatusResponse is the QUIC wire format for daemon status
type QUICDaemonStatusResponse struct {
	Status    string         `codec:"status"`
	Version   string         `codec:"version"`
	BuildTime string         `codec:"build_time"`
	GitCommit string         `codec:"git_commit"`
	GoVersion string         `codec:"go_version"`
	System    QUICSystemInfo `codec:"system"`
	Timestamp int64          `codec:"timestamp"`
}

// QUICSystemInfo is the QUIC wire format for system information
type QUICSystemInfo struct {
	OS                string `codec:"os"`
	Arch              string `codec:"arch"`
	NumCPUs           int    `codec:"num_cpus"`
	TotalMemoryMB     uint64 `codec:"total_memory_mb"`
	AvailableMemoryMB uint64 `codec:"available_memory_mb"`
	Uptime            string `codec:"uptime"`
}

// QUICDaemonVersionResponse is the QUIC wire format for daemon version
type QUICDaemonVersionResponse struct {
	Version   string `codec:"version"`
	BuildTime string `codec:"build_time"`
	GitCommit string `codec:"git_commit"`
	GoVersion string `codec:"go_version"`
}

// QUICDaemonServiceInfo is the QUIC wire format for service information
type QUICDaemonServiceInfo struct {
	Name       string `codec:"name"`
	Status     string `codec:"status"`
	StartedAt  int64  `codec:"started_at"`
	Uptime     string `codec:"uptime"`
	StartCount uint64 `codec:"start_count"`
	StopCount  uint64 `codec:"stop_count"`
	LastError  string `codec:"last_error"`
}

// QUICDaemonListServicesResponse is the QUIC wire format for listing services
type QUICDaemonListServicesResponse struct {
	Services  []QUICDaemonServiceInfo `codec:"services"`
	Count     int                     `codec:"count"`
	Timestamp int64                   `codec:"timestamp"`
}

// QUICDaemonServiceRequest is the QUIC wire format for service action requests
type QUICDaemonServiceRequest struct {
	Name string `codec:"name"`
}

// QUICDaemonServiceActionResponse is the QUIC wire format for service action results
type QUICDaemonServiceActionResponse struct {
	Service string `codec:"service"`
	Action  string `codec:"action"`
	Success bool   `codec:"success"`
	Message string `codec:"message"`
}

// QUICDaemonProtocolInfo is the QUIC wire format for protocol information
type QUICDaemonProtocolInfo struct {
	Name    string `codec:"name"`
	Enabled bool   `codec:"enabled"`
	Address string `codec:"address"`
	Port    int    `codec:"port"`
	Status  string `codec:"status"`
	TLS     bool   `codec:"tls"`
}

// QUICDaemonListProtocolsResponse is the QUIC wire format for listing protocols
type QUICDaemonListProtocolsResponse struct {
	Protocols []QUICDaemonProtocolInfo `codec:"protocols"`
	Timestamp int64                    `codec:"timestamp"`
}

// =============================================================================
// Daemon Operation Handlers
// =============================================================================

// handleDaemonOperation routes daemon management operations to the appropriate handler
func (h *QUICServiceHandler) handleDaemonOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.daemonService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrServiceNotAvailable{Service: "daemon"})
	}

	switch req.Opcode {
	case quic.OpDaemonStatus:
		return h.handleDaemonStatus(ctx, req)
	case quic.OpDaemonVersion:
		return h.handleDaemonVersion(ctx, req)
	case quic.OpDaemonListServices:
		return h.handleDaemonListServices(ctx, req)
	case quic.OpDaemonGetService:
		return h.handleDaemonGetService(ctx, req)
	case quic.OpDaemonStartService:
		return h.handleDaemonStartService(ctx, req)
	case quic.OpDaemonStopService:
		return h.handleDaemonStopService(ctx, req)
	case quic.OpDaemonRestartService:
		return h.handleDaemonRestartService(ctx, req)
	case quic.OpDaemonListProtocols:
		return h.handleDaemonListProtocols(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDaemonStatus retrieves the daemon status
func (h *QUICServiceHandler) handleDaemonStatus(ctx context.Context, req *quic.Request) *quic.Response {
	statusResp, err := h.daemonService.GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStatus", Cause: err})
	}

	// Normalize system status enum to lowercase
	normalizedStatus := normalizeSystemStatusEnum(statusResp.Status.String())

	// Build system info
	var sysInfo QUICSystemInfo
	if statusResp.Info != nil && statusResp.Info.SystemInfo != nil {
		si := statusResp.Info.SystemInfo
		uptimeDuration := time.Duration(si.UptimeSeconds) * time.Second
		sysInfo = QUICSystemInfo{
			OS:                si.Os,
			Arch:              si.Arch,
			NumCPUs:           int(si.NumCpus),
			TotalMemoryMB:     si.TotalMemoryMb,
			AvailableMemoryMB: si.AvailableMemoryMb,
			Uptime:            uptimeDuration.String(),
		}
	}

	var version, buildTime, gitCommit string
	if statusResp.Info != nil {
		version = statusResp.Info.Version
		buildTime = statusResp.Info.BuildTime
		gitCommit = statusResp.Info.GitCommit
	}

	resp := &QUICDaemonStatusResponse{
		Status:    normalizedStatus,
		Version:   version,
		BuildTime: buildTime,
		GitCommit: gitCommit,
		GoVersion: runtime.Version(),
		System:    sysInfo,
		Timestamp: time.Now().Unix(),
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonVersion retrieves the daemon version
func (h *QUICServiceHandler) handleDaemonVersion(ctx context.Context, req *quic.Request) *quic.Response {
	versionResp, err := h.daemonService.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonVersion", Cause: err})
	}

	resp := &QUICDaemonVersionResponse{
		Version:   versionResp.Version,
		BuildTime: versionResp.BuildTime,
		GitCommit: versionResp.GitCommit,
		GoVersion: versionResp.GoVersion,
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonListServices lists all managed services
func (h *QUICServiceHandler) handleDaemonListServices(ctx context.Context, req *quic.Request) *quic.Response {
	listResp, err := h.daemonService.ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonListServices", Cause: err})
	}

	services := make([]QUICDaemonServiceInfo, 0, len(listResp.Services))
	for _, svc := range listResp.Services {
		info := convertServiceInfoToQUIC(svc)
		services = append(services, info)
	}

	resp := &QUICDaemonListServicesResponse{
		Services:  services,
		Count:     len(services),
		Timestamp: time.Now().Unix(),
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonGetService retrieves a single service's status
func (h *QUICServiceHandler) handleDaemonGetService(ctx context.Context, req *quic.Request) *quic.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quic.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	statusResp, err := h.daemonService.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonGetService", Cause: err})
	}

	info := convertServiceInfoToQUIC(statusResp.Service)

	payload, encErr := quic.EncodePayload(&info)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonStartService starts a managed service
func (h *QUICServiceHandler) handleDaemonStartService(ctx context.Context, req *quic.Request) *quic.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quic.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStartService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "start",
		Success: true,
		Message: "service started successfully",
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonStopService stops a managed service
func (h *QUICServiceHandler) handleDaemonStopService(ctx context.Context, req *quic.Request) *quic.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quic.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.StopService(ctx, &platformv1.StopServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStopService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "stop",
		Success: true,
		Message: "service stopped successfully",
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonRestartService restarts a managed service
func (h *QUICServiceHandler) handleDaemonRestartService(ctx context.Context, req *quic.Request) *quic.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quic.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.RestartService(ctx, &platformv1.RestartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonRestartService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "restart",
		Success: true,
		Message: "service restarted successfully",
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDaemonListProtocols lists all configured protocols
func (h *QUICServiceHandler) handleDaemonListProtocols(ctx context.Context, req *quic.Request) *quic.Response {
	config := h.daemonService.config

	var protocols []QUICDaemonProtocolInfo

	// REST
	protocols = append(protocols, buildProtocolInfo(
		"REST", config.EnableREST, config.RESTListenAddr, true))

	// gRPC TCP
	protocols = append(protocols, buildProtocolInfo(
		"gRPC", config.EnableGRPCTCP, config.GRPCListenAddr, true))

	// QUIC
	protocols = append(protocols, buildProtocolInfo(
		"QUIC", config.EnableQUIC, config.QUICListenAddr, true))

	// MCP
	mcpAddr := ""
	if config.MCPConfig != nil {
		mcpAddr = config.MCPConfig.HTTPAddr
	}
	protocols = append(protocols, buildProtocolInfo(
		"MCP", config.EnableMCP, mcpAddr, false))

	// gRPC UDS
	protocols = append(protocols, QUICDaemonProtocolInfo{
		Name:    "Unix",
		Enabled: config.EnableGRPCUDS,
		Address: config.GRPCSocketPath,
		Port:    0,
		Status:  protocolStatus(config.EnableGRPCUDS),
		TLS:     false,
	})

	resp := &QUICDaemonListProtocolsResponse{
		Protocols: protocols,
		Timestamp: time.Now().Unix(),
	}

	payload, encErr := quic.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Daemon Helper Functions
// =============================================================================

// convertServiceInfoToQUIC converts a protobuf ServiceInfo to the QUIC wire format
func convertServiceInfoToQUIC(svc *platformv1.ServiceInfo) QUICDaemonServiceInfo {
	if svc == nil {
		return QUICDaemonServiceInfo{}
	}

	normalizedStatus := normalizeServiceStatusEnum(svc.Status.String())
	uptimeDuration := time.Duration(svc.UptimeSeconds) * time.Second

	var startedAt int64
	if svc.StartedAt != nil {
		startedAt = svc.StartedAt.Seconds
	}

	var startCount, stopCount uint64
	var lastError string
	if svc.Metadata != nil {
		if v, ok := svc.Metadata["start_count"]; ok {
			startCount, _ = strconv.ParseUint(v, 10, 64)
		}
		if v, ok := svc.Metadata["stop_count"]; ok {
			stopCount, _ = strconv.ParseUint(v, 10, 64)
		}
		lastError = svc.Metadata["last_error"]
	}

	return QUICDaemonServiceInfo{
		Name:       svc.Name,
		Status:     normalizedStatus,
		StartedAt:  startedAt,
		Uptime:     uptimeDuration.String(),
		StartCount: startCount,
		StopCount:  stopCount,
		LastError:  lastError,
	}
}

// normalizeSystemStatusEnum converts a protobuf SystemStatus enum string to lowercase
func normalizeSystemStatusEnum(s string) string {
	switch s {
	case "SYSTEM_STATUS_READY":
		return "ready"
	case "SYSTEM_STATUS_INITIALIZING":
		return "initializing"
	case "SYSTEM_STATUS_DEGRADED":
		return "degraded"
	case "SYSTEM_STATUS_UNAVAILABLE":
		return "unavailable"
	case "SYSTEM_STATUS_SHUTTING_DOWN":
		return "shutting_down"
	default:
		return strings.ToLower(strings.TrimPrefix(s, "SYSTEM_STATUS_"))
	}
}

// normalizeServiceStatusEnum converts a protobuf ServiceStatus enum string to lowercase
func normalizeServiceStatusEnum(s string) string {
	switch s {
	case "SERVICE_STATUS_RUNNING":
		return "running"
	case "SERVICE_STATUS_STOPPED":
		return "stopped"
	case "SERVICE_STATUS_STARTING":
		return "starting"
	case "SERVICE_STATUS_STOPPING":
		return "stopping"
	case "SERVICE_STATUS_ERROR":
		return "error"
	default:
		return strings.ToLower(strings.TrimPrefix(s, "SERVICE_STATUS_"))
	}
}

// buildProtocolInfo creates a QUICDaemonProtocolInfo from an address string
func buildProtocolInfo(name string, enabled bool, addr string, tlsEnabled bool) QUICDaemonProtocolInfo {
	host, portStr, splitErr := net.SplitHostPort(addr)
	port := 0
	if splitErr == nil {
		port, _ = strconv.Atoi(portStr)
	} else {
		host = addr
	}

	return QUICDaemonProtocolInfo{
		Name:    name,
		Enabled: enabled,
		Address: host,
		Port:    port,
		Status:  protocolStatus(enabled),
		TLS:     tlsEnabled,
	}
}

// protocolStatus returns the status string for an enabled/disabled protocol
func protocolStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
