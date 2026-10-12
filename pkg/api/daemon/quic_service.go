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
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// QUICServiceHandler implements quic.Handler interface and delegates to daemon services.
// It provides a unified request handler that routes QUIC protocol operations to the
// appropriate service implementations (CA, vTPM, Device, DNS, SDN, KMS, TPM2, Container,
// Attestation, VM, PXE, Tenant, etc.).
type QUICServiceHandler struct {
	logger         *logging.Logger
	authMiddleware *quic.AuthMiddleware
	caHandler      *quic.CAHandler
	vtpmService    vtpm.VTPMService
	deviceService  device.DeviceService
	profileService device.DeviceProfileService
	// deviceGRPC is the shared DeviceGRPCService the device QUIC handlers
	// delegate to so the QUIC transport has identical semantics to gRPC.
	// It is (re)built by the device service setters (rebuildDeviceGRPC).
	deviceGRPC *DeviceGRPCService
	// akTrust and deviceVerdicts are the device quote verifier's
	// dependencies, threaded into deviceGRPC on every rebuild.
	akTrust        AKTrustAnchor
	deviceVerdicts verdict.Sink
	// attestCertRecorder backs the DeviceSubRecordAttestCert sub-opcode.
	attestCertRecorder AttestCertRecorder
	// bootCA backs the DeviceSubBootDelivery sub-opcode.
	bootCA BootCABundle
	// requireClientCert makes every request but the boot-certificate one need
	// a verified client certificate on its connection (the listener verifies
	// one only if given).
	requireClientCert atomic.Bool
	dnsService        DNSService
	// dnsGRPC is the shared *DNSServiceServer the SDK-mapped DNS QUIC handlers
	// delegate to so the QUIC transport has identical semantics to gRPC.
	// It is (re)built by the DNS service setters (rebuildDNSGRPC).
	dnsGRPC        *DNSServiceServer
	computeGRPC    *ComputeGRPCService
	attestGRPC     *AttestationServiceServer
	healthRegistry health.Registry
	sdnService     *SDNService
	iamService     QUICIAMService
	// iamGRPC is the shared *IAMGRPCService the converged IAM QUIC handlers
	// delegate to (pb wire), wired via SetIAMGRPCService.
	iamGRPC        *IAMGRPCService
	kmsService     KMSServiceInterface
	cryptoService  CryptoServiceInterface
	secretsService SecretsServiceInterface
	// configDeliveryService backs the OpProvisioningCategory handlers with
	// the same ConfigDeliveryGRPCService as the gRPC transport.
	configDeliveryService ConfigDeliveryQUICService
	// eabService backs the EAB sub-opcodes multiplexed under
	// OpProvisioningCategory with the same EABGRPCService as the gRPC
	// transport (see quic_eab.go).
	eabService  EABQUICService
	tpm2Service xkmssdk.TrustedPlatformModule
	// idevidService is the shared IDevIDGRPCService the QUIC LDevID handler
	// delegates to so QUIC has identical 802.1AR semantics as gRPC/Unix.
	idevidService *IDevIDGRPCService
	// tpm2Handler serves the physical-TPM category opcode
	// (quicwire.OpTPM2Category, 0x99) with sub-opcode dispatch in payload[0].
	tpm2Handler        *quic.TPM2Handler
	containerHandler   *quic.ContainerHandler
	attestationHandler *quic.AttestationHandler
	vmHandler          *quic.VMHandler
	pxeService         pxe.Service
	tenantManager      TenantManagerInterface
	// tenantGRPC is the shared *TenantGRPCServer the converged tenant QUIC
	// handlers delegate to (pb wire), wired via SetTenantGRPCServer.
	tenantGRPC     *TenantGRPCServer
	daemonService  *Service
	overlayHandler *quic.OverlayHandler
	gatewayHandler *quic.GatewayHandler

	// proxyHandler serves the reverse-proxy configuration sub-opcodes
	// (0x20-0x2D) multiplexed under the gateway category opcode (0x2F).
	proxyHandler  *quic.ProxyHandler
	switchService switchServiceProvider
	// ntpService serves the time-synchronization category opcode
	// (quicwire.OpNTPCategory, 0x50) with sub-opcode dispatch in payload[0].
	// It is the same NTPGRPCService instance the other transports use.
	ntpService platformv1.NTPServiceServer
	// Phase 3.5 handlers - wired via Set*Service on the daemon.
	ceremonyQUIC *ceremonyQUICHandlers
	pivQUIC      *pivQUICHandlers
	luksQUIC     *luksQUICHandlers
	fido2QUIC    *fido2QUICHandlers
	// bmcEnrollQUIC is wired via SetBMCEnroller for the OpBMCCategory handler.
	bmcEnrollQUIC *bmcEnrollQUICHandlers
	// bmcRestoreQUIC is wired via SetBMCRestorer for the BMCSubRestore handler.
	bmcRestoreQUIC *bmcRestoreQUICHandlers
}

// QUICServiceHandlerOption is a functional option for configuring QUICServiceHandler
type QUICServiceHandlerOption func(*QUICServiceHandler)

// WithQUICCAService sets the CA service for the QUIC handler.
// objStorage may be nil; if nil, the revocation object-store check is skipped.
func WithQUICCAService(ca quicbaasca.CACertificateAuthority) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		if ca != nil {
			h.caHandler = quic.NewCAHandler(h.logger, ca, nil)
			h.akTrust = ca
			h.rebuildDeviceGRPC()
		}
	}
}

// WithQUICDeviceVerdictSink sets the sink that receives device quote
// verdicts (attestation event log + SDN quarantine observers).
func WithQUICDeviceVerdictSink(sink verdict.Sink) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.deviceVerdicts = sink
		h.rebuildDeviceGRPC()
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
		h.rebuildDeviceGRPC()
	}
}

// WithQUICDeviceProfileService sets the Device Profile service for the QUIC handler
func WithQUICDeviceProfileService(svc device.DeviceProfileService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.profileService = svc
		h.rebuildDeviceGRPC()
	}
}

// WithQUICDNSService sets the DNS service for the QUIC handler
func WithQUICDNSService(svc DNSService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.dnsService = svc
		h.rebuildDNSGRPC()
	}
}

// WithQUICHealthRegistry sets the health registry for the QUIC handler
func WithQUICHealthRegistry(reg health.Registry) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.healthRegistry = reg
	}
}

// WithQUICAuthMiddleware sets the auth middleware that authenticates and
// authorizes every request before it is dispatched. It is mandatory:
// NewQUICServiceHandler refuses to build a handler without it.
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

// WithQUICConfigDeliveryService sets the config delivery service for the
// QUIC handler.
func WithQUICConfigDeliveryService(svc ConfigDeliveryQUICService) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.configDeliveryService = svc
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
		h.tpm2Handler.SetTPM2Service(svc)
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

// NewQUICServiceHandler creates a new QUIC service handler that delegates to
// daemon services. It returns ErrQUICAuthMiddlewareRequired unless an auth
// middleware is configured with WithQUICAuthMiddleware.
func NewQUICServiceHandler(logger *logging.Logger, opts ...QUICServiceHandlerOption) (*QUICServiceHandler, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	h := &QUICServiceHandler{
		logger:      logger,
		tpm2Handler: quic.NewTPM2Handler(logger),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.authMiddleware == nil {
		return nil, ErrQUICAuthMiddlewareRequired{}
	}
	return h, nil
}

// SetCAHandler sets the CA handler after construction
func (h *QUICServiceHandler) SetCAHandler(handler *quic.CAHandler) {
	h.caHandler = handler
}

// SetDeviceAKTrust sets the CA used to chain device attestation
// certificates after construction.
func (h *QUICServiceHandler) SetDeviceAKTrust(trust AKTrustAnchor) {
	h.akTrust = trust
	h.rebuildDeviceGRPC()
}

// SetDeviceVerdictSink sets the device quote verdict sink after
// construction.
func (h *QUICServiceHandler) SetDeviceVerdictSink(sink verdict.Sink) {
	h.deviceVerdicts = sink
	h.rebuildDeviceGRPC()
}

// SetDeviceAttestCertRecorder sets the attestation-certificate recorder
// behind DeviceSubRecordAttestCert after construction.
func (h *QUICServiceHandler) SetDeviceAttestCertRecorder(recorder AttestCertRecorder) {
	h.attestCertRecorder = recorder
	h.rebuildDeviceGRPC()
}

// SetDeviceBootCA sets the CA bundle source behind the diskless boot
// sub-opcodes (DeviceSubBootCertificate, DeviceSubBootDelivery) after
// construction.
func (h *QUICServiceHandler) SetDeviceBootCA(ca BootCABundle) {
	h.bootCA = ca
	h.rebuildDeviceGRPC()
}

// RequireClientCert makes the handler refuse every request that does not
// arrive over a connection with a verified client certificate, except the
// diskless boot-certificate request (the node has no certificate yet). The
// listener must verify a client certificate if one is given.
func (h *QUICServiceHandler) RequireClientCert() {
	h.requireClientCert.Store(true)
}

// SetVTPMService sets the vTPM service after construction
func (h *QUICServiceHandler) SetVTPMService(svc vtpm.VTPMService) {
	h.vtpmService = svc
}

// SetDeviceService sets the Device service after construction
func (h *QUICServiceHandler) SetDeviceService(svc device.DeviceService) {
	h.deviceService = svc
	h.rebuildDeviceGRPC()
}

// SetDeviceProfileService sets the Device Profile service after construction.
// Required for the QUIC profile sub-opcodes (OpDeviceGetProfile, OpDeviceListProfiles, etc.).
func (h *QUICServiceHandler) SetDeviceProfileService(svc device.DeviceProfileService) {
	h.profileService = svc
	h.rebuildDeviceGRPC()
}

// SetDNSService sets the DNS service after construction
func (h *QUICServiceHandler) SetDNSService(svc DNSService) {
	h.dnsService = svc
	h.rebuildDNSGRPC()
}

// SetComputeGRPCService sets the shared compute gRPC service the container
// QUIC handlers delegate to.
func (h *QUICServiceHandler) SetComputeGRPCService(svc *ComputeGRPCService) { h.computeGRPC = svc }

// SetAttestationGRPCService sets the shared attestation gRPC service the
// quote QUIC handlers delegate to.
func (h *QUICServiceHandler) SetAttestationGRPCService(svc *AttestationServiceServer) {
	h.attestGRPC = svc
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

// SetConfigDeliveryService sets the config delivery service after
// construction.
func (h *QUICServiceHandler) SetConfigDeliveryService(svc ConfigDeliveryQUICService) {
	h.configDeliveryService = svc
}

// SetCryptoService sets the Crypto service after construction
func (h *QUICServiceHandler) SetCryptoService(svc CryptoServiceInterface) {
	h.cryptoService = svc
}

// SetTPM2Service sets the TPM2 service after construction
func (h *QUICServiceHandler) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	h.tpm2Service = svc
	h.tpm2Handler.SetTPM2Service(svc)
}

// SetIDevIDService injects the shared IDevID gRPC service used for LDevID
// (802.1AR) issuance over QUIC.
func (h *QUICServiceHandler) SetIDevIDService(svc *IDevIDGRPCService) {
	h.idevidService = svc
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

// SetProxyHandler sets the proxy configuration handler serving the proxy
// sub-opcodes multiplexed under the gateway category opcode.
func (h *QUICServiceHandler) SetProxyHandler(handler *quic.ProxyHandler) {
	h.proxyHandler = handler
}

// errorResponse creates an error response with the given status and error
func (h *QUICServiceHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// HandleRequest processes a QUIC request and returns a response.
// It routes the request to the appropriate service handler based on the opcode.
// A deferred recover guard converts any panicking handler into a StatusInternalError
// response, ensuring the QUIC stream always receives a valid frame and the server
// goroutine is never killed by a misbehaving sub-handler.
func (h *QUICServiceHandler) HandleRequest(ctx context.Context, req *quicwire.Request) (resp *quicwire.Response) {
	defer func() {
		if r := recover(); r != nil {
			h.logger.Errorf("QUIC handler panic (opcode 0x%02x): %v\n%s",
				func() byte {
					if req != nil {
						return req.Opcode
					}
					return 0
				}(), r, debug.Stack())
			resp = h.errorResponse(quicwire.StatusInternalError, ErrQUICHandlerPanic{Cause: r})
		}
	}()

	if req == nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICNilRequest{})
	}

	if refusal := h.clientCertRefusal(ctx, req); refusal != nil {
		return refusal
	}

	// Every request is authenticated and authorized against the operation
	// catalog before dispatch. A handler not built by NewQUICServiceHandler
	// has no middleware and serves nothing.
	if h.authMiddleware == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICAuthMiddlewareRequired{})
	}
	guardCtx, guardResp := h.authMiddleware.GuardRequest(ctx, req)
	if guardResp != nil {
		return guardResp
	}
	ctx = guardCtx

	// Route based on opcode ranges
	switch {
	// Health Operations (0x00-0x02)
	case req.Opcode >= quicwire.OpHealth && req.Opcode <= quicwire.OpReadiness:
		return h.handleHealth(ctx, req)

	// vTPM Extended Operations (0x03-0x0F) - Template and Bundle Management
	case req.Opcode >= quicwire.OpVTPMCreateTemplate && req.Opcode <= quicwire.OpVTPMIsRunning:
		return h.handleVTPMOperation(ctx, req)

	// vTPM Operations (0x10-0x1F)
	case req.Opcode >= quicwire.OpVTPMCreate && req.Opcode <= quicwire.OpVTPMGetRandom:
		return h.handleVTPM(ctx, req)

	// DNS Operations (0x20-0x2F)
	case req.Opcode >= quicwire.OpDNSAddRecord && req.Opcode <= quicwire.OpDNSFlushCache:
		return h.handleDNS(ctx, req)

	// Overlay Category Opcode (0x2E) - multiplexes overlay sub-operations
	case req.Opcode == quicwire.OpOverlayCategory:
		return h.handleOverlayCategory(ctx, req)

	// Gateway Category Opcode (0x2F) - multiplexes gateway sub-operations
	case req.Opcode == quicwire.OpGatewayCategory:
		return h.handleGatewayCategory(ctx, req)

	// NTP Category Opcode (0x50) - multiplexes time-synchronization
	// sub-operations (status, sources, step) in payload[0].
	case req.Opcode == quicwire.OpNTPCategory:
		return h.handleNTPCategory(ctx, req)

	// IAM Category Opcode (0x51) - multiplexes the IAM tenant-record
	// sub-operations, kept apart from the platform tenancy opcodes.
	case req.Opcode == quicwire.OpIAMCategory:
		return h.handleIAMCategory(ctx, req)

	// Device Operations (0x30-0x3F)
	case req.Opcode >= quicwire.OpDeviceRegister && req.Opcode <= quicwire.OpDeviceGetMetrics:
		return h.handleDevice(ctx, req)

	// IPAM Category Opcode (0x3F) - multiplexes IPAM sub-operations
	case req.Opcode == quicwire.OpIPAMCategory:
		return h.handleIPAMCategory(ctx, req)

	// SDN Operations (0x40-0x4F) - Full range from GetPortState to GetPort
	case req.Opcode >= quicwire.OpSDNGetPortState && req.Opcode <= quicwire.OpSDNGetPort:
		return h.handleSDNOperation(ctx, req)

	// IDevID/IAK Device Identity Operations (0x56-0x5F)
	case req.Opcode >= quicwire.OpIDevIDGenerate && req.Opcode <= quicwire.OpIAKCSR:
		return h.handleIDevIDOperation(ctx, req)

	// Compute/VM Operations (0x60-0x6A). The compute extended category
	// opcode (0x69) inside this range carries extended VM sub-opcodes AND
	// container sub-opcodes (create/start/stop/remove/get/list/logs/attest,
	// whose direct opcodes are shadowed by the PXE ranges) in payload[0];
	// handleVMServiceOperation routes container sub-opcodes to the
	// container handler and everything else to the VM handler.
	case req.Opcode >= quicwire.OpVMCreate && req.Opcode <= quicwire.OpVMGetState:
		return h.handleVMServiceOperation(ctx, req)

	// IAK Extended Operations (0x6B-0x6E)
	case req.Opcode >= quicwire.OpIAKInstallCert && req.Opcode <= quicwire.OpActivateCredential:
		return h.handleIDevIDOperation(ctx, req)

	// Container Get (0x6F - reused reserved code)
	case req.Opcode == quicwire.OpContainerGet:
		return h.handleContainerOperation(ctx, req)

	// Attestation Operations (0x70-0x77)
	case req.Opcode >= quicwire.OpAttestQuote && req.Opcode <= quicwire.OpAttestGetReportByID:
		return h.handleAttestationOperation(ctx, req)

	// IDevID Extended Operations (0x78-0x7B) - HasIDevID, HasIAK, IDevIDDeleteCert, IAKDeleteCert
	case req.Opcode >= quicwire.OpHasIDevID && req.Opcode <= quicwire.OpIAKDeleteCert:
		return h.handleIDevIDOperation(ctx, req)

	// Attestation Manifest/Host/Workload Operations (0x7C-0x7F) -
	// BuildManifest, VerifyManifest, CollectHostAttestation, AttestVM.
	case req.Opcode >= quicwire.OpAttestBuildManifest && req.Opcode <= quicwire.OpAttestVMWorkload:
		return h.handleAttestationOperation(ctx, req)

	// Certificate/PKI Operations (0x80-0x88)
	case req.Opcode >= quicwire.OpCertIssue && req.Opcode <= quicwire.OpCertGetOCSP:
		return h.handleCertificate(ctx, req)

	// Daemon Management Operations (0x89-0x8F)
	case req.Opcode >= quicwire.OpDaemonStatus && req.Opcode <= quicwire.OpDaemonRestartService:
		return h.handleDaemonOperation(ctx, req)

	// Daemon ListProtocols (0x98)
	case req.Opcode == quicwire.OpDaemonListProtocols:
		return h.handleDaemonOperation(ctx, req)

	// Physical TPM2 Category Opcode (0x99) - multiplexes TPM2 device
	// operations (info, provision, EK/SRK/IAK, quote, PCRs, NV, ...) as
	// sub-opcodes carried in payload[0].
	case req.Opcode == quicwire.OpTPM2Category:
		return h.handleTPM2Category(ctx, req)

	// CA Operations (0xA0-0xA8)
	case req.Opcode >= quicwire.OpCAInfo && req.Opcode <= quicwire.OpCABundle:
		return h.handleCA(ctx, req)

	// IAM User Operations (0xA9-0xAD)
	case req.Opcode >= quicwire.OpIAMUserCreate && req.Opcode <= quicwire.OpIAMUserUpdate:
		return h.handleIAMOperation(ctx, req)

	// Container List (0xAE) and Container Logs (0xAF)
	case req.Opcode == quicwire.OpContainerList || req.Opcode == quicwire.OpContainerLogs:
		return h.handleContainerOperation(ctx, req)

	// SDN Extended Operations (0xB0-0xB4) - CreateBridge to DeletePolicy
	case req.Opcode >= quicwire.OpSDNCreateBridge && req.Opcode <= quicwire.OpSDNDeletePolicy:
		return h.handleSDNOperation(ctx, req)

	// IAM Role Operations (0xB5-0xBA)
	case req.Opcode >= quicwire.OpIAMRoleCreate && req.Opcode <= quicwire.OpIAMRoleRevoke:
		return h.handleIAMOperation(ctx, req)

	// IAM Group Operations (0xBB-0xBF)
	case req.Opcode >= quicwire.OpIAMGroupCreate && req.Opcode <= quicwire.OpIAMGroupAddMember:
		return h.handleIAMOperation(ctx, req)

	// Switch Management Category Opcode (0xCC)
	case req.Opcode == quicwire.OpSwitchCategory:
		return h.handleSwitchCategory(ctx, req)

	// KMS Extended Category Opcode (0xCD) - multiplexes revoke, metadata,
	// policy, and supported-algorithms sub-operations.
	case req.Opcode == quicwire.OpKMSExtendedCategory:
		return h.handleKMSExtendedCategory(ctx, req)

	// Secrets Category Opcode (0xCE) - multiplexes secrets store/get/list/
	// delete and rotation-policy sub-operations.
	case req.Opcode == quicwire.OpSecretsCategory:
		return h.handleSecretsCategory(ctx, req)

	// Provisioning Category Opcode (0xCF) - multiplexes config delivery
	// get-nonce, fetch-config, sign-digest and session sub-operations plus
	// the EAB credential sub-opcodes (0x10-0x1A, see quic_eab.go) and the
	// device profile assignment sub-opcodes (0x20-0x21, see
	// quic_device_handlers.go). EAB and device profile sub-opcodes are
	// routed first; everything else falls through to the config delivery
	// dispatcher.
	case req.Opcode == quicwire.OpProvisioningCategory:
		if resp, handled := h.handleEABCategorySub(ctx, req); handled {
			return resp
		}
		if resp, handled := h.handleDeviceProfileCategorySub(ctx, req); handled {
			return resp
		}
		return h.handleProvisioningCategory(ctx, req)

	// Phase 3.5 category opcodes (0x9A-0x9D): ceremony, piv, luks, fido2.
	case req.Opcode == quicwire.OpCeremonyCategory:
		return h.handleCeremonyCategory(ctx, req)
	case req.Opcode == quicwire.OpPIVCategory:
		return h.handlePIVCategory(ctx, req)
	case req.Opcode == quicwire.OpLUKSCategory:
		return h.handleLUKSCategory(ctx, req)
	case req.Opcode == quicwire.OpFIDO2Category:
		return h.handleFIDO2Category(ctx, req)

	// Tenant barrier category opcode (0x9E) - multiplexes per-tenant
	// barrier Init/Unseal/Seal/Status sub-operations.
	case req.Opcode == quicwire.OpTenantBarrierCategory:
		return h.handleTenantBarrierCategory(ctx, req)

	// BMC category opcode (0x9F) - multiplexes BMC enrollment sub-operations.
	case req.Opcode == quicwire.OpBMCCategory:
		return h.handleBMCCategory(ctx, req)

	// KMS Key Management Operations (0xC0-0xCB) - Includes BatchEncrypt and BatchDecrypt
	case req.Opcode >= quicwire.OpKMSGenerateKey && req.Opcode <= quicwire.OpKMSBatchDecrypt:
		return h.handleKMSOperation(ctx, req)

	// KMS Crypto Operations (0xD0-0xDA) - Includes GenerateDataKey and GenerateWrappedDataKey
	case req.Opcode >= quicwire.OpKMSEncrypt && req.Opcode <= quicwire.OpKMSGenerateWrappedDataKey:
		return h.handleKMSOperation(ctx, req)

	// Tenant Operations (0xDB-0xE9)
	case quicwire.IsTenantOpcode(req.Opcode):
		return h.handleTenantOperation(ctx, req)

	// PXE Operations (0xEC-0xEF) - ListDevices, GetDevice, RegisterDevice, UpdateState
	case req.Opcode >= OpPXEListDevices && req.Opcode <= OpPXEUpdateState:
		return h.handlePXEOperation(ctx, req)

	// IAM Extended Operations (0xF6-0xFB) - GroupRemoveMember through TokenVerify
	case req.Opcode >= quicwire.OpIAMGroupRemoveMember && req.Opcode <= quicwire.OpIAMTokenVerify:
		return h.handleIAMOperation(ctx, req)

	// PXE Extended Operations (0xFC-0xFF) - Authorize, Quarantine, Retry, RemoveDevice
	case req.Opcode >= OpPXEAuthorize && req.Opcode <= OpPXERemoveDevice:
		return h.handlePXEOperation(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleHealth handles health-related operations
func (h *QUICServiceHandler) handleHealth(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	switch req.Opcode {
	case quicwire.OpHealth:
		return h.handleHealthCheck(ctx, req)
	case quicwire.OpLiveness:
		return h.handleLiveness(ctx, req)
	case quicwire.OpReadiness:
		return h.handleReadiness(ctx, req)
	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDNS handles DNS-related operations
func (h *QUICServiceHandler) handleDNS(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	return h.handleDNSOperation(ctx, req)
}

// handleVTPM handles vTPM-related operations
func (h *QUICServiceHandler) handleVTPM(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	return h.handleVTPMOperation(ctx, req)
}

// handleDevice handles Device-related operations
func (h *QUICServiceHandler) handleDevice(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "device"})
	}
	return h.handleDeviceOperation(ctx, req)
}

// handleCertificate handles Certificate/PKI-related operations
func (h *QUICServiceHandler) handleCertificate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.caHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "ca"})
	}
	return h.caHandler.HandleRequest(ctx, req)
}

// handleCA handles CA-related operations
func (h *QUICServiceHandler) handleCA(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.caHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "ca"})
	}
	return h.caHandler.HandleRequest(ctx, req)
}

// handleCASignCSR serves quicwire.KMSSubSignCSR. The dispatcher has already
// authorized the request against the operation catalog, where the sub-opcode
// needs ca:sign-csr: a token holding only ca:write must not certify a key for
// code signing.
func (h *QUICServiceHandler) handleCASignCSR(ctx context.Context, payload []byte) *quicwire.Response {
	if h.caHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "ca"})
	}
	return h.caHandler.SignCSR(ctx, payload)
}

// handleTPM2Category handles the physical TPM2 category opcode (0x99).
// The first byte of the payload is the sub-opcode that selects the TPM2
// operation; the remaining payload bytes are the operation request payload.
func (h *QUICServiceHandler) handleTPM2Category(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	// LDevID (802.1AR) issuance is CA-backed and lives in the shared
	// IDevIDGRPCService, not the physical-TPM handler. Intercept the LDevID
	// sub-opcode and delegate so QUIC matches gRPC/Unix/embedded semantics.
	if h.idevidService != nil && len(req.Payload) > 0 && req.Payload[0] == quicwire.SubOpTPM2LDevIDCSR {
		return h.handleLDevIDCreate(ctx, req.Payload[1:])
	}
	return h.tpm2Handler.HandleMessage(ctx, req)
}

// handleOverlayCategory handles overlay category opcode (0x2E).
// The first byte of the payload is the sub-opcode that maps to an overlay operation.
// The remaining payload bytes are the actual request payload for the sub-operation.
func (h *QUICServiceHandler) handleOverlayCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "overlay"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to overlay handler with the sub-opcode as the request opcode
	subReq := &quicwire.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	return h.overlayHandler.HandleRequest(ctx, subReq)
}

// handleGatewayCategory handles gateway category opcode (0x2F).
// The first byte of the payload is the sub-opcode that maps to a gateway operation.
// The remaining payload bytes are the actual request payload for the sub-operation.
func (h *QUICServiceHandler) handleGatewayCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if len(req.Payload) == 0 {
		// Preserve the unwired-category contract: a daemon without a
		// gateway handler reports Unavailable even for malformed
		// requests (see TestQUICDispatchWireOwnership).
		if h.gatewayHandler == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "gateway"})
		}
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to the sub-handler with the sub-opcode as the request opcode
	subReq := &quicwire.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	// Proxy configuration sub-opcodes (0x20-0x2D) multiplex under the
	// gateway category and route to the proxy handler; everything else
	// falls through to the gateway handler.
	if quic.IsProxySubOpcode(subOpcode) {
		if h.proxyHandler == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "proxy"})
		}
		return h.proxyHandler.HandleRequest(ctx, subReq)
	}

	if h.gatewayHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "gateway"})
	}

	return h.gatewayHandler.HandleRequest(ctx, subReq)
}

// handleIPAMCategory handles IPAM category opcode (0x3F).
// The first byte of the payload is the sub-opcode that maps to an IPAM operation
// within the gateway handler. The remaining payload bytes are the actual request payload.
func (h *QUICServiceHandler) handleIPAMCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "ipam"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	// Extract sub-opcode from the first byte of the payload
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	// Forward to gateway handler with the sub-opcode as the request opcode
	// IPAM operations use the gateway handler's IPAM sub-opcodes
	subReq := &quicwire.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	return h.gatewayHandler.HandleRequest(ctx, subReq)
}

// handleHealthCheck handles the health check operation
func (h *QUICServiceHandler) handleHealthCheck(ctx context.Context, req *quicwire.Request) *quicwire.Response {
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleLiveness handles the liveness probe operation
func (h *QUICServiceHandler) handleLiveness(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	resp := &HealthCheckResponse{
		Healthy:   true,
		Status:    "alive",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleReadiness handles the readiness probe operation
func (h *QUICServiceHandler) handleReadiness(ctx context.Context, req *quicwire.Request) *quicwire.Response {
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
	if h.tenantGRPC != nil {
		resp.Components["tenant"] = "ready"
	}
	if h.overlayHandler != nil {
		resp.Components["overlay"] = "ready"
	}
	if h.gatewayHandler != nil {
		resp.Components["gateway"] = "ready"
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
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
func (h *QUICServiceHandler) handleDaemonOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.daemonService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "daemon"})
	}

	switch req.Opcode {
	case quicwire.OpDaemonStatus:
		return h.handleDaemonStatus(ctx, req)
	case quicwire.OpDaemonVersion:
		return h.handleDaemonVersion(ctx, req)
	case quicwire.OpDaemonListServices:
		return h.handleDaemonListServices(ctx, req)
	case quicwire.OpDaemonGetService:
		return h.handleDaemonGetService(ctx, req)
	case quicwire.OpDaemonStartService:
		return h.handleDaemonStartService(ctx, req)
	case quicwire.OpDaemonStopService:
		return h.handleDaemonStopService(ctx, req)
	case quicwire.OpDaemonRestartService:
		return h.handleDaemonRestartService(ctx, req)
	case quicwire.OpDaemonListProtocols:
		return h.handleDaemonListProtocols(ctx, req)
	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDaemonStatus retrieves the daemon status
func (h *QUICServiceHandler) handleDaemonStatus(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	statusResp, err := h.daemonService.GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStatus", Cause: err})
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

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonVersion retrieves the daemon version
func (h *QUICServiceHandler) handleDaemonVersion(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	versionResp, err := h.daemonService.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonVersion", Cause: err})
	}

	resp := &QUICDaemonVersionResponse{
		Version:   versionResp.Version,
		BuildTime: versionResp.BuildTime,
		GitCommit: versionResp.GitCommit,
		GoVersion: versionResp.GoVersion,
	}

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonListServices lists all managed services
func (h *QUICServiceHandler) handleDaemonListServices(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	listResp, err := h.daemonService.ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonListServices", Cause: err})
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

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonGetService retrieves a single service's status
func (h *QUICServiceHandler) handleDaemonGetService(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quicwire.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	statusResp, err := h.daemonService.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonGetService", Cause: err})
	}

	info := convertServiceInfoToQUIC(statusResp.Service)

	payload, encErr := quicwire.EncodePayload(&info)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonStartService starts a managed service
func (h *QUICServiceHandler) handleDaemonStartService(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quicwire.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStartService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "start",
		Success: true,
		Message: "service started successfully",
	}

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonStopService stops a managed service
func (h *QUICServiceHandler) handleDaemonStopService(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quicwire.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.StopService(ctx, &platformv1.StopServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonStopService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "stop",
		Success: true,
		Message: "service stopped successfully",
	}

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonRestartService restarts a managed service
func (h *QUICServiceHandler) handleDaemonRestartService(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var svcReq QUICDaemonServiceRequest
	if err := quicwire.DecodePayload(req.Payload, &svcReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if svcReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "name"})
	}

	svcType := serviceTypeFromName(svcReq.Name)
	_, err := h.daemonService.RestartService(ctx, &platformv1.RestartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DaemonRestartService", Cause: err})
	}

	resp := &QUICDaemonServiceActionResponse{
		Service: svcReq.Name,
		Action:  "restart",
		Success: true,
		Message: "service restarted successfully",
	}

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDaemonListProtocols lists all configured protocols
func (h *QUICServiceHandler) handleDaemonListProtocols(ctx context.Context, req *quicwire.Request) *quicwire.Response {
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
		"MCP", config.EnableMCP, mcpAddr, config.MCPServesHTTP()))

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

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
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

// handleCeremonyCategory handles the Phase 3.5 ceremony category opcode.
// The first byte of the payload is the sub-opcode.
func (h *QUICServiceHandler) handleCeremonyCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.ceremonyQUIC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "ceremony"})
	}
	return h.ceremonyQUIC.Handle(ctx, req)
}

// handlePIVCategory handles the Phase 3.5 PIV category opcode.
func (h *QUICServiceHandler) handlePIVCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.pivQUIC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "piv"})
	}
	return h.pivQUIC.Handle(ctx, req)
}

// handleLUKSCategory handles the Phase 3.5 LUKS category opcode.
func (h *QUICServiceHandler) handleLUKSCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.luksQUIC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "luks"})
	}
	return h.luksQUIC.Handle(ctx, req)
}

// handleFIDO2Category handles the Phase 3.5 FIDO2 category opcode.
func (h *QUICServiceHandler) handleFIDO2Category(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.fido2QUIC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "fido2"})
	}
	return h.fido2QUIC.Handle(ctx, req)
}

// SetCeremonyService wires the ceremony service into the QUIC handler.
// Passing nil is a no-op.
func (h *QUICServiceHandler) SetCeremonyService(svc *CeremonyService) {
	if svc == nil {
		return
	}
	h.ceremonyQUIC = &ceremonyQUICHandlers{service: svc}
}

// SetPIVService wires the PIV service into the QUIC handler.
func (h *QUICServiceHandler) SetPIVService(svc *PIVService) {
	if svc == nil {
		return
	}
	h.pivQUIC = &pivQUICHandlers{service: svc}
}

// SetLUKSService wires the LUKS service into the QUIC handler.
func (h *QUICServiceHandler) SetLUKSService(svc *LUKSService) {
	if svc == nil {
		return
	}
	h.luksQUIC = &luksQUICHandlers{service: svc}
}

// SetFIDO2Service wires the FIDO2 service into the QUIC handler.
func (h *QUICServiceHandler) SetFIDO2Service(svc *FIDO2Service) {
	if svc == nil {
		return
	}
	h.fido2QUIC = &fido2QUICHandlers{service: svc}
}
