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
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmpcr"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmsrk"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	computecontainer "github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// MCPServiceProviderConfig holds configuration for MCPServiceProvider.
type MCPServiceProviderConfig struct {
	CAService            *CAGRPCService
	VTPMService          vtpm.VTPMService
	DeviceService        device.DeviceService
	DeviceProfileService device.DeviceProfileService
	// DeviceTemplateService backs device_template_create and
	// profile_create_from_template; nil answers that no template service
	// is configured.
	DeviceTemplateService device.DeviceTemplateService
	// VerdictSink receives device quote verdicts (event log + quarantine
	// observers); nil means verdicts are only logged.
	VerdictSink verdict.Sink
	// AttestCertRecorder backs device_record_attest_cert; nil means the
	// tool answers that no certificate authority is configured.
	AttestCertRecorder AttestCertRecorder
	// DeviceLifecycle backs device_disable and device_enable; nil means
	// the tools answer that no SDN policy engine enforces them.
	DeviceLifecycle DeviceLifecycle
	// AttestationReporting carries the reporting service's report view,
	// refresh trigger and caller policy for the MCP report tools (#226).
	AttestationReporting *ReportingHandles
	// AttestationServer serves the device verdict feed for
	// attestation_device_verdicts_poll (#709); nil answers that no feed is
	// configured.
	AttestationServer     *AttestationServiceServer
	DNSService            dns.DNSService
	SDNService            *SDNService
	HealthService         *Service
	IAMClient             quicbaassdk.IAMClient
	PEPClient             quicbaassdk.IAMPEPClient
	IAMTokens             *IAMTokenService // iam_*_token tools; nil refuses verification
	KMSService            baasservice.KMSService
	CryptoService         baasservice.CryptoService
	SecretsService        baasservice.SecretsService
	TPM2Service           xkmssdk.TrustedPlatformModule
	Logger                *slog.Logger
	ComputeOrchestrator   compute.Orchestrator
	BMCService            BMCServicer
	ClusterService        ClusterServicer
	RegistryService       grpcapi.RegistryService
	InvitationService     platformservice.InvitationServicer
	EABService            EABServicer
	EABDelivery           EABDeliveryServicer
	BMCEnroller           BMCEnroller
	ZoneService           gateway.ZoneService
	IPAMService           ipam.Allocator
	ConfigDeliveryService *configdelivery.Service
	// ProxyService is the shared reverse-proxy configuration service that
	// backs the proxy_* MCP tools (same instance as gRPC/REST/QUIC).
	ProxyService *grpcapi.ProxyGRPCService

	// GatewayLB serves gateway load balancer VIP tools (gateway_lb_*).
	GatewayLB GatewayLoadBalancerInterface

	// GatewaySnapshots serves the gateway telemetry snapshot tools
	// (gateway_snapshot, gateway_snapshots); nil answers that no gateway
	// snapshot surface is configured on this node.
	GatewaySnapshots GatewaySnapshotReader
	// GatewayStatus serves the gateway_status and gateway_mode_set tools;
	// nil answers that the gateway service is not available.
	GatewayStatus GatewayStatusController
	// GatewayBGP serves the gateway_bgp_* tools; nil answers that the
	// gateway service is not available.
	GatewayBGP GatewayBGPController
	// Overlay serves the overlay_* tools from the overlay controller the
	// gRPC, REST and QUIC overlay services use; nil answers that the
	// overlay service is not available.
	Overlay OverlayControllerInterface

	// GatewayPerf serves gateway performance verification tools
	// (gateway_perf_*).
	GatewayPerf GatewayPerfInterface
}

// MCPServiceProvider implements mcp.ServiceProvider by bridging to daemon services.
// This provides MCP tools with access to the platform's service layer.
type MCPServiceProvider struct {
	caService             *CAGRPCService
	vtpmService           vtpm.VTPMService
	deviceService         device.DeviceService
	deviceProfileService  device.DeviceProfileService
	deviceTemplateService device.DeviceTemplateService
	deviceVerdicts        verdict.Sink
	attestCertRecorder    AttestCertRecorder
	lifecycle             DeviceLifecycle
	attestationReporting  *ReportingHandles
	attestationServer     *AttestationServiceServer
	dnsService            dns.DNSService
	sdnService            *SDNService
	healthService         *Service
	iam                   *IAMGRPCService // the iam_* tools answer what its gRPC methods answer
	iamTokens             *IAMTokenService
	kmsService            baasservice.KMSService
	cryptoService         baasservice.CryptoService
	secretsService        baasservice.SecretsService
	tpm2Service           xkmssdk.TrustedPlatformModule
	computeOrchestrator   compute.Orchestrator
	bmcService            BMCServicer
	clusterService        ClusterServicer
	registryService       grpcapi.RegistryService
	invitationService     platformservice.InvitationServicer
	eabService            EABServicer
	eabDelivery           EABDeliveryServicer
	bmcEnroller           BMCEnroller
	bmcRestorer           BMCRestorer
	phase35               phase35State
	zoneService           gateway.ZoneService
	configDeliveryService *configdelivery.Service
	proxyService          *grpcapi.ProxyGRPCService
	gatewayLB             GatewayLoadBalancerInterface
	gatewayNAT64          GatewayNAT64Interface
	gatewayPerf           GatewayPerfInterface
	// gatewaySnapshotTools serves the telemetry snapshot tools.
	gatewaySnapshotTools
	// gatewayStatusTools serves the gateway status and mode tools (#65).
	gatewayStatusTools
	// gatewayBGPTools serves the gateway BGP tools (#65).
	gatewayBGPTools
	// gatewayIPAMTools serves the gateway IPAM tools.
	gatewayIPAMTools
	// overlayTools serves the overlay_* tools (#709).
	overlayTools
	ntpService    platformv1.NTPServiceServer
	vpnService    platformv1.VPNServiceServer
	logger        *slog.Logger
	idevidService *IDevIDGRPCService
	// appServices serves the cache_*, scheduler_* and messaging_* tools.
	appServices mcp.AppServiceServers
}

// NewMCPServiceProvider creates a new MCPServiceProvider.
func NewMCPServiceProvider(config *MCPServiceProviderConfig) *MCPServiceProvider {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &MCPServiceProvider{
		caService:             config.CAService,
		vtpmService:           config.VTPMService,
		deviceService:         config.DeviceService,
		deviceProfileService:  config.DeviceProfileService,
		deviceTemplateService: config.DeviceTemplateService,
		deviceVerdicts:        config.VerdictSink,
		attestCertRecorder:    config.AttestCertRecorder,
		lifecycle:             config.DeviceLifecycle,
		attestationReporting:  config.AttestationReporting,
		attestationServer:     config.AttestationServer,
		dnsService:            config.DNSService,
		sdnService:            config.SDNService,
		healthService:         config.HealthService,
		iam:                   NewIAMGRPCService(logger, config.IAMClient, config.PEPClient),
		iamTokens:             config.IAMTokens,
		kmsService:            config.KMSService,
		cryptoService:         config.CryptoService,
		secretsService:        config.SecretsService,
		tpm2Service:           config.TPM2Service,
		computeOrchestrator:   config.ComputeOrchestrator,
		bmcService:            config.BMCService,
		bmcEnroller:           config.BMCEnroller,
		clusterService:        config.ClusterService,
		registryService:       config.RegistryService,
		invitationService:     config.InvitationService,
		eabService:            config.EABService,
		eabDelivery:           config.EABDelivery,
		zoneService:           config.ZoneService,
		gatewayIPAMTools:      gatewayIPAMTools{ipam: config.IPAMService},
		configDeliveryService: config.ConfigDeliveryService,
		proxyService:          config.ProxyService,
		gatewayLB:             config.GatewayLB,
		gatewayPerf:           config.GatewayPerf,
		gatewaySnapshotTools:  gatewaySnapshotTools{reader: config.GatewaySnapshots},
		gatewayStatusTools:    gatewayStatusTools{controller: config.GatewayStatus},
		gatewayBGPTools:       gatewayBGPTools{controller: config.GatewayBGP},
		overlayTools:          overlayTools{ctrl: config.Overlay},
		logger:                logger,
	}
}

// Compile-time interface compliance check
var _ mcp.ServiceProvider = (*MCPServiceProvider)(nil)

// SetTPM2Service sets the TPM2 service after construction.
// This allows dynamic injection of the TPM2 service.
func (p *MCPServiceProvider) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	p.tpm2Service = svc
}

// SetIDevIDService injects the shared IDevID gRPC service used for LDevID
// (802.1AR) issuance over MCP.
func (p *MCPServiceProvider) SetIDevIDService(svc *IDevIDGRPCService) {
	p.idevidService = svc
}

// =============================================================================
// vTPM Operations
// =============================================================================

// VTPMCreate creates a new vTPM bundle.
func (p *MCPServiceProvider) VTPMCreate(ctx context.Context, name string, algorithm string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	opts := &vtpm.CreateBundleOptions{
		Hostname:    name,
		EKAlgorithm: ekAlg,
		Mode:        vtpm.BundleModePreAssigned,
	}

	bundle, err := p.vtpmService.CreateBundle(ctx, opts)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// VTPMDelete deletes a vTPM bundle.
func (p *MCPServiceProvider) VTPMDelete(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.DeleteBundle(ctx, name)
}

// VTPMList lists all vTPM bundles.
func (p *MCPServiceProvider) VTPMList(ctx context.Context) ([]interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}

	bundles, err := p.vtpmService.ListBundles(ctx, nil)
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, len(bundles))
	for i, b := range bundles {
		result[i] = b
	}
	return result, nil
}

// VTPMStart starts a vTPM instance.
func (p *MCPServiceProvider) VTPMStart(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return err
	}
	return p.vtpmService.Start(ctx, name)
}

// VTPMStop stops a vTPM instance.
func (p *MCPServiceProvider) VTPMStop(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return err
	}
	return p.vtpmService.Stop(ctx, name)
}

// VTPMQuote generates a TPM quote.
func (p *MCPServiceProvider) VTPMQuote(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return nil, err
	}
	return p.vtpmService.Quote(ctx, name, nonce, pcrs)
}

// VTPMSeal seals data to a vTPM.
func (p *MCPServiceProvider) VTPMSeal(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return nil, err
	}
	opts := &vtpm.SealOptions{PCRs: pcrs}
	return p.vtpmService.Seal(ctx, name, data, opts)
}

// VTPMUnseal unseals data from a vTPM.
func (p *MCPServiceProvider) VTPMUnseal(ctx context.Context, name string, sealed []byte) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return nil, err
	}
	return p.vtpmService.Unseal(ctx, name, sealed, "")
}

// VTPMExtendPCR extends a PCR value.
func (p *MCPServiceProvider) VTPMExtendPCR(ctx context.Context, name string, pcr int, data []byte) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return err
	}
	return p.vtpmService.ExtendPCR(ctx, name, pcr, data)
}

// VTPMReadPCR reads a PCR value.
func (p *MCPServiceProvider) VTPMReadPCR(ctx context.Context, name string, pcr int) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if _, err := p.vtpmService.GetBundle(ctx, name); err != nil {
		return nil, err
	}
	return p.vtpmService.ReadPCR(ctx, name, pcr)
}

// VTPMGet retrieves a vTPM bundle by name.
func (p *MCPServiceProvider) VTPMGet(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	bundle, err := p.vtpmService.GetBundle(ctx, name)
	if err != nil {
		return nil, mapVTPMError(err)
	}
	return bundle, nil
}

// VTPMValidate validates bundle integrity. It answers as gRPC ValidateBundle
// does: any validation error, including an absent bundle, is valid=false with
// the error listed.
func (p *MCPServiceProvider) VTPMValidate(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	if err := p.vtpmService.ValidateBundle(ctx, name); err != nil {
		return map[string]interface{}{
			"id":     name,
			"valid":  false,
			"errors": []string{err.Error()},
		}, nil
	}
	return map[string]interface{}{
		"id":    name,
		"valid": true,
	}, nil
}

// VTPMExport exports a bundle to a base64-encoded archive.
func (p *MCPServiceProvider) VTPMExport(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	var buf bytes.Buffer
	if err := p.vtpmService.ExportBundle(ctx, name, &buf); err != nil {
		return nil, mapVTPMError(err)
	}
	data := buf.Bytes()
	checksum := sha256.Sum256(data)
	return map[string]interface{}{
		"id":       name,
		"data":     base64.StdEncoding.EncodeToString(data),
		"size":     int64(len(data)),
		"checksum": hex.EncodeToString(checksum[:]),
	}, nil
}

// VTPMImport imports a bundle from raw archive data.
func (p *MCPServiceProvider) VTPMImport(ctx context.Context, data []byte) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	bundle, err := p.vtpmService.ImportBundle(ctx, bytes.NewReader(data))
	if err != nil {
		return nil, mapVTPMError(err)
	}
	return bundle, nil
}

// VTPMCreateTemplate creates a new vTPM template.
func (p *MCPServiceProvider) VTPMCreateTemplate(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	ekAlg, err := vtpm.ParseEKAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	opts := &vtpm.CreateTemplateOptions{
		ID:                id,
		Description:       description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: secureBoot,
	}
	template, err := p.vtpmService.CreateTemplate(ctx, opts)
	if err != nil {
		return nil, mapVTPMError(err)
	}
	return template, nil
}

// VTPMGetTemplate retrieves a template by ID.
func (p *MCPServiceProvider) VTPMGetTemplate(ctx context.Context, id string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if id == "" {
		return nil, ErrVTPMIDRequired{Field: "template id"}
	}
	template, err := p.vtpmService.GetTemplate(ctx, id)
	if err != nil {
		return nil, mapVTPMError(err)
	}
	return template, nil
}

// VTPMDeleteTemplate deletes a template.
func (p *MCPServiceProvider) VTPMDeleteTemplate(ctx context.Context, id string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	if id == "" {
		return ErrVTPMIDRequired{Field: "template id"}
	}
	return mapVTPMError(p.vtpmService.DeleteTemplate(ctx, id))
}

// VTPMListTemplates lists all templates.
func (p *MCPServiceProvider) VTPMListTemplates(ctx context.Context) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	templates, err := p.vtpmService.ListTemplates(ctx)
	if err != nil {
		return nil, mapVTPMError(err)
	}
	result := make([]interface{}, len(templates))
	for i, t := range templates {
		result[i] = t
	}
	return map[string]interface{}{
		"templates": result,
		"total":     len(templates),
	}, nil
}

// VTPMCloneTemplate clones a template to create a new bundle with identity.
func (p *MCPServiceProvider) VTPMCloneTemplate(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	opts := &vtpm.CloneOptions{
		TemplateID: templateID,
		Hostname:   hostname,
		Labels:     labels,
	}
	bundle, err := p.vtpmService.CloneTemplate(ctx, opts)
	if err != nil {
		return nil, mapVTPMError(err)
	}
	return bundle, nil
}

// VTPMGetBundlePath returns the filesystem path to a bundle.
func (p *MCPServiceProvider) VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	path := p.vtpmService.GetBundlePath(name)
	return map[string]interface{}{
		"id":   name,
		"path": path,
	}, nil
}

// VTPMGetTPMSocketPath returns the TPM socket path for a bundle.
func (p *MCPServiceProvider) VTPMGetTPMSocketPath(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	path := p.vtpmService.GetTPMSocketPath(name)
	return map[string]interface{}{
		"id":   name,
		"path": path,
	}, nil
}

// VTPMGetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (p *MCPServiceProvider) VTPMGetNVRAMPath(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle id"}
	}
	path := p.vtpmService.GetNVRAMPath(name)
	return map[string]interface{}{
		"id":   name,
		"path": path,
	}, nil
}

// VTPMIsRunning checks if a vTPM bundle is running.
func (p *MCPServiceProvider) VTPMIsRunning(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	if name == "" {
		return nil, ErrVTPMIDRequired{Field: "bundle_id"}
	}
	running := p.vtpmService.IsRunning(name)
	return map[string]interface{}{
		"bundle_id": name,
		"running":   running,
	}, nil
}

// =============================================================================
// DNS Operations
// =============================================================================

// DNSAddRecord adds a DNS record to a zone.
func (p *MCPServiceProvider) DNSAddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	if p.dnsService == nil {
		return ErrDNSServiceNotAvailable{}
	}

	if name == "" {
		return ErrDNSInvalidParameter{Parameter: "name", Reason: "record name is required"}
	}
	if recordType == "" {
		return ErrDNSInvalidParameter{Parameter: "recordType", Reason: "record type is required"}
	}
	if value == "" {
		return ErrDNSInvalidParameter{Parameter: "value", Reason: "record value is required"}
	}
	if ttl < 0 {
		return ErrDNSInvalidParameter{Parameter: "ttl", Reason: "TTL cannot be negative"}
	}

	// Default TTL if not specified
	if ttl == 0 {
		ttl = 3600
	}

	return p.dnsService.AddRecord(ctx, name, recordType, value, ttl)
}

// DNSDeleteRecord deletes a DNS record from a zone.
func (p *MCPServiceProvider) DNSDeleteRecord(ctx context.Context, name string, recordType string) error {
	if p.dnsService == nil {
		return ErrDNSServiceNotAvailable{}
	}

	if name == "" {
		return ErrDNSInvalidParameter{Parameter: "name", Reason: "record name is required"}
	}
	if recordType == "" {
		return ErrDNSInvalidParameter{Parameter: "recordType", Reason: "record type is required"}
	}

	return p.dnsService.DeleteRecord(ctx, name, recordType)
}

// DNSGetRecord retrieves a DNS record by name and type.
func (p *MCPServiceProvider) DNSGetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	if p.dnsService == nil {
		return nil, ErrDNSServiceNotAvailable{}
	}

	if name == "" {
		return nil, ErrDNSInvalidParameter{Parameter: "name", Reason: "record name is required"}
	}
	if recordType == "" {
		return nil, ErrDNSInvalidParameter{Parameter: "recordType", Reason: "record type is required"}
	}

	return p.dnsService.GetRecord(ctx, name, recordType)
}

// DNSListRecords lists all DNS records in a zone.
func (p *MCPServiceProvider) DNSListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	if p.dnsService == nil {
		return nil, ErrDNSServiceNotAvailable{}
	}

	if zone == "" {
		return nil, ErrDNSInvalidParameter{Parameter: "zone", Reason: "zone name is required"}
	}

	return p.dnsService.ListRecords(ctx, zone)
}

// DNSResolve resolves a DNS name to its values.
func (p *MCPServiceProvider) DNSResolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if p.dnsService == nil {
		return nil, ErrDNSServiceNotAvailable{}
	}

	if name == "" {
		return nil, ErrDNSInvalidParameter{Parameter: "name", Reason: "DNS name is required"}
	}
	if recordType == "" {
		return nil, ErrDNSInvalidParameter{Parameter: "recordType", Reason: "record type is required"}
	}

	return p.dnsService.Resolve(ctx, name, recordType)
}

// DNSCreateZone creates a new DNS zone.
func (p *MCPServiceProvider) DNSCreateZone(ctx context.Context, zone string) error {
	if p.dnsService == nil {
		return ErrDNSServiceNotAvailable{}
	}

	if zone == "" {
		return ErrDNSInvalidParameter{Parameter: "zone", Reason: "zone name is required"}
	}

	return p.dnsService.CreateZone(ctx, zone)
}

// DNSDeleteZone deletes a DNS zone.
func (p *MCPServiceProvider) DNSDeleteZone(ctx context.Context, zone string) error {
	if p.dnsService == nil {
		return ErrDNSServiceNotAvailable{}
	}

	if zone == "" {
		return ErrDNSInvalidParameter{Parameter: "zone", Reason: "zone name is required"}
	}

	return p.dnsService.DeleteZone(ctx, zone)
}

// DNSListZones lists all DNS zones.
func (p *MCPServiceProvider) DNSListZones(ctx context.Context) ([]string, error) {
	if p.dnsService == nil {
		return nil, ErrDNSServiceNotAvailable{}
	}

	zones, err := p.dnsService.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	// Convert zone entities to zone names
	zoneNames := make([]string, len(zones))
	for i, z := range zones {
		zoneNames[i] = z.Name
	}

	return zoneNames, nil
}

// =============================================================================
// Device Operations
// =============================================================================

// DeviceRegister registers a new device.
func (p *MCPServiceProvider) DeviceRegister(ctx context.Context, req *mcp.DeviceRegisterRequest) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	return registerMCPDevice(ctx, p.deviceService, req)
}

// DeviceFindBySerial returns the device registered under the serial number.
func (p *MCPServiceProvider) DeviceFindBySerial(ctx context.Context, serial string) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	return p.deviceService.FindBySerial(ctx, serial)
}

// registerMCPDevice stores the device described by a device_register request
// and returns it with its server-assigned id. Both MCP service providers
// register through it so the argument-to-field mapping lives in one place.
func registerMCPDevice(ctx context.Context, svc device.DeviceService, req *mcp.DeviceRegisterRequest) (*deviceentities.Device, error) {
	if req == nil || req.Serial == "" {
		return nil, ErrMissingRequiredField{Field: "serial"}
	}
	dev := &deviceentities.Device{
		Serial:     req.Serial,
		Model:      req.Model,
		EKCert:     req.EKCert,
		AttestPub:  req.AttestPub,
		AttestCert: req.AttestCert,
		SigningPub: req.SigningPub,
		HashAlgoId: req.HashAlgoID,
	}
	if err := svc.Create(ctx, dev); err != nil {
		return nil, err
	}
	return dev, nil
}

// DeviceGet retrieves a device by ID.
func (p *MCPServiceProvider) DeviceGet(ctx context.Context, deviceID string) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceIDFromString(deviceID)
	if err != nil {
		return nil, err
	}
	return p.deviceService.Get(ctx, id)
}

// DeviceList lists devices with optional filter.
func (p *MCPServiceProvider) DeviceList(ctx context.Context, filter map[string]string) ([]interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}

	query := datastore.PageQuery{
		PageSize:  100,
		SortOrder: datastore.SortAscending,
	}
	result, err := p.deviceService.Page(ctx, query)
	if err != nil {
		return nil, err
	}

	devices := make([]interface{}, len(result.Entities))
	for i, d := range result.Entities {
		devices[i] = d
	}
	return devices, nil
}

// DeviceDelete deletes a device.
func (p *MCPServiceProvider) DeviceDelete(ctx context.Context, deviceID string) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceIDFromString(deviceID)
	if err != nil {
		return err
	}
	dev, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return err
	}
	return p.deviceService.Delete(ctx, dev)
}

// DeviceUpdate updates a device.
func (p *MCPServiceProvider) DeviceUpdate(ctx context.Context, deviceID string, updates map[string]interface{}) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceIDFromString(deviceID)
	if err != nil {
		return err
	}
	dev, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return err
	}
	if model, ok := updates["model"].(string); ok {
		dev.Model = model
	}
	if serial, ok := updates["serial"].(string); ok {
		dev.Serial = serial
	}
	return p.deviceService.Update(ctx, dev)
}

// DeviceAttest verifies a TPM quote submitted for a device over MCP. It
// delegates to the same DeviceQuoteVerifier as gRPC, Unix, QUIC and REST,
// so the MCP transport can neither overwrite a device's enrolled attestation
// material from caller-supplied evidence nor report a verdict the other
// transports would not reach.
func (p *MCPServiceProvider) DeviceAttest(ctx context.Context, deviceID string, evidence []byte) (interface{}, error) {
	verifier := NewDeviceQuoteVerifier(p.deviceService, p.deviceProfileService, p.akTrust(), p.deviceVerdicts, p.logger)
	result, err := verifier.Verify(ctx, deviceID, evidence)
	if err != nil {
		return nil, err
	}
	p.logger.Info("device attestation completed",
		"device_id", result.DeviceID,
		"serial", result.Serial,
		"verified", result.Verified,
		"transport", "mcp",
	)
	return result, nil
}

// DeviceRecordAttestCert records a device's attestation certificate over
// MCP through the shared recorder: the same fail-closed preflight and the
// same refusal as gRPC, Unix, QUIC and REST.
func (p *MCPServiceProvider) DeviceRecordAttestCert(ctx context.Context, deviceID string, reissue, clearOnRefusal bool) (interface{}, error) {
	return recordAttestCertForMCP(ctx, p.attestCertRecorder, deviceID, reissue, clearOnRefusal, p.logger)
}

// DeviceDisable serves the MCP device_disable tool with the gRPC answer.
func (p *MCPServiceProvider) DeviceDisable(ctx context.Context, deviceID, reason string) (interface{}, error) {
	return deviceLifecycleForMCP(ctx, p.lifecycle, deviceID, reason, false, p.logger)
}

// DeviceEnable serves the MCP device_enable tool with the gRPC answer.
func (p *MCPServiceProvider) DeviceEnable(ctx context.Context, deviceID string) (interface{}, error) {
	return deviceLifecycleForMCP(ctx, p.lifecycle, deviceID, "", true, p.logger)
}

// DeviceBootCertificate refuses a diskless node's boot-certificate request:
// MCP carries no TLS connection for the proof to be bound to.
func (p *MCPServiceProvider) DeviceBootCertificate(context.Context, string, []byte) (interface{}, error) {
	return nil, errBootOverMCP()
}

// DeviceBootDelivery refuses a diskless node's boot-delivery request: MCP
// carries no TLS connection for the evidence to be bound to.
func (p *MCPServiceProvider) DeviceBootDelivery(context.Context, []byte) (interface{}, error) {
	return nil, errBootOverMCP()
}

// akTrust returns the CA behind the MCP provider's CA service, or nil when
// none is configured (every device quote then fails closed).
func (p *MCPServiceProvider) akTrust() AKTrustAnchor {
	if p.caService == nil {
		return nil
	}
	return p.caService.TrustAnchor()
}

// DeviceProvision provisions a device with a profile.
// It finds a matching device profile and applies the provisioning configuration.
// The profile parameter can be either a profile ID (numeric) or used to find
// a matching profile based on device characteristics.
func (p *MCPServiceProvider) DeviceProvision(ctx context.Context, deviceID string, profile string) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}
	if p.deviceProfileService == nil {
		return ErrServiceNotAvailable{Service: "device_profile"}
	}

	// Validate device ID
	if deviceID == "" {
		return ErrProvisioningFailed{Reason: "device ID is required"}
	}

	// Parse the device ID
	id, err := parseDeviceIDFromString(deviceID)
	if err != nil {
		return err
	}

	// Retrieve the device to ensure it exists
	dev, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	// Find the matching profile
	var deviceProfile *deviceentities.DeviceProfile

	// First, try to parse profile as a numeric ID
	if profileID, parseErr := parseUint64(profile); parseErr == nil && profileID > 0 {
		deviceProfile, err = p.deviceProfileService.Get(ctx, profileID)
		if err != nil {
			return ErrProfileNotFound{Profile: profile}
		}
	} else {
		// Profile is not a valid numeric ID, try to find by matching rules
		// Use the device's characteristics to find a matching profile
		deviceProfile, err = p.deviceProfileService.FindMatchingProfile(ctx, "", dev.Serial, dev.Model)
		if err != nil {
			return ErrProfileNotFound{Profile: profile}
		}
	}

	// Validate the profile has provisioning configuration
	if deviceProfile.GetEnrollmentNetworkConfig() == nil && deviceProfile.GetPostEnrollmentNetworkConfig() == nil {
		return ErrProvisioningFailed{Reason: "profile has no network configuration"}
	}

	p.logger.Info("device provisioned successfully",
		"device_id", dev.ID,
		"device_serial", dev.Serial,
		"profile_id", deviceProfile.ID,
		"profile_name", deviceProfile.Name,
	)

	return nil
}

// =============================================================================
// SDN Operations
// =============================================================================

// SDNGetPortState gets the state of an SDN port.
func (p *MCPServiceProvider) SDNGetPortState(ctx context.Context, bridgeName string, portName string) (interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetPort(), nil
}

// SDNSetPortState sets a port's admin state ("up" or "down") and ingress
// policing through the shared SDNService, as gRPC SetPortState does, and
// returns the updated port.
func (p *MCPServiceProvider) SDNSetPortState(ctx context.Context, bridgeName string, portName string, state string, rates mcp.PortRates) (interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.SetPortState(ctx, &platformv1.SetPortStateRequest{
		BridgeId:     bridgeName,
		PortId:       portName,
		AdminState:   state,
		IngressRate:  rates.IngressRate,
		IngressBurst: rates.IngressBurst,
		EgressRate:   rates.EgressRate,
		EgressBurst:  rates.EgressBurst,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetPort(), nil
}

// SDNListBridges lists all SDN bridges.
func (p *MCPServiceProvider) SDNListBridges(ctx context.Context) ([]interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.ListBridges(ctx, &platformv1.ListBridgesRequest{})
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(resp.GetBridges()))
	for i, b := range resp.GetBridges() {
		result[i] = b
	}
	return result, nil
}

// SDNCreateBridge creates an SDN bridge.
func (p *MCPServiceProvider) SDNCreateBridge(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.CreateBridge(ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: bridgeName},
	})
	return err
}

// SDNDeleteBridge deletes an SDN bridge.
func (p *MCPServiceProvider) SDNDeleteBridge(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{Id: bridgeName})
	return err
}

// SDNAddPort adds a port of the given type to an SDN bridge.
func (p *MCPServiceProvider) SDNAddPort(ctx context.Context, bridgeName string, portName string, portType string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	pbType, err := portTypeFromName(portType)
	if err != nil {
		return err
	}
	_, err = p.sdnService.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeName,
		Config:   &platformv1.PortConfig{Name: portName, Type: pbType},
	})
	return err
}

// portTypeFromName parses the sdn_add_port port_type argument. It takes the
// schema's short form ("internal", "tap") or the enum name
// ("PORT_TYPE_INTERNAL"), in any case; an empty name leaves the type
// unspecified, and an unknown one is refused rather than dropped.
func portTypeFromName(name string) (platformv1.PortType, error) {
	if name == "" {
		return platformv1.PortType_PORT_TYPE_UNSPECIFIED, nil
	}
	const prefix = "PORT_TYPE_"
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, prefix) {
		upper = prefix + upper
	}
	value, ok := platformv1.PortType_value[upper]
	if !ok {
		return platformv1.PortType_PORT_TYPE_UNSPECIFIED, ErrInvalidPortType{Type: name}
	}
	return platformv1.PortType(value), nil
}

// SDNDeletePort deletes a port from an SDN bridge.
func (p *MCPServiceProvider) SDNDeletePort(ctx context.Context, bridgeName string, portName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.DeletePort(ctx, &platformv1.DeletePortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	return err
}

// SDNApplyPolicy creates or replaces a policy, given as the REST create-policy
// body, through the shared SDNService.
func (p *MCPServiceProvider) SDNApplyPolicy(ctx context.Context, policy json.RawMessage) (interface{}, error) {
	return applySDNPolicy(ctx, p.sdnService, policy)
}

// SDNGetPolicy returns a policy by ID or name from the shared SDNService.
func (p *MCPServiceProvider) SDNGetPolicy(ctx context.Context, policyID string) (interface{}, error) {
	return getSDNPolicy(ctx, p.sdnService, policyID)
}

// SDNListPolicies lists the shared SDNService's policies, optionally filtered by
// type and target.
func (p *MCPServiceProvider) SDNListPolicies(ctx context.Context, policyType string, targetID string) ([]interface{}, error) {
	return listSDNPolicies(ctx, p.sdnService, policyType, targetID)
}

// SDNDeletePolicy deletes a policy by ID or name through the shared SDNService.
func (p *MCPServiceProvider) SDNDeletePolicy(ctx context.Context, policyID string) error {
	return deleteSDNPolicy(ctx, p.sdnService, policyID)
}

// SDNAddFlow adds a flow to an SDN bridge.
func (p *MCPServiceProvider) SDNAddFlow(ctx context.Context, bridgeName string, flow map[string]interface{}) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	flowConfig := &platformv1.FlowConfig{BridgeId: bridgeName}
	_, err := p.sdnService.AddFlow(ctx, &platformv1.AddFlowRequest{Config: flowConfig})
	return err
}

// SDNDeleteFlow deletes a flow from an SDN bridge.
func (p *MCPServiceProvider) SDNDeleteFlow(ctx context.Context, bridgeName string, flowID string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{
		BridgeId: bridgeName,
		FlowId:   flowID,
	})
	return err
}

// SDNListFlows lists flows on an SDN bridge.
func (p *MCPServiceProvider) SDNListFlows(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: bridgeName})
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(resp.GetFlows()))
	for i, f := range resp.GetFlows() {
		result[i] = f
	}
	return result, nil
}

// SDNFlushFlows flushes all flows from an SDN bridge.
func (p *MCPServiceProvider) SDNFlushFlows(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.FlushFlows(ctx, &platformv1.FlushFlowsRequest{BridgeId: bridgeName})
	return err
}

// SDNCreateVLAN creates a VLAN on an SDN bridge.
func (p *MCPServiceProvider) SDNCreateVLAN(ctx context.Context, bridgeName string, vlanID int, name string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			BridgeId: bridgeName,
			VlanId:   uint32(vlanID),
			Name:     name,
		},
	})
	return err
}

// SDNDeleteVLAN deletes a VLAN from an SDN bridge.
func (p *MCPServiceProvider) SDNDeleteVLAN(ctx context.Context, bridgeName string, vlanID int) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{
		BridgeId: bridgeName,
		VlanId:   uint32(vlanID),
	})
	return err
}

// SDNListVLANs lists VLANs on an SDN bridge.
func (p *MCPServiceProvider) SDNListVLANs(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: bridgeName})
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(resp.GetVlans()))
	for i, v := range resp.GetVlans() {
		result[i] = v
	}
	return result, nil
}

// SDNAuthenticatePort authenticates a port.
func (p *MCPServiceProvider) SDNAuthenticatePort(ctx context.Context, bridgeName string, portName string, credentials map[string]string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	certificate := credentials["certificate"]
	format := credentials["format"]
	if format == "" {
		format = "PEM"
	}
	_, err := p.sdnService.AuthenticatePort(ctx, &platformv1.AuthenticatePortRequest{
		BridgeId:    bridgeName,
		PortId:      portName,
		Certificate: []byte(certificate),
		Format:      format,
	})
	return err
}

// SDNRevokePortAuth revokes port authentication.
func (p *MCPServiceProvider) SDNRevokePortAuth(ctx context.Context, bridgeName string, portName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	return err
}

// SDNGetPortStats gets port statistics.
func (p *MCPServiceProvider) SDNGetPortStats(ctx context.Context, bridgeName string, portName string) (interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.GetPortStats(ctx, &platformv1.GetPortStatsRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStats(), nil
}

// SDNGetFlowStats gets flow statistics.
func (p *MCPServiceProvider) SDNGetFlowStats(ctx context.Context, bridgeName string) (interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := p.sdnService.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: bridgeName})
	if err != nil {
		return nil, err
	}
	return resp.GetStats(), nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health returns the platform health status as an MCP-compatible map with
// lowercase string status values and Unix millisecond timestamps.
func (p *MCPServiceProvider) Health(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "health"}
	}
	resp, err := p.healthService.GetHealth(ctx, &platformv1.GetHealthRequest{})
	if err != nil {
		return nil, err
	}
	return mcpHealthResponseMap(resp), nil
}

// Liveness returns the platform liveness status.
func (p *MCPServiceProvider) Liveness(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "health"}
	}
	resp, err := p.healthService.GetHealth(ctx, &platformv1.GetHealthRequest{})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"live":   resp.GetStatus() == platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		"status": mcpHealthStatusString(resp.GetStatus()),
	}, nil
}

// Readiness returns the platform readiness status.
func (p *MCPServiceProvider) Readiness(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "health"}
	}
	resp, err := p.healthService.GetHealth(ctx, &platformv1.GetHealthRequest{})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ready":  resp.GetStatus() == platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		"status": mcpHealthStatusString(resp.GetStatus()),
	}, nil
}

// =============================================================================
// Daemon Management Operations
// =============================================================================

// DaemonStatus returns the daemon status including system info and uptime.
func (p *MCPServiceProvider) DaemonStatus(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	resp, err := p.healthService.GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return nil, err
	}
	result := mcpStatusResponseMap(resp)
	// Populate goVersion from the version response
	vResp, vErr := p.healthService.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if vErr == nil {
		result["goVersion"] = vResp.GetGoVersion()
	}
	return result, nil
}

// DaemonVersion returns the daemon version information.
func (p *MCPServiceProvider) DaemonVersion(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	resp, err := p.healthService.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return nil, err
	}
	return mcpVersionResponseMap(resp), nil
}

// DaemonListServices lists all managed services.
func (p *MCPServiceProvider) DaemonListServices(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	resp, err := p.healthService.ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	return mcpListServicesResponseMap(resp), nil
}

// DaemonGetService returns the status of a specific service.
func (p *MCPServiceProvider) DaemonGetService(ctx context.Context, name string) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	svcType := serviceTypeFromName(name)
	resp, err := p.healthService.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, err
	}
	return mcpServiceInfoMap(resp.GetService()), nil
}

// DaemonStartService starts a managed service.
func (p *MCPServiceProvider) DaemonStartService(ctx context.Context, name string) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	svcType := serviceTypeFromName(name)
	resp, err := p.healthService.StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, err
	}
	return mcpServiceActionMap(
		name, "start",
		resp.GetStatus().GetSuccess(),
		resp.GetStatus().GetMessage(),
	), nil
}

// DaemonStopService stops a managed service.
func (p *MCPServiceProvider) DaemonStopService(ctx context.Context, name string) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	svcType := serviceTypeFromName(name)
	resp, err := p.healthService.StopService(ctx, &platformv1.StopServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, err
	}
	return mcpServiceActionMap(
		name, "stop",
		resp.GetStatus().GetSuccess(),
		resp.GetStatus().GetMessage(),
	), nil
}

// DaemonRestartService restarts a managed service.
func (p *MCPServiceProvider) DaemonRestartService(ctx context.Context, name string) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	svcType := serviceTypeFromName(name)
	resp, err := p.healthService.RestartService(ctx, &platformv1.RestartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		return nil, err
	}
	return mcpServiceActionMap(
		name, "restart",
		resp.GetStatus().GetSuccess(),
		resp.GetStatus().GetMessage(),
	), nil
}

// DaemonListProtocols lists all supported protocol endpoints.
func (p *MCPServiceProvider) DaemonListProtocols(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	return mcpListProtocolsMap(p.healthService.config), nil
}

// =============================================================================
// CA Operations
// =============================================================================

// CAInfo returns CA information.
func (p *MCPServiceProvider) CAInfo(ctx context.Context) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
}

// CAIssue issues a new certificate.
func (p *MCPServiceProvider) CAIssue(ctx context.Context, req *mcp.CAIssueRequest) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}

	keyAlgorithm, err := parsePlatformKeyAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	// Convert MCP request to platformv1 request
	certRequest := &platformv1.CertificateRequest{
		Subject: &platformv1.Subject{
			CommonName:         req.CommonName,
			Organization:       req.Organization,
			OrganizationalUnit: req.OrganizationalUnit,
			Country:            req.Country,
			Province:           req.Province,
			Locality:           req.Locality,
			Address:            req.Address,
			PostalCode:         req.PostalCode,
		},
		ValidDays:    int32(req.ValidDays),
		KeyAlgorithm: keyAlgorithm,
		StoreType:    req.StoreType,
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
		IsCa:         req.IsCA,
		MaxPathLen:   int32(req.MaxPathLen),
	}

	// Add SANs if provided
	if len(req.DNSNames) > 0 || len(req.IPAddresses) > 0 || len(req.EmailAddresses) > 0 || len(req.URIs) > 0 {
		certRequest.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       req.DNSNames,
			IpAddresses:    req.IPAddresses,
			EmailAddresses: req.EmailAddresses,
			Uris:           req.URIs,
		}
	}

	caReq := &platformv1.IssueCertificateRequest{
		Request: certRequest,
	}

	return p.caService.IssueCertificate(ctx, caReq)
}

// CASignCSR certifies the KMS key a CSR names for code signing. The CA
// service authorizes the caller from the gRPC context, so the MCP caller's
// validated platform token is carried over to it; a caller without one is
// refused there.
func (p *MCPServiceProvider) CASignCSR(ctx context.Context, req *mcp.CASignCSRRequest) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	if authCtx, ok := mcp.AuthorizedContextFromContext(ctx); ok {
		ctx = grpcapi.ContextWithAuthorizedContext(ctx, authCtx)
	}
	return p.caService.SignCSR(ctx, &platformv1.SignCSRRequest{
		CsrPem:    req.CSRPEM,
		ValidDays: int32(req.ValidDays),
	})
}

// CAGet retrieves a certificate by serial number.
func (p *MCPServiceProvider) CAGet(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: includePEM,
		IncludeDer: includeDER,
	})
}

// CAList lists certificates.
func (p *MCPServiceProvider) CAList(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}

	pageSize := uint32(limit)
	if pageSize == 0 {
		pageSize = 50
	}

	return p.caService.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: pageSize,
		},
	})
}

// CARevoke revokes a certificate.
func (p *MCPServiceProvider) CARevoke(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     platformv1.RevocationReason(reason),
		DeleteKeys: deleteKeys,
	})
}

// CARenew renews a certificate.
func (p *MCPServiceProvider) CARenew(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:       serial,
		ValidDays:    int32(extendDays),
		PreserveSans: preserveAttrs,
	})
}

// CAVerify verifies a certificate.
func (p *MCPServiceProvider) CAVerify(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   []byte(certificatePEM),
		CertificateDer:   certificateDER,
		VerifyRevocation: checkRevoked,
	})
}

// CACRL returns the Certificate Revocation List.
func (p *MCPServiceProvider) CACRL(ctx context.Context) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.GetCRL(ctx, &platformv1.GetCRLRequest{})
}

// CABundle returns the CA certificate bundle.
func (p *MCPServiceProvider) CABundle(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.GetCABundle(ctx, &platformv1.GetCABundleRequest{
		IncludeIntermediates: true,
	})
}

// =============================================================================
// IAM Operations
// =============================================================================

// The iam_* tools below answer through p.iam, the gRPC PlatformIAMService
// implementation, so each tool gives its gRPC method's response message and
// error class: the same validation, tenant isolation and SDK status codes. A
// daemon without QuicBaaS IAM answers ErrIAMServiceNotAvailable.

// IAMCreateUser creates an IAM user, as gRPC CreateUser.
func (p *MCPServiceProvider) IAMCreateUser(ctx context.Context, req *mcp.IAMCreateUserRequest) (interface{}, error) {
	return p.iam.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId:   req.TenantID,
		Email:      req.Email,
		Name:       req.Name,
		Roles:      req.Roles,
		Attributes: req.Attributes,
	})
}

// IAMDeleteUser deletes an IAM user, as gRPC DeleteUser.
func (p *MCPServiceProvider) IAMDeleteUser(ctx context.Context, tenantID string, userID string) (interface{}, error) {
	return p.iam.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{TenantId: tenantID, UserId: userID})
}

// IAMGetUser returns an IAM user, as gRPC GetUser.
func (p *MCPServiceProvider) IAMGetUser(ctx context.Context, tenantID string, userID string) (interface{}, error) {
	return p.iam.GetUser(ctx, &platformv1.GetIAMUserRequest{TenantId: tenantID, UserId: userID})
}

// IAMListUsers lists a tenant's IAM users, as gRPC ListUsers.
func (p *MCPServiceProvider) IAMListUsers(ctx context.Context, req *mcp.IAMListUsersRequest) (interface{}, error) {
	return p.iam.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
		TenantId:    req.TenantID,
		Pagination:  iamPaginationRequest(req.Pagination),
		EmailFilter: req.EmailFilter,
		RoleFilter:  req.RoleFilter,
	})
}

// IAMCreateRole creates an IAM role, as gRPC CreateRole.
func (p *MCPServiceProvider) IAMCreateRole(ctx context.Context, req *mcp.IAMCreateRoleRequest) (interface{}, error) {
	return p.iam.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
		TenantId:    req.TenantID,
		Id:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	})
}

// IAMDeleteRole deletes an IAM role, as gRPC DeleteRole.
func (p *MCPServiceProvider) IAMDeleteRole(ctx context.Context, tenantID string, roleID string) (interface{}, error) {
	return p.iam.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{TenantId: tenantID, RoleId: roleID})
}

// IAMGetRole returns an IAM role, as gRPC GetRole.
func (p *MCPServiceProvider) IAMGetRole(ctx context.Context, tenantID string, roleID string) (interface{}, error) {
	return p.iam.GetRole(ctx, &platformv1.GetIAMRoleRequest{TenantId: tenantID, RoleId: roleID})
}

// IAMListRoles lists a tenant's IAM roles, as gRPC ListRoles.
func (p *MCPServiceProvider) IAMListRoles(ctx context.Context, tenantID string, page mcp.IAMPagination) (interface{}, error) {
	return p.iam.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
		TenantId:   tenantID,
		Pagination: iamPaginationRequest(page),
	})
}

// IAMAssignRole assigns a role to a user, as gRPC AssignRole.
func (p *MCPServiceProvider) IAMAssignRole(ctx context.Context, tenantID string, userID string, roleID string) (interface{}, error) {
	return p.iam.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{TenantId: tenantID, UserId: userID, RoleId: roleID})
}

// IAMRevokeRole revokes a role from a user, as gRPC RevokeRole.
func (p *MCPServiceProvider) IAMRevokeRole(ctx context.Context, tenantID string, userID string, roleID string) (interface{}, error) {
	return p.iam.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{TenantId: tenantID, UserId: userID, RoleId: roleID})
}

// IAMCheckPermission asks the policy decision point whether a subject may
// act on a resource, as gRPC CheckPermission.
func (p *MCPServiceProvider) IAMCheckPermission(ctx context.Context, req *mcp.IAMCheckPermissionRequest) (interface{}, error) {
	return p.iam.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
		TenantId:   req.TenantID,
		SubjectId:  req.SubjectID,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Action:     req.Action,
		Resource:   req.Resource,
		Context:    req.Context,
		Attributes: req.Attributes,
	})
}

// IAMAuthenticate refuses credential login with ErrIAMAuthenticationViaOIDC.
// The IAM service holds no credentials to check, and the platform has no
// Authenticate RPC: users sign in through the broker's OIDC flows, which
// issue the platform token.
func (p *MCPServiceProvider) IAMAuthenticate(ctx context.Context, req *mcp.IAMAuthenticateRequest) (interface{}, error) {
	return nil, ErrIAMAuthenticationViaOIDC{}
}

// IAMCreateTenant creates a tenant, as gRPC CreateTenant.
func (p *MCPServiceProvider) IAMCreateTenant(ctx context.Context, req *mcp.IAMCreateTenantRequest) (interface{}, error) {
	grpcReq := &platformv1.CreateIAMTenantRequest{Id: req.ID, Name: req.Name}
	if req.Settings != nil {
		grpcReq.Settings = &platformv1.IAMTenantSettings{
			MaxUsers:    req.Settings.MaxUsers,
			MfaRequired: req.Settings.MFARequired,
		}
	}
	return p.iam.CreateTenant(ctx, grpcReq)
}

// IAMDeleteTenant deletes a tenant, as gRPC DeleteTenant.
func (p *MCPServiceProvider) IAMDeleteTenant(ctx context.Context, tenantID string) (interface{}, error) {
	return p.iam.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{TenantId: tenantID})
}

// IAMGetTenant returns a tenant, as gRPC GetTenant.
func (p *MCPServiceProvider) IAMGetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	return p.iam.GetTenant(ctx, &platformv1.GetIAMTenantRequest{TenantId: tenantID})
}

// IAMListTenants lists the tenants, as gRPC ListTenants.
func (p *MCPServiceProvider) IAMListTenants(ctx context.Context, page mcp.IAMPagination) (interface{}, error) {
	return p.iam.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{Pagination: iamPaginationRequest(page)})
}

// iamPaginationRequest is the gRPC PaginationRequest of an IAM list tool's page.
func iamPaginationRequest(page mcp.IAMPagination) *platformv1.PaginationRequest {
	return &platformv1.PaginationRequest{Page: page.Page, PageSize: page.PageSize}
}

// =============================================================================
// IAM Token Operations
// =============================================================================

// IAMCreateToken refuses token issuance with ErrIAMTokenViaOIDC, the refusal
// the gRPC and QUIC token-create operations give: the SDK IAM client cannot
// issue tokens; platform tokens come from the broker's OIDC flows.
func (p *MCPServiceProvider) IAMCreateToken(ctx context.Context, req *mcp.IAMCreateTokenRequest) (interface{}, error) {
	return nil, p.iamTokens.Create()
}

// IAMRevokeToken refuses token revocation with ErrIAMTokenViaOIDC, the
// refusal the gRPC and QUIC token-revoke operations give: the SDK IAM client
// cannot revoke tokens; platform tokens are revoked by the broker's OIDC flows.
func (p *MCPServiceProvider) IAMRevokeToken(ctx context.Context, tokenID string) error {
	return p.iamTokens.Revoke()
}

// IAMVerifyToken verifies a token through IAMTokenService.Verify, the function
// the gRPC and QUIC verify operations call. The result uses the
// VerifyIAMTokenResponse JSON names: valid, plus reason for a rejected token,
// or user_id, tenant_id, scopes and expires_at for a valid one. The token is
// never echoed or logged.
func (p *MCPServiceProvider) IAMVerifyToken(ctx context.Context, token string) (interface{}, error) {
	verification, err := p.iamTokens.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if !verification.Valid {
		return map[string]interface{}{
			"valid":  false,
			"reason": string(verification.Reason),
		}, nil
	}
	return map[string]interface{}{
		"valid":      true,
		"user_id":    verification.Claims.Subject,
		"tenant_id":  verification.Claims.TenantID,
		"scopes":     verification.Claims.Scopes,
		"expires_at": verification.Claims.ExpiresAt,
	}, nil
}

// =============================================================================
// KMS Operations
// =============================================================================

// KMSCreateKey creates a new cryptographic key in the KMS.
func (p *MCPServiceProvider) KMSCreateKey(ctx context.Context, req *mcp.KMSCreateKeyRequest) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	// Validate required parameters
	if req.Name == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "name", Reason: "key name is required"}
	}
	if req.Algorithm == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "algorithm", Reason: "algorithm is required"}
	}
	if len(req.KeyUsage) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "key_usage", Reason: "at least one key usage is required"}
	}

	// Convert key usages
	usages := make([]baasservice.KeyUsage, 0, len(req.KeyUsage))
	for _, u := range req.KeyUsage {
		usage, err := parseKMSKeyUsage(u)
		if err != nil {
			return nil, err
		}
		usages = append(usages, usage)
	}

	// Build key attributes based on algorithm
	keyAttrs, err := buildKeyAttributes(req)
	if err != nil {
		return nil, err
	}

	// Create the generate key request
	genReq := &baasservice.GenerateKeyRequest{
		Name:               req.Name,
		Description:        req.Description,
		Usage:              usages,
		KeyAttributes:      keyAttrs,
		Exportable:         req.Exportable,
		DeletionProtection: req.DeletionProtection,
		Owner:              req.Owner,
	}

	// Generate the key
	resp, err := p.kmsService.GenerateKey(ctx, genReq)
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "CreateKey", Cause: err}
	}

	p.logger.Info("KMS key created",
		"key_id", resp.Key.KeyID,
		"algorithm", req.Algorithm,
		"usage", req.KeyUsage,
	)

	return resp.Key, nil
}

// KMSDeleteKey deletes a key from the KMS.
func (p *MCPServiceProvider) KMSDeleteKey(ctx context.Context, keyID string) error {
	if p.kmsService == nil {
		return ErrServiceNotAvailable{Service: "kms"}
	}

	if keyID == "" {
		return ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	_, err := p.kmsService.DeleteKey(ctx, &baasservice.DeleteKeyRequest{
		KeyID: keyID,
	})
	if err != nil {
		return ErrKMSOperationFailed{Operation: "DeleteKey", Cause: err}
	}

	p.logger.Info("KMS key deleted", "key_id", keyID)
	return nil
}

// KMSGetKey retrieves key metadata from the KMS. A version of 0 retrieves
// the latest key version.
func (p *MCPServiceProvider) KMSGetKey(ctx context.Context, keyID string, version uint64) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if keyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	resp, err := p.kmsService.GetKey(ctx, &baasservice.GetKeyRequest{
		KeyID:   keyID,
		Version: version,
	})
	if err != nil {
		return nil, ErrKMSKeyNotFound{KeyID: keyID}
	}

	return resp.Key, nil
}

// KMSListKeys lists all keys in the KMS.
func (p *MCPServiceProvider) KMSListKeys(ctx context.Context, limit int, offset int) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	pageSize := limit
	if pageSize == 0 {
		pageSize = 50
	}

	resp, err := p.kmsService.ListKeys(ctx, &baasservice.ListKeysRequest{
		Limit: pageSize,
	})
	if err != nil {
		return nil, ErrKMSOperationFailed{Operation: "ListKeys", Cause: err}
	}

	return map[string]interface{}{
		"keys":        resp.Keys,
		"total_count": resp.TotalCount,
		"has_more":    resp.HasMore,
		"next_cursor": resp.NextCursor,
	}, nil
}

// KMSRotateKey rotates a key in the KMS.
func (p *MCPServiceProvider) KMSRotateKey(ctx context.Context, keyID string) (interface{}, error) {
	if p.kmsService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if keyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}

	resp, err := p.kmsService.RotateKey(ctx, &baasservice.RotateKeyRequest{
		KeyID: keyID,
	})
	if err != nil {
		return nil, ErrKMSKeyRotationFailed{KeyID: keyID, Cause: err}
	}

	p.logger.Info("KMS key rotated",
		"key_id", keyID,
		"new_version", resp.NewVersion,
	)

	return resp, nil
}

// KMSEncrypt encrypts data using a KMS key.
func (p *MCPServiceProvider) KMSEncrypt(ctx context.Context, req *mcp.KMSEncryptRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}
	if len(req.Plaintext) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "plaintext", Reason: "plaintext is required"}
	}

	encReq := &baasservice.EncryptRequest{
		KeyID:     req.KeyID,
		Plaintext: req.Plaintext,
		Context:   req.Context,
		Nonce:     req.Nonce,
	}

	resp, err := p.cryptoService.Encrypt(ctx, encReq)
	if err != nil {
		return nil, ErrKMSEncryptionFailed{KeyID: req.KeyID, Cause: err}
	}

	return map[string]interface{}{
		"ciphertext":  resp.Ciphertext,
		"nonce":       resp.Nonce,
		"key_version": resp.KeyVersion,
	}, nil
}

// KMSDecrypt decrypts data using a KMS key.
func (p *MCPServiceProvider) KMSDecrypt(ctx context.Context, req *mcp.KMSDecryptRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}
	if len(req.Ciphertext) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "ciphertext", Reason: "ciphertext is required"}
	}

	decReq := &baasservice.DecryptRequest{
		KeyID:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Context:    req.Context,
		KeyVersion: uint64(req.KeyVersion),
	}

	resp, err := p.cryptoService.Decrypt(ctx, decReq)
	if err != nil {
		return nil, ErrKMSDecryptionFailed{KeyID: req.KeyID, Cause: err}
	}

	return map[string]interface{}{
		"plaintext": resp.Plaintext,
	}, nil
}

// KMSSign signs data using a KMS key.
func (p *MCPServiceProvider) KMSSign(ctx context.Context, req *mcp.KMSSignRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}
	if len(req.Message) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "message", Reason: "message is required"}
	}

	hashAlg := parseHashAlgorithm(req.HashAlgorithm)

	signReq := &baasservice.SignRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		HashAlgorithm: hashAlg,
		PreHashed:     req.PreHashed,
	}

	resp, err := p.cryptoService.Sign(ctx, signReq)
	if err != nil {
		return nil, ErrKMSSigningFailed{KeyID: req.KeyID, Cause: err}
	}

	return map[string]interface{}{
		"signature":   resp.Signature,
		"key_version": resp.KeyVersion,
	}, nil
}

// KMSVerify verifies a signature using a KMS key.
func (p *MCPServiceProvider) KMSVerify(ctx context.Context, req *mcp.KMSVerifyRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key ID is required"}
	}
	if len(req.Message) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "message", Reason: "message is required"}
	}
	if len(req.Signature) == 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "signature", Reason: "signature is required"}
	}

	hashAlg := parseHashAlgorithm(req.HashAlgorithm)

	verifyReq := &baasservice.VerifyRequest{
		KeyID:         req.KeyID,
		Message:       req.Message,
		Signature:     req.Signature,
		HashAlgorithm: hashAlg,
		KeyVersion:    uint64(req.KeyVersion),
	}

	resp, err := p.cryptoService.Verify(ctx, verifyReq)
	if err != nil {
		return nil, ErrKMSVerificationFailed{KeyID: req.KeyID, Cause: err}
	}

	return map[string]interface{}{
		"valid": resp.Valid,
	}, nil
}

// KMSGenerateRandom generates cryptographically secure random bytes.
func (p *MCPServiceProvider) KMSGenerateRandom(ctx context.Context, numBytes int) ([]byte, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	if numBytes <= 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "num_bytes", Reason: "number of bytes must be positive"}
	}

	// The KMS answers, as it does for gRPC GenerateRandom; the SDK enforces
	// its own size limit.
	resp, err := p.cryptoService.GenerateRandom(ctx, &baasservice.GenerateRandomRequest{NumBytes: numBytes})
	if err != nil {
		return nil, ErrKMSRandomGenerationFailed{Cause: err}
	}

	return resp.RandomBytes, nil
}

// KMSGenerateDataKey generates a data encryption key (DEK) for envelope encryption.
// This returns both the plaintext DEK (for immediate use) and the wrapped version
// (for storage). The plaintext should be used for local encryption and then discarded;
// only the wrapped version should be persisted.
func (p *MCPServiceProvider) KMSGenerateDataKey(ctx context.Context, req *mcp.KMSGenerateDataKeyRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	// Validate required parameters
	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key encryption key ID is required"}
	}

	// Parse algorithm (default to AES-256-GCM)
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}

	// Build key attributes based on the algorithm
	keyAttrs, err := buildDataKeyAttributes(algorithm)
	if err != nil {
		return nil, err
	}

	// Parse context if provided
	var contextBytes []byte
	if req.Context != "" {
		contextBytes = []byte(req.Context)
	}

	// Build the request
	genReq := &baasservice.GenerateDataKeyRequest{
		KeyID:         req.KeyID,
		KeyAttributes: keyAttrs,
		Context:       contextBytes,
	}

	// Generate the data key
	resp, err := p.cryptoService.GenerateDataKey(ctx, genReq)
	if err != nil {
		return nil, ErrKMSDataKeyGenerationFailed{KeyID: req.KeyID, Cause: err}
	}

	p.logger.Info("generated data encryption key",
		"key_id", req.KeyID,
		"algorithm", algorithm,
	)

	return map[string]interface{}{
		"key_id":          resp.KeyID,
		"plaintext":       resp.Plaintext,
		"ciphertext_blob": resp.CiphertextBlob,
		"timestamp":       resp.Timestamp.Format(time.RFC3339),
	}, nil
}

// KMSGenerateWrappedDataKey generates only a wrapped (encrypted) data encryption key.
// This command generates a DEK and returns only the wrapped version - the plaintext
// DEK is never exposed. This is useful for pre-generating keys for later use,
// distributing encrypted keys to systems that will decrypt them later,
// or key escrow scenarios.
func (p *MCPServiceProvider) KMSGenerateWrappedDataKey(ctx context.Context, req *mcp.KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
	if p.cryptoService == nil {
		return nil, ErrServiceNotAvailable{Service: "kms"}
	}

	// Validate required parameters
	if req.KeyID == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "key_id", Reason: "key encryption key ID is required"}
	}

	// Parse algorithm (default to AES-256-GCM)
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}

	// Build key attributes based on the algorithm
	keyAttrs, err := buildDataKeyAttributes(algorithm)
	if err != nil {
		return nil, err
	}

	// Parse context if provided
	var contextBytes []byte
	if req.Context != "" {
		contextBytes = []byte(req.Context)
	}

	// Build the request
	genReq := &baasservice.GenerateWrappedDataKeyRequest{
		KeyID:         req.KeyID,
		KeyAttributes: keyAttrs,
		Context:       contextBytes,
	}

	// Generate the wrapped data key
	resp, err := p.cryptoService.GenerateWrappedDataKey(ctx, genReq)
	if err != nil {
		return nil, ErrKMSDataKeyGenerationFailed{KeyID: req.KeyID, Cause: err}
	}

	p.logger.Info("generated wrapped data encryption key",
		"key_id", req.KeyID,
		"algorithm", algorithm,
	)

	return map[string]interface{}{
		"key_id":          resp.KeyID,
		"ciphertext_blob": resp.CiphertextBlob,
		"timestamp":       resp.Timestamp.Format(time.RFC3339),
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// parseDeviceIDFromString parses a device ID string to uint64.
func parseDeviceIDFromString(id string) (uint64, error) {
	n, err := parseUint64(id)
	if err != nil {
		return 0, ErrInvalidDeviceID{ID: id}
	}
	return n, nil
}

// parseUint64 parses a string to uint64.
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, ErrInvalidDeviceID{ID: s}
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrInvalidDeviceID{ID: s}
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

// parsePlatformKeyAlgorithm converts a string algorithm to platformv1.KeyAlgorithm.
// An empty name leaves the CA's default; a name it does not know is refused,
// as the gRPC service refuses an unknown enum, rather than issued as the
// default.
func parsePlatformKeyAlgorithm(alg string) (platformv1.KeyAlgorithm, error) {
	switch alg {
	case "":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, nil
	case "RSA", "RSA2048", "RSA-2048":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, nil
	case "RSA3072", "RSA-3072":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, nil
	case "RSA4096", "RSA-4096":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, nil
	case "ECDSA", "EC", "ECDSA-P256", "P256":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, nil
	case "ECDSA-P384", "P384":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, nil
	case "ECDSA-P521", "P521":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521, nil
	case "ED25519":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, nil
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, ErrCAInvalidKeyAlgorithm{Algorithm: alg}
	}
}

// parseKMSKeyUsage converts a string key usage to baasservice.KeyUsage.
func parseKMSKeyUsage(usage string) (baasservice.KeyUsage, error) {
	normalizedUsage := strings.ToLower(strings.TrimSpace(usage))
	switch normalizedUsage {
	case "encrypt":
		return baasservice.KeyUsageEncrypt, nil
	case "decrypt":
		return baasservice.KeyUsageDecrypt, nil
	case "sign":
		return baasservice.KeyUsageSign, nil
	case "verify":
		return baasservice.KeyUsageVerify, nil
	case "wrap":
		return baasservice.KeyUsageWrapKey, nil
	case "unwrap":
		return baasservice.KeyUsageWrapKey, nil
	case "derive":
		return baasservice.KeyUsageDeriveKey, nil
	case "generate_mac":
		return baasservice.KeyUsageGenerateMAC, nil
	case "verify_mac":
		return baasservice.KeyUsageVerifyMAC, nil
	default:
		return baasservice.KeyUsageEncrypt, ErrKMSInvalidKeyUsage{Usage: usage}
	}
}

// buildKeyAttributes builds KeyAttributes from the create key request.
func buildKeyAttributes(req *mcp.KMSCreateKeyRequest) (*xkmssdk.KeyAttributes, error) {
	attrs := &xkmssdk.KeyAttributes{
		CN: req.Name,
	}

	normalizedAlg := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	switch normalizedAlg {
	case "AES128", "AES-128", "AES128GCM", "AES-128-GCM":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES128GCM
		attrs.KeyType = xkmssdk.KeyTypeEncryption
	case "AES256", "AES-256", "AES256GCM", "AES-256-GCM":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES256GCM
		attrs.KeyType = xkmssdk.KeyTypeEncryption
	case "CHACHA20", "CHACHA20POLY1305", "CHACHA20-POLY1305":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricChaCha20Poly1305
		attrs.KeyType = xkmssdk.KeyTypeEncryption
	case "XCHACHA20", "XCHACHA20POLY1305", "XCHACHA20-POLY1305":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricXChaCha20Poly1305
		attrs.KeyType = xkmssdk.KeyTypeEncryption
	case "RSA", "RSA2048", "RSA-2048":
		attrs.KeyAlgorithm = x509.RSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 2048}
	case "RSA3072", "RSA-3072":
		attrs.KeyAlgorithm = x509.RSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 3072}
	case "RSA4096", "RSA-4096":
		attrs.KeyAlgorithm = x509.RSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 4096}
	case "ECDSA", "EC", "ECDSAP256", "ECDSA-P256", "P256":
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P256()}
	case "ECDSAP384", "ECDSA-P384", "P384":
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P384()}
	case "ECDSAP521", "ECDSA-P521", "P521":
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.KeyType = xkmssdk.KeyTypeSigning
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: elliptic.P521()}
	case "ED25519":
		attrs.KeyAlgorithm = x509.Ed25519
		attrs.KeyType = xkmssdk.KeyTypeSigning
	default:
		return nil, ErrKMSInvalidAlgorithm{Algorithm: req.Algorithm}
	}

	return attrs, nil
}

// parseHashAlgorithm converts a string hash algorithm to baasservice.HashAlgorithm.
func parseHashAlgorithm(hashAlg string) baasservice.HashAlgorithm {
	normalizedHash := strings.ToUpper(strings.TrimSpace(hashAlg))
	switch normalizedHash {
	case "SHA256", "SHA-256":
		return baasservice.HashAlgSHA256
	case "SHA384", "SHA-384":
		return baasservice.HashAlgSHA384
	case "SHA512", "SHA-512":
		return baasservice.HashAlgSHA512
	default:
		return baasservice.HashAlgSHA256
	}
}

// buildDataKeyAttributes builds KeyAttributes for data key generation from an algorithm string.
func buildDataKeyAttributes(algorithm string) (*xkmssdk.KeyAttributes, error) {
	attrs := &xkmssdk.KeyAttributes{
		KeyType: xkmssdk.KeyTypeEncryption,
	}

	normalizedAlg := strings.ToLower(strings.TrimSpace(algorithm))
	switch normalizedAlg {
	case "aes-128-gcm", "aes128gcm", "aes128":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES128GCM
	case "aes-192-gcm", "aes192gcm", "aes192":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES192GCM
	case "aes-256-gcm", "aes256gcm", "aes256":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES256GCM
	case "chacha20-poly1305", "chacha20poly1305", "chacha20":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricChaCha20Poly1305
	case "xchacha20-poly1305", "xchacha20poly1305", "xchacha20":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricXChaCha20Poly1305
	default:
		return nil, ErrKMSInvalidAlgorithm{Algorithm: algorithm}
	}

	return attrs, nil
}

// encodeHex converts bytes to a hex-encoded string.
func encodeHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// =============================================================================
// Container Operations - Stub implementations pending container service integration
// =============================================================================

// ContainerCreate creates a new container.
func (m *MCPServiceProvider) ContainerCreate(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}

	if name == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "name", Reason: "container name is required"}
	}
	if image == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "image", Reason: "container image is required"}
	}

	// Build device profile from request config
	profile := &deviceentities.DeviceProfile{
		Name:  name,
		Model: "container:image=" + image,
	}

	// Create the instance using orchestrator
	instance, err := m.computeOrchestrator.Create(ctx, profile)
	if err != nil {
		m.logger.Error("failed to create container", "name", name, "error", err)
		return nil, ErrContainerOperationFailed{Operation: "create", Cause: err}
	}

	return m.instanceToContainerResponse(instance), nil
}

// ContainerStart starts a container.
func (m *MCPServiceProvider) ContainerStart(ctx context.Context, id string) error {
	if m.computeOrchestrator == nil {
		return ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	if err := m.computeOrchestrator.Start(ctx, id); err != nil {
		m.logger.Error("failed to start container", "container_id", id, "error", err)
		return ErrContainerOperationFailed{Operation: "start", Cause: err}
	}

	return nil
}

// ContainerStop stops a container.
func (m *MCPServiceProvider) ContainerStop(ctx context.Context, id string, timeout int) error {
	if m.computeOrchestrator == nil {
		return ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	// Note: timeout parameter is ignored as orchestrator.Stop does not accept it
	if err := m.computeOrchestrator.Stop(ctx, id); err != nil {
		m.logger.Error("failed to stop container", "container_id", id, "error", err)
		return ErrContainerOperationFailed{Operation: "stop", Cause: err}
	}

	return nil
}

// ContainerRemove removes a container.
func (m *MCPServiceProvider) ContainerRemove(ctx context.Context, id string, force bool) error {
	if m.computeOrchestrator == nil {
		return ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	// Note: force parameter is ignored as orchestrator.Delete does not accept it
	if err := m.computeOrchestrator.Delete(ctx, id); err != nil {
		m.logger.Error("failed to remove container", "container_id", id, "error", err)
		return ErrContainerOperationFailed{Operation: "remove", Cause: err}
	}

	return nil
}

// ContainerGet retrieves a container by ID.
func (m *MCPServiceProvider) ContainerGet(ctx context.Context, id string) (interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	instance, err := m.computeOrchestrator.Get(ctx, id)
	if err != nil {
		m.logger.Error("failed to get container", "container_id", id, "error", err)
		return nil, ErrContainerNotFound{ContainerID: id}
	}

	return m.instanceToContainerResponse(instance), nil
}

// ContainerList lists containers.
func (m *MCPServiceProvider) ContainerList(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}

	// Create filter for container type
	containerType := compute.ComputeTypeContainer
	filter := &compute.InstanceFilter{
		Type: &containerType,
	}

	// Apply state filter if only running containers are requested
	if !all {
		runningState := compute.StateRunning
		filter.State = &runningState
	}

	instances, err := m.computeOrchestrator.List(ctx, filter)
	if err != nil {
		m.logger.Error("failed to list containers", "error", err)
		return nil, ErrContainerOperationFailed{Operation: "list", Cause: err}
	}

	// Convert to response format
	result := make([]interface{}, 0, len(instances))
	for i, instance := range instances {
		if limit > 0 && i >= limit {
			break
		}
		result = append(result, m.instanceToContainerResponse(instance))
	}

	return result, nil
}

// ContainerLogs retrieves container logs. The MCP tool response model is a
// single string, so logs are returned as a snapshot; the follow flag is
// ignored (streaming is available on the gRPC and REST transports).
func (m *MCPServiceProvider) ContainerLogs(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error) {
	if m.computeOrchestrator == nil {
		return "", ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return "", ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	streamer, ok := m.computeOrchestrator.(containerLogStreamer)
	if !ok {
		return "", ErrContainerLogsNotSupported{}
	}

	opts := computecontainer.LogOptions{
		Stdout:     stdout,
		Stderr:     stderr,
		Tail:       tail,
		Timestamps: timestamps,
	}
	if !opts.Stdout && !opts.Stderr {
		opts.Stdout = true
		opts.Stderr = true
	}

	reader, err := streamer.Logs(ctx, id, opts)
	if err != nil {
		m.logger.Error("failed to get container logs", "container_id", id, "error", err)
		return "", ErrContainerOperationFailed{Operation: "logs", Cause: err}
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", ErrContainerOperationFailed{Operation: "logs", Cause: err}
	}

	return string(data), nil
}

// ContainerAttest performs quote-based TPM attestation for a container. It
// delegates to the orchestrator's Attest verb — the same service logic the
// gRPC AttestContainer RPC and REST container attest route use.
func (m *MCPServiceProvider) ContainerAttest(ctx context.Context, id string) (interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}

	if id == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	attester, ok := m.computeOrchestrator.(containerAttester)
	if !ok {
		return nil, ErrContainerAttestNotSupported{}
	}

	report, err := attester.Attest(ctx, id)
	if err != nil {
		m.logger.Error("failed to attest container", "container_id", id, "error", err)
		return nil, ErrContainerOperationFailed{Operation: "attest", Cause: err}
	}

	return attestationReportToMCPResponse(report), nil
}

// attestationReportToMCPResponse converts a container attestation report to
// the MCP tool response map. Binary fields are hex encoded.
func attestationReportToMCPResponse(report *computecontainer.AttestationReport) map[string]interface{} {
	if report == nil {
		return nil
	}

	result := map[string]interface{}{
		"container_id":   report.ContainerID,
		"container_name": report.ContainerName,
		"timestamp":      report.Timestamp.Format(time.RFC3339),
		"quote":          encodeHex(report.Quote),
		"signature":      encodeHex(report.Signature),
		// Already canonical OCI digest strings ("sha256:<64 hex>"), so
		// they are emitted verbatim rather than hex-encoded again.
		"image_digest":  report.ImageDigest,
		"config_digest": report.ConfigDigest,
		"verified":      report.Verified,
	}

	if len(report.PCRValues) > 0 {
		pcrValues := make(map[string]string, len(report.PCRValues))
		for idx, value := range report.PCRValues {
			pcrValues[strconv.Itoa(idx)] = encodeHex(value)
		}
		result["pcr_values"] = pcrValues
	}

	if len(report.AIKCertificate) > 0 {
		result["aik_certificate"] = encodeHex(report.AIKCertificate)
	}

	return result
}

// instanceToContainerResponse converts a compute.Instance to a container response map.
func (m *MCPServiceProvider) instanceToContainerResponse(instance *compute.Instance) map[string]interface{} {
	if instance == nil {
		return nil
	}

	response := map[string]interface{}{
		"id":         instance.ID,
		"name":       instance.Name,
		"state":      string(instance.State),
		"created_at": instance.CreatedAt.Format(time.RFC3339),
		"updated_at": instance.UpdatedAt.Format(time.RFC3339),
	}

	if instance.Config != nil {
		response["memory"] = instance.Config.Memory
		response["cpus"] = instance.Config.CPUs
	}

	if instance.Metadata != nil {
		response["metadata"] = instance.Metadata
	}

	return response
}

// SetComputeOrchestrator sets the compute orchestrator after construction.
// This allows dynamic injection of the orchestrator.
func (m *MCPServiceProvider) SetComputeOrchestrator(orchestrator compute.Orchestrator) {
	m.computeOrchestrator = orchestrator
}

// The overlay network operations are served by the embedded overlayTools
// (overlay_mcp_bindings.go).

// =============================================================================
// Gateway Operations - Stub implementations pending gateway service integration
// =============================================================================

// GatewayStatus and GatewayModeSet come from the embedded gatewayStatusTools
// (gateway_status_bindings.go), the BGP tools from the embedded
// gatewayBGPTools (gateway_bgp_bindings.go) and the IPAM tools from the
// embedded gatewayIPAMTools (gateway_ipam_tools.go).

// =============================================================================
// Network Zone Operations
// =============================================================================

// GatewayNetworkZoneList lists the underlay zones with their policy and
// derived numbering, optionally filtered by lifecycle role.
func (m *MCPServiceProvider) GatewayNetworkZoneList(ctx context.Context, lifecycleRole string) ([]interface{}, error) {
	if m.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	recs, err := m.zoneService.List(ctx, zone.LifecycleRole(lifecycleRole))
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.View(false))
	}
	return out, nil
}

// GatewayNetworkZoneCreate creates an owner-defined zone.
func (m *MCPServiceProvider) GatewayNetworkZoneCreate(ctx context.Context, req *mcp.NetworkZoneCreateRequest) (interface{}, error) {
	if m.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	rec, restartRequired, err := m.zoneService.Create(ctx, req.ZoneConfig())
	if err != nil {
		return nil, err
	}
	return rec.View(restartRequired), nil
}

// GatewayNetworkZoneUpdate tunes a built-in zone or replaces an
// owner-defined zone.
func (m *MCPServiceProvider) GatewayNetworkZoneUpdate(ctx context.Context, name string, req *mcp.NetworkZoneUpdateRequest) (interface{}, error) {
	if m.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	rec, restartRequired, err := m.zoneService.Update(ctx, zone.Zone(name), req.ZoneConfig(name))
	if err != nil {
		return nil, err
	}
	return rec.View(restartRequired), nil
}

// GatewayNetworkZoneDelete deletes an owner-defined zone or omits an
// optional built-in.
func (m *MCPServiceProvider) GatewayNetworkZoneDelete(ctx context.Context, name string) (bool, error) {
	if m.zoneService == nil {
		return false, ErrServiceNotAvailable{Service: "zone"}
	}
	return m.zoneService.Delete(ctx, zone.Zone(name))
}

// GatewayNetworkZoneVLAN resolves a zone name to its VLAN ID through the
// zone service's derived numbering.
func (m *MCPServiceProvider) GatewayNetworkZoneVLAN(ctx context.Context, zoneName string) (uint16, error) {
	return zoneVLAN(ctx, m.zoneService, zoneName)
}

// zoneVLAN resolves a zone name to its VLAN through the zone service's
// derived numbering. It fails when there is no zone service, the zone does
// not exist, or the service has no environment to number it.
func zoneVLAN(ctx context.Context, svc gateway.ZoneService, zoneName string) (uint16, error) {
	if svc == nil {
		return 0, ErrServiceNotAvailable{Service: "zone"}
	}
	recs, err := svc.List(ctx, "")
	if err != nil {
		return 0, err
	}
	for _, r := range recs {
		if string(r.Config.Name) != zoneName {
			continue
		}
		if r.Numbering == nil {
			return 0, ErrServiceNotAvailable{Service: "zone-vlan: no sdn.environment numbers zone " + zoneName}
		}
		return r.Numbering.VLAN, nil
	}
	return 0, gateway.ErrZoneNotFound{Name: zone.Zone(zoneName)}
}

// =============================================================================
// Physical TPM Operations
// =============================================================================

// TPMInfo retrieves TPM device information.
func (p *MCPServiceProvider) TPMInfo(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	info, err := p.tpm2Service.Info()
	if err != nil {
		return nil, mapTPMError(err)
	}

	result := map[string]interface{}{
		"info": info,
	}
	for key, value := range tpmsrk.InfoProperties(p.tpm2Service) {
		result[key] = value
	}

	props, err := p.tpm2Service.FixedProperties()
	if err == nil && props != nil {
		result["manufacturer"] = props.Manufacturer
		result["model"] = props.Model
		result["firmware_version"] = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
		result["family"] = props.Family
		result["revision"] = props.Revision
		result["vendor_id"] = props.VendorID
		result["fips_mode"] = props.Fips1402
		result["max_nvram_size"] = props.NVBufferMax
	}

	cfg := p.tpm2Service.Config()
	if cfg != nil {
		result["is_simulator"] = cfg.UseSimulator
	}

	return result, nil
}

// TPMProvision provisions the TPM with owner authorization.
func (p *MCPServiceProvider) TPMProvision(ctx context.Context, ownerPassword string) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	var ownerPwd xkmssdk.Password
	if ownerPassword != "" {
		held, err := xkmssdk.NewPasswordFromString(ownerPassword)
		if err != nil {
			return nil, mapTPMError(err)
		}
		ownerPwd = held
	}

	_, err := p.tpm2Service.ProvisionOwner(ownerPwd)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "TPM provisioned successfully",
	}, nil
}

// TPMClear clears the TPM.
func (p *MCPServiceProvider) TPMClear(ctx context.Context, ownerPassword string) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	var lockoutAuth []byte
	if ownerPassword != "" {
		lockoutAuth = []byte(ownerPassword)
	}

	if err := p.tpm2Service.Clear(lockoutAuth); err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "TPM cleared successfully",
	}, nil
}

// TPMGetEK retrieves the Endorsement Key.
func (p *MCPServiceProvider) TPMGetEK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"handle":     uint32(ekAttrs.TPMAttributes.Handle),
		"public_key": base64.StdEncoding.EncodeToString(ekAttrs.TPMAttributes.PublicKeyBytes),
		"algorithm":  ekAttrs.KeyAlgorithm.String(),
	}, nil
}

// TPMGetEKCert retrieves the EK certificate.
func (p *MCPServiceProvider) TPMGetEKCert(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	cert, err := p.tpm2Service.EKCertificate()
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"certificate": base64.StdEncoding.EncodeToString(cert.Raw),
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"not_before":  cert.NotBefore,
		"not_after":   cert.NotAfter,
	}, nil
}

// TPMImportEKCert imports an EK certificate.
func (p *MCPServiceProvider) TPMImportEKCert(ctx context.Context, certDER []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	if err := p.tpm2Service.ProvisionEKCert(nil, certDER); err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "EK certificate imported successfully",
	}, nil
}

// TPMCreateEK creates an Endorsement Key.
func (p *MCPServiceProvider) TPMCreateEK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, mapTPMError(err)
	}

	if err := p.tpm2Service.CreateEK(ekAttrs); err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "EK created successfully",
		"handle":  uint32(ekAttrs.TPMAttributes.Handle),
	}, nil
}

// TPMDeleteEK deletes the Endorsement Key.
func (p *MCPServiceProvider) TPMDeleteEK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, err
	}

	p.tpm2Service.Flush(ekAttrs.TPMAttributes.Handle)

	return map[string]interface{}{
		"success": true,
		"message": "EK handle flushed",
	}, nil
}

// TPMGetSRK retrieves the Storage Root Key.
func (p *MCPServiceProvider) TPMGetSRK(ctx context.Context, handle uint32) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	srkAttrs, err := resolveTPMSRK(p.tpm2Service, handle)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"handle":     uint32(srkAttrs.TPMAttributes.Handle),
		"public_key": base64.StdEncoding.EncodeToString(srkAttrs.TPMAttributes.PublicKeyBytes),
		"algorithm":  srkAttrs.KeyAlgorithm.String(),
	}, nil
}

// TPMCreateSRK creates a Storage Root Key.
func (p *MCPServiceProvider) TPMCreateSRK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	srkAttrs, err := p.tpm2Service.SSRKAttributes()
	if err != nil {
		return nil, mapTPMError(err)
	}

	if err := p.tpm2Service.CreateSRK(srkAttrs); err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "SRK created successfully",
		"handle":  uint32(srkAttrs.TPMAttributes.Handle),
	}, nil
}

// TPMDeleteSRK deletes the Storage Root Key.
func (p *MCPServiceProvider) TPMDeleteSRK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	srkAttrs, err := p.tpm2Service.SSRKAttributes()
	if err != nil {
		return nil, err
	}

	p.tpm2Service.Flush(srkAttrs.TPMAttributes.Handle)

	return map[string]interface{}{
		"success": true,
		"message": "SRK handle flushed",
	}, nil
}

// TPMGetIAK retrieves the Initial Attestation Key.
func (p *MCPServiceProvider) TPMGetIAK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	iakAttrs, err := tpmIAKAttributes(p.tpm2Service)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"handle":     uint32(iakAttrs.TPMAttributes.Handle),
		"public_key": base64.StdEncoding.EncodeToString(iakAttrs.TPMAttributes.PublicKeyBytes),
		"algorithm":  iakAttrs.KeyAlgorithm.String(),
	}, nil
}

// TPMCreateIAK creates an Initial Attestation Key.
func (p *MCPServiceProvider) TPMCreateIAK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, mapTPMError(err)
	}

	iakAttrs, err := p.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"success": true,
		"message": "IAK created successfully",
		"handle":  uint32(iakAttrs.TPMAttributes.Handle),
	}, nil
}

// TPMDeleteIAK deletes the Initial Attestation Key.
func (p *MCPServiceProvider) TPMDeleteIAK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	iakAttrs, err := p.tpm2Service.IAKAttributes()
	if err != nil {
		return nil, err
	}

	p.tpm2Service.Flush(iakAttrs.TPMAttributes.Handle)

	return map[string]interface{}{
		"success": true,
		"message": "IAK handle flushed",
	}, nil
}

// tpmQuotes serves the quote tools on the provider's TPM, so an MCP quote is
// bound to its connection and verified exactly as on every other transport
// (#482).
func (p *MCPServiceProvider) tpmQuotes() tpmQuoteTools {
	return tpmQuoteTools{tpm: p.tpm2Service, logger: p.logger}
}

// TPMQuote generates a TPM quote over SHA-256(nonce || channel_binding),
// where channel_binding is the TLS exporter of the MCP connection the
// request arrived on. MCP over stdio has no TLS connection and is refused.
func (p *MCPServiceProvider) TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error) {
	return p.tpmQuotes().quote(ctx, nonce, pcrs)
}

// TPMVerifyQuote verifies a TPM quote against req.AKPublic, or the platform
// IAK when it is empty, under the scheme req.SignatureAlgorithm declares (as
// tpm_quote returned it). A non-empty req.ChannelBinding is the binding the
// quote was produced under; the quote must then carry
// SHA-256(nonce || channel_binding).
func (p *MCPServiceProvider) TPMVerifyQuote(ctx context.Context, req *mcp.TPMVerifyQuoteRequest) (interface{}, error) {
	return p.tpmQuotes().verify(ctx, req)
}

// TPMReadPCRs reads PCR values.
func (p *MCPServiceProvider) TPMReadPCRs(ctx context.Context, indices []int) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	pcrIndices := make([]uint, len(indices))
	for i, idx := range indices {
		pcrIndices[i] = uint(idx)
	}

	// If no indices specified, read all 24 PCRs
	if len(pcrIndices) == 0 {
		pcrIndices = make([]uint, 24)
		for i := 0; i < 24; i++ {
			pcrIndices[i] = uint(i)
		}
	}

	pcrBanks, err := p.tpm2Service.ReadPCRs(pcrIndices)
	if err != nil {
		return nil, mapTPMError(err)
	}

	banks := make([]map[string]interface{}, 0, len(pcrBanks))
	for _, bank := range pcrBanks {
		pcrs := make([]map[string]interface{}, 0, len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			pcrs = append(pcrs, map[string]interface{}{
				"index": pcr.ID,
				"value": base64.StdEncoding.EncodeToString(pcr.Value),
			})
		}
		banks = append(banks, map[string]interface{}{
			"algorithm": bank.Algorithm,
			"pcrs":      pcrs,
		})
	}

	return map[string]interface{}{
		"banks": banks,
	}, nil
}

// TPMExtendPCR extends a PCR in the hashAlg bank (sha256 when empty)
// through the shared tpmpcr layer the QUIC handler uses.
func (p *MCPServiceProvider) TPMExtendPCR(ctx context.Context, pcrIndex int, hashAlg string, data []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	if err := tpmpcr.Extend(p.tpm2Service, pcrIndex, hashAlg, data); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("PCR %d extended", pcrIndex),
	}, nil
}

// TPMEventLog retrieves the TPM event log.
func (p *MCPServiceProvider) TPMEventLog(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	rawLog, err := p.tpm2Service.EventLog()
	if err != nil {
		return nil, mapTPMError(err)
	}

	result := map[string]interface{}{
		"event_log": base64.StdEncoding.EncodeToString(rawLog),
		"format":    "tcg2",
	}

	events, err := p.tpm2Service.ParsedEventLog()
	if err == nil {
		result["event_count"] = len(events)
	}

	return result, nil
}

// TPMCapabilities retrieves TPM capabilities.
func (p *MCPServiceProvider) TPMCapabilities(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	props, err := p.tpm2Service.FixedProperties()
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"manufacturer":    props.Manufacturer,
		"model":           props.Model,
		"family":          props.Family,
		"revision":        props.Revision,
		"vendor_id":       props.VendorID,
		"fw_major":        props.FwMajor,
		"fw_minor":        props.FwMinor,
		"fips_mode":       props.Fips1402,
		"lockout_counter": props.LockoutCounter,
		"max_auth_fail":   props.MaxAuthFail,
		"max_nvram_size":  props.NVBufferMax,
	}

	return result, nil
}

// TPMRandom generates random bytes from the TPM.
func (p *MCPServiceProvider) TPMRandom(ctx context.Context, numBytes int) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	if numBytes <= 0 {
		numBytes = 32
	}
	if numBytes > 1024 {
		return nil, ErrTPMInvalidSize{Max: 1024, Requested: numBytes}
	}

	random, err := p.tpm2Service.RandomBytes(numBytes)
	if err != nil {
		return nil, mapTPMError(err)
	}
	return random, nil
}

// TPMSeal seals data to the TPM.
//
// It runs the gRPC Seal, so the PCR policy, CN and password apply and the
// answer is the same encoded TPM2B_PUBLIC/TPM2B_PRIVATE payload. It used to
// call Seal with no options and return the SealedData ciphertext, which a
// TPM seal never fills: every seal answered success with empty sealed_data
// and ignored the PCRs it was given (#304).
func (p *MCPServiceProvider) TPMSeal(ctx context.Context, data []byte, pcrs []uint32, cn, password string) ([]byte, error) {
	svc, err := p.tpmQuotes().service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Seal(ctx, &platformv1.SealRequest{
		Data:       data,
		PcrIndices: pcrs,
		Cn:         cn,
		Password:   password,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetSealedData(), nil
}

// TPMUnseal unseals data from the TPM.
//
// It runs the gRPC Unseal. It used to pass SealedData without a backend,
// which the SDK refuses as a backend mismatch, so no unseal ever succeeded
// (#304).
func (p *MCPServiceProvider) TPMUnseal(ctx context.Context, cn, password string) ([]byte, error) {
	svc, err := p.tpmQuotes().service()
	if err != nil {
		return nil, err
	}
	resp, err := svc.Unseal(ctx, &platformv1.UnsealRequest{Cn: cn, Password: password})
	if err != nil {
		return nil, err
	}
	return resp.GetData(), nil
}

// TPMCertify certifies a TPM key.
func (p *MCPServiceProvider) TPMCertify(ctx context.Context, keyHandle int) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	// Key certification requires additional context (which AK to use, qualifying data)
	// Not yet fully implemented in the gRPC service either
	return nil, ErrTPMOperationNotImplemented{Operation: "Certify"}
}

// TPMNVList lists the NV indexes defined on the TPM, from the same
// FixedProperties inventory the QUIC and gRPC transports report.
func (p *MCPServiceProvider) TPMNVList(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	props, err := p.tpm2Service.FixedProperties()
	if err != nil {
		return nil, err
	}

	indexes := make([]map[string]interface{}, 0, len(props.NVIndexes))
	for _, ix := range props.NVIndexes {
		indexes = append(indexes, map[string]interface{}{
			"handle":     uint32(ix.Handle),
			"type":       ix.Type,
			"size":       uint32(ix.Size),
			"auth_read":  ix.AuthRead,
			"auth_write": ix.AuthWrite,
		})
	}

	return map[string]interface{}{"indexes": indexes}, nil
}

// TPMNVRead reads size bytes (the whole index when 0) at offset from an
// NV index through the shared tpmnv layer.
func (p *MCPServiceProvider) TPMNVRead(ctx context.Context, index uint32, size, offset uint16, password string) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	return tpmnv.Read(p.tpm2Service.Transport(), index, size, offset, tpmnv.Password(password))
}

// TPMNVWrite writes data at offset to an NV index through the shared
// tpmnv layer.
func (p *MCPServiceProvider) TPMNVWrite(ctx context.Context, index uint32, data []byte, offset uint16, password string) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	if err := tpmnv.Write(p.tpm2Service.Transport(), index, data, offset, tpmnv.Password(password)); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("wrote %d bytes to NV index 0x%08X", len(data), index),
	}, nil
}

// TPMNVDelete undefines an NV index under the owner hierarchy, which
// parentPassword authorizes, through the shared tpmnv layer.
func (p *MCPServiceProvider) TPMNVDelete(ctx context.Context, index uint32, parentPassword string) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	if err := tpmnv.Undefine(p.tpm2Service.Transport(), index, tpmnv.Password(parentPassword)); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("NV index 0x%08X undefined", index),
	}, nil
}

// TPMPlatform retrieves platform-level TPM attributes.
func (p *MCPServiceProvider) TPMPlatform(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	cfg := p.tpm2Service.Config()
	result := map[string]interface{}{
		"available": true,
	}

	if cfg != nil {
		result["is_simulator"] = cfg.UseSimulator
		result["device"] = cfg.Device
	}

	// Include EK info if available
	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err == nil {
		result["ek_handle"] = uint32(ekAttrs.TPMAttributes.Handle)
		result["ek_algorithm"] = ekAttrs.KeyAlgorithm.String()
	}

	// Include SRK info if available
	srkAttrs, err := p.tpm2Service.SSRKAttributes()
	if err == nil {
		result["srk_handle"] = uint32(srkAttrs.TPMAttributes.Handle)
		result["srk_algorithm"] = srkAttrs.KeyAlgorithm.String()
	}

	// Include IAK info if available
	iakAttrs, err := p.tpm2Service.IAKAttributes()
	if err == nil {
		result["iak_handle"] = uint32(iakAttrs.TPMAttributes.Handle)
		result["iak_algorithm"] = iakAttrs.KeyAlgorithm.String()
	}

	return result, nil
}

// TPMMakeCredential creates a TPM2_MakeCredential challenge, delegating to
// the shared makeCredential path so every transport routes identically.
func (p *MCPServiceProvider) TPMMakeCredential(ctx context.Context, akName, secret, ekCert, iakPub []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	credentialBlob, encryptedSecret, plaintextSecret, err := makeCredential(p.tpm2Service, akName, secret, ekCert, iakPub)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"credential_blob":  base64.StdEncoding.EncodeToString(credentialBlob),
		"encrypted_secret": base64.StdEncoding.EncodeToString(encryptedSecret),
		"secret":           base64.StdEncoding.EncodeToString(plaintextSecret),
	}, nil
}

// TPMActivateCredential activates a TPM2_MakeCredential challenge, delegating
// to the shared activateCredential path.
func (p *MCPServiceProvider) TPMActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	secret, err := activateCredential(p.tpm2Service, credentialBlob, encryptedSecret)
	if err != nil {
		return nil, mapTPMError(err)
	}

	return map[string]interface{}{
		"secret": base64.StdEncoding.EncodeToString(secret),
	}, nil
}
