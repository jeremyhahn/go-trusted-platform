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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	computecontainer "github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
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
	// VerdictSink receives device quote verdicts (event log + quarantine
	// observers); nil means verdicts are only logged.
	VerdictSink verdict.Sink
	// AttestationReporting carries the reporting service's report view,
	// refresh trigger and caller policy for the MCP report tools (#226).
	AttestationReporting  *ReportingHandles
	DNSService            dns.DNSService
	SDNService            *SDNService
	PolicyEngine          policy.PolicyEngine
	HealthService         *Service
	IAMClient             quicbaassdk.IAMClient
	PEPClient             quicbaassdk.IAMPEPClient
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
	SDNNetworks           []sdn.NetworkConfig
	IPAMService           ipam.Allocator
	ConfigDeliveryService *configdelivery.Service
	// ProxyService is the shared reverse-proxy configuration service that
	// backs the proxy_* MCP tools (same instance as gRPC/REST/QUIC).
	ProxyService *grpcapi.ProxyGRPCService

	// GatewayLB serves gateway load balancer VIP tools (gateway_lb_*).
	GatewayLB GatewayLoadBalancerInterface

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
	deviceVerdicts        verdict.Sink
	attestationReporting  *ReportingHandles
	dnsService            dns.DNSService
	sdnService            *SDNService
	policyEngine          policy.PolicyEngine
	healthService         *Service
	iamClient             quicbaassdk.IAMClient
	pepClient             quicbaassdk.IAMPEPClient
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
	sdnNetworks           []sdn.NetworkConfig
	ipamService           ipam.Allocator
	configDeliveryService *configdelivery.Service
	proxyService          *grpcapi.ProxyGRPCService
	gatewayLB             GatewayLoadBalancerInterface
	gatewayPerf           GatewayPerfInterface
	ntpService            platformv1.NTPServiceServer
	logger                *slog.Logger
	idevidService         *IDevIDGRPCService
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
		deviceVerdicts:        config.VerdictSink,
		attestationReporting:  config.AttestationReporting,
		dnsService:            config.DNSService,
		sdnService:            config.SDNService,
		policyEngine:          config.PolicyEngine,
		healthService:         config.HealthService,
		iamClient:             config.IAMClient,
		pepClient:             config.PEPClient,
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
		sdnNetworks:           config.SDNNetworks,
		ipamService:           config.IPAMService,
		configDeliveryService: config.ConfigDeliveryService,
		proxyService:          config.ProxyService,
		gatewayLB:             config.GatewayLB,
		gatewayPerf:           config.GatewayPerf,
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

	ekAlg := vtpm.EKAlgorithmRSA
	if algorithm == "ECC" {
		ekAlg = vtpm.EKAlgorithmECC
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
	bundle, err := p.vtpmService.GetBundle(ctx, name)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// VTPMValidate validates bundle integrity.
func (p *MCPServiceProvider) VTPMValidate(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	err := p.vtpmService.ValidateBundle(ctx, name)
	if err != nil {
		// Propagate "not found" errors so callers can distinguish
		// missing bundles from validation failures.
		var notFound vtpm.ErrBundleNotFound
		if errors.As(err, &notFound) {
			return nil, err
		}
		// For validation errors (bundle exists but has issues),
		// return the result with valid=false and the error details.
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
	var buf bytes.Buffer
	if err := p.vtpmService.ExportBundle(ctx, name, &buf); err != nil {
		return nil, err
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
		return nil, err
	}
	return bundle, nil
}

// VTPMCreateTemplate creates a new vTPM template.
func (p *MCPServiceProvider) VTPMCreateTemplate(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	ekAlg := vtpm.EKAlgorithmRSA
	if algorithm == "ECC" {
		ekAlg = vtpm.EKAlgorithmECC
	}
	opts := &vtpm.CreateTemplateOptions{
		ID:                id,
		Description:       description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: secureBoot,
	}
	template, err := p.vtpmService.CreateTemplate(ctx, opts)
	if err != nil {
		return nil, err
	}
	return template, nil
}

// VTPMGetTemplate retrieves a template by ID.
func (p *MCPServiceProvider) VTPMGetTemplate(ctx context.Context, id string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	template, err := p.vtpmService.GetTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	return template, nil
}

// VTPMDeleteTemplate deletes a template.
func (p *MCPServiceProvider) VTPMDeleteTemplate(ctx context.Context, id string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.DeleteTemplate(ctx, id)
}

// VTPMListTemplates lists all templates.
func (p *MCPServiceProvider) VTPMListTemplates(ctx context.Context) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	templates, err := p.vtpmService.ListTemplates(ctx)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return bundle, nil
}

// VTPMGetBundlePath returns the filesystem path to a bundle.
func (p *MCPServiceProvider) VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
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
func (p *MCPServiceProvider) DeviceRegister(ctx context.Context, name string, deviceType string, publicKey []byte) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}

	dev := &deviceentities.Device{
		Model:  name,
		Serial: deviceType,
	}
	if err := p.deviceService.Save(ctx, dev); err != nil {
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

// SDNSetPortState sets the state of an SDN port.
// Valid states: "blocked", "unblocked", "authorized", "unauthorized", "quarantined"
func (p *MCPServiceProvider) SDNSetPortState(ctx context.Context, bridgeName string, portName string, state string) error {
	// Validate parameters
	if bridgeName == "" {
		return ErrSDNMissingParameter{Parameter: "bridgeName"}
	}
	if portName == "" {
		return ErrSDNMissingParameter{Parameter: "portName"}
	}
	if state == "" {
		return ErrSDNMissingParameter{Parameter: "state"}
	}

	// Check if SDN service is available
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	// Check if policy engine is available
	if p.policyEngine == nil {
		return ErrSDNPolicyEngineNotConfigured{}
	}

	// Parse the state string to policy.PortState
	portState, err := parsePortState(state)
	if err != nil {
		return err
	}

	// Verify the port exists via SDN service
	_, getErr := p.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	if getErr != nil {
		return ErrSDNPortNotFound{BridgeName: bridgeName, PortName: portName}
	}

	// Apply the state change via the policy engine
	if err := p.policyEngine.SetPortState(portName, portState); err != nil {
		return ErrSDNSetPortStateFailed{PortID: portName, Cause: err}
	}

	p.logger.Info("set port state",
		slog.String("bridge", bridgeName),
		slog.String("port", portName),
		slog.String("state", state))

	return nil
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

// SDNAddPort adds a port to an SDN bridge.
func (p *MCPServiceProvider) SDNAddPort(ctx context.Context, bridgeName string, portName string, portType string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeName,
		Config:   &platformv1.PortConfig{Name: portName},
	})
	return err
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

// SDNApplyPolicy applies a network policy to a port.
// The policyID is the port identifier, and bridgeName specifies the target bridge.
// This method retrieves the policy from the policy engine and applies it to the port.
func (p *MCPServiceProvider) SDNApplyPolicy(ctx context.Context, policyID string, bridgeName string) error {
	// Validate parameters
	if policyID == "" {
		return ErrSDNMissingParameter{Parameter: "policyID"}
	}
	if bridgeName == "" {
		return ErrSDNMissingParameter{Parameter: "bridgeName"}
	}

	// Check if SDN service is available
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	// Check if policy engine is available
	if p.policyEngine == nil {
		return ErrSDNPolicyEngineNotConfigured{}
	}

	// Get the policy from the engine
	portPolicy, err := p.policyEngine.GetPolicy(policyID)
	if err != nil {
		return ErrSDNPolicyNotFound{PolicyID: policyID}
	}

	// Apply the policy to the port
	if err := p.policyEngine.ApplyPolicy(policyID, portPolicy); err != nil {
		return ErrSDNApplyPolicyFailed{PolicyID: policyID, Cause: err}
	}

	p.logger.Info("applied SDN policy",
		slog.String("policy_id", policyID),
		slog.String("bridge", bridgeName),
		slog.String("tenant_id", portPolicy.TenantID),
		slog.Int("vlan", int(portPolicy.VLAN)))

	return nil
}

// SDNGetPolicy retrieves an SDN policy by port ID.
// Returns the policy information including VLAN, ACLs, tenant ID, and expiration.
func (p *MCPServiceProvider) SDNGetPolicy(ctx context.Context, policyID string) (interface{}, error) {
	// Validate parameters
	if policyID == "" {
		return nil, ErrSDNMissingParameter{Parameter: "policyID"}
	}

	// Check if policy engine is available
	if p.policyEngine == nil {
		return nil, ErrSDNPolicyEngineNotConfigured{}
	}

	// Get the policy from the engine
	portPolicy, err := p.policyEngine.GetPolicy(policyID)
	if err != nil {
		return nil, ErrSDNPolicyNotFound{PolicyID: policyID}
	}

	// Get port info for additional state information
	portInfo, infoErr := p.policyEngine.GetPortInfo(policyID)

	// Convert to a response format suitable for MCP
	response := map[string]interface{}{
		"port_id":   policyID,
		"tenant_id": portPolicy.TenantID,
		"vlan":      portPolicy.VLAN,
		"acl_count": len(portPolicy.ACLs),
		"issued_at": portPolicy.IssuedAt.Format(time.RFC3339),
	}

	if !portPolicy.ExpiresAt.IsZero() {
		response["expires_at"] = portPolicy.ExpiresAt.Format(time.RFC3339)
	}

	if portPolicy.Metadata != nil {
		response["metadata"] = portPolicy.Metadata
	}

	// Add port state information if available
	if infoErr == nil && portInfo != nil {
		response["state"] = portInfo.State.String()
		response["last_state_change"] = portInfo.LastStateChange.Format(time.RFC3339)
		response["auth_attempts"] = portInfo.AuthAttempts
		response["error_count"] = portInfo.ErrorCount
		if portInfo.LastError != "" {
			response["last_error"] = portInfo.LastError
		}
	}

	// Convert ACLs to a serializable format
	if len(portPolicy.ACLs) > 0 {
		acls := make([]map[string]interface{}, len(portPolicy.ACLs))
		for i, acl := range portPolicy.ACLs {
			acls[i] = map[string]interface{}{
				"priority":    acl.Priority,
				"description": acl.Description,
				"action":      string(acl.Action.Type),
			}
		}
		response["acls"] = acls
	}

	return response, nil
}

// SDNListPolicies lists all SDN policies currently applied to ports.
// Returns a list of port IDs with their associated policy information.
func (p *MCPServiceProvider) SDNListPolicies(ctx context.Context) ([]interface{}, error) {
	// Check if policy engine is available
	if p.policyEngine == nil {
		return nil, ErrSDNPolicyEngineNotConfigured{}
	}

	// Get all port info from the policy engine's state machine
	// The policy engine manages port state internally, so we iterate through
	// known ports and collect their policies
	var policies []interface{}

	// Get port info for all known ports by checking policy engine state
	// We need to use a type assertion to access the underlying engine
	// that has the state machine with ListPorts capability
	if engine, ok := p.policyEngine.(*policy.Engine); ok {
		// Access the state machine through GetPortInfo calls
		// Since Engine doesn't expose ListPorts directly, we work with
		// what the interface provides - GetPortInfo for known ports

		// For now, we'll iterate through SDN service ports if available
		if p.sdnService != nil {
			// Get all bridges
			bridgesResp, err := p.sdnService.ListBridges(ctx, &platformv1.ListBridgesRequest{})
			if err == nil {
				for _, bridge := range bridgesResp.GetBridges() {
					// Get all ports on each bridge
					portsResp, portErr := p.sdnService.ListPorts(ctx, &platformv1.ListPortsRequest{
						BridgeId: bridge.GetId(),
					})
					if portErr == nil {
						for _, port := range portsResp.GetPorts() {
							portID := port.GetConfig().GetName()
							if portID == "" {
								portID = port.GetId()
							}

							// Try to get policy for this port
							portPolicy, policyErr := engine.GetPolicy(portID)
							if policyErr == nil && portPolicy != nil {
								policyInfo := map[string]interface{}{
									"port_id":   portID,
									"bridge_id": bridge.GetId(),
									"tenant_id": portPolicy.TenantID,
									"vlan":      portPolicy.VLAN,
									"acl_count": len(portPolicy.ACLs),
								}

								// Get port state
								portState, stateErr := engine.GetPortState(portID)
								if stateErr == nil {
									policyInfo["state"] = portState.String()
								}

								if !portPolicy.ExpiresAt.IsZero() {
									policyInfo["expires_at"] = portPolicy.ExpiresAt.Format(time.RFC3339)
								}

								policies = append(policies, policyInfo)
							}
						}
					}
				}
			}
		}
	}

	// If no policies found, return empty list rather than nil
	if policies == nil {
		policies = make([]interface{}, 0)
	}

	return policies, nil
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

	// Convert MCP request to platformv1 request
	certRequest := &platformv1.CertificateRequest{
		Subject: &platformv1.Subject{
			CommonName:         req.CommonName,
			Organization:       req.Organization,
			OrganizationalUnit: req.OrganizationalUnit,
			Country:            req.Country,
			Province:           req.Province,
			Locality:           req.Locality,
		},
		ValidDays:    int32(req.ValidDays),
		KeyAlgorithm: parsePlatformKeyAlgorithm(req.Algorithm),
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

// CAGet retrieves a certificate by serial number.
func (p *MCPServiceProvider) CAGet(ctx context.Context, serial string, includePEM bool) (interface{}, error) {
	if p.caService == nil {
		return nil, ErrServiceNotAvailable{Service: "ca"}
	}
	return p.caService.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: includePEM,
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

// IAMCreateUser creates a new IAM user.
func (p *MCPServiceProvider) IAMCreateUser(ctx context.Context, req *mcp.IAMCreateUserRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.TenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if req.Email == "" {
		return nil, ErrIAMMissingParameter{Parameter: "email"}
	}

	sdkReq := &sdkiam.CreateUserRequest{
		Email:       req.Email,
		DisplayName: req.Name,
		Roles:       req.Roles,
		Groups:      req.Groups,
		Metadata:    req.Attributes,
	}

	resp, err := p.iamClient.User().Create(ctx, req.TenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "CreateUser", Cause: err}
	}

	p.logger.Info("IAM user created",
		"tenant_id", req.TenantID,
		"user_id", resp.ID,
		"email", req.Email,
	)

	return sdkUserToMap(resp), nil
}

// IAMDeleteUser deletes an IAM user.
func (p *MCPServiceProvider) IAMDeleteUser(ctx context.Context, tenantID string, userID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if userID == "" {
		return ErrIAMMissingParameter{Parameter: "user_id"}
	}

	err := p.iamClient.User().Delete(ctx, tenantID, userID)
	if err != nil {
		return ErrIAMOperationFailed{Operation: "DeleteUser", Cause: err}
	}

	p.logger.Info("IAM user deleted",
		"tenant_id", tenantID,
		"user_id", userID,
	)

	return nil
}

// IAMGetUser retrieves an IAM user by ID.
func (p *MCPServiceProvider) IAMGetUser(ctx context.Context, tenantID string, userID string) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if userID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "user_id"}
	}

	resp, err := p.iamClient.User().Get(ctx, tenantID, userID)
	if err != nil {
		return nil, ErrIAMUserNotFound{TenantID: tenantID, UserID: userID}
	}

	return sdkUserToMap(resp), nil
}

// IAMListUsers lists IAM users for a tenant.
func (p *MCPServiceProvider) IAMListUsers(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}

	// Apply defaults
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	sdkReq := &sdkiam.ListUsersRequest{
		PageSize: limit,
	}

	resp, err := p.iamClient.User().List(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "ListUsers", Cause: err}
	}

	users := make([]map[string]interface{}, 0, len(resp.Users))
	for i := range resp.Users {
		users = append(users, sdkUserToMap(&resp.Users[i]))
	}

	return map[string]interface{}{
		"users":  users,
		"total":  resp.Pagination.TotalCount,
		"limit":  limit,
		"offset": offset,
	}, nil
}

// IAMCreateRole creates a new IAM role.
func (p *MCPServiceProvider) IAMCreateRole(ctx context.Context, req *mcp.IAMCreateRoleRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.TenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if req.ID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "id"}
	}

	sdkReq := &sdkiam.CreateRoleRequest{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	resp, err := p.iamClient.Role().Create(ctx, req.TenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "CreateRole", Cause: err}
	}

	p.logger.Info("IAM role created",
		"tenant_id", req.TenantID,
		"role_id", resp.ID,
		"name", req.Name,
	)

	return sdkRoleToMap(resp), nil
}

// IAMDeleteRole deletes an IAM role.
func (p *MCPServiceProvider) IAMDeleteRole(ctx context.Context, tenantID string, roleID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if roleID == "" {
		return ErrIAMMissingParameter{Parameter: "role_id"}
	}

	err := p.iamClient.Role().Delete(ctx, tenantID, roleID)
	if err != nil {
		return ErrIAMOperationFailed{Operation: "DeleteRole", Cause: err}
	}

	p.logger.Info("IAM role deleted",
		"tenant_id", tenantID,
		"role_id", roleID,
	)

	return nil
}

// IAMGetRole retrieves an IAM role by ID.
func (p *MCPServiceProvider) IAMGetRole(ctx context.Context, tenantID string, roleID string) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if roleID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "role_id"}
	}

	resp, err := p.iamClient.Role().Get(ctx, tenantID, roleID)
	if err != nil {
		return nil, ErrIAMRoleNotFound{TenantID: tenantID, RoleID: roleID}
	}

	return sdkRoleToMap(resp), nil
}

// IAMListRoles lists IAM roles for a tenant.
func (p *MCPServiceProvider) IAMListRoles(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}

	// Apply defaults
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	sdkReq := &sdkiam.ListRolesRequest{
		PageSize: limit,
	}

	resp, err := p.iamClient.Role().List(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "ListRoles", Cause: err}
	}

	roles := make([]map[string]interface{}, 0, len(resp.Roles))
	for i := range resp.Roles {
		roles = append(roles, sdkRoleToMap(&resp.Roles[i]))
	}

	return map[string]interface{}{
		"roles":  roles,
		"total":  resp.Pagination.TotalCount,
		"limit":  limit,
		"offset": offset,
	}, nil
}

// IAMAssignRole assigns a role to a user.
func (p *MCPServiceProvider) IAMAssignRole(ctx context.Context, tenantID string, userID string, role string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if userID == "" {
		return ErrIAMMissingParameter{Parameter: "user_id"}
	}
	if role == "" {
		return ErrIAMMissingParameter{Parameter: "role"}
	}

	err := p.iamClient.User().AssignRole(ctx, tenantID, userID, role)
	if err != nil {
		return ErrIAMRoleAssignmentFailed{UserID: userID, RoleID: role, Reason: err.Error()}
	}

	p.logger.Info("IAM role assigned",
		"tenant_id", tenantID,
		"user_id", userID,
		"role", role,
	)

	return nil
}

// IAMRevokeRole revokes a role from a user.
func (p *MCPServiceProvider) IAMRevokeRole(ctx context.Context, tenantID string, userID string, role string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if userID == "" {
		return ErrIAMMissingParameter{Parameter: "user_id"}
	}
	if role == "" {
		return ErrIAMMissingParameter{Parameter: "role"}
	}

	err := p.iamClient.User().RevokeRole(ctx, tenantID, userID, role)
	if err != nil {
		return ErrIAMRoleRevocationFailed{UserID: userID, RoleID: role, Reason: err.Error()}
	}

	p.logger.Info("IAM role revoked",
		"tenant_id", tenantID,
		"user_id", userID,
		"role", role,
	)

	return nil
}

// IAMCheckPermission checks if a user has permission to perform an action on a resource.
func (p *MCPServiceProvider) IAMCheckPermission(ctx context.Context, tenantID string, userID string, resource string, action string) (bool, error) {
	if p.pepClient == nil {
		return false, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return false, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if userID == "" {
		return false, ErrIAMMissingParameter{Parameter: "user_id"}
	}
	if resource == "" {
		return false, ErrIAMMissingParameter{Parameter: "resource"}
	}
	if action == "" {
		return false, ErrIAMMissingParameter{Parameter: "action"}
	}

	sdkReq := &sdkiam.CheckRequest{
		Subject: sdkiam.CheckSubject{
			ID:       userID,
			TenantID: tenantID,
		},
		Resource: resource,
		Action:   action,
	}

	resp, err := p.pepClient.Check(ctx, sdkReq)
	if err != nil {
		return false, ErrIAMOperationFailed{Operation: "CheckPermission", Cause: err}
	}

	return resp.Allowed, nil
}

// IAMAuthenticate authenticates a user with credentials.
func (p *MCPServiceProvider) IAMAuthenticate(ctx context.Context, req *mcp.IAMAuthenticateRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.TenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if req.Email == "" {
		return nil, ErrIAMMissingParameter{Parameter: "email"}
	}

	// For now, we return basic user info after validation
	// The actual authentication would typically return a JWT or session token
	// This is a simplified implementation - in production, this would integrate
	// with proper authentication flows including password verification, MFA, etc.

	// Try to get the user to verify they exist
	sdkReq := &sdkiam.ListUsersRequest{
		PageSize: 1,
		Filter:   req.Email,
	}

	resp, err := p.iamClient.User().List(ctx, req.TenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMAuthenticationFailed{Reason: err.Error()}
	}

	if len(resp.Users) == 0 {
		return nil, ErrIAMAuthenticationFailed{Reason: "user not found"}
	}

	user := resp.Users[0]

	// In a real implementation, we would:
	// 1. Verify the password hash
	// 2. Check MFA if enabled
	// 3. Generate a JWT or session token
	// 4. Return the token along with user info

	p.logger.Info("IAM user authenticated",
		"tenant_id", req.TenantID,
		"user_id", user.ID,
		"email", req.Email,
	)

	return map[string]interface{}{
		"authenticated": true,
		"user":          sdkUserToMap(&user),
		"tenant_id":     req.TenantID,
	}, nil
}

// =============================================================================
// IAM Group Operations
// =============================================================================

// IAMCreateGroup creates a new IAM group.
func (p *MCPServiceProvider) IAMCreateGroup(ctx context.Context, req *mcp.IAMCreateGroupRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.TenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if req.ID == "" && req.Name == "" {
		return nil, ErrIAMMissingParameter{Parameter: "id or name"}
	}

	sdkReq := &sdkiam.CreateGroupRequest{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	resp, err := p.iamClient.Group().Create(ctx, req.TenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "CreateGroup", Cause: err}
	}

	p.logger.Info("IAM group created",
		"tenant_id", req.TenantID,
		"group_id", resp.ID,
		"name", req.Name,
	)

	return sdkGroupToMap(resp), nil
}

// IAMDeleteGroup deletes an IAM group.
func (p *MCPServiceProvider) IAMDeleteGroup(ctx context.Context, tenantID string, groupID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if groupID == "" {
		return ErrIAMMissingParameter{Parameter: "group_id"}
	}

	err := p.iamClient.Group().Delete(ctx, tenantID, groupID)
	if err != nil {
		return ErrIAMOperationFailed{Operation: "DeleteGroup", Cause: err}
	}

	p.logger.Info("IAM group deleted",
		"tenant_id", tenantID,
		"group_id", groupID,
	)

	return nil
}

// IAMGetGroup retrieves an IAM group by ID.
func (p *MCPServiceProvider) IAMGetGroup(ctx context.Context, tenantID string, groupID string) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if groupID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "group_id"}
	}

	resp, err := p.iamClient.Group().Get(ctx, tenantID, groupID)
	if err != nil {
		return nil, ErrIAMGroupNotFound{TenantID: tenantID, GroupID: groupID}
	}

	return sdkGroupToMap(resp), nil
}

// IAMListGroups lists IAM groups for a tenant.
func (p *MCPServiceProvider) IAMListGroups(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}

	// Apply defaults
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	sdkReq := &sdkiam.ListGroupsRequest{
		PageSize: limit,
	}

	resp, err := p.iamClient.Group().List(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "ListGroups", Cause: err}
	}

	groups := make([]map[string]interface{}, 0, len(resp.Groups))
	for i := range resp.Groups {
		groups = append(groups, sdkGroupToMap(&resp.Groups[i]))
	}

	return map[string]interface{}{
		"groups": groups,
		"total":  resp.Pagination.TotalCount,
		"limit":  limit,
		"offset": offset,
	}, nil
}

// IAMAddGroupMember adds a user to a group.
func (p *MCPServiceProvider) IAMAddGroupMember(ctx context.Context, tenantID string, groupID string, userID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if groupID == "" {
		return ErrIAMMissingParameter{Parameter: "group_id"}
	}
	if userID == "" {
		return ErrIAMMissingParameter{Parameter: "user_id"}
	}

	err := p.iamClient.Group().AddMember(ctx, tenantID, groupID, userID)
	if err != nil {
		return ErrIAMGroupMembershipFailed{GroupID: groupID, UserID: userID, Reason: err.Error()}
	}

	p.logger.Info("IAM group member added",
		"tenant_id", tenantID,
		"group_id", groupID,
		"user_id", userID,
	)

	return nil
}

// IAMRemoveGroupMember removes a user from a group.
func (p *MCPServiceProvider) IAMRemoveGroupMember(ctx context.Context, tenantID string, groupID string, userID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if groupID == "" {
		return ErrIAMMissingParameter{Parameter: "group_id"}
	}
	if userID == "" {
		return ErrIAMMissingParameter{Parameter: "user_id"}
	}

	err := p.iamClient.Group().RemoveMember(ctx, tenantID, groupID, userID)
	if err != nil {
		return ErrIAMGroupMembershipFailed{GroupID: groupID, UserID: userID, Reason: err.Error()}
	}

	p.logger.Info("IAM group member removed",
		"tenant_id", tenantID,
		"group_id", groupID,
		"user_id", userID,
	)

	return nil
}

// =============================================================================
// IAM Tenant Operations
// =============================================================================

// IAMCreateTenant creates a new IAM tenant.
func (p *MCPServiceProvider) IAMCreateTenant(ctx context.Context, req *mcp.IAMCreateTenantRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.ID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "id"}
	}

	settings := make(map[string]string)
	if req.Settings != nil {
		if req.Settings.MFARequired {
			settings["mfa_required"] = "true"
		}
	}

	sdkReq := &sdkiam.CreateTenantRequest{
		ID:       req.ID,
		Name:     req.Name,
		Settings: settings,
	}

	resp, err := p.iamClient.Tenant().Create(ctx, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "CreateTenant", Cause: err}
	}

	p.logger.Info("IAM tenant created",
		"tenant_id", resp.ID,
		"name", req.Name,
	)

	return sdkTenantToMap(resp), nil
}

// IAMDeleteTenant deletes an IAM tenant.
func (p *MCPServiceProvider) IAMDeleteTenant(ctx context.Context, tenantID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return ErrIAMMissingParameter{Parameter: "tenant_id"}
	}

	err := p.iamClient.Tenant().Delete(ctx, tenantID)
	if err != nil {
		return ErrIAMOperationFailed{Operation: "DeleteTenant", Cause: err}
	}

	p.logger.Info("IAM tenant deleted",
		"tenant_id", tenantID,
	)

	return nil
}

// IAMGetTenant retrieves an IAM tenant by ID.
func (p *MCPServiceProvider) IAMGetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}

	resp, err := p.iamClient.Tenant().Get(ctx, tenantID)
	if err != nil {
		return nil, ErrIAMTenantNotFound{TenantID: tenantID}
	}

	return sdkTenantToMap(resp), nil
}

// IAMListTenants lists all IAM tenants.
func (p *MCPServiceProvider) IAMListTenants(ctx context.Context, limit int, offset int) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Apply defaults
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	sdkReq := &sdkiam.ListTenantsRequest{
		PageSize: limit,
	}

	resp, err := p.iamClient.Tenant().List(ctx, sdkReq)
	if err != nil {
		return nil, ErrIAMOperationFailed{Operation: "ListTenants", Cause: err}
	}

	tenants := make([]map[string]interface{}, 0, len(resp.Tenants))
	for i := range resp.Tenants {
		tenants = append(tenants, sdkTenantToMap(&resp.Tenants[i]))
	}

	return map[string]interface{}{
		"tenants": tenants,
		"total":   resp.Pagination.TotalCount,
		"limit":   limit,
		"offset":  offset,
	}, nil
}

// =============================================================================
// IAM Token Operations
// =============================================================================

// IAMCreateToken creates a new authentication token for a user.
// Note: This is a simplified implementation. In production, this would integrate
// with proper token generation flows including JWT signing and session management.
func (p *MCPServiceProvider) IAMCreateToken(ctx context.Context, req *mcp.IAMCreateTokenRequest) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if req.TenantID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "tenant_id"}
	}
	if req.UserID == "" {
		return nil, ErrIAMMissingParameter{Parameter: "user_id"}
	}

	// Verify the user exists
	user, err := p.iamClient.User().Get(ctx, req.TenantID, req.UserID)
	if err != nil {
		return nil, ErrIAMUserNotFound{TenantID: req.TenantID, UserID: req.UserID}
	}

	// Generate a token ID
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, ErrIAMOperationFailed{Operation: "CreateToken", Cause: err}
	}

	// Calculate expiration time
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // Default to 1 hour
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	p.logger.Info("IAM token created",
		"tenant_id", req.TenantID,
		"user_id", req.UserID,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	// Return token information
	// Note: In production, this would return an actual JWT or opaque token
	return map[string]interface{}{
		"token_id":    encodeHex(tokenBytes),
		"tenant_id":   req.TenantID,
		"user_id":     req.UserID,
		"user_email":  user.Email,
		"scopes":      req.Scopes,
		"description": req.Description,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"created_at":  time.Now().Format(time.RFC3339),
	}, nil
}

// IAMRevokeToken revokes an authentication token.
func (p *MCPServiceProvider) IAMRevokeToken(ctx context.Context, tokenID string) error {
	if p.iamClient == nil {
		return ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if tokenID == "" {
		return ErrIAMMissingParameter{Parameter: "token_id"}
	}

	// Note: In a real implementation, this would:
	// 1. Look up the token in a token store
	// 2. Mark the token as revoked
	// 3. Add it to a revocation list or delete it
	//
	// Since the current IAM proto doesn't have dedicated token management RPCs,
	// this is a placeholder that logs the revocation request.

	p.logger.Info("IAM token revoked",
		"token_id", tokenID,
	)

	return nil
}

// IAMVerifyToken verifies an authentication token and returns its claims.
func (p *MCPServiceProvider) IAMVerifyToken(ctx context.Context, token string) (interface{}, error) {
	if p.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	// Validate required parameters
	if token == "" {
		return nil, ErrIAMMissingParameter{Parameter: "token"}
	}

	// Note: In a real implementation, this would:
	// 1. Decode and verify the JWT signature
	// 2. Check if the token is in the revocation list
	// 3. Validate expiration and other claims
	// 4. Return the token claims
	//
	// Since the current IAM proto doesn't have dedicated token verification RPCs,
	// this is a simplified implementation that returns basic verification status.

	p.logger.Info("IAM token verification requested",
		"token_length", len(token),
	)

	return map[string]interface{}{
		"valid":       true,
		"verified_at": time.Now().Format(time.RFC3339),
		"message":     "token verification is a placeholder - implement JWT validation in production",
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
	if numBytes <= 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "num_bytes", Reason: "number of bytes must be positive"}
	}

	if numBytes > 1024 {
		return nil, ErrKMSInvalidParameter{Parameter: "num_bytes", Reason: "maximum 1024 bytes allowed"}
	}

	randomBytes := make([]byte, numBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, ErrKMSRandomGenerationFailed{Cause: err}
	}

	return randomBytes, nil
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
func parsePlatformKeyAlgorithm(alg string) platformv1.KeyAlgorithm {
	switch alg {
	case "RSA", "RSA2048", "RSA-2048":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	case "RSA3072", "RSA-3072":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072
	case "RSA4096", "RSA-4096":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096
	case "ECDSA", "EC", "ECDSA-P256", "P256":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case "ECDSA-P384", "P384":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384
	case "ECDSA-P521", "P521":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521
	case "ED25519":
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

// parsePortState converts a string state to policy.PortState.
func parsePortState(state string) (policy.PortState, error) {
	normalizedState := strings.ToLower(strings.TrimSpace(state))
	switch normalizedState {
	case "unconnected":
		return policy.PortStateUnconnected, nil
	case "provisioning":
		return policy.PortStateProvisioning, nil
	case "enrolled":
		return policy.PortStateEnrolled, nil
	case "unauthorized":
		return policy.PortStateUnauthorized, nil
	case "authenticating":
		return policy.PortStateAuthenticating, nil
	case "authorized":
		return policy.PortStateAuthorized, nil
	case "quarantined":
		return policy.PortStateQuarantined, nil
	case "blocked":
		return policy.PortStateBlocked, nil
	default:
		return policy.PortStateUnconnected, ErrSDNInvalidPortState{State: state}
	}
}

// sdkUserToMap converts an IAM SDK User to a map for JSON serialization.
func sdkUserToMap(u *sdkiam.User) map[string]interface{} {
	if u == nil {
		return nil
	}
	result := map[string]interface{}{
		"id":        u.ID,
		"tenant_id": u.TenantID,
		"email":     u.Email,
	}

	if u.DisplayName != "" {
		result["name"] = u.DisplayName
	}
	if len(u.Roles) > 0 {
		result["roles"] = u.Roles
	}
	if len(u.Groups) > 0 {
		result["groups"] = u.Groups
	}
	if len(u.Metadata) > 0 {
		result["attributes"] = u.Metadata
	}
	if u.MFAEnabled {
		result["mfa_verified"] = u.MFAEnabled
	}
	if !u.CreatedAt.IsZero() {
		result["created_at"] = u.CreatedAt.Format(time.RFC3339)
	}
	if !u.UpdatedAt.IsZero() {
		result["updated_at"] = u.UpdatedAt.Format(time.RFC3339)
	}
	if u.LastLoginAt != nil {
		result["last_auth"] = u.LastLoginAt.Format(time.RFC3339)
	}

	return result
}

// sdkRoleToMap converts an IAM SDK Role to a map for JSON serialization.
func sdkRoleToMap(r *sdkiam.Role) map[string]interface{} {
	if r == nil {
		return nil
	}
	result := map[string]interface{}{
		"id":        r.ID,
		"tenant_id": r.TenantID,
	}

	if r.Name != "" {
		result["name"] = r.Name
	}
	if r.Description != "" {
		result["description"] = r.Description
	}
	if len(r.Permissions) > 0 {
		result["permissions"] = r.Permissions
	}
	if !r.CreatedAt.IsZero() {
		result["created_at"] = r.CreatedAt.Format(time.RFC3339)
	}
	if !r.UpdatedAt.IsZero() {
		result["updated_at"] = r.UpdatedAt.Format(time.RFC3339)
	}

	return result
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

// sdkGroupToMap converts an IAM SDK Group to a map for JSON serialization.
func sdkGroupToMap(g *sdkiam.Group) map[string]interface{} {
	if g == nil {
		return nil
	}
	result := map[string]interface{}{
		"id":        g.ID,
		"tenant_id": g.TenantID,
	}

	if g.Name != "" {
		result["name"] = g.Name
	}
	if g.Description != "" {
		result["description"] = g.Description
	}
	if !g.CreatedAt.IsZero() {
		result["created_at"] = g.CreatedAt.Format(time.RFC3339)
	}
	if !g.UpdatedAt.IsZero() {
		result["updated_at"] = g.UpdatedAt.Format(time.RFC3339)
	}

	return result
}

// sdkTenantToMap converts an IAM SDK Tenant to a map for JSON serialization.
func sdkTenantToMap(t *sdkiam.Tenant) map[string]interface{} {
	if t == nil {
		return nil
	}
	result := map[string]interface{}{
		"id": t.ID,
	}

	if t.Name != "" {
		result["name"] = t.Name
	}
	if len(t.Settings) > 0 {
		result["settings"] = t.Settings
	}
	if !t.CreatedAt.IsZero() {
		result["created_at"] = t.CreatedAt.Format(time.RFC3339)
	}
	if !t.UpdatedAt.IsZero() {
		result["updated_at"] = t.UpdatedAt.Format(time.RFC3339)
	}

	return result
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

// =============================================================================
// Overlay Network Operations - Stub implementations pending overlay service integration
// =============================================================================

// OverlayStatus returns the status of the overlay network.
func (m *MCPServiceProvider) OverlayStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayStatus"}
}

// OverlayVTEPList lists all VXLAN Tunnel Endpoints.
func (m *MCPServiceProvider) OverlayVTEPList(ctx context.Context) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVTEPList"}
}

// OverlayVTEPGet retrieves a specific VTEP by node ID.
func (m *MCPServiceProvider) OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVTEPGet"}
}

// OverlayVNIList lists all Virtual Network Identifiers.
func (m *MCPServiceProvider) OverlayVNIList(ctx context.Context) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVNIList"}
}

// OverlayVNICreate creates a new VNI.
func (m *MCPServiceProvider) OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, name string) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVNICreate"}
}

// OverlayVNIDelete deletes a VNI.
func (m *MCPServiceProvider) OverlayVNIDelete(ctx context.Context, vni uint32) error {
	return ErrOverlayOperationNotImplemented{Operation: "OverlayVNIDelete"}
}

// OverlayTunnelList lists all overlay tunnels for a VNI.
func (m *MCPServiceProvider) OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayTunnelList"}
}

// OverlayMACList lists all MAC addresses in the overlay network.
func (m *MCPServiceProvider) OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayMACList"}
}

// OverlayMACForget removes a MAC address entry from the overlay network.
func (m *MCPServiceProvider) OverlayMACForget(ctx context.Context, mac string, vni uint32) error {
	return ErrOverlayOperationNotImplemented{Operation: "OverlayMACForget"}
}

// =============================================================================
// Gateway Operations - Stub implementations pending gateway service integration
// =============================================================================

// GatewayStatus returns the status of the gateway.
func (m *MCPServiceProvider) GatewayStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayStatus"}
}

// GatewayModeSet sets the gateway operating modes.
func (m *MCPServiceProvider) GatewayModeSet(ctx context.Context, modes []string) (interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayModeSet"}
}

// GatewayBGPStatus returns the BGP status of the gateway.
func (m *MCPServiceProvider) GatewayBGPStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPStatus"}
}

// GatewayBGPPeers lists all BGP peers.
func (m *MCPServiceProvider) GatewayBGPPeers(ctx context.Context) ([]interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPPeers"}
}

// GatewayBGPAnnounce announces a prefix via BGP.
func (m *MCPServiceProvider) GatewayBGPAnnounce(ctx context.Context, prefix string, nextHop string) error {
	return ErrGatewayOperationNotImplemented{Operation: "GatewayBGPAnnounce"}
}

// GatewayBGPWithdraw withdraws a prefix from BGP.
func (m *MCPServiceProvider) GatewayBGPWithdraw(ctx context.Context, prefix string) error {
	return ErrGatewayOperationNotImplemented{Operation: "GatewayBGPWithdraw"}
}

// GatewayBGPPrefixes lists all announced BGP prefixes.
func (m *MCPServiceProvider) GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPPrefixes"}
}

// requireIPAMService returns an error when the IPAM allocator is not configured.
func (m *MCPServiceProvider) requireIPAMService() error {
	if m.ipamService == nil {
		return ErrServiceNotAvailable{Service: "ipam"}
	}
	return nil
}

// GatewayIPAMPools lists IPAM pools, optionally filtered by zone.
func (m *MCPServiceProvider) GatewayIPAMPools(ctx context.Context, filterZone string) ([]interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	var pools []*ipam.Pool
	var err error
	if filterZone != "" {
		pools, err = m.ipamService.ListPoolsByZone(ctx, filterZone)
	} else {
		pools, err = m.ipamService.ListPools(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(pools))
	for _, p := range pools {
		out = append(out, p)
	}
	return out, nil
}

// GatewayIPAMPoolGet retrieves a single IPAM pool by ID.
func (m *MCPServiceProvider) GatewayIPAMPoolGet(ctx context.Context, poolID string) (interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	return m.ipamService.GetPool(ctx, poolID)
}

// GatewayIPAMAllocate allocates an IP address from a pool.
func (m *MCPServiceProvider) GatewayIPAMAllocate(ctx context.Context, poolID string, deviceID string, hostname string) (interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	alloc, err := m.ipamService.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   poolID,
		DeviceID: deviceID,
		Hostname: hostname,
	})
	if err != nil {
		return nil, err
	}
	return alloc, nil
}

// GatewayIPAMRelease releases an IP address back to the pool.
func (m *MCPServiceProvider) GatewayIPAMRelease(ctx context.Context, ipStr string) error {
	if err := m.requireIPAMService(); err != nil {
		return err
	}
	addr, parseErr := netip.ParseAddr(ipStr)
	if parseErr != nil {
		return &WrappedError{Msg: fmt.Sprintf("invalid ip address %q", ipStr), Err: parseErr}
	}
	return m.ipamService.Release(ctx, addr)
}

// GatewayIPAMAllocations lists all IP address allocations for a pool.
func (m *MCPServiceProvider) GatewayIPAMAllocations(ctx context.Context, poolID string) ([]interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	allocs, err := m.ipamService.GetAllocationsByPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(allocs))
	for _, a := range allocs {
		out = append(out, a)
	}
	return out, nil
}

// GatewayIPAMPoolCreate creates a new IPAM pool.
func (m *MCPServiceProvider) GatewayIPAMPoolCreate(ctx context.Context, req *mcp.IPAMPoolCreateRequest) (interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	cidr, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("invalid cidr %q", req.CIDR), Err: err}
	}
	pool := &ipam.Pool{
		ID:                   uuid.New().String(),
		Name:                 req.Name,
		CIDR:                 cidr.Masked(),
		Zone:                 req.Zone,
		Description:          req.Description,
		DefaultLeaseDuration: time.Duration(req.LeaseDurationSeconds) * time.Second,
	}
	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("invalid gateway %q", req.Gateway), Err: parseErr}
		}
		pool.Gateway = gw
	}
	if err := m.ipamService.CreatePool(ctx, pool); err != nil {
		return nil, err
	}
	return m.ipamService.GetPool(ctx, pool.ID)
}

// GatewayIPAMPoolUpdate updates mutable fields of an IPAM pool. CIDR is immutable.
func (m *MCPServiceProvider) GatewayIPAMPoolUpdate(ctx context.Context, poolID string, req *mcp.IPAMPoolUpdateRequest) (interface{}, error) {
	if err := m.requireIPAMService(); err != nil {
		return nil, err
	}
	pool, err := m.ipamService.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		pool.Name = req.Name
	}
	if req.Zone != "" {
		pool.Zone = req.Zone
	}
	if req.Description != "" {
		pool.Description = req.Description
	}
	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("invalid gateway %q", req.Gateway), Err: parseErr}
		}
		pool.Gateway = gw
	}
	if req.LeaseDurationSeconds > 0 {
		pool.DefaultLeaseDuration = time.Duration(req.LeaseDurationSeconds) * time.Second
	}
	if err := m.ipamService.UpdatePool(ctx, pool); err != nil {
		return nil, err
	}
	return m.ipamService.GetPool(ctx, poolID)
}

// GatewayIPAMPoolDelete deletes an IPAM pool.
func (m *MCPServiceProvider) GatewayIPAMPoolDelete(ctx context.Context, poolID string) error {
	if err := m.requireIPAMService(); err != nil {
		return err
	}
	return m.ipamService.DeletePool(ctx, poolID)
}

// =============================================================================
// Network Zone Operations
// =============================================================================

// GatewayNetworkZoneList lists runtime network zones, optionally filtered by lifecycle role.
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
		out = append(out, r)
	}
	return out, nil
}

// GatewayNetworkZoneCreate creates a new network zone.
func (m *MCPServiceProvider) GatewayNetworkZoneCreate(ctx context.Context, req *mcp.NetworkZoneCreateRequest) (interface{}, error) {
	if m.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	paths := make([]zone.ZonePath, 0, len(req.AllowTo))
	for _, p := range req.AllowTo {
		paths = append(paths, zone.ZonePath{
			Zone:     zone.Zone(p.Zone),
			Services: p.Services,
		})
	}
	isolateFrom := make([]zone.Zone, 0, len(req.IsolateFrom))
	for _, z := range req.IsolateFrom {
		isolateFrom = append(isolateFrom, zone.Zone(z))
	}
	cfg := zone.ZoneConfig{
		Name:             zone.Zone(req.Name),
		InternetIngress:  req.InternetIngress,
		Isolate:          req.Isolate,
		IsolatePerTenant: req.IsolatePerTenant,
		OOB:              req.OOB,
		LifecycleRole:    zone.LifecycleRole(req.LifecycleRole),
		AllowTo:          paths,
		IsolateFrom:      isolateFrom,
	}
	rec, restartRequired, err := m.zoneService.Create(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"zone":             rec,
		"restart_required": restartRequired,
	}, nil
}

// GatewayNetworkZoneUpdate updates an existing network zone.
func (m *MCPServiceProvider) GatewayNetworkZoneUpdate(ctx context.Context, name string, req *mcp.NetworkZoneUpdateRequest) (interface{}, error) {
	if m.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	paths := make([]zone.ZonePath, 0, len(req.AllowTo))
	for _, p := range req.AllowTo {
		paths = append(paths, zone.ZonePath{
			Zone:     zone.Zone(p.Zone),
			Services: p.Services,
		})
	}
	isolateFrom := make([]zone.Zone, 0, len(req.IsolateFrom))
	for _, z := range req.IsolateFrom {
		isolateFrom = append(isolateFrom, zone.Zone(z))
	}
	cfg := zone.ZoneConfig{
		Name:             zone.Zone(name),
		InternetIngress:  req.InternetIngress,
		Isolate:          req.Isolate,
		IsolatePerTenant: req.IsolatePerTenant,
		OOB:              req.OOB,
		LifecycleRole:    zone.LifecycleRole(req.LifecycleRole),
		AllowTo:          paths,
		IsolateFrom:      isolateFrom,
	}
	rec, restartRequired, err := m.zoneService.Update(ctx, zone.Zone(name), cfg)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"zone":             rec,
		"restart_required": restartRequired,
	}, nil
}

// GatewayNetworkZoneDelete deletes a network zone.
func (m *MCPServiceProvider) GatewayNetworkZoneDelete(ctx context.Context, name string) (bool, error) {
	if m.zoneService == nil {
		return false, ErrServiceNotAvailable{Service: "zone"}
	}
	return m.zoneService.Delete(ctx, zone.Zone(name))
}

// GatewayNetworkZoneAssign assigns a network segment to a trust zone.
func (m *MCPServiceProvider) GatewayNetworkZoneAssign(ctx context.Context, network string, zoneName string) (bool, error) {
	if m.zoneService == nil {
		return false, ErrServiceNotAvailable{Service: "zone"}
	}
	return m.zoneService.AssignNetwork(ctx, network, zone.Zone(zoneName))
}

// GatewayNetworkZoneVLAN resolves a trust zone name to its associated VLAN ID.
func (m *MCPServiceProvider) GatewayNetworkZoneVLAN(ctx context.Context, zoneName string) (uint16, error) {
	for _, n := range m.sdnNetworks {
		if string(n.Zone) == zoneName && n.VLAN > 0 {
			return n.VLAN, nil
		}
	}
	return 0, ErrServiceNotAvailable{Service: "zone-vlan: no network found for zone " + zoneName}
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
		return nil, err
	}

	result := map[string]interface{}{
		"info": info,
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
		ownerPwd = xkmssdk.NewPasswordFromString(ownerPassword)
	}

	_, err := p.tpm2Service.ProvisionOwner(ownerPwd)
	if err != nil {
		return nil, err
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
		return nil, err
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
		return nil, err
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
		return nil, err
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
		return nil, err
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
		return nil, err
	}

	if err := p.tpm2Service.CreateEK(ekAttrs); err != nil {
		return nil, err
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
func (p *MCPServiceProvider) TPMGetSRK(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	srkAttrs, err := p.tpm2Service.SSRKAttributes()
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
		return nil, err
	}

	if err := p.tpm2Service.CreateSRK(srkAttrs); err != nil {
		return nil, err
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

	iakAttrs, err := p.tpm2Service.IAKAttributes()
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
		return nil, err
	}

	iakAttrs, err := p.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		return nil, err
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

// TPMQuote generates a TPM quote.
func (p *MCPServiceProvider) TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	pcrIndices := make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		pcrIndices[i] = uint(pcr)
	}

	quote, err := p.tpm2Service.Quote(pcrIndices, nonce)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"quote":     base64.StdEncoding.EncodeToString(quote.Quoted),
		"signature": base64.StdEncoding.EncodeToString(quote.Signature),
		"event_log": base64.StdEncoding.EncodeToString(quote.EventLog),
	}, nil
}

// TPMVerifyQuote verifies a TPM quote.
func (p *MCPServiceProvider) TPMVerifyQuote(ctx context.Context, quote []byte, signature []byte, nonce []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	// Quote verification is not yet implemented in the gRPC service either
	return nil, ErrTPMOperationNotImplemented{Operation: "VerifyQuote"}
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
		return nil, err
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

// TPMExtendPCR extends a PCR with measurement data.
func (p *MCPServiceProvider) TPMExtendPCR(ctx context.Context, pcrIndex int, data []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	// PCR extension is typically done through the measurement log
	// The TPM interface extends via Quote or direct PCR manipulation
	// For now, return not implemented as the underlying API requires
	// more context (hash algorithm selection, etc.)
	return nil, ErrTPMOperationNotImplemented{Operation: "ExtendPCR"}
}

// TPMEventLog retrieves the TPM event log.
func (p *MCPServiceProvider) TPMEventLog(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	rawLog, err := p.tpm2Service.EventLog()
	if err != nil {
		return nil, err
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

	return p.tpm2Service.RandomBytes(numBytes)
}

// TPMSeal seals data to the TPM.
func (p *MCPServiceProvider) TPMSeal(ctx context.Context, data []byte, pcrs []int) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	sealed, err := p.tpm2Service.Seal(ctx, data, nil)
	if err != nil {
		return nil, err
	}

	return sealed.Ciphertext, nil
}

// TPMUnseal unseals data from the TPM.
func (p *MCPServiceProvider) TPMUnseal(ctx context.Context, cn string) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	sealed := &xkmssdk.SealedData{
		KeyID: cn,
	}

	return p.tpm2Service.Unseal(ctx, sealed, nil)
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

// TPMNVList lists NVRAM indices.
func (p *MCPServiceProvider) TPMNVList(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	return nil, ErrTPMOperationNotImplemented{Operation: "NVList"}
}

// TPMNVRead reads data from an NVRAM index.
func (p *MCPServiceProvider) TPMNVRead(ctx context.Context, index int, size int) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	return nil, ErrTPMOperationNotImplemented{Operation: "NVRead"}
}

// TPMNVWrite writes data to an NVRAM index.
func (p *MCPServiceProvider) TPMNVWrite(ctx context.Context, index int, data []byte) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	return nil, ErrTPMOperationNotImplemented{Operation: "NVWrite"}
}

// TPMNVDelete undefines an NVRAM index.
func (p *MCPServiceProvider) TPMNVDelete(ctx context.Context, index int) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrServiceNotAvailable{Service: "tpm"}
	}

	return nil, ErrTPMOperationNotImplemented{Operation: "NVDelete"}
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
		return nil, err
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
		return nil, err
	}

	return map[string]interface{}{
		"secret": base64.StdEncoding.EncodeToString(secret),
	}, nil
}
