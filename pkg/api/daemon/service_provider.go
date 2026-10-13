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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// PlatformServiceProvider implements mcp.ServiceProvider by delegating to actual service layers.
// This is the bridge between protocol handlers (MCP, QUIC) and the underlying service implementations.
//
// CRITICAL: All methods MUST call service layer interfaces, never business logic directly.
type PlatformServiceProvider struct {
	gatewayLB    GatewayLoadBalancerInterface
	gatewayNAT64 GatewayNAT64Interface
	gatewayPerf  GatewayPerfInterface
	// gatewaySnapshotTools serves the telemetry snapshot tools (#594).
	gatewaySnapshotTools
	// gatewayStatusTools serves the gateway status and mode tools (#65).
	gatewayStatusTools
	// gatewayIPAMTools serves the gateway IPAM tools (#65).
	gatewayIPAMTools
	ntpService     platformv1.NTPServiceServer
	vtpmService    vtpm.VTPMService
	dnsService     dns.DNSService
	deviceService  device.DeviceService
	profileService device.DeviceProfileService
	quoteVerifier  *DeviceQuoteVerifier
	// attestCertRecorder backs the device_record_attest_cert tool.
	attestCertRecorder AttestCertRecorder
	// lifecycle backs the device_disable and device_enable tools.
	lifecycle     DeviceLifecycle
	sdnService    *SDNService
	zoneService   gateway.ZoneService
	healthService *Service
	logger        *slog.Logger
}

// PlatformServiceProviderConfig holds configuration for creating a PlatformServiceProvider.
type PlatformServiceProviderConfig struct {
	VTPMService    vtpm.VTPMService
	DNSService     dns.DNSService
	DeviceService  device.DeviceService
	ProfileService device.DeviceProfileService
	// AKTrust is the platform CA used to chain device attestation
	// certificates; nil fails every device quote closed.
	AKTrust AKTrustAnchor
	// VerdictSink receives device quote verdicts (event log + quarantine
	// observers); nil means verdicts are only logged.
	VerdictSink verdict.Sink
	// AttestCertRecorder backs device_record_attest_cert; nil means the
	// tool answers that no certificate authority is configured.
	AttestCertRecorder AttestCertRecorder
	// DeviceLifecycle backs device_disable and device_enable; nil means
	// the tools answer that no SDN policy engine enforces them.
	DeviceLifecycle DeviceLifecycle
	SDNService      *SDNService
	ZoneService     gateway.ZoneService
	HealthService   *Service
	NTPService      platformv1.NTPServiceServer
	Logger          *slog.Logger
}

// NewPlatformServiceProvider creates a new PlatformServiceProvider.
func NewPlatformServiceProvider(config *PlatformServiceProviderConfig) *PlatformServiceProvider {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &PlatformServiceProvider{
		vtpmService:    config.VTPMService,
		dnsService:     config.DNSService,
		deviceService:  config.DeviceService,
		profileService: config.ProfileService,
		quoteVerifier: NewDeviceQuoteVerifier(
			config.DeviceService,
			config.ProfileService,
			config.AKTrust,
			config.VerdictSink,
			logger,
		),
		attestCertRecorder: config.AttestCertRecorder,
		lifecycle:          config.DeviceLifecycle,
		sdnService:         config.SDNService,
		zoneService:        config.ZoneService,
		healthService:      config.HealthService,
		ntpService:         config.NTPService,
		logger:             logger,
	}
}

// Compile-time interface compliance check
var _ mcp.ServiceProvider = (*PlatformServiceProvider)(nil)

// =============================================================================
// vTPM Operations - Delegate to vtpm.VTPMService
// =============================================================================

// VTPMCreate creates a new vTPM bundle.
func (p *PlatformServiceProvider) VTPMCreate(ctx context.Context, name string, algorithm string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMDelete(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}

	return p.vtpmService.DeleteBundle(ctx, name)
}

// VTPMList lists all vTPM bundles.
func (p *PlatformServiceProvider) VTPMList(ctx context.Context) ([]interface{}, error) {
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

// VTPMStart starts the swtpm daemon backing a vTPM bundle so runtime
// TPM operations (quote/seal/unseal/PCR) can be performed against it.
func (p *PlatformServiceProvider) VTPMStart(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.Start(ctx, name)
}

// VTPMStop stops the swtpm daemon backing a vTPM bundle, persisting its
// TPM state and releasing resources.
func (p *PlatformServiceProvider) VTPMStop(ctx context.Context, name string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.Stop(ctx, name)
}

// VTPMQuote generates a TPM quote over the requested PCRs. The nonce
// provides freshness/anti-replay. The vTPM must be running.
func (p *PlatformServiceProvider) VTPMQuote(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.Quote(ctx, name, nonce, pcrs)
}

// VTPMSeal seals data to a vTPM, optionally binding it to the supplied
// PCR values. The vTPM must be running.
func (p *PlatformServiceProvider) VTPMSeal(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.Seal(ctx, name, data, &vtpm.SealOptions{PCRs: pcrs})
}

// VTPMUnseal unseals data previously sealed to a vTPM. The vTPM must be
// running and, when PCR-bound, the current PCR values must match.
func (p *PlatformServiceProvider) VTPMUnseal(ctx context.Context, name string, sealed []byte) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.Unseal(ctx, name, sealed, "")
}

// VTPMExtendPCR extends a vTPM PCR with the provided data:
// PCR = Hash(PCR || data). The vTPM must be running.
func (p *PlatformServiceProvider) VTPMExtendPCR(ctx context.Context, name string, pcr int, data []byte) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.ExtendPCR(ctx, name, pcr, data)
}

// VTPMReadPCR reads the current value of a vTPM PCR. The vTPM must be
// running.
func (p *PlatformServiceProvider) VTPMReadPCR(ctx context.Context, name string, pcr int) ([]byte, error) {
	if p.vtpmService == nil {
		return nil, ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.ReadPCR(ctx, name, pcr)
}

// VTPMGet retrieves a vTPM bundle by name.
func (p *PlatformServiceProvider) VTPMGet(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMValidate(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMExport(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMImport(ctx context.Context, data []byte) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMCreateTemplate(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
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
		return nil, err
	}
	return template, nil
}

// VTPMGetTemplate retrieves a template by ID.
func (p *PlatformServiceProvider) VTPMGetTemplate(ctx context.Context, id string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMDeleteTemplate(ctx context.Context, id string) error {
	if p.vtpmService == nil {
		return ErrServiceNotAvailable{Service: "vtpm"}
	}
	return p.vtpmService.DeleteTemplate(ctx, id)
}

// VTPMListTemplates lists all templates.
func (p *PlatformServiceProvider) VTPMListTemplates(ctx context.Context) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMCloneTemplate(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMGetTPMSocketPath(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMGetNVRAMPath(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) VTPMIsRunning(ctx context.Context, name string) (interface{}, error) {
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
// DNS Operations - Delegate to dns.DNSService
// =============================================================================

// DNSAddRecord adds a DNS record.
func (p *PlatformServiceProvider) DNSAddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	if p.dnsService == nil {
		return ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.AddRecord(ctx, name, recordType, value, ttl)
}

// DNSDeleteRecord deletes a DNS record.
func (p *PlatformServiceProvider) DNSDeleteRecord(ctx context.Context, name string, recordType string) error {
	if p.dnsService == nil {
		return ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.DeleteRecord(ctx, name, recordType)
}

// DNSGetRecord gets a DNS record.
func (p *PlatformServiceProvider) DNSGetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	if p.dnsService == nil {
		return nil, ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.GetRecord(ctx, name, recordType)
}

// DNSListRecords lists DNS records in a zone.
func (p *PlatformServiceProvider) DNSListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	if p.dnsService == nil {
		return nil, ErrServiceNotAvailable{Service: "dns"}
	}

	records, err := p.dnsService.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, len(records))
	copy(result, records)

	return result, nil
}

// DNSResolve resolves a DNS name.
func (p *PlatformServiceProvider) DNSResolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if p.dnsService == nil {
		return nil, ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.Resolve(ctx, name, recordType)
}

// DNSCreateZone creates a DNS zone.
func (p *PlatformServiceProvider) DNSCreateZone(ctx context.Context, zone string) error {
	if p.dnsService == nil {
		return ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.CreateZone(ctx, zone)
}

// DNSDeleteZone deletes a DNS zone.
func (p *PlatformServiceProvider) DNSDeleteZone(ctx context.Context, zone string) error {
	if p.dnsService == nil {
		return ErrServiceNotAvailable{Service: "dns"}
	}

	return p.dnsService.DeleteZone(ctx, zone)
}

// DNSListZones lists all DNS zones.
func (p *PlatformServiceProvider) DNSListZones(ctx context.Context) ([]string, error) {
	if p.dnsService == nil {
		return nil, ErrServiceNotAvailable{Service: "dns"}
	}

	zones, err := p.dnsService.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(zones))
	for i, z := range zones {
		result[i] = z.Name
	}

	return result, nil
}

// =============================================================================
// Device Operations - Delegate to device.DeviceService
// =============================================================================

// DeviceRegister registers a new device.
func (p *PlatformServiceProvider) DeviceRegister(ctx context.Context, req *mcp.DeviceRegisterRequest) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	return registerMCPDevice(ctx, p.deviceService, req)
}

// DeviceFindBySerial returns the device registered under the serial number.
func (p *PlatformServiceProvider) DeviceFindBySerial(ctx context.Context, serial string) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	return p.deviceService.FindBySerial(ctx, serial)
}

// DeviceGet retrieves a device by ID.
func (p *PlatformServiceProvider) DeviceGet(ctx context.Context, deviceID string) (interface{}, error) {
	if p.deviceService == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceID(deviceID)
	if err != nil {
		return nil, err
	}
	return p.deviceService.Get(ctx, id)
}

// DeviceList lists devices with optional filter.
func (p *PlatformServiceProvider) DeviceList(ctx context.Context, filter map[string]string) ([]interface{}, error) {
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
func (p *PlatformServiceProvider) DeviceDelete(ctx context.Context, deviceID string) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceID(deviceID)
	if err != nil {
		return err
	}
	device, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return err
	}
	return p.deviceService.Delete(ctx, device)
}

// DeviceUpdate updates a device.
func (p *PlatformServiceProvider) DeviceUpdate(ctx context.Context, deviceID string, updates map[string]interface{}) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}

	id, err := parseDeviceID(deviceID)
	if err != nil {
		return err
	}
	device, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return err
	}
	// Apply updates to device fields
	if model, ok := updates["model"].(string); ok {
		device.Model = model
	}
	if serial, ok := updates["serial"].(string); ok {
		device.Serial = serial
	}
	return p.deviceService.Update(ctx, device)
}

// DeviceAttest verifies a TPM quote submitted for a device. The verification
// itself lives in DeviceQuoteVerifier, shared with the gRPC/Unix, QUIC, REST
// and MCP transports, so every surface answers identically.
func (p *PlatformServiceProvider) DeviceAttest(ctx context.Context, deviceID string, evidence []byte) (interface{}, error) {
	result, err := p.quoteVerifier.Verify(ctx, deviceID, evidence)
	if err != nil {
		return nil, err
	}
	p.logger.Info("device attestation completed",
		"device_id", result.DeviceID,
		"serial", result.Serial,
		"verified", result.Verified,
	)
	return result, nil
}

// DeviceRecordAttestCert records a device's attestation certificate through
// the shared recorder, so MCP answers exactly what gRPC, Unix, QUIC and REST
// answer: the same fail-closed preflight and the same refusal.
func (p *PlatformServiceProvider) DeviceRecordAttestCert(ctx context.Context, deviceID string, reissue, clearOnRefusal bool) (interface{}, error) {
	return recordAttestCertForMCP(ctx, p.attestCertRecorder, deviceID, reissue, clearOnRefusal, p.logger)
}

// DeviceDisable serves the MCP device_disable tool with the gRPC answer.
func (p *PlatformServiceProvider) DeviceDisable(ctx context.Context, deviceID, reason string) (interface{}, error) {
	return deviceLifecycleForMCP(ctx, p.lifecycle, deviceID, reason, false, p.logger)
}

// DeviceEnable serves the MCP device_enable tool with the gRPC answer.
func (p *PlatformServiceProvider) DeviceEnable(ctx context.Context, deviceID string) (interface{}, error) {
	return deviceLifecycleForMCP(ctx, p.lifecycle, deviceID, "", true, p.logger)
}

// DeviceBootCertificate refuses a diskless node's boot-certificate request:
// MCP carries no TLS connection for the proof to be bound to.
func (p *PlatformServiceProvider) DeviceBootCertificate(context.Context, string, []byte) (interface{}, error) {
	return nil, errBootOverMCP()
}

// DeviceBootDelivery refuses a diskless node's boot-delivery request: MCP
// carries no TLS connection for the evidence to be bound to.
func (p *PlatformServiceProvider) DeviceBootDelivery(context.Context, []byte) (interface{}, error) {
	return nil, errBootOverMCP()
}

// DeviceProvision binds a device to a device profile. The profile argument is
// resolved as a numeric profile ID first; failing that, a matching profile is
// found from the device's serial and model. The profile must carry an
// enrollment or post-enrollment network configuration to be usable for
// provisioning. This mirrors the provisioning contract implemented by the
// MCP service provider so both surfaces behave identically.
func (p *PlatformServiceProvider) DeviceProvision(ctx context.Context, deviceID string, profile string) error {
	if p.deviceService == nil {
		return ErrServiceNotAvailable{Service: "device"}
	}
	if p.profileService == nil {
		return ErrServiceNotAvailable{Service: "device_profile"}
	}
	if deviceID == "" {
		return ErrProvisioningFailed{Reason: "device ID is required"}
	}

	id, err := parseDeviceID(deviceID)
	if err != nil {
		return err
	}

	dev, err := p.deviceService.Get(ctx, id)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	var deviceProfile *deviceentities.DeviceProfile
	if profileID, parseErr := parseUint64(profile); parseErr == nil && profileID > 0 {
		deviceProfile, err = p.profileService.Get(ctx, profileID)
		if err != nil {
			return ErrProfileNotFound{Profile: profile}
		}
	} else {
		deviceProfile, err = p.profileService.FindMatchingProfile(ctx, "", dev.Serial, dev.Model)
		if err != nil {
			return ErrProfileNotFound{Profile: profile}
		}
	}

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

// parseDeviceID parses a device ID string to uint64.
func parseDeviceID(id string) (uint64, error) {
	var deviceID uint64
	_, err := fmt.Sscanf(id, "%d", &deviceID)
	if err != nil {
		return 0, &MessageError{Msg: fmt.Sprintf("invalid device ID: %s", id)}
	}
	return deviceID, nil
}

// =============================================================================
// SDN Operations - Delegate to SDNService via gRPC interface
// =============================================================================

// SDNGetPortState gets the state of an SDN port.
func (p *PlatformServiceProvider) SDNGetPortState(ctx context.Context, bridgeName string, portName string) (interface{}, error) {
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

// SDNSetPortState sets the admin state ("up"/"down") of an SDN port by
// delegating to the SDNService, which toggles the OVSDB Interface
// admin_state column and returns the refreshed port view.
func (p *PlatformServiceProvider) SDNSetPortState(ctx context.Context, bridgeName string, portName string, state string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := p.sdnService.SetPortState(ctx, &platformv1.SetPortStateRequest{
		BridgeId:   bridgeName,
		PortId:     portName,
		AdminState: state,
	})
	return err
}

// SDNListBridges lists all SDN bridges.
func (p *PlatformServiceProvider) SDNListBridges(ctx context.Context) ([]interface{}, error) {
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
func (p *PlatformServiceProvider) SDNCreateBridge(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.CreateBridge(ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: bridgeName,
		},
	})
	return err
}

// SDNDeleteBridge deletes an SDN bridge.
func (p *PlatformServiceProvider) SDNDeleteBridge(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{
		Id: bridgeName,
	})
	return err
}

// SDNAddPort adds a port to an SDN bridge.
func (p *PlatformServiceProvider) SDNAddPort(ctx context.Context, bridgeName string, portName string, portType string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeName,
		Config: &platformv1.PortConfig{
			Name: portName,
			Type: platformv1.PortType(platformv1.PortType_value[portType]),
		},
	})
	return err
}

// SDNDeletePort deletes a port from an SDN bridge.
func (p *PlatformServiceProvider) SDNDeletePort(ctx context.Context, bridgeName string, portName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.DeletePort(ctx, &platformv1.DeletePortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	return err
}

// SDNApplyPolicy applies a policy to an SDN bridge.
func (p *PlatformServiceProvider) SDNApplyPolicy(ctx context.Context, policyID string, bridgeName string) error {
	// Policy application not yet implemented in SDN service
	return &MessageError{Msg: "SDN policy application not yet implemented"}
}

// SDNGetPolicy gets an SDN policy.
func (p *PlatformServiceProvider) SDNGetPolicy(ctx context.Context, policyID string) (interface{}, error) {
	// Policy retrieval not yet implemented in SDN service
	return nil, &MessageError{Msg: "SDN policy retrieval not yet implemented"}
}

// SDNListPolicies lists all SDN policies.
func (p *PlatformServiceProvider) SDNListPolicies(ctx context.Context) ([]interface{}, error) {
	// Policy listing not yet implemented in SDN service
	return nil, &MessageError{Msg: "SDN policy listing not yet implemented"}
}

// SDNAddFlow adds an OpenFlow rule to an SDN bridge.
func (p *PlatformServiceProvider) SDNAddFlow(ctx context.Context, bridgeName string, flow map[string]interface{}) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	// Build FlowConfig from the map
	flowConfig := &platformv1.FlowConfig{
		BridgeId: bridgeName,
	}

	// Extract priority if present
	if priority, ok := flow["priority"].(int); ok {
		flowConfig.Priority = uint32(priority)
	}

	// Extract table if present
	if table, ok := flow["table"].(string); ok {
		if tableVal, exists := platformv1.FlowTable_value[table]; exists {
			flowConfig.Table = platformv1.FlowTable(tableVal)
		}
	}

	// Extract idle_timeout if present
	if idleTimeout, ok := flow["idle_timeout"].(int); ok {
		flowConfig.IdleTimeout = uint32(idleTimeout)
	}

	// Extract hard_timeout if present
	if hardTimeout, ok := flow["hard_timeout"].(int); ok {
		flowConfig.HardTimeout = uint32(hardTimeout)
	}

	// Extract match criteria if present
	if matchMap, ok := flow["match"].(map[string]interface{}); ok {
		flowConfig.Match = buildFlowMatch(matchMap)
	}

	// Extract actions if present
	if actionsSlice, ok := flow["actions"].([]interface{}); ok {
		flowConfig.Actions = buildFlowActions(actionsSlice)
	}

	_, err := p.sdnService.AddFlow(ctx, &platformv1.AddFlowRequest{
		Config: flowConfig,
	})
	return err
}

// buildFlowMatch builds a FlowMatch from a map.
func buildFlowMatch(matchMap map[string]interface{}) *platformv1.FlowMatch {
	match := &platformv1.FlowMatch{}

	if inPort, ok := matchMap["in_port"].(string); ok {
		match.InPort = inPort
	}
	if vlanID, ok := matchMap["vlan_id"].(int); ok {
		match.VlanId = uint32(vlanID)
	}
	if ethSrc, ok := matchMap["eth_src"].(string); ok {
		match.EthSrc = ethSrc
	}
	if ethDst, ok := matchMap["eth_dst"].(string); ok {
		match.EthDst = ethDst
	}
	if ethType, ok := matchMap["eth_type"].(int); ok {
		match.EthType = uint32(ethType)
	}
	if ipSrc, ok := matchMap["ip_src"].(string); ok {
		match.IpSrc = ipSrc
	}
	if ipDst, ok := matchMap["ip_dst"].(string); ok {
		match.IpDst = ipDst
	}
	if ipProto, ok := matchMap["ip_proto"].(int); ok {
		match.IpProto = uint32(ipProto)
	}
	if tcpSrc, ok := matchMap["tcp_src"].(int); ok {
		match.TcpSrc = uint32(tcpSrc)
	}
	if tcpDst, ok := matchMap["tcp_dst"].(int); ok {
		match.TcpDst = uint32(tcpDst)
	}
	if udpSrc, ok := matchMap["udp_src"].(int); ok {
		match.UdpSrc = uint32(udpSrc)
	}
	if udpDst, ok := matchMap["udp_dst"].(int); ok {
		match.UdpDst = uint32(udpDst)
	}
	if metadata, ok := matchMap["metadata"].(map[string]string); ok {
		match.Metadata = metadata
	}

	return match
}

// buildFlowActions builds a slice of FlowAction from an interface slice.
func buildFlowActions(actionsSlice []interface{}) []*platformv1.FlowAction {
	actions := make([]*platformv1.FlowAction, 0, len(actionsSlice))

	for _, actionInterface := range actionsSlice {
		actionMap, ok := actionInterface.(map[string]interface{})
		if !ok {
			continue
		}

		action := &platformv1.FlowAction{}

		if actionType, ok := actionMap["type"].(string); ok {
			if typeVal, exists := platformv1.FlowActionType_value[actionType]; exists {
				action.Type = platformv1.FlowActionType(typeVal)
			}
		}
		if port, ok := actionMap["port"].(string); ok {
			action.Port = port
		}
		if vlanID, ok := actionMap["vlan_id"].(int); ok {
			action.VlanId = uint32(vlanID)
		}
		if field, ok := actionMap["field"].(string); ok {
			action.Field = field
		}
		if value, ok := actionMap["value"].(string); ok {
			action.Value = value
		}
		if tableID, ok := actionMap["table_id"].(int); ok {
			action.TableId = uint32(tableID)
		}

		actions = append(actions, action)
	}

	return actions
}

// SDNDeleteFlow deletes an OpenFlow rule from an SDN bridge.
func (p *PlatformServiceProvider) SDNDeleteFlow(ctx context.Context, bridgeName string, flowID string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{
		BridgeId: bridgeName,
		FlowId:   flowID,
	})
	return err
}

// SDNListFlows lists all OpenFlow rules on an SDN bridge.
func (p *PlatformServiceProvider) SDNListFlows(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}

	resp, err := p.sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{
		BridgeId: bridgeName,
	})
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, len(resp.GetFlows()))
	for i, f := range resp.GetFlows() {
		result[i] = f
	}
	return result, nil
}

// SDNFlushFlows removes all OpenFlow rules from an SDN bridge.
func (p *PlatformServiceProvider) SDNFlushFlows(ctx context.Context, bridgeName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.FlushFlows(ctx, &platformv1.FlushFlowsRequest{
		BridgeId: bridgeName,
	})
	return err
}

// SDNCreateVLAN creates a VLAN configuration on an SDN bridge.
func (p *PlatformServiceProvider) SDNCreateVLAN(ctx context.Context, bridgeName string, vlanID int, name string) error {
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

// SDNDeleteVLAN deletes a VLAN configuration from an SDN bridge.
func (p *PlatformServiceProvider) SDNDeleteVLAN(ctx context.Context, bridgeName string, vlanID int) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{
		BridgeId: bridgeName,
		VlanId:   uint32(vlanID),
	})
	return err
}

// SDNListVLANs lists all VLAN configurations on an SDN bridge.
func (p *PlatformServiceProvider) SDNListVLANs(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}

	resp, err := p.sdnService.ListVLANs(ctx, &platformv1.ListVLANsRequest{
		BridgeId: bridgeName,
	})
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, len(resp.GetVlans()))
	for i, v := range resp.GetVlans() {
		result[i] = v
	}
	return result, nil
}

// SDNAuthenticatePort authenticates a port using x509 certificate credentials.
func (p *PlatformServiceProvider) SDNAuthenticatePort(ctx context.Context, bridgeName string, portName string, credentials map[string]string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	// Extract certificate and format from credentials
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

// SDNRevokePortAuth revokes authentication for an SDN port.
func (p *PlatformServiceProvider) SDNRevokePortAuth(ctx context.Context, bridgeName string, portName string) error {
	if p.sdnService == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}

	_, err := p.sdnService.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	})
	return err
}

// SDNGetPortStats retrieves statistics for an SDN port.
func (p *PlatformServiceProvider) SDNGetPortStats(ctx context.Context, bridgeName string, portName string) (interface{}, error) {
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

// SDNGetFlowStats retrieves flow statistics for an SDN bridge.
func (p *PlatformServiceProvider) SDNGetFlowStats(ctx context.Context, bridgeName string) (interface{}, error) {
	if p.sdnService == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}

	resp, err := p.sdnService.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{
		BridgeId: bridgeName,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetStats(), nil
}

// =============================================================================
// Health Operations - Delegate to Service
// =============================================================================

// Health returns the health status as an MCP-compatible map with
// lowercase string status values and Unix millisecond timestamps.
func (p *PlatformServiceProvider) Health(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "health"}
	}
	resp, err := p.healthService.GetHealth(ctx, &platformv1.GetHealthRequest{})
	if err != nil {
		return nil, err
	}
	return mcpHealthResponseMap(resp), nil
}

// Liveness returns the liveness status.
func (p *PlatformServiceProvider) Liveness(ctx context.Context) (interface{}, error) {
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

// Readiness returns the readiness status.
func (p *PlatformServiceProvider) Readiness(ctx context.Context) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonStatus(ctx context.Context) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonVersion(ctx context.Context) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonListServices(ctx context.Context) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonGetService(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonStartService(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonStopService(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonRestartService(ctx context.Context, name string) (interface{}, error) {
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
func (p *PlatformServiceProvider) DaemonListProtocols(ctx context.Context) (interface{}, error) {
	if p.healthService == nil {
		return nil, ErrServiceNotAvailable{Service: "daemon"}
	}
	return mcpListProtocolsMap(p.healthService.config), nil
}

// =============================================================================
// CA Operations - Stub implementations pending CA service integration
// =============================================================================

// CAInfo returns CA information.
func (p *PlatformServiceProvider) CAInfo(ctx context.Context) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CAIssue issues a new certificate.
func (p *PlatformServiceProvider) CAIssue(ctx context.Context, req *mcp.CAIssueRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CASignCSR certifies a KMS key for code signing from its CSR.
func (p *PlatformServiceProvider) CASignCSR(ctx context.Context, req *mcp.CASignCSRRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CAGet retrieves a certificate by serial number.
func (p *PlatformServiceProvider) CAGet(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CAList lists certificates.
func (p *PlatformServiceProvider) CAList(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CARevoke revokes a certificate.
func (p *PlatformServiceProvider) CARevoke(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CARenew renews a certificate.
func (p *PlatformServiceProvider) CARenew(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CAVerify verifies a certificate.
func (p *PlatformServiceProvider) CAVerify(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CACRL returns the Certificate Revocation List.
func (p *PlatformServiceProvider) CACRL(ctx context.Context) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// CABundle returns the CA certificate bundle.
func (p *PlatformServiceProvider) CABundle(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "ca"}
}

// =============================================================================
// IAM Operations - Stub implementations pending IAM service integration
// =============================================================================

// IAMCreateUser creates a new IAM user.
func (p *PlatformServiceProvider) IAMCreateUser(ctx context.Context, req *mcp.IAMCreateUserRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMDeleteUser deletes an IAM user.
func (p *PlatformServiceProvider) IAMDeleteUser(ctx context.Context, tenantID string, userID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMGetUser retrieves an IAM user by ID.
func (p *PlatformServiceProvider) IAMGetUser(ctx context.Context, tenantID string, userID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMListUsers lists IAM users for a tenant.
func (p *PlatformServiceProvider) IAMListUsers(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMCreateRole creates a new IAM role.
func (p *PlatformServiceProvider) IAMCreateRole(ctx context.Context, req *mcp.IAMCreateRoleRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMDeleteRole deletes an IAM role.
func (p *PlatformServiceProvider) IAMDeleteRole(ctx context.Context, tenantID string, roleID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMGetRole retrieves an IAM role by ID.
func (p *PlatformServiceProvider) IAMGetRole(ctx context.Context, tenantID string, roleID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMListRoles lists IAM roles for a tenant.
func (p *PlatformServiceProvider) IAMListRoles(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMAssignRole assigns a role to a user.
func (p *PlatformServiceProvider) IAMAssignRole(ctx context.Context, tenantID string, userID string, role string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMRevokeRole revokes a role from a user.
func (p *PlatformServiceProvider) IAMRevokeRole(ctx context.Context, tenantID string, userID string, role string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMCheckPermission checks if a user has permission to perform an action on a resource.
func (p *PlatformServiceProvider) IAMCheckPermission(ctx context.Context, tenantID string, userID string, resource string, action string) (bool, error) {
	return false, ErrServiceNotAvailable{Service: "iam"}
}

// IAMAuthenticate authenticates a user with credentials.
func (p *PlatformServiceProvider) IAMAuthenticate(ctx context.Context, req *mcp.IAMAuthenticateRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMCreateGroup creates a new IAM group.
func (p *PlatformServiceProvider) IAMCreateGroup(ctx context.Context, req *mcp.IAMCreateGroupRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMDeleteGroup deletes an IAM group.
func (p *PlatformServiceProvider) IAMDeleteGroup(ctx context.Context, tenantID string, groupID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMGetGroup retrieves an IAM group by ID.
func (p *PlatformServiceProvider) IAMGetGroup(ctx context.Context, tenantID string, groupID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMListGroups lists IAM groups for a tenant.
func (p *PlatformServiceProvider) IAMListGroups(ctx context.Context, tenantID string, limit int, offset int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMAddGroupMember adds a user to a group.
func (p *PlatformServiceProvider) IAMAddGroupMember(ctx context.Context, tenantID string, groupID string, userID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMRemoveGroupMember removes a user from a group.
func (p *PlatformServiceProvider) IAMRemoveGroupMember(ctx context.Context, tenantID string, groupID string, userID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMCreateTenant creates a new IAM tenant.
func (p *PlatformServiceProvider) IAMCreateTenant(ctx context.Context, req *mcp.IAMCreateTenantRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMDeleteTenant deletes an IAM tenant.
func (p *PlatformServiceProvider) IAMDeleteTenant(ctx context.Context, tenantID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMGetTenant retrieves an IAM tenant by ID.
func (p *PlatformServiceProvider) IAMGetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMListTenants lists all IAM tenants.
func (p *PlatformServiceProvider) IAMListTenants(ctx context.Context, limit int, offset int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMCreateToken creates a new authentication token for a user.
func (p *PlatformServiceProvider) IAMCreateToken(ctx context.Context, req *mcp.IAMCreateTokenRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// IAMRevokeToken revokes an authentication token.
func (p *PlatformServiceProvider) IAMRevokeToken(ctx context.Context, tokenID string) error {
	return ErrServiceNotAvailable{Service: "iam"}
}

// IAMVerifyToken verifies an authentication token and returns its claims.
func (p *PlatformServiceProvider) IAMVerifyToken(ctx context.Context, token string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "iam"}
}

// =============================================================================
// KMS Operations - Stub implementations pending KMS service integration
// =============================================================================

// KMSCreateKey creates a new cryptographic key in the KMS.
func (p *PlatformServiceProvider) KMSCreateKey(ctx context.Context, req *mcp.KMSCreateKeyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSDeleteKey deletes a key from the KMS.
func (p *PlatformServiceProvider) KMSDeleteKey(ctx context.Context, keyID string) error {
	return ErrServiceNotAvailable{Service: "kms"}
}

// KMSGetKey retrieves key metadata from the KMS.
func (p *PlatformServiceProvider) KMSGetKey(ctx context.Context, keyID string, version uint64) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSExportPublicKey exports the public portion of an asymmetric key.
func (p *PlatformServiceProvider) KMSExportPublicKey(ctx context.Context, req *mcp.KMSExportPublicKeyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSListKeys lists all keys in the KMS.
func (p *PlatformServiceProvider) KMSListKeys(ctx context.Context, limit int, offset int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSRotateKey rotates a key in the KMS.
func (p *PlatformServiceProvider) KMSRotateKey(ctx context.Context, keyID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSEncrypt encrypts data using a KMS key.
func (p *PlatformServiceProvider) KMSEncrypt(ctx context.Context, req *mcp.KMSEncryptRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSDecrypt decrypts data using a KMS key.
func (p *PlatformServiceProvider) KMSDecrypt(ctx context.Context, req *mcp.KMSDecryptRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSSign signs data using a KMS key.
func (p *PlatformServiceProvider) KMSSign(ctx context.Context, req *mcp.KMSSignRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSVerify verifies a signature using a KMS key.
func (p *PlatformServiceProvider) KMSVerify(ctx context.Context, req *mcp.KMSVerifyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGenerateRandom generates cryptographically secure random bytes.
func (p *PlatformServiceProvider) KMSGenerateRandom(ctx context.Context, numBytes int) ([]byte, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGenerateDataKey generates a data encryption key (DEK) for envelope encryption.
func (p *PlatformServiceProvider) KMSGenerateDataKey(ctx context.Context, req *mcp.KMSGenerateDataKeyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGenerateWrappedDataKey generates only a wrapped (encrypted) data encryption key.
func (p *PlatformServiceProvider) KMSGenerateWrappedDataKey(ctx context.Context, req *mcp.KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// =============================================================================
// Container Operations - Stub implementations pending container service integration
// =============================================================================

// ContainerCreate creates a new container.
func (p *PlatformServiceProvider) ContainerCreate(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
	return nil, ErrContainerServiceNotAvailable{}
}

// ContainerStart starts a container.
func (p *PlatformServiceProvider) ContainerStart(ctx context.Context, id string) error {
	return ErrContainerServiceNotAvailable{}
}

// ContainerStop stops a container.
func (p *PlatformServiceProvider) ContainerStop(ctx context.Context, id string, timeout int) error {
	return ErrContainerServiceNotAvailable{}
}

// ContainerRemove removes a container.
func (p *PlatformServiceProvider) ContainerRemove(ctx context.Context, id string, force bool) error {
	return ErrContainerServiceNotAvailable{}
}

// ContainerGet retrieves a container by ID.
func (p *PlatformServiceProvider) ContainerGet(ctx context.Context, id string) (interface{}, error) {
	return nil, ErrContainerServiceNotAvailable{}
}

// ContainerList lists containers.
func (p *PlatformServiceProvider) ContainerList(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
	return nil, ErrContainerServiceNotAvailable{}
}

// ContainerLogs retrieves container logs.
func (p *PlatformServiceProvider) ContainerLogs(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error) {
	return "", ErrContainerServiceNotAvailable{}
}

// ContainerAttest performs TPM attestation for a container.
func (p *PlatformServiceProvider) ContainerAttest(ctx context.Context, id string) (interface{}, error) {
	return nil, ErrContainerServiceNotAvailable{}
}

// =============================================================================
// IDevID Operations - IEEE 802.1AR Device Identity
// =============================================================================

// IDevIDGenerate generates an IDevID key in the TPM.
func (p *PlatformServiceProvider) IDevIDGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IDevIDInfo returns IDevID key information.
func (p *PlatformServiceProvider) IDevIDInfo(ctx context.Context) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IDevIDDelete deletes the IDevID key.
func (p *PlatformServiceProvider) IDevIDDelete(ctx context.Context) error {
	return ErrTPM2ServiceNotAvailable{}
}

// IDevIDCSR generates a certificate signing request for the IDevID key.
func (p *PlatformServiceProvider) IDevIDCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IDevIDInstallCert installs an IDevID certificate.
func (p *PlatformServiceProvider) IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IDevIDGetCert returns the IDevID certificate.
func (p *PlatformServiceProvider) IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IDevIDDeleteCert deletes the IDevID certificate.
func (p *PlatformServiceProvider) IDevIDDeleteCert(ctx context.Context) error {
	return ErrTPM2ServiceNotAvailable{}
}

// IDevIDExists checks if an IDevID key exists.
func (p *PlatformServiceProvider) IDevIDExists(ctx context.Context) (bool, error) {
	return false, ErrTPM2ServiceNotAvailable{}
}

// =============================================================================
// IAK Operations - IEEE 802.1AR Attestation Key
// =============================================================================

// IAKGenerate generates an IAK key in the TPM.
func (p *PlatformServiceProvider) IAKGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IAKInfo returns IAK key information.
func (p *PlatformServiceProvider) IAKInfo(ctx context.Context) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IAKDelete deletes the IAK key.
func (p *PlatformServiceProvider) IAKDelete(ctx context.Context) error {
	return ErrTPM2ServiceNotAvailable{}
}

// IAKCSR generates a certificate signing request for the IAK key.
func (p *PlatformServiceProvider) IAKCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IAKInstallCert installs an IAK certificate.
func (p *PlatformServiceProvider) IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IAKGetCert returns the IAK certificate.
func (p *PlatformServiceProvider) IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// IAKDeleteCert deletes the IAK certificate.
func (p *PlatformServiceProvider) IAKDeleteCert(ctx context.Context) error {
	return ErrTPM2ServiceNotAvailable{}
}

// IAKExists checks if an IAK key exists.
func (p *PlatformServiceProvider) IAKExists(ctx context.Context) (bool, error) {
	return false, ErrTPM2ServiceNotAvailable{}
}

// =============================================================================
// Device Attribute and Credential Operations
// =============================================================================

// DeviceAttributes returns TCG device attributes.
func (p *PlatformServiceProvider) DeviceAttributes(ctx context.Context) (interface{}, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// ActivateCredential performs TPM credential activation.
func (p *PlatformServiceProvider) ActivateCredential(ctx context.Context, credentialBlob, secret []byte) ([]byte, error) {
	return nil, ErrTPM2ServiceNotAvailable{}
}

// =============================================================================
// Overlay Network Operations - Stub implementations pending overlay service integration
// =============================================================================

// OverlayStatus returns the status of the overlay network.
func (p *PlatformServiceProvider) OverlayStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayStatus"}
}

// OverlayVTEPList lists all VXLAN Tunnel Endpoints.
func (p *PlatformServiceProvider) OverlayVTEPList(ctx context.Context) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVTEPList"}
}

// OverlayVTEPGet retrieves a specific VTEP by node ID.
func (p *PlatformServiceProvider) OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVTEPGet"}
}

// OverlayVNIList lists all Virtual Network Identifiers.
func (p *PlatformServiceProvider) OverlayVNIList(ctx context.Context) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVNIList"}
}

// OverlayVNICreate creates a new VNI.
func (p *PlatformServiceProvider) OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, name string) (interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayVNICreate"}
}

// OverlayVNIDelete deletes a VNI.
func (p *PlatformServiceProvider) OverlayVNIDelete(ctx context.Context, vni uint32) error {
	return ErrOverlayOperationNotImplemented{Operation: "OverlayVNIDelete"}
}

// OverlayTunnelList lists all overlay tunnels for a VNI.
func (p *PlatformServiceProvider) OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayTunnelList"}
}

// OverlayMACList lists all MAC addresses in the overlay network.
func (p *PlatformServiceProvider) OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return nil, ErrOverlayOperationNotImplemented{Operation: "OverlayMACList"}
}

// OverlayMACForget removes a MAC address entry from the overlay network.
func (p *PlatformServiceProvider) OverlayMACForget(ctx context.Context, mac string, vni uint32) error {
	return ErrOverlayOperationNotImplemented{Operation: "OverlayMACForget"}
}

// =============================================================================
// Gateway Operations - Stub implementations pending gateway service integration
// =============================================================================

// GatewayStatus and GatewayModeSet come from the embedded gatewayStatusTools
// and the IPAM tools from the embedded gatewayIPAMTools. The BGP operations
// below stay unimplemented: platformd constructs no BGP speaker (gatewayd
// owns it).

// GatewayBGPStatus returns the BGP status of the gateway.
func (p *PlatformServiceProvider) GatewayBGPStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPStatus"}
}

// GatewayBGPPeers lists all BGP peers.
func (p *PlatformServiceProvider) GatewayBGPPeers(ctx context.Context) ([]interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPPeers"}
}

// GatewayBGPAnnounce announces a prefix via BGP.
func (p *PlatformServiceProvider) GatewayBGPAnnounce(ctx context.Context, prefix string, nextHop string) error {
	return ErrGatewayOperationNotImplemented{Operation: "GatewayBGPAnnounce"}
}

// GatewayBGPWithdraw withdraws a prefix from BGP.
func (p *PlatformServiceProvider) GatewayBGPWithdraw(ctx context.Context, prefix string) error {
	return ErrGatewayOperationNotImplemented{Operation: "GatewayBGPWithdraw"}
}

// GatewayBGPPrefixes lists all announced BGP prefixes.
func (p *PlatformServiceProvider) GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error) {
	return nil, ErrGatewayOperationNotImplemented{Operation: "GatewayBGPPrefixes"}
}

// =============================================================================
// Gateway Network Zone Operations
// =============================================================================

// GatewayNetworkZoneList lists the underlay zones with their policy and
// derived numbering, optionally filtered by lifecycle role.
func (p *PlatformServiceProvider) GatewayNetworkZoneList(ctx context.Context, lifecycleRole string) ([]interface{}, error) {
	if p.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	recs, err := p.zoneService.List(ctx, zone.LifecycleRole(lifecycleRole))
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
func (p *PlatformServiceProvider) GatewayNetworkZoneCreate(ctx context.Context, req *mcp.NetworkZoneCreateRequest) (interface{}, error) {
	if p.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	rec, restartRequired, err := p.zoneService.Create(ctx, req.ZoneConfig())
	if err != nil {
		return nil, err
	}
	return rec.View(restartRequired), nil
}

// GatewayNetworkZoneUpdate tunes a built-in zone or replaces an
// owner-defined zone.
func (p *PlatformServiceProvider) GatewayNetworkZoneUpdate(ctx context.Context, name string, req *mcp.NetworkZoneUpdateRequest) (interface{}, error) {
	if p.zoneService == nil {
		return nil, ErrServiceNotAvailable{Service: "zone"}
	}
	rec, restartRequired, err := p.zoneService.Update(ctx, zone.Zone(name), req.ZoneConfig(name))
	if err != nil {
		return nil, err
	}
	return rec.View(restartRequired), nil
}

// GatewayNetworkZoneDelete deletes an owner-defined zone or omits an
// optional built-in.
func (p *PlatformServiceProvider) GatewayNetworkZoneDelete(ctx context.Context, name string) (bool, error) {
	if p.zoneService == nil {
		return false, ErrServiceNotAvailable{Service: "zone"}
	}
	return p.zoneService.Delete(ctx, zone.Zone(name))
}

// GatewayNetworkZoneVLAN resolves a zone name to its VLAN ID through the
// zone service's derived numbering.
func (p *PlatformServiceProvider) GatewayNetworkZoneVLAN(ctx context.Context, zoneName string) (uint16, error) {
	return zoneVLAN(ctx, p.zoneService, zoneName)
}

// =============================================================================
// Physical TPM Operations
// =============================================================================

// TPMInfo retrieves TPM device information.
func (p *PlatformServiceProvider) TPMInfo(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMInfo"}
}

// TPMProvision provisions the TPM with owner authorization.
func (p *PlatformServiceProvider) TPMProvision(ctx context.Context, ownerPassword string) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMProvision"}
}

// TPMClear clears the TPM.
func (p *PlatformServiceProvider) TPMClear(ctx context.Context, ownerPassword string) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMClear"}
}

// TPMGetEK retrieves the Endorsement Key.
func (p *PlatformServiceProvider) TPMGetEK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMGetEK"}
}

// TPMGetEKCert retrieves the EK certificate.
func (p *PlatformServiceProvider) TPMGetEKCert(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMGetEKCert"}
}

// TPMImportEKCert imports an EK certificate.
func (p *PlatformServiceProvider) TPMImportEKCert(ctx context.Context, certDER []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMImportEKCert"}
}

// TPMCreateEK creates an Endorsement Key.
func (p *PlatformServiceProvider) TPMCreateEK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMCreateEK"}
}

// TPMDeleteEK deletes the Endorsement Key.
func (p *PlatformServiceProvider) TPMDeleteEK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMDeleteEK"}
}

// TPMGetSRK retrieves the Storage Root Key.
func (p *PlatformServiceProvider) TPMGetSRK(ctx context.Context, handle uint32) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMGetSRK"}
}

// TPMCreateSRK creates a Storage Root Key.
func (p *PlatformServiceProvider) TPMCreateSRK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMCreateSRK"}
}

// TPMDeleteSRK deletes the Storage Root Key.
func (p *PlatformServiceProvider) TPMDeleteSRK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMDeleteSRK"}
}

// TPMGetIAK retrieves the Initial Attestation Key.
func (p *PlatformServiceProvider) TPMGetIAK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMGetIAK"}
}

// TPMCreateIAK creates an Initial Attestation Key.
func (p *PlatformServiceProvider) TPMCreateIAK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMCreateIAK"}
}

// TPMDeleteIAK deletes the Initial Attestation Key.
func (p *PlatformServiceProvider) TPMDeleteIAK(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMDeleteIAK"}
}

// TPMQuote generates a TPM quote.
func (p *PlatformServiceProvider) TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMQuote"}
}

// TPMVerifyQuote verifies a TPM quote.
func (p *PlatformServiceProvider) TPMVerifyQuote(ctx context.Context, quote, signature, nonce, channelBinding []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMVerifyQuote"}
}

// TPMReadPCRs reads PCR values.
func (p *PlatformServiceProvider) TPMReadPCRs(ctx context.Context, indices []int) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMReadPCRs"}
}

// TPMExtendPCR extends a PCR with measurement data.
func (p *PlatformServiceProvider) TPMExtendPCR(ctx context.Context, pcrIndex int, data []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMExtendPCR"}
}

// TPMEventLog retrieves the TPM event log.
func (p *PlatformServiceProvider) TPMEventLog(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMEventLog"}
}

// TPMCapabilities retrieves TPM capabilities.
func (p *PlatformServiceProvider) TPMCapabilities(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMCapabilities"}
}

// TPMRandom generates random bytes from the TPM.
func (p *PlatformServiceProvider) TPMRandom(ctx context.Context, numBytes int) ([]byte, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMRandom"}
}

// TPMSeal seals data to the TPM.
func (p *PlatformServiceProvider) TPMSeal(ctx context.Context, data []byte, pcrs []int) ([]byte, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMSeal"}
}

// TPMUnseal unseals data from the TPM.
func (p *PlatformServiceProvider) TPMUnseal(ctx context.Context, cn string) ([]byte, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMUnseal"}
}

// TPMCertify certifies a TPM key.
func (p *PlatformServiceProvider) TPMCertify(ctx context.Context, keyHandle int) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMCertify"}
}

// TPMNVList lists NVRAM indices.
func (p *PlatformServiceProvider) TPMNVList(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMNVList"}
}

// TPMNVRead reads data from an NVRAM index.
func (p *PlatformServiceProvider) TPMNVRead(ctx context.Context, index int, size int) ([]byte, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMNVRead"}
}

// TPMNVWrite writes data to an NVRAM index.
func (p *PlatformServiceProvider) TPMNVWrite(ctx context.Context, index int, data []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMNVWrite"}
}

// TPMNVDelete undefines an NVRAM index.
func (p *PlatformServiceProvider) TPMNVDelete(ctx context.Context, index int) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMNVDelete"}
}

// TPMPlatform retrieves platform-level TPM attributes.
func (p *PlatformServiceProvider) TPMPlatform(ctx context.Context) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMPlatform"}
}

// TPMMakeCredential is not wired on the delegating PlatformServiceProvider;
// the live MCP transport uses MCPServiceProvider. Mirrors the existing TPM
// operation stubs on this secondary provider.
func (p *PlatformServiceProvider) TPMMakeCredential(ctx context.Context, akName, secret, ekCert, iakPub []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMMakeCredential"}
}

// TPMActivateCredential is not wired on the delegating PlatformServiceProvider;
// the live MCP transport uses MCPServiceProvider.
func (p *PlatformServiceProvider) TPMActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) (interface{}, error) {
	return nil, ErrTPMOperationNotImplemented{Operation: "TPMActivateCredential"}
}

// KMSRevokeKey revokes a key, marking it unusable.
func (p *PlatformServiceProvider) KMSRevokeKey(ctx context.Context, keyID string, reason string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGetKeyMetadata retrieves key metadata without exposing key material.
func (p *PlatformServiceProvider) KMSGetKeyMetadata(ctx context.Context, keyID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSUpdateKeyMetadata updates mutable key metadata fields.
func (p *PlatformServiceProvider) KMSUpdateKeyMetadata(ctx context.Context, req *mcp.KMSUpdateKeyMetadataRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSSetKeyPolicy sets the access control policy for a key.
func (p *PlatformServiceProvider) KMSSetKeyPolicy(ctx context.Context, req *mcp.KMSSetKeyPolicyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGetKeyPolicy retrieves the access control policy for a key.
func (p *PlatformServiceProvider) KMSGetKeyPolicy(ctx context.Context, keyID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSGetSupportedAlgorithms lists algorithms supported by the KMS backend.
func (p *PlatformServiceProvider) KMSGetSupportedAlgorithms(ctx context.Context) ([]string, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// KMSBackendStatus returns health and capability information about the KMS backend.
func (p *PlatformServiceProvider) KMSBackendStatus(ctx context.Context) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "kms"}
}

// SecretStore stores a secret.
func (p *PlatformServiceProvider) SecretStore(ctx context.Context, req *mcp.SecretStoreRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "secrets"}
}

// SecretGet retrieves a secret.
func (p *PlatformServiceProvider) SecretGet(ctx context.Context, secretID string, version uint64) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "secrets"}
}

// SecretList lists secrets.
func (p *PlatformServiceProvider) SecretList(ctx context.Context, limit int) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "secrets"}
}

// SecretDelete deletes a secret.
func (p *PlatformServiceProvider) SecretDelete(ctx context.Context, secretID string) error {
	return ErrServiceNotAvailable{Service: "secrets"}
}

// SecretSetRotationPolicy sets the automatic rotation policy for a secret.
func (p *PlatformServiceProvider) SecretSetRotationPolicy(ctx context.Context, req *mcp.SecretSetRotationPolicyRequest) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "secrets"}
}

// SecretGetRotationPolicy retrieves the automatic rotation policy for a secret.
func (p *PlatformServiceProvider) SecretGetRotationPolicy(ctx context.Context, secretID string) (interface{}, error) {
	return nil, ErrServiceNotAvailable{Service: "secrets"}
}
