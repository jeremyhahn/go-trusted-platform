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
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// Mock vTPM Service for MCP tests
// =============================================================================

type mcpMockVTPMService struct {
	bundles map[string]*vtpm.Bundle
	running map[string]bool

	// The last options each call received, so tests can assert what the
	// provider forwards.
	lastCreateOpts *vtpm.CreateBundleOptions
	lastListOpts   *vtpm.ListOptions
	lastSealOpts   *vtpm.SealOptions
	lastUnsealAuth string
}

func newMCPMockVTPMService() *mcpMockVTPMService {
	return &mcpMockVTPMService{
		bundles: make(map[string]*vtpm.Bundle),
		running: make(map[string]bool),
	}
}

func (m *mcpMockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	m.lastCreateOpts = opts
	bundle := &vtpm.Bundle{
		ID:        opts.Hostname,
		Mode:      opts.Mode,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:    opts.Hostname,
			EKAlgorithm: opts.EKAlgorithm,
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mcpMockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if bundle, ok := m.bundles[id]; ok {
		return bundle, nil
	}
	return nil, vtpm.ErrBundleNotFound{ID: id}
}

func (m *mcpMockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	delete(m.bundles, id)
	return nil
}

func (m *mcpMockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	m.lastListOpts = opts
	bundles := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		bundles = append(bundles, b)
	}
	return bundles, nil
}

func (m *mcpMockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	return &vtpm.Template{ID: opts.ID}, nil
}

func (m *mcpMockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	return nil, nil
}

func (m *mcpMockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	return nil, vtpm.ErrTemplateNotFound{ID: id}
}

func (m *mcpMockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	return nil
}

func (m *mcpMockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	return nil, nil
}

func (m *mcpMockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	return nil
}

func (m *mcpMockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	return nil, nil
}

func (m *mcpMockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	return nil
}

func (m *mcpMockVTPMService) GetBundlePath(id string) string {
	return "/var/lib/vtpm/bundles/" + id
}

func (m *mcpMockVTPMService) GetTPMSocketPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/swtpm-sock"
}

func (m *mcpMockVTPMService) GetNVRAMPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/OVMF_VARS.fd"
}

func (m *mcpMockVTPMService) Start(ctx context.Context, bundleID string) error {
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	if m.running[bundleID] {
		return vtpm.ErrVTPMAlreadyRunning{BundleID: bundleID}
	}
	m.running[bundleID] = true
	return nil
}

func (m *mcpMockVTPMService) Stop(ctx context.Context, bundleID string) error {
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	m.running[bundleID] = false
	return nil
}

func (m *mcpMockVTPMService) IsRunning(bundleID string) bool {
	return m.running[bundleID]
}

func (m *mcpMockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}
	return &vtpm.QuoteResult{
		Quote:         []byte("mock-quote"),
		Signature:     []byte("mock-signature"),
		PCRValues:     map[int][]byte{0: []byte("mock-pcr-value")},
		HashAlgorithm: "SHA256",
	}, nil
}

func (m *mcpMockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	m.lastSealOpts = opts
	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}
	return []byte("sealed-" + string(data)), nil
}

func (m *mcpMockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	m.lastUnsealAuth = authValue
	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}
	return []byte("unsealed-data"), nil
}

func (m *mcpMockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	return nil
}

func (m *mcpMockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}
	return []byte("mock-pcr-value"), nil
}

func (m *mcpMockVTPMService) Close() error {
	return nil
}

// =============================================================================
// Mock DNS Service for MCP tests
// =============================================================================

type mcpMockDNSService struct {
	zones   map[string]*dnsentities.Zone
	records map[string]interface{}
}

func newMCPMockDNSService() *mcpMockDNSService {
	return &mcpMockDNSService{
		zones:   make(map[string]*dnsentities.Zone),
		records: make(map[string]interface{}),
	}
}

func (m *mcpMockDNSService) Save(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}

func (m *mcpMockDNSService) SaveAndSign(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}

func (m *mcpMockDNSService) SignZone(zone *dnsentities.Zone) error {
	return nil
}

func (m *mcpMockDNSService) Delete(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}

func (m *mcpMockDNSService) Zone(ctx context.Context, zoneName string) (*dnsentities.Zone, error) {
	return nil, nil
}

func (m *mcpMockDNSService) ListZones(ctx context.Context) ([]*dnsentities.Zone, error) {
	zones := make([]*dnsentities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *mcpMockDNSService) Register(ctx context.Context, fqdn, ip string) (*dnsentities.Zone, error) {
	return nil, nil
}

func (m *mcpMockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *dnsentities.TLSARecord) error {
	return nil
}

func (m *mcpMockDNSService) InternalZone(ctx context.Context) (*dnsentities.Zone, error) {
	return nil, nil
}

func (m *mcpMockDNSService) PublicZone(ctx context.Context) (*dnsentities.Zone, error) {
	return nil, nil
}

func (m *mcpMockDNSService) InternalDomain() string {
	return "internal.example.com"
}

func (m *mcpMockDNSService) PublicDomain() string {
	return "example.com"
}

func (m *mcpMockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *mcpMockDNSService) IsDNSSECEnabled() bool {
	return false
}

func (m *mcpMockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	m.zones[zoneName] = &dnsentities.Zone{Name: zoneName}
	return nil
}

func (m *mcpMockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	delete(m.zones, zoneName)
	return nil
}

func (m *mcpMockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	key := name + ":" + recordType
	m.records[key] = map[string]interface{}{
		"name":  name,
		"type":  recordType,
		"value": value,
		"ttl":   ttl,
	}
	return nil
}

func (m *mcpMockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	key := name + ":" + recordType
	delete(m.records, key)
	return nil
}

func (m *mcpMockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	key := name + ":" + recordType
	if record, ok := m.records[key]; ok {
		return record, nil
	}
	return map[string]interface{}{
		"name":  name,
		"type":  recordType,
		"value": "192.168.1.1",
		"ttl":   3600,
	}, nil
}

func (m *mcpMockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	records := make([]interface{}, 0)
	for _, r := range m.records {
		records = append(records, r)
	}
	return records, nil
}

func (m *mcpMockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	return []string{"192.168.1.1"}, nil
}

func (m *mcpMockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return nil
}

// =============================================================================
// Mock Device Service for MCP tests
// =============================================================================

type mcpMockDeviceService struct {
	devices map[uint64]*deviceentities.Device
	nextID  uint64
}

func newMCPMockDeviceService() *mcpMockDeviceService {
	return &mcpMockDeviceService{
		devices: make(map[uint64]*deviceentities.Device),
		nextID:  1,
	}
}

// Create mints an ID when the caller has none, then takes the ordinary
// Save path, mirroring the real service (#525).
func (m *mcpMockDeviceService) Create(ctx context.Context, dev *deviceentities.Device) error {
	if dev == nil {
		return device.ErrNilDevice
	}
	if dev.ID == 0 {
		dev.ID = m.nextID
		m.nextID++
	}
	return m.Save(ctx, dev)
}

func (m *mcpMockDeviceService) Save(ctx context.Context, dev *deviceentities.Device) error {
	// Save refuses a zero ID exactly as the real service does; minting
	// one here is what let the MCP create path look healthy while
	// production refused it (#525). Create above does the minting.
	if dev == nil || dev.ID == 0 {
		return device.ErrInvalidDeviceID
	}
	m.devices[dev.ID] = dev
	return nil
}

func (m *mcpMockDeviceService) Get(ctx context.Context, id uint64) (*deviceentities.Device, error) {
	if device, ok := m.devices[id]; ok {
		return device, nil
	}
	return nil, ErrDeviceNotFound{DeviceID: string(rune(id))}
}

func (m *mcpMockDeviceService) Delete(ctx context.Context, device *deviceentities.Device) error {
	delete(m.devices, device.ID)
	return nil
}

func (m *mcpMockDeviceService) Update(ctx context.Context, device *deviceentities.Device) error {
	if _, ok := m.devices[device.ID]; !ok {
		return ErrDeviceNotFound{DeviceID: string(rune(device.ID))}
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mcpMockDeviceService) Count(ctx context.Context) (int, error) {
	return len(m.devices), nil
}

func (m *mcpMockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*deviceentities.Device], error) {
	devices := make([]*deviceentities.Device, 0, len(m.devices))
	for _, d := range m.devices {
		devices = append(devices, d)
	}
	return datastore.PageResult[*deviceentities.Device]{
		Entities: devices,
		Total:    len(devices),
	}, nil
}

func (m *mcpMockDeviceService) FindBySerial(ctx context.Context, serial string) (*deviceentities.Device, error) {
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, ErrDeviceNotFound{DeviceID: serial}
}

// FindByHostname finds a device by its IDevID hostname.
func (m *mcpMockDeviceService) FindByHostname(ctx context.Context, hostname string) (*deviceentities.Device, error) {
	for _, d := range m.devices {
		if d.Hostname == hostname {
			return d, nil
		}
	}
	return nil, ErrDeviceNotFound{DeviceID: hostname}
}

// =============================================================================
// Mock Device Profile Service for MCP tests
// =============================================================================

type mcpMockDeviceProfileService struct {
	profiles map[uint64]*deviceentities.DeviceProfile
	nextID   uint64
}

func newMCPMockDeviceProfileService() *mcpMockDeviceProfileService {
	return &mcpMockDeviceProfileService{
		profiles: make(map[uint64]*deviceentities.DeviceProfile),
		nextID:   1,
	}
}

func (m *mcpMockDeviceProfileService) Save(ctx context.Context, profile *deviceentities.DeviceProfile) error {
	if profile.ID == 0 {
		profile.ID = m.nextID
		m.nextID++
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mcpMockDeviceProfileService) Get(ctx context.Context, id uint64) (*deviceentities.DeviceProfile, error) {
	if profile, ok := m.profiles[id]; ok {
		return profile, nil
	}
	return nil, ErrProfileNotFound{Profile: string(rune(id))}
}

func (m *mcpMockDeviceProfileService) Delete(ctx context.Context, profile *deviceentities.DeviceProfile) error {
	delete(m.profiles, profile.ID)
	return nil
}

func (m *mcpMockDeviceProfileService) Update(ctx context.Context, profile *deviceentities.DeviceProfile, opts ...device.ProfileUpdateOption) error {
	if _, ok := m.profiles[profile.ID]; !ok {
		return ErrProfileNotFound{Profile: string(rune(profile.ID))}
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mcpMockDeviceProfileService) Count(ctx context.Context) (int, error) {
	return len(m.profiles), nil
}

func (m *mcpMockDeviceProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*deviceentities.DeviceProfile], error) {
	profiles := make([]*deviceentities.DeviceProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		profiles = append(profiles, p)
	}
	return datastore.PageResult[*deviceentities.DeviceProfile]{
		Entities: profiles,
		Total:    len(profiles),
	}, nil
}

func (m *mcpMockDeviceProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*deviceentities.DeviceProfile, error) {
	return nil, ErrProfileNotFound{Profile: macAddr}
}

func (m *mcpMockDeviceProfileService) FindBySerial(ctx context.Context, serial string) (*deviceentities.DeviceProfile, error) {
	return nil, ErrProfileNotFound{Profile: serial}
}

func (m *mcpMockDeviceProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*deviceentities.DeviceProfile, error) {
	for _, p := range m.profiles {
		if p.Model == model {
			return p, nil
		}
	}
	return nil, ErrProfileNotFound{Profile: model}
}

func (m *mcpMockDeviceProfileService) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	if ekSerial != "" {
		profile.EKSerial = ekSerial
	}
	if mac != "" {
		profile.MACAddress = mac
	}
	if ekCertPEM != "" {
		profile.EKCert = ekCertPEM
	}
	profile.Assigned = true
	profile.AssignedAt = time.Now().UTC()
	return nil
}

func (m *mcpMockDeviceProfileService) UnassignFromDevice(ctx context.Context, profileID uint64) error {
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}
	return nil
}

// =============================================================================
// vTPM Method Tests
// =============================================================================

func TestMCPServiceProvider_VTPMStart_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.VTPMStart(ctx, "test-bundle")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMStart_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStart(ctx, "test-bundle")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !mockSvc.running["test-bundle"] {
		t.Error("expected bundle to be running")
	}
}

func TestMCPServiceProvider_VTPMStart_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStart(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestMCPServiceProvider_VTPMStop_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.VTPMStop(ctx, "test-bundle")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMStop_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}
	mockSvc.running["test-bundle"] = true

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStop(ctx, "test-bundle")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if mockSvc.running["test-bundle"] {
		t.Error("expected bundle to be stopped")
	}
}

func TestMCPServiceProvider_VTPMStop_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStop(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestMCPServiceProvider_VTPMQuote_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMQuote(ctx, "test-bundle", []byte("nonce"), []int{0, 1, 2})
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMQuote_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMQuote(ctx, "test-bundle", []byte("nonce"), []int{0, 1, 2})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMQuote_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMQuote(ctx, "nonexistent", []byte("nonce"), []int{0})
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestMCPServiceProvider_VTPMSeal_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMSeal(ctx, "test-bundle", []byte("secret"), []int{0, 1, 2}, "")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMSeal_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMSeal(ctx, "test-bundle", []byte("secret"), []int{0, 1, 2}, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMSeal_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMSeal(ctx, "nonexistent", []byte("secret"), []int{0}, "")
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestMCPServiceProvider_VTPMUnseal_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMUnseal(ctx, "test-bundle", []byte("sealed"), "")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMUnseal_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMUnseal(ctx, "test-bundle", []byte("sealed"), "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMUnseal_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMUnseal(ctx, "nonexistent", []byte("sealed"), "")
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

// The MCP vTPM create, list, seal and unseal calls forward the options the
// gRPC VTPMService carries, so vtpm_bundle_* and vtpm_* reach the same backend.
func TestMCPServiceProvider_VTPMCreate_ForwardsSecureBootAndLabels(t *testing.T) {
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{VTPMService: mockSvc})

	labels := map[string]string{"env": "prod"}
	if _, err := provider.VTPMCreate(context.Background(), "web-1", "ECC", true, labels); err != nil {
		t.Fatalf("VTPMCreate: %v", err)
	}
	opts := mockSvc.lastCreateOpts
	if opts == nil || !opts.SecureBootEnabled || opts.Labels["env"] != "prod" || opts.EKAlgorithm != vtpm.EKAlgorithmECC {
		t.Fatalf("CreateBundleOptions = %+v, want secure boot, env=prod and ECC", opts)
	}
}

func TestMCPServiceProvider_VTPMCreate_InvalidAlgorithm(t *testing.T) {
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{VTPMService: mockSvc})

	if _, err := provider.VTPMCreate(context.Background(), "web-1", "DSA", true, nil); err == nil {
		t.Fatal("VTPMCreate with algorithm DSA succeeded")
	}
	if mockSvc.lastCreateOpts != nil {
		t.Fatalf("invalid algorithm reached CreateBundle: %+v", mockSvc.lastCreateOpts)
	}
}

func TestMCPServiceProvider_VTPMList_ForwardsFilters(t *testing.T) {
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{VTPMService: mockSvc})

	want := &vtpm.ListOptions{Mode: vtpm.BundleModeTemplate, Limit: 5, Offset: 2}
	if _, err := provider.VTPMList(context.Background(), want); err != nil {
		t.Fatalf("VTPMList: %v", err)
	}
	if mockSvc.lastListOpts != want {
		t.Fatalf("ListBundles got %+v, want %+v", mockSvc.lastListOpts, want)
	}
}

func TestMCPServiceProvider_VTPMSeal_ForwardsAuthValue(t *testing.T) {
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["b-1"] = &vtpm.Bundle{ID: "b-1"}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{VTPMService: mockSvc})

	if _, err := provider.VTPMSeal(context.Background(), "b-1", []byte("secret"), []int{7}, "pw"); err != nil {
		t.Fatalf("VTPMSeal: %v", err)
	}
	opts := mockSvc.lastSealOpts
	if opts == nil || opts.AuthValue != "pw" || len(opts.PCRs) != 1 || opts.PCRs[0] != 7 {
		t.Fatalf("SealOptions = %+v, want PCRs [7] and auth pw", opts)
	}
}

func TestMCPServiceProvider_VTPMUnseal_ForwardsAuthValue(t *testing.T) {
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["b-1"] = &vtpm.Bundle{ID: "b-1"}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{VTPMService: mockSvc})

	if _, err := provider.VTPMUnseal(context.Background(), "b-1", []byte("sealed"), "pw"); err != nil {
		t.Fatalf("VTPMUnseal: %v", err)
	}
	if mockSvc.lastUnsealAuth != "pw" {
		t.Fatalf("Unseal auth = %q, want pw", mockSvc.lastUnsealAuth)
	}
}

func TestMCPServiceProvider_VTPMExtendPCR_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.VTPMExtendPCR(ctx, "test-bundle", 0, []byte("data"))
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMExtendPCR_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMExtendPCR(ctx, "test-bundle", 0, []byte("data"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_VTPMExtendPCR_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMExtendPCR(ctx, "nonexistent", 0, []byte("data"))
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestMCPServiceProvider_VTPMReadPCR_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMReadPCR(ctx, "test-bundle", 0)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMReadPCR_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{ID: "test-bundle"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMReadPCR(ctx, "test-bundle", 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMReadPCR_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMReadPCR(ctx, "nonexistent", 0)
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

// =============================================================================
// DNS Method Tests
// =============================================================================

func TestMCPServiceProvider_DNSGetRecord_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DNSGetRecord(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSGetRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSGetRecord(ctx, "test.example.com", "A")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_DNSGetRecord_EmptyName(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSGetRecord(ctx, "", "A")
	if err == nil {
		t.Error("expected error for empty name")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSGetRecord_EmptyType(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSGetRecord(ctx, "test.example.com", "")
	if err == nil {
		t.Error("expected error for empty record type")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSListRecords_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DNSListRecords(ctx, "example.com")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSListRecords_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListRecords(ctx, "example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_DNSListRecords_EmptyZone(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSListRecords(ctx, "")
	if err == nil {
		t.Error("expected error for empty zone")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSResolve_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DNSResolve(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSResolve_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSResolve(ctx, "test.example.com", "A")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestMCPServiceProvider_DNSResolve_EmptyName(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSResolve(ctx, "", "A")
	if err == nil {
		t.Error("expected error for empty name")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSResolve_EmptyType(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSResolve(ctx, "test.example.com", "")
	if err == nil {
		t.Error("expected error for empty type")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSCreateZone_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSCreateZone(ctx, "example.com")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSCreateZone_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSCreateZone(ctx, "example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSCreateZone_EmptyZone(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSCreateZone(ctx, "")
	if err == nil {
		t.Error("expected error for empty zone")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSDeleteZone_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSDeleteZone(ctx, "example.com")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSDeleteZone_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	mockSvc.zones["example.com"] = &dnsentities.Zone{Name: "example.com"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteZone(ctx, "example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSDeleteZone_EmptyZone(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteZone(ctx, "")
	if err == nil {
		t.Error("expected error for empty zone")
	}
	if _, ok := err.(ErrDNSInvalidParameter); !ok {
		t.Errorf("expected ErrDNSInvalidParameter, got %T", err)
	}
}

func TestMCPServiceProvider_DNSListZones_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DNSListZones(ctx)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSListZones_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	mockSvc.zones["example.com"] = &dnsentities.Zone{Name: "example.com"}
	mockSvc.zones["test.com"] = &dnsentities.Zone{Name: "test.com"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListZones(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 zones, got %d", len(result))
	}
}

// =============================================================================
// Device Method Tests
// =============================================================================

func TestMCPServiceProvider_DeviceList_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceList(ctx, nil)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceList_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	mockSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}
	mockSvc.devices[2] = &deviceentities.Device{ID: 2, Model: "test-model-2", Serial: "SN002"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	result, err := provider.DeviceList(ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 devices, got %d", len(result))
	}
}

func TestMCPServiceProvider_DeviceDelete_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DeviceDelete(ctx, "1")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceDelete_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	mockSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	err := provider.DeviceDelete(ctx, "1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if _, ok := mockSvc.devices[1]; ok {
		t.Error("expected device to be deleted")
	}
}

func TestMCPServiceProvider_DeviceDelete_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	err := provider.DeviceDelete(ctx, "invalid")
	if err == nil {
		t.Error("expected error for invalid ID")
	}
	if _, ok := err.(ErrInvalidDeviceID); !ok {
		t.Errorf("expected ErrInvalidDeviceID, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceUpdate_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DeviceUpdate(ctx, "1", map[string]interface{}{"model": "new-model"})
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceUpdate_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	mockSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "old-model", Serial: "SN001"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	err := provider.DeviceUpdate(ctx, "1", map[string]interface{}{"model": "new-model"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if mockSvc.devices[1].Model != "new-model" {
		t.Errorf("expected model to be 'new-model', got %s", mockSvc.devices[1].Model)
	}
}

func TestMCPServiceProvider_DeviceUpdate_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	err := provider.DeviceUpdate(ctx, "invalid", map[string]interface{}{"model": "new-model"})
	if err == nil {
		t.Error("expected error for invalid ID")
	}
	if _, ok := err.(ErrInvalidDeviceID); !ok {
		t.Errorf("expected ErrInvalidDeviceID, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceAttest_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceAttest(ctx, "1", []byte(`{"quote":"x"}`))
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// TestMCPServiceProvider_DeviceAttest_DelegatesToTheSharedVerifier pins the
// MCP transport to the same verifier as gRPC/QUIC/REST: with no CA wired the
// quote fails closed on the trust anchor, and — the regression this guards —
// caller-supplied evidence never rewrites the device's enrolled material.
func TestMCPServiceProvider_DeviceAttest_DelegatesToTheSharedVerifier(t *testing.T) {
	ctx := context.Background()
	f := newQuoteFixture(t)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        f.devices,
		DeviceProfileService: f.profiles,
		VerdictSink:          f.sink,
	})
	enrolledCert := f.device.AttestCert

	raw, err := provider.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, []byte("nonce-mcp"), goldenPCRs()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, ok := raw.(*DeviceAttestationResult)
	if !ok {
		t.Fatalf("result type = %T, want *DeviceAttestationResult", raw)
	}
	if result.Verified || result.AKCertificateVerified {
		t.Fatalf("no CA is wired: the quote must fail closed, got %+v", result)
	}
	if got := f.devices.devices[f.device.ID].AttestCert; got != enrolledCert {
		t.Fatal("MCP attestation must never overwrite the device's enrolled attestation certificate")
	}
	if v := f.sink.last(t); v.Passed || v.Cryptographic {
		t.Fatalf("a missing trust anchor is an absence of evidence, got %+v", v)
	}
}

func TestMCPServiceProvider_DeviceAttest_RejectsUnusableRequests(t *testing.T) {
	ctx := context.Background()
	f := newQuoteFixture(t)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        f.devices,
		DeviceProfileService: f.profiles,
	})

	cases := []struct {
		name     string
		deviceID string
		evidence []byte
		want     error
	}{
		{"empty device id", "", []byte(`{"quote":"x"}`), ErrAttestationFailed{}},
		{"empty evidence", "1", []byte{}, ErrAttestationFailed{}},
		{"not json", itoa(f.device.ID), []byte("not json"), ErrInvalidAttestationEvidence{}},
		{"legacy enrollment shape", itoa(f.device.ID), []byte(`{"ek_cert":"x","attest_pub":"y"}`), ErrInvalidAttestationEvidence{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.DeviceAttest(ctx, tc.deviceID, tc.evidence)
			if err == nil {
				t.Fatal("expected error")
			}
			if fmt.Sprintf("%T", err) != fmt.Sprintf("%T", tc.want) {
				t.Errorf("expected %T, got %T (%v)", tc.want, err, err)
			}
		})
	}
}

func TestMCPServiceProvider_DeviceProvision_NilDeviceService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DeviceProvision(ctx, "1", "profile-1")
	if err == nil {
		t.Error("expected error for nil device service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_NilProfileService(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockDevSvc,
	})

	err := provider.DeviceProvision(ctx, "1", "profile-1")
	if err == nil {
		t.Error("expected error for nil profile service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_EmptyDeviceID(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockProfileSvc := newMCPMockDeviceProfileService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "", "profile-1")
	if err == nil {
		t.Error("expected error for empty device ID")
	}
	if _, ok := err.(ErrProvisioningFailed); !ok {
		t.Errorf("expected ErrProvisioningFailed, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_InvalidDeviceID(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockProfileSvc := newMCPMockDeviceProfileService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "invalid", "profile-1")
	if err == nil {
		t.Error("expected error for invalid device ID")
	}
	if _, ok := err.(ErrInvalidDeviceID); !ok {
		t.Errorf("expected ErrInvalidDeviceID, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockProfileSvc := newMCPMockDeviceProfileService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "999", "profile-1")
	if err == nil {
		t.Error("expected error for device not found")
	}
	if _, ok := err.(ErrDeviceNotFound); !ok {
		t.Errorf("expected ErrDeviceNotFound, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_ProfileByID_Success(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockDevSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}

	mockProfileSvc := newMCPMockDeviceProfileService()
	mockProfileSvc.profiles[1] = &deviceentities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {
				VLAN: 100,
			},
		},
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "1", "1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_ProfileByMatch_Success(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockDevSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}

	mockProfileSvc := newMCPMockDeviceProfileService()
	mockProfileSvc.profiles[1] = &deviceentities.DeviceProfile{
		ID:    1,
		Name:  "test-profile",
		Model: "test-model",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {
				VLAN: 100,
			},
		},
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "1", "auto")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_ProfileNotFound(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockDevSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}

	mockProfileSvc := newMCPMockDeviceProfileService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "1", "999")
	if err == nil {
		t.Error("expected error for profile not found")
	}
	if _, ok := err.(ErrProfileNotFound); !ok {
		t.Errorf("expected ErrProfileNotFound, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceProvision_NoNetworkConfig(t *testing.T) {
	ctx := context.Background()
	mockDevSvc := newMCPMockDeviceService()
	mockDevSvc.devices[1] = &deviceentities.Device{ID: 1, Model: "test-model", Serial: "SN001"}

	mockProfileSvc := newMCPMockDeviceProfileService()
	mockProfileSvc.profiles[1] = &deviceentities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
		// No network configuration
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:        mockDevSvc,
		DeviceProfileService: mockProfileSvc,
	})

	err := provider.DeviceProvision(ctx, "1", "1")
	if err == nil {
		t.Error("expected error for no network config")
	}
	if _, ok := err.(ErrProvisioningFailed); !ok {
		t.Errorf("expected ErrProvisioningFailed, got %T", err)
	}
}

// FindProfileForDevice mirrors the real resolver's precedence: a profile
// bound to the device's EK identity first, else the match rules.
func (m *mcpMockDeviceProfileService) FindProfileForDevice(ctx context.Context, dev *deviceentities.Device) (*deviceentities.DeviceProfile, error) {
	if dev == nil {
		return nil, device.ErrDeviceRequired{}
	}
	ekSerial := ""
	if dev.EKCert != "" {
		if serial, err := deviceentities.EKSerialFromCertPEM(dev.EKCert); err == nil {
			ekSerial = serial
		}
	}
	if ekSerial != "" {
		for _, p := range m.profiles {
			if p.EKSerial == ekSerial {
				return p, nil
			}
		}
	}
	profile, err := m.FindMatchingProfile(ctx, "", dev.Serial, dev.Model)
	if err != nil {
		return nil, device.ErrNoProfileForDevice{DeviceID: dev.ID, Serial: dev.Serial, EKSerial: ekSerial}
	}
	return profile, nil
}
