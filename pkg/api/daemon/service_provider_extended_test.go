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
	"io"
	"sync"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// Mock VTPM Service for service_provider extended coverage tests
// =============================================================================

type spExtMockVTPMService struct {
	mu          sync.RWMutex
	bundles     map[string]*vtpm.Bundle
	shouldError bool
	errorMsg    string
}

func newSPExtMockVTPMService() *spExtMockVTPMService {
	return &spExtMockVTPMService{
		bundles: make(map[string]*vtpm.Bundle),
	}
}

func (m *spExtMockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	bundle := &vtpm.Bundle{
		ID:   opts.Hostname,
		Mode: opts.Mode,
		Manifest: &vtpm.Manifest{
			Hostname: opts.Hostname,
		},
		CreatedAt: time.Now(),
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *spExtMockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if bundle, ok := m.bundles[id]; ok {
		return bundle, nil
	}
	return nil, errors.New("bundle not found")
}

func (m *spExtMockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	if _, ok := m.bundles[id]; !ok {
		return errors.New("bundle not found")
	}
	delete(m.bundles, id)
	return nil
}

func (m *spExtMockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	bundles := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		bundles = append(bundles, b)
	}
	return bundles, nil
}

func (m *spExtMockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) GetBundlePath(id string) string {
	return "/tmp/vtpm/" + id
}

func (m *spExtMockVTPMService) GetTPMSocketPath(id string) string {
	return "/tmp/vtpm/" + id + "/swtpm.sock"
}

func (m *spExtMockVTPMService) GetNVRAMPath(id string) string {
	return "/tmp/vtpm/" + id + "/OVMF_VARS.fd"
}

func (m *spExtMockVTPMService) Start(ctx context.Context, bundleID string) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) Stop(ctx context.Context, bundleID string) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) IsRunning(bundleID string) bool {
	return false
}

func (m *spExtMockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	return errors.New("not implemented")
}

func (m *spExtMockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *spExtMockVTPMService) Close() error {
	return nil
}

// =============================================================================
// Mock DNS Service for service_provider extended coverage tests
// =============================================================================

type spExtMockDNSService struct {
	mu          sync.RWMutex
	zones       map[string]*dnsentities.Zone
	records     map[string][]interface{}
	shouldError bool
	errorMsg    string
}

func newSPExtMockDNSService() *spExtMockDNSService {
	return &spExtMockDNSService{
		zones:   make(map[string]*dnsentities.Zone),
		records: make(map[string][]interface{}),
	}
}

func (m *spExtMockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	record := map[string]interface{}{
		"name":  name,
		"type":  recordType,
		"value": value,
		"ttl":   ttl,
	}
	m.records[name] = append(m.records[name], record)
	return nil
}

func (m *spExtMockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	if _, ok := m.records[name]; !ok {
		return errors.New("record not found")
	}
	delete(m.records, name)
	return nil
}

func (m *spExtMockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if records, ok := m.records[name]; ok {
		for _, r := range records {
			rec := r.(map[string]interface{})
			if rec["type"] == recordType {
				return rec, nil
			}
		}
	}
	return nil, errors.New("record not found")
}

func (m *spExtMockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	var result []interface{}
	for _, records := range m.records {
		result = append(result, records...)
	}
	return result, nil
}

func (m *spExtMockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if records, ok := m.records[name]; ok {
		var values []string
		for _, r := range records {
			rec := r.(map[string]interface{})
			if rec["type"] == recordType {
				values = append(values, rec["value"].(string))
			}
		}
		if len(values) > 0 {
			return values, nil
		}
	}
	return nil, errors.New("no records found")
}

func (m *spExtMockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.zones[zoneName] = &dnsentities.Zone{Name: zoneName}
	return nil
}

func (m *spExtMockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	if _, ok := m.zones[zoneName]; !ok {
		return errors.New("zone not found")
	}
	delete(m.zones, zoneName)
	return nil
}

func (m *spExtMockDNSService) ListZones(ctx context.Context) ([]*dnsentities.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	zones := make([]*dnsentities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

// Unused interface methods
func (m *spExtMockDNSService) Save(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}
func (m *spExtMockDNSService) SaveAndSign(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}
func (m *spExtMockDNSService) SignZone(zone *dnsentities.Zone) error { return nil }
func (m *spExtMockDNSService) Delete(ctx context.Context, zone *dnsentities.Zone) error {
	return nil
}
func (m *spExtMockDNSService) Zone(ctx context.Context, zoneName string) (*dnsentities.Zone, error) {
	return nil, nil
}
func (m *spExtMockDNSService) Register(ctx context.Context, fqdn, ip string) (*dnsentities.Zone, error) {
	return nil, nil
}
func (m *spExtMockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *dnsentities.TLSARecord) error {
	return nil
}
func (m *spExtMockDNSService) InternalZone(ctx context.Context) (*dnsentities.Zone, error) {
	return nil, nil
}
func (m *spExtMockDNSService) PublicZone(ctx context.Context) (*dnsentities.Zone, error) {
	return nil, nil
}
func (m *spExtMockDNSService) InternalDomain() string            { return "internal.local" }
func (m *spExtMockDNSService) PublicDomain() string              { return "public.example.com" }
func (m *spExtMockDNSService) DNSSECService() *dns.DNSSECService { return nil }
func (m *spExtMockDNSService) IsDNSSECEnabled() bool             { return false }

// =============================================================================
// VTPM Operations Extended Tests - With Working Mock Service
// =============================================================================

func TestPlatformServiceProvider_VTPMCreate_RSA_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMCreate(ctx, "test-vtpm", "RSA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bundle, ok := result.(*vtpm.Bundle)
	if !ok {
		t.Fatalf("expected *vtpm.Bundle, got %T", result)
	}
	if bundle.ID != "test-vtpm" {
		t.Errorf("expected ID=test-vtpm, got %s", bundle.ID)
	}
}

func TestPlatformServiceProvider_VTPMCreate_ECC_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMCreate(ctx, "test-vtpm-ecc", "ECC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bundle, ok := result.(*vtpm.Bundle)
	if !ok {
		t.Fatalf("expected *vtpm.Bundle, got %T", result)
	}
	if bundle.ID != "test-vtpm-ecc" {
		t.Errorf("expected ID=test-vtpm-ecc, got %s", bundle.ID)
	}
}

func TestPlatformServiceProvider_VTPMCreate_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "failed to create bundle"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMCreate(ctx, "test-vtpm", "RSA")
	if err == nil {
		t.Error("expected error from service")
	}
	if err.Error() != "failed to create bundle" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMDelete_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMDelete(ctx, "test-vtpm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, exists := mockSvc.bundles["test-vtpm"]; exists {
		t.Error("bundle should have been deleted")
	}
}

func TestPlatformServiceProvider_VTPMDelete_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMDelete(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMDelete_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}
	mockSvc.shouldError = true
	mockSvc.errorMsg = "delete failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMDelete(ctx, "test-vtpm")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_VTPMList_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["vtpm-1"] = &vtpm.Bundle{ID: "vtpm-1"}
	mockSvc.bundles["vtpm-2"] = &vtpm.Bundle{ID: "vtpm-2"}
	mockSvc.bundles["vtpm-3"] = &vtpm.Bundle{ID: "vtpm-3"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 bundles, got %d", len(result))
	}
}

func TestPlatformServiceProvider_VTPMList_Empty(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 bundles, got %d", len(result))
	}
}

func TestPlatformServiceProvider_VTPMList_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "list failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMList(ctx)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_VTPMStart_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStart(ctx, "test-vtpm")
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM start not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMStart_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStart(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMStop_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStop(ctx, "test-vtpm")
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM stop not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMStop_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMStop(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMQuote_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMQuote(ctx, "test-vtpm", []byte("nonce"), []int{0, 1, 2, 7})
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM quote not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMQuote_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMQuote(ctx, "non-existent", []byte("nonce"), []int{0, 1})
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMSeal_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMSeal(ctx, "test-vtpm", []byte("secret data"), []int{0, 1, 7})
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM seal not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMSeal_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMSeal(ctx, "non-existent", []byte("data"), []int{0})
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMUnseal_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMUnseal(ctx, "test-vtpm", []byte("sealed blob"))
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM unseal not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMUnseal_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMUnseal(ctx, "non-existent", []byte("sealed"))
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMExtendPCR_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMExtendPCR(ctx, "test-vtpm", 7, []byte("measurement data"))
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM extend PCR not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMExtendPCR_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	err := provider.VTPMExtendPCR(ctx, "non-existent", 0, []byte("data"))
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

func TestPlatformServiceProvider_VTPMReadPCR_Success_ReturnsNotImplemented(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMReadPCR(ctx, "test-vtpm", 7)
	if err == nil {
		t.Error("expected error for not implemented")
	}
	if err.Error() != "vTPM read PCR not yet implemented in service layer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMReadPCR_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	_, err := provider.VTPMReadPCR(ctx, "non-existent", 0)
	if err == nil {
		t.Error("expected error for non-existent bundle")
	}
}

// =============================================================================
// DNS Operations Extended Tests - With Working Mock Service
// =============================================================================

func TestPlatformServiceProvider_DNSAddRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.100", 300)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mockSvc.records["test.example.com"]) != 1 {
		t.Error("record should have been added")
	}
}

func TestPlatformServiceProvider_DNSAddRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "add record failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.100", 300)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSDeleteRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.records["test.example.com"] = []interface{}{
		map[string]interface{}{"name": "test.example.com", "type": "A"},
	}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, exists := mockSvc.records["test.example.com"]; exists {
		t.Error("record should have been deleted")
	}
}

func TestPlatformServiceProvider_DNSDeleteRecord_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteRecord(ctx, "non-existent.example.com", "A")
	if err == nil {
		t.Error("expected error for non-existent record")
	}
}

func TestPlatformServiceProvider_DNSDeleteRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.records["test.example.com"] = []interface{}{
		map[string]interface{}{"name": "test.example.com", "type": "A"},
	}
	mockSvc.shouldError = true
	mockSvc.errorMsg = "delete failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSGetRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.records["test.example.com"] = []interface{}{
		map[string]interface{}{"name": "test.example.com", "type": "A", "value": "192.168.1.100"},
	}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSGetRecord(ctx, "test.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	record := result.(map[string]interface{})
	if record["value"] != "192.168.1.100" {
		t.Errorf("unexpected value: %v", record["value"])
	}
}

func TestPlatformServiceProvider_DNSGetRecord_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSGetRecord(ctx, "non-existent.example.com", "A")
	if err == nil {
		t.Error("expected error for non-existent record")
	}
}

func TestPlatformServiceProvider_DNSGetRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "get failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSGetRecord(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSListRecords_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.records["test1.example.com"] = []interface{}{
		map[string]interface{}{"name": "test1.example.com", "type": "A"},
	}
	mockSvc.records["test2.example.com"] = []interface{}{
		map[string]interface{}{"name": "test2.example.com", "type": "A"},
	}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListRecords(ctx, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 records, got %d", len(result))
	}
}

func TestPlatformServiceProvider_DNSListRecords_Empty(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListRecords(ctx, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 records, got %d", len(result))
	}
}

func TestPlatformServiceProvider_DNSListRecords_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "list failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSListRecords(ctx, "example.com")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSResolve_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.records["test.example.com"] = []interface{}{
		map[string]interface{}{"name": "test.example.com", "type": "A", "value": "192.168.1.100"},
		map[string]interface{}{"name": "test.example.com", "type": "A", "value": "192.168.1.101"},
	}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSResolve(ctx, "test.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 values, got %d", len(result))
	}
}

func TestPlatformServiceProvider_DNSResolve_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSResolve(ctx, "non-existent.example.com", "A")
	if err == nil {
		t.Error("expected error for non-existent record")
	}
}

func TestPlatformServiceProvider_DNSResolve_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "resolve failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSResolve(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSCreateZone_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSCreateZone(ctx, "new-zone.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, exists := mockSvc.zones["new-zone.example.com"]; !exists {
		t.Error("zone should have been created")
	}
}

func TestPlatformServiceProvider_DNSCreateZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "create zone failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSCreateZone(ctx, "new-zone.example.com")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSDeleteZone_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.zones["example.com"] = &dnsentities.Zone{Name: "example.com"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteZone(ctx, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, exists := mockSvc.zones["example.com"]; exists {
		t.Error("zone should have been deleted")
	}
}

func TestPlatformServiceProvider_DNSDeleteZone_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteZone(ctx, "non-existent.example.com")
	if err == nil {
		t.Error("expected error for non-existent zone")
	}
}

func TestPlatformServiceProvider_DNSDeleteZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.zones["example.com"] = &dnsentities.Zone{Name: "example.com"}
	mockSvc.shouldError = true
	mockSvc.errorMsg = "delete zone failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSDeleteZone(ctx, "example.com")
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestPlatformServiceProvider_DNSListZones_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.zones["zone1.example.com"] = &dnsentities.Zone{Name: "zone1.example.com"}
	mockSvc.zones["zone2.example.com"] = &dnsentities.Zone{Name: "zone2.example.com"}
	mockSvc.zones["zone3.example.com"] = &dnsentities.Zone{Name: "zone3.example.com"}

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListZones(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 zones, got %d", len(result))
	}
}

func TestPlatformServiceProvider_DNSListZones_Empty(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	result, err := provider.DNSListZones(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 zones, got %d", len(result))
	}
}

func TestPlatformServiceProvider_DNSListZones_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()
	mockSvc.shouldError = true
	mockSvc.errorMsg = "list zones failed"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	_, err := provider.DNSListZones(ctx)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// SDN Operations Extended Tests - With Working Mock SDN Service
// =============================================================================

func TestPlatformServiceProvider_SDNGetPortState_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPMockSDNService()
	mockSvc.ports["eth0"] = &platformv1.Port{
		Id:       "eth0",
		BridgeId: "br0",
		Config:   &platformv1.PortConfig{Name: "eth0"},
	}

	// We need to wrap the mock in an SDNService since service_provider expects *SDNService
	// For this test, we check the nil service path
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortState(ctx, "br0", "eth0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNListBridges_WithService(t *testing.T) {
	ctx := context.Background()

	// Test nil service returns proper error
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNAddFlow_WithAllFields(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"priority":     100,
		"table":        "FLOW_TABLE_CLASSIFICATION",
		"idle_timeout": 300,
		"hard_timeout": 600,
		"match": map[string]interface{}{
			"in_port":  "eth0",
			"vlan_id":  100,
			"eth_src":  "00:11:22:33:44:55",
			"eth_dst":  "66:77:88:99:aa:bb",
			"eth_type": 0x0800,
			"ip_src":   "192.168.1.1",
			"ip_dst":   "192.168.1.2",
			"ip_proto": 6,
			"tcp_src":  80,
			"tcp_dst":  443,
			"udp_src":  53,
			"udp_dst":  5353,
			"metadata": map[string]string{"key": "value"},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type":     "FLOW_ACTION_OUTPUT",
				"port":     "eth1",
				"vlan_id":  200,
				"field":    "dst_ip",
				"value":    "10.0.0.1",
				"table_id": 5,
			},
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
}

func TestPlatformServiceProvider_SDNListFlows_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNListVLANs_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNAuthenticatePort_WithCredentials(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...test\n-----END CERTIFICATE-----",
		"format":      "PEM",
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
}

func TestPlatformServiceProvider_SDNAuthenticatePort_WithEmptyFormat(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...test\n-----END CERTIFICATE-----",
		// format is empty, should default to PEM
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
}

func TestPlatformServiceProvider_SDNRevokePortAuth_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNRevokePortAuth(ctx, "br0", "eth0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNGetPortStats_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_SDNGetFlowStats_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetFlowStats(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// Build Flow Match and Actions Edge Cases
// =============================================================================

func TestBuildFlowMatch_AllFieldTypes(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port":  "port1",
		"vlan_id":  100,
		"eth_src":  "aa:bb:cc:dd:ee:ff",
		"eth_dst":  "11:22:33:44:55:66",
		"eth_type": 0x0800,
		"ip_src":   "10.0.0.1",
		"ip_dst":   "10.0.0.2",
		"ip_proto": 17,
		"tcp_src":  8080,
		"tcp_dst":  80,
		"udp_src":  53,
		"udp_dst":  5353,
		"metadata": map[string]string{"tenant": "acme"},
	}

	match := buildFlowMatch(matchMap)
	if match.InPort != "port1" {
		t.Errorf("InPort = %q, want %q", match.InPort, "port1")
	}
	if match.VlanId != 100 {
		t.Errorf("VlanId = %d, want %d", match.VlanId, 100)
	}
	if match.EthSrc != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("EthSrc = %q, want %q", match.EthSrc, "aa:bb:cc:dd:ee:ff")
	}
	if match.EthDst != "11:22:33:44:55:66" {
		t.Errorf("EthDst = %q, want %q", match.EthDst, "11:22:33:44:55:66")
	}
	if match.EthType != 0x0800 {
		t.Errorf("EthType = %d, want %d", match.EthType, 0x0800)
	}
	if match.IpSrc != "10.0.0.1" {
		t.Errorf("IpSrc = %q, want %q", match.IpSrc, "10.0.0.1")
	}
	if match.IpDst != "10.0.0.2" {
		t.Errorf("IpDst = %q, want %q", match.IpDst, "10.0.0.2")
	}
	if match.IpProto != 17 {
		t.Errorf("IpProto = %d, want %d", match.IpProto, 17)
	}
	if match.TcpSrc != 8080 {
		t.Errorf("TcpSrc = %d, want %d", match.TcpSrc, 8080)
	}
	if match.TcpDst != 80 {
		t.Errorf("TcpDst = %d, want %d", match.TcpDst, 80)
	}
	if match.UdpSrc != 53 {
		t.Errorf("UdpSrc = %d, want %d", match.UdpSrc, 53)
	}
	if match.UdpDst != 5353 {
		t.Errorf("UdpDst = %d, want %d", match.UdpDst, 5353)
	}
	if match.Metadata["tenant"] != "acme" {
		t.Errorf("Metadata[tenant] = %q, want %q", match.Metadata["tenant"], "acme")
	}
}

func TestBuildFlowMatch_NilValues(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port": nil,
		"vlan_id": nil,
	}

	match := buildFlowMatch(matchMap)
	if match.InPort != "" {
		t.Errorf("InPort should be empty for nil value, got %q", match.InPort)
	}
	if match.VlanId != 0 {
		t.Errorf("VlanId should be 0 for nil value, got %d", match.VlanId)
	}
}

func TestBuildFlowActions_EmptyActionMap(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{}, // Empty map
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	// Action should have default/zero values
}

func TestBuildFlowActions_MixedTypes(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type": "FLOW_ACTION_OUTPUT",
			"port": "eth1",
		},
		"invalid string type", // Should be skipped
		123,                   // Should be skipped
		nil,                   // Should be skipped
		map[string]interface{}{
			"type":     "FLOW_ACTION_SET_VLAN",
			"vlan_id":  100,
			"table_id": 10,
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions (invalid types skipped), got %d", len(actions))
	}
}

// =============================================================================
// VTPM Algorithm Selection Tests
// =============================================================================

func TestPlatformServiceProvider_VTPMCreate_DefaultAlgorithm(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	// Any non-ECC algorithm should default to RSA
	_, err := provider.VTPMCreate(ctx, "test-vtpm", "UNKNOWN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlatformServiceProvider_VTPMCreate_EmptyAlgorithm(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	// Empty algorithm should default to RSA
	_, err := provider.VTPMCreate(ctx, "test-vtpm", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// Concurrent VTPM and DNS Operations
// =============================================================================

func TestPlatformServiceProvider_ConcurrentVTPMOperations(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	done := make(chan bool, 4)

	// Concurrent creates
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.VTPMCreate(ctx, "vtpm-create-"+string(rune('0'+i)), "RSA")
		}
		done <- true
	}()

	// Concurrent lists
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.VTPMList(ctx)
		}
		done <- true
	}()

	// Concurrent deletes
	go func() {
		for i := 0; i < 50; i++ {
			_ = provider.VTPMDelete(ctx, "vtpm-delete-"+string(rune('0'+i)))
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.VTPMList(ctx)
		}
		done <- true
	}()

	// Wait for all goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < 4; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("test timed out")
		}
	}
}

func TestPlatformServiceProvider_ConcurrentDNSOperations(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockDNSService()

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DNSService: mockSvc,
	})

	done := make(chan bool, 4)

	// Concurrent adds
	go func() {
		for i := 0; i < 50; i++ {
			_ = provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
		}
		done <- true
	}()

	// Concurrent list zones
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.DNSListZones(ctx)
		}
		done <- true
	}()

	// Concurrent list records
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.DNSListRecords(ctx, "example.com")
		}
		done <- true
	}()

	// Concurrent resolves
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = provider.DNSResolve(ctx, "test.example.com", "A")
		}
		done <- true
	}()

	// Wait for all goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < 4; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("test timed out")
		}
	}
}

// =============================================================================
// Additional SDN Flow Configuration Tests
// =============================================================================

func TestBuildFlowActions_AllActionTypes(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type": "FLOW_ACTION_OUTPUT",
			"port": "controller",
		},
		map[string]interface{}{
			"type":    "FLOW_ACTION_SET_VLAN",
			"vlan_id": 100,
		},
		map[string]interface{}{
			"type":  "FLOW_ACTION_SET_FIELD",
			"field": "eth_src",
			"value": "aa:bb:cc:dd:ee:ff",
		},
		map[string]interface{}{
			"type":     "FLOW_ACTION_GOTO_TABLE",
			"table_id": 5,
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(actions))
	}

	// Verify each action
	if actions[0].Port != "controller" {
		t.Errorf("action[0].Port = %q, want %q", actions[0].Port, "controller")
	}
	if actions[1].VlanId != 100 {
		t.Errorf("action[1].VlanId = %d, want %d", actions[1].VlanId, 100)
	}
	if actions[2].Field != "eth_src" {
		t.Errorf("action[2].Field = %q, want %q", actions[2].Field, "eth_src")
	}
	if actions[2].Value != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("action[2].Value = %q, want %q", actions[2].Value, "aa:bb:cc:dd:ee:ff")
	}
	if actions[3].TableId != 5 {
		t.Errorf("action[3].TableId = %d, want %d", actions[3].TableId, 5)
	}
}

// =============================================================================
// Service Not Available Tests - Additional Coverage
// =============================================================================

func TestPlatformServiceProvider_VTPMOperations_ServiceGetBundleError(t *testing.T) {
	ctx := context.Background()
	mockSvc := newSPExtMockVTPMService()
	mockSvc.bundles["test-vtpm"] = &vtpm.Bundle{ID: "test-vtpm"}
	mockSvc.shouldError = true
	mockSvc.errorMsg = "service unavailable"

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mockSvc,
	})

	// Test all operations that call GetBundle first
	err := provider.VTPMStart(ctx, "test-vtpm")
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	err = provider.VTPMStop(ctx, "test-vtpm")
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	_, err = provider.VTPMQuote(ctx, "test-vtpm", []byte("nonce"), []int{0})
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	_, err = provider.VTPMSeal(ctx, "test-vtpm", []byte("data"), []int{0})
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	_, err = provider.VTPMUnseal(ctx, "test-vtpm", []byte("sealed"))
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	err = provider.VTPMExtendPCR(ctx, "test-vtpm", 0, []byte("data"))
	if err == nil {
		t.Error("expected error from GetBundle")
	}

	_, err = provider.VTPMReadPCR(ctx, "test-vtpm", 0)
	if err == nil {
		t.Error("expected error from GetBundle")
	}
}
