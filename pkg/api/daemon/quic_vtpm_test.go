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

//go:build codec_msgpack

package daemon

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Mock vTPM Service for QUIC tests
// =============================================================================

type quicMockVTPMService struct {
	bundles   map[string]*vtpm.Bundle
	templates map[string]*vtpm.Template
	running   map[string]bool
}

func newQuicMockVTPMService() *quicMockVTPMService {
	return &quicMockVTPMService{
		bundles:   make(map[string]*vtpm.Bundle),
		templates: make(map[string]*vtpm.Template),
		running:   make(map[string]bool),
	}
}

func (m *quicMockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	bundle := &vtpm.Bundle{
		ID:        "test-bundle-001",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Version:           "1.0",
			ID:                "test-bundle-001",
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          opts.Hostname,
			CreatedAt:         time.Now(),
			EKAlgorithm:       opts.EKAlgorithm,
			SecureBootEnabled: opts.SecureBootEnabled,
			Labels:            opts.Labels,
		},
		TPMState: &vtpm.TPMState{
			StateDir:    "/var/lib/vtpm/bundles/test-bundle-001/tpm",
			PermallFile: "/var/lib/vtpm/bundles/test-bundle-001/tpm/tpm2-00.permall",
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *quicMockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if bundle, ok := m.bundles[id]; ok {
		return bundle, nil
	}
	return nil, vtpm.ErrBundleNotFound{ID: id}
}

func (m *quicMockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	delete(m.bundles, id)
	return nil
}

func (m *quicMockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	bundles := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		bundles = append(bundles, b)
	}
	return bundles, nil
}

func (m *quicMockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	template := &vtpm.Template{
		ID:                opts.ID,
		Description:       opts.Description,
		EKAlgorithm:       opts.EKAlgorithm,
		SecureBootEnabled: opts.SecureBootEnabled,
		CreatedAt:         time.Now(),
	}
	m.templates[template.ID] = template
	return template, nil
}

func (m *quicMockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if _, ok := m.templates[opts.TemplateID]; !ok {
		return nil, vtpm.ErrTemplateNotFound{ID: opts.TemplateID}
	}
	bundle := &vtpm.Bundle{
		ID:         "cloned-bundle-001",
		Mode:       vtpm.BundleModePreAssigned,
		CreatedAt:  time.Now(),
		ClonedFrom: opts.TemplateID,
		Manifest: &vtpm.Manifest{
			Hostname: opts.Hostname,
			Labels:   opts.Labels,
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *quicMockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	if template, ok := m.templates[id]; ok {
		return template, nil
	}
	return nil, vtpm.ErrTemplateNotFound{ID: id}
}

func (m *quicMockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	if _, ok := m.templates[id]; !ok {
		return vtpm.ErrTemplateNotFound{ID: id}
	}
	delete(m.templates, id)
	return nil
}

func (m *quicMockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	templates := make([]*vtpm.Template, 0, len(m.templates))
	for _, t := range m.templates {
		templates = append(templates, t)
	}
	return templates, nil
}

func (m *quicMockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	_, err := w.Write([]byte("mock-exported-bundle-data"))
	return err
}

func (m *quicMockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	bundle := &vtpm.Bundle{
		ID:        "imported-bundle-001",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname: "imported-host",
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *quicMockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	return nil
}

func (m *quicMockVTPMService) GetBundlePath(id string) string {
	return "/var/lib/vtpm/bundles/" + id
}

func (m *quicMockVTPMService) GetTPMSocketPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/swtpm-sock"
}

func (m *quicMockVTPMService) GetNVRAMPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/OVMF_VARS.fd"
}

func (m *quicMockVTPMService) Start(ctx context.Context, bundleID string) error {
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	if m.running[bundleID] {
		return vtpm.ErrVTPMAlreadyRunning{BundleID: bundleID}
	}
	m.running[bundleID] = true
	return nil
}

func (m *quicMockVTPMService) Stop(ctx context.Context, bundleID string) error {
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	m.running[bundleID] = false
	return nil
}

func (m *quicMockVTPMService) IsRunning(bundleID string) bool {
	return m.running[bundleID]
}

func (m *quicMockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	return &vtpm.QuoteResult{
		Quote:         []byte("mock-quote"),
		Signature:     []byte("mock-signature"),
		PCRValues:     map[int][]byte{0: []byte("mock-pcr-value")},
		HashAlgorithm: "SHA256",
	}, nil
}

func (m *quicMockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	// Mirrors vtpm.Service.Seal: a PCR-bound seal is refused.
	if opts != nil && len(opts.PCRs) > 0 {
		return nil, vtpm.ErrTPMSealFailed{BundleID: bundleID, Cause: common.ErrPCRBoundSealUnavailable{}}
	}
	return []byte("sealed-" + string(data)), nil
}

func (m *quicMockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	return []byte("unsealed-data"), nil
}

func (m *quicMockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	return nil
}

func (m *quicMockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	return []byte("mock-pcr-value"), nil
}

func (m *quicMockVTPMService) Close() error {
	return nil
}

// =============================================================================
// Test Setup
// =============================================================================

func createQUICTestHandler() (*QUICServiceHandler, *quicMockVTPMService) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockSvc := newQuicMockVTPMService()

	handler := newTestQUICServiceHandler(logger, WithQUICVTPMService(mockSvc))
	return handler, mockSvc
}

// =============================================================================
// Tests
// =============================================================================

func TestVTPMGetBundle_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a bundle first
	mockSvc.bundles["test-001"] = &vtpm.Bundle{
		ID:        "test-001",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:    "test-host",
			EKAlgorithm: vtpm.EKAlgorithmRSA,
		},
	}

	// Create request
	getReq := VTPMGetBundleRequest{ID: "test-001"}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var bundleResp VTPMGetBundleResponse
	if err := quicwire.DecodePayload(resp.Payload, &bundleResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if bundleResp.ID != "test-001" {
		t.Errorf("expected bundle ID test-001, got %s", bundleResp.ID)
	}
}

func TestVTPMGetBundle_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	getReq := VTPMGetBundleRequest{ID: "nonexistent"}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMGetBundle_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	getReq := VTPMGetBundleRequest{ID: ""}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMStart_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a bundle first
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	startReq := VTPMStartRequest{BundleID: "test-001"}
	payload, err := quicwire.EncodePayload(&startReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMStart,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var startResp VTPMStartResponse
	if err := quicwire.DecodePayload(resp.Payload, &startResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !startResp.Running {
		t.Error("expected vTPM to be running")
	}
}

func TestVTPMStart_AlreadyRunning(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	startReq := VTPMStartRequest{BundleID: "test-001"}
	payload, err := quicwire.EncodePayload(&startReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMStart,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusAlreadyExists {
		t.Errorf("expected status AlreadyExists, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMStop_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	stopReq := VTPMStopRequest{BundleID: "test-001"}
	payload, err := quicwire.EncodePayload(&stopReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMStop,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMStop_NotRunning(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a bundle but don't start it
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	stopReq := VTPMStopRequest{BundleID: "test-001"}
	payload, err := quicwire.EncodePayload(&stopReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMStop,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected status Unavailable, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMCreateTemplate_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateTemplateRequest{
		ID:                "test-template",
		Description:       "Test template",
		EKAlgorithm:       "RSA",
		SecureBootEnabled: true,
	}
	payload, err := quicwire.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMCreateTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var templateResp VTPMCreateTemplateResponse
	if err := quicwire.DecodePayload(resp.Payload, &templateResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if templateResp.ID != "test-template" {
		t.Errorf("expected template ID test-template, got %s", templateResp.ID)
	}
}

func TestVTPMCreateTemplate_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateTemplateRequest{
		ID:          "",
		Description: "Test template",
	}
	payload, err := quicwire.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMCreateTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMGetTemplate_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a template first
	mockSvc.templates["test-template"] = &vtpm.Template{
		ID:          "test-template",
		Description: "Test",
		EKAlgorithm: vtpm.EKAlgorithmRSA,
		CreatedAt:   time.Now(),
	}

	getReq := VTPMGetTemplateRequest{ID: "test-template"}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMGetTemplate_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	getReq := VTPMGetTemplateRequest{ID: "nonexistent"}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMListTemplates_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create some templates
	mockSvc.templates["template-1"] = &vtpm.Template{ID: "template-1", CreatedAt: time.Now()}
	mockSvc.templates["template-2"] = &vtpm.Template{ID: "template-2", CreatedAt: time.Now()}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMListTemplates,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var listResp VTPMListTemplatesResponse
	if err := quicwire.DecodePayload(resp.Payload, &listResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if listResp.Total != 2 {
		t.Errorf("expected 2 templates, got %d", listResp.Total)
	}
}

func TestVTPMCloneTemplate_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a template first
	mockSvc.templates["base-template"] = &vtpm.Template{ID: "base-template"}

	cloneReq := VTPMCloneTemplateRequest{
		TemplateID: "base-template",
		Hostname:   "new-vm",
		Labels:     map[string]string{"env": "test"},
	}
	payload, err := quicwire.EncodePayload(&cloneReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMCloneTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMCloneTemplate_TemplateNotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	cloneReq := VTPMCloneTemplateRequest{
		TemplateID: "nonexistent",
		Hostname:   "new-vm",
	}
	payload, err := quicwire.EncodePayload(&cloneReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMCloneTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMQuote_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	quoteReq := VTPMQuoteRequest{
		BundleID: "test-001",
		Nonce:    []byte("random-nonce"),
		PCRs:     []int{0, 1, 2},
	}
	payload, err := quicwire.EncodePayload(&quoteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMQuote,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMQuote_NotRunning(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a bundle but don't start it
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	quoteReq := VTPMQuoteRequest{
		BundleID: "test-001",
		Nonce:    []byte("random-nonce"),
		PCRs:     []int{0, 1, 2},
	}
	payload, err := quicwire.EncodePayload(&quoteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMQuote,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected status Unavailable, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMSeal_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	sealReq := VTPMSealRequest{
		BundleID:  "test-001",
		Data:      []byte("secret-data"),
		AuthValue: "password",
	}
	payload, err := quicwire.EncodePayload(&sealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMSeal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMSeal_RefusesPCRBoundSeal(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	sealReq := VTPMSealRequest{
		BundleID:  "test-001",
		Data:      []byte("secret-data"),
		PCRs:      []int{7},
		AuthValue: "password",
	}
	payload, err := quicwire.EncodePayload(&sealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpVTPMSeal, Payload: payload})

	if resp.Status != quicwire.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quicwire.StatusToString(resp.Status))
	}
	if !bytes.Contains(resp.Payload, []byte("go-quicbaas #1171")) {
		t.Errorf("the refusal must name the missing upstream capability, got %q", resp.Payload)
	}
}

func TestVTPMSeal_MissingData(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	sealReq := VTPMSealRequest{
		BundleID: "test-001",
		Data:     nil,
	}
	payload, err := quicwire.EncodePayload(&sealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMSeal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMUnseal_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	unsealReq := VTPMUnsealRequest{
		BundleID:   "test-001",
		SealedData: []byte("sealed-secret"),
		AuthValue:  "password",
	}
	payload, err := quicwire.EncodePayload(&unsealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMUnseal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMExtendPCR_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	extendReq := VTPMExtendPCRRequest{
		BundleID: "test-001",
		PCRIndex: 7,
		Data:     []byte("measurement-data"),
	}
	payload, err := quicwire.EncodePayload(&extendReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMExtendPCR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMReadPCR_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create and start a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	readReq := VTPMReadPCRRequest{
		BundleID: "test-001",
		PCRIndex: 0,
	}
	payload, err := quicwire.EncodePayload(&readReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMReadPCR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}
}

func TestVTPMGetBundlePath_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: "test-001"}
	payload, err := quicwire.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetBundlePath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var pathResp VTPMGetPathResponse
	if err := quicwire.DecodePayload(resp.Payload, &pathResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if pathResp.Path == "" {
		t.Error("expected non-empty path")
	}
}

func TestVTPMValidateBundle_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	// Create a bundle
	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	validateReq := VTPMValidateBundleRequest{ID: "test-001"}
	payload, err := quicwire.EncodePayload(&validateReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMValidateBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusOK {
		t.Errorf("expected status OK, got %s", quicwire.StatusToString(resp.Status))
	}

	var validateResp VTPMValidateBundleResponse
	if err := quicwire.DecodePayload(resp.Payload, &validateResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !validateResp.Valid {
		t.Error("expected bundle to be valid")
	}
}

func TestVTPMServiceUnavailable(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	getReq := VTPMGetBundleRequest{ID: "test-001"}
	payload, err := quicwire.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quicwire.Request{
		Opcode:  quicwire.OpVTPMGetBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("expected status Unavailable when service is nil, got %s", quicwire.StatusToString(resp.Status))
	}
}
