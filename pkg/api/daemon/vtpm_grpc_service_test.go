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
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// mockVTPMService implements vtpm.VTPMService for testing.
type mockVTPMService struct {
	createBundleFunc     func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error)
	getBundleFunc        func(ctx context.Context, id string) (*vtpm.Bundle, error)
	deleteBundleFunc     func(ctx context.Context, id string) error
	listBundlesFunc      func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error)
	createTemplateFunc   func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error)
	cloneTemplateFunc    func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error)
	getTemplateFunc      func(ctx context.Context, id string) (*vtpm.Template, error)
	deleteTemplateFunc   func(ctx context.Context, id string) error
	listTemplatesFunc    func(ctx context.Context) ([]*vtpm.Template, error)
	exportBundleFunc     func(ctx context.Context, id string, w io.Writer) error
	importBundleFunc     func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error)
	validateBundleFunc   func(ctx context.Context, id string) error
	getBundlePathFunc    func(id string) string
	getTPMSocketPathFunc func(id string) string
	getNVRAMPathFunc     func(id string) string
	startFunc            func(ctx context.Context, bundleID string) error
	stopFunc             func(ctx context.Context, bundleID string) error
	isRunningFunc        func(bundleID string) bool
	quoteFunc            func(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error)
	sealFunc             func(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error)
	unsealFunc           func(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error)
	extendPCRFunc        func(ctx context.Context, bundleID string, pcrIndex int, data []byte) error
	readPCRFunc          func(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error)
	closeFunc            func() error
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	if m.createBundleFunc != nil {
		return m.createBundleFunc(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.getBundleFunc != nil {
		return m.getBundleFunc(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if m.deleteBundleFunc != nil {
		return m.deleteBundleFunc(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	if m.listBundlesFunc != nil {
		return m.listBundlesFunc(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	if m.createTemplateFunc != nil {
		return m.createTemplateFunc(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if m.cloneTemplateFunc != nil {
		return m.cloneTemplateFunc(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	if m.getTemplateFunc != nil {
		return m.getTemplateFunc(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	if m.deleteTemplateFunc != nil {
		return m.deleteTemplateFunc(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	if m.listTemplatesFunc != nil {
		return m.listTemplatesFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if m.exportBundleFunc != nil {
		return m.exportBundleFunc(ctx, id, w)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	if m.importBundleFunc != nil {
		return m.importBundleFunc(ctx, r)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	if m.validateBundleFunc != nil {
		return m.validateBundleFunc(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) GetBundlePath(id string) string {
	if m.getBundlePathFunc != nil {
		return m.getBundlePathFunc(id)
	}
	return ""
}

func (m *mockVTPMService) GetTPMSocketPath(id string) string {
	if m.getTPMSocketPathFunc != nil {
		return m.getTPMSocketPathFunc(id)
	}
	return ""
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	if m.getNVRAMPathFunc != nil {
		return m.getNVRAMPathFunc(id)
	}
	return ""
}

func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	if m.startFunc != nil {
		return m.startFunc(ctx, bundleID)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) Stop(ctx context.Context, bundleID string) error {
	if m.stopFunc != nil {
		return m.stopFunc(ctx, bundleID)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) IsRunning(bundleID string) bool {
	if m.isRunningFunc != nil {
		return m.isRunningFunc(bundleID)
	}
	return false
}

func (m *mockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	if m.quoteFunc != nil {
		return m.quoteFunc(ctx, bundleID, nonce, pcrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	if m.sealFunc != nil {
		return m.sealFunc(ctx, bundleID, data, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	if m.unsealFunc != nil {
		return m.unsealFunc(ctx, bundleID, sealedData, authValue)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	if m.extendPCRFunc != nil {
		return m.extendPCRFunc(ctx, bundleID, pcrIndex, data)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	if m.readPCRFunc != nil {
		return m.readPCRFunc(ctx, bundleID, pcrIndex)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func vtpmTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewVTPMServiceServer(t *testing.T) {
	mock := &mockVTPMService{}
	logger := vtpmTestLogger()

	server := NewVTPMServiceServer(mock, logger)

	if server == nil {
		t.Fatal("expected non-nil server")
	}

	if server.service != mock {
		t.Error("expected service to be set")
	}

	if server.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestVTPMServiceServer_CreateBundle_Success(t *testing.T) {
	now := time.Now()
	expectedBundle := &vtpm.Bundle{
		ID:        "bundle-123",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: now,
		Manifest: &vtpm.Manifest{
			Version:   "1.0",
			ID:        "bundle-123",
			Mode:      vtpm.BundleModePreAssigned,
			Hostname:  "test-host",
			CreatedAt: now,
		},
	}

	mock := &mockVTPMService{
		createBundleFunc: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			if opts.Mode != vtpm.BundleModePreAssigned {
				t.Errorf("expected mode %v, got %v", vtpm.BundleModePreAssigned, opts.Mode)
			}
			if opts.Hostname != "test-host" {
				t.Errorf("expected hostname test-host, got %s", opts.Hostname)
			}
			return expectedBundle, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:     platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Hostname: "test-host",
		},
	}

	resp, err := server.CreateBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Status.Success {
		t.Error("expected success status")
	}

	if resp.Bundle.Id != "bundle-123" {
		t.Errorf("expected bundle ID bundle-123, got %s", resp.Bundle.Id)
	}

	if resp.Bundle.Mode != platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED {
		t.Errorf("expected pre-assigned mode, got %v", resp.Bundle.Mode)
	}
}

func TestVTPMServiceServer_CreateBundle_MissingOptions(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateBundleRequest{
		Options: nil,
	}

	_, err := server.CreateBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing options")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetBundle_Success(t *testing.T) {
	now := time.Now()
	expectedBundle := &vtpm.Bundle{
		ID:        "bundle-123",
		Mode:      vtpm.BundleModeTemplate,
		CreatedAt: now,
	}

	mock := &mockVTPMService{
		getBundleFunc: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			if id != "bundle-123" {
				t.Errorf("expected ID bundle-123, got %s", id)
			}
			return expectedBundle, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetBundleRequest{
		Id: "bundle-123",
	}

	resp, err := server.GetBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Bundle.Id != "bundle-123" {
		t.Errorf("expected bundle ID bundle-123, got %s", resp.Bundle.Id)
	}
}

func TestVTPMServiceServer_GetBundle_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetBundleRequest{
		Id: "",
	}

	_, err := server.GetBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetBundle_NotFound(t *testing.T) {
	mock := &mockVTPMService{
		getBundleFunc: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return nil, errors.New("bundle not found")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetBundleRequest{
		Id: "nonexistent",
	}

	_, err := server.GetBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for not found")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_DeleteBundle_Success(t *testing.T) {
	mock := &mockVTPMService{
		deleteBundleFunc: func(ctx context.Context, id string) error {
			if id != "bundle-123" {
				t.Errorf("expected ID bundle-123, got %s", id)
			}
			return nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteBundleRequest{
		Id: "bundle-123",
	}

	resp, err := server.DeleteBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Status.Success {
		t.Error("expected success status")
	}
}

func TestVTPMServiceServer_DeleteBundle_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteBundleRequest{
		Id: "",
	}

	_, err := server.DeleteBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ListBundles_Success(t *testing.T) {
	now := time.Now()
	bundles := []*vtpm.Bundle{
		{ID: "bundle-1", Mode: vtpm.BundleModeTemplate, CreatedAt: now},
		{ID: "bundle-2", Mode: vtpm.BundleModePreAssigned, CreatedAt: now},
	}

	mock := &mockVTPMService{
		listBundlesFunc: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return bundles, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Limit:  10,
			Offset: 0,
		},
	}

	resp, err := server.ListBundles(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Bundles) != 2 {
		t.Errorf("expected 2 bundles, got %d", len(resp.Bundles))
	}

	if resp.Total != 2 {
		t.Errorf("expected total 2, got %d", resp.Total)
	}
}

func TestVTPMServiceServer_CreateTemplate_Success(t *testing.T) {
	now := time.Now()
	expectedTemplate := &vtpm.Template{
		ID:                "template-123",
		Description:       "Test template",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: true,
		CreatedAt:         now,
	}

	mock := &mockVTPMService{
		createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			if opts.ID != "template-123" {
				t.Errorf("expected ID template-123, got %s", opts.ID)
			}
			return expectedTemplate, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                "template-123",
			Description:       "Test template",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
			SecureBootEnabled: true,
		},
	}

	resp, err := server.CreateTemplate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Status.Success {
		t.Error("expected success status")
	}

	if resp.Template.Id != "template-123" {
		t.Errorf("expected template ID template-123, got %s", resp.Template.Id)
	}
}

func TestVTPMServiceServer_CreateTemplate_MissingOptions(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateTemplateRequest{
		Options: nil,
	}

	_, err := server.CreateTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing options")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetTemplate_Success(t *testing.T) {
	now := time.Now()
	expectedTemplate := &vtpm.Template{
		ID:          "template-123",
		EKAlgorithm: vtpm.EKAlgorithmECC,
		CreatedAt:   now,
	}

	mock := &mockVTPMService{
		getTemplateFunc: func(ctx context.Context, id string) (*vtpm.Template, error) {
			if id != "template-123" {
				t.Errorf("expected ID template-123, got %s", id)
			}
			return expectedTemplate, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetTemplateRequest{
		Id: "template-123",
	}

	resp, err := server.GetTemplate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Template.Id != "template-123" {
		t.Errorf("expected template ID template-123, got %s", resp.Template.Id)
	}

	if resp.Template.EkAlgorithm != platformv1.EKAlgorithm_EK_ALGORITHM_ECC {
		t.Errorf("expected ECC algorithm, got %v", resp.Template.EkAlgorithm)
	}
}

func TestVTPMServiceServer_GetTemplate_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetTemplateRequest{
		Id: "",
	}

	_, err := server.GetTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_DeleteTemplate_Success(t *testing.T) {
	mock := &mockVTPMService{
		deleteTemplateFunc: func(ctx context.Context, id string) error {
			if id != "template-123" {
				t.Errorf("expected ID template-123, got %s", id)
			}
			return nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteTemplateRequest{
		Id: "template-123",
	}

	resp, err := server.DeleteTemplate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Status.Success {
		t.Error("expected success status")
	}
}

func TestVTPMServiceServer_DeleteTemplate_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteTemplateRequest{
		Id: "",
	}

	_, err := server.DeleteTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ListTemplates_Success(t *testing.T) {
	now := time.Now()
	templates := []*vtpm.Template{
		{ID: "template-1", EKAlgorithm: vtpm.EKAlgorithmRSA, CreatedAt: now},
		{ID: "template-2", EKAlgorithm: vtpm.EKAlgorithmECC, CreatedAt: now},
	}

	mock := &mockVTPMService{
		listTemplatesFunc: func(ctx context.Context) ([]*vtpm.Template, error) {
			return templates, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ListTemplatesRequest{}

	resp, err := server.ListTemplates(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Templates) != 2 {
		t.Errorf("expected 2 templates, got %d", len(resp.Templates))
	}
}

func TestVTPMServiceServer_CloneTemplate_Success(t *testing.T) {
	now := time.Now()
	expectedBundle := &vtpm.Bundle{
		ID:         "bundle-cloned",
		Mode:       vtpm.BundleModePreAssigned,
		ClonedFrom: "template-123",
		CreatedAt:  now,
	}

	mock := &mockVTPMService{
		cloneTemplateFunc: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			if opts.TemplateID != "template-123" {
				t.Errorf("expected template ID template-123, got %s", opts.TemplateID)
			}
			if opts.Hostname != "cloned-host" {
				t.Errorf("expected hostname cloned-host, got %s", opts.Hostname)
			}
			return expectedBundle, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: "template-123",
			Hostname:   "cloned-host",
		},
	}

	resp, err := server.CloneTemplate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Status.Success {
		t.Error("expected success status")
	}

	if resp.Bundle.Id != "bundle-cloned" {
		t.Errorf("expected bundle ID bundle-cloned, got %s", resp.Bundle.Id)
	}

	if resp.Bundle.ClonedFrom != "template-123" {
		t.Errorf("expected cloned from template-123, got %s", resp.Bundle.ClonedFrom)
	}
}

func TestVTPMServiceServer_CloneTemplate_MissingOptions(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CloneTemplateRequest{
		Options: nil,
	}

	_, err := server.CloneTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing options")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ValidateBundle_Valid(t *testing.T) {
	mock := &mockVTPMService{
		validateBundleFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ValidateBundleRequest{
		Id: "bundle-123",
	}

	resp, err := server.ValidateBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Valid {
		t.Error("expected bundle to be valid")
	}

	if len(resp.Errors) > 0 {
		t.Errorf("expected no errors, got %v", resp.Errors)
	}
}

func TestVTPMServiceServer_ValidateBundle_Invalid(t *testing.T) {
	mock := &mockVTPMService{
		validateBundleFunc: func(ctx context.Context, id string) error {
			return errors.New("checksum mismatch")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ValidateBundleRequest{
		Id: "bundle-123",
	}

	resp, err := server.ValidateBundle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Valid {
		t.Error("expected bundle to be invalid")
	}

	if len(resp.Errors) == 0 {
		t.Error("expected errors to be populated")
	}
}

func TestVTPMServiceServer_ValidateBundle_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ValidateBundleRequest{
		Id: "",
	}

	_, err := server.ValidateBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetBundlePath_Success(t *testing.T) {
	mock := &mockVTPMService{
		getBundlePathFunc: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetBundlePathRequest{
		Id: "bundle-123",
	}

	resp, err := server.GetBundlePath(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "/var/lib/vtpm/bundles/bundle-123"
	if resp.Path != expected {
		t.Errorf("expected path %s, got %s", expected, resp.Path)
	}
}

func TestVTPMServiceServer_GetBundlePath_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetBundlePathRequest{
		Id: "",
	}

	_, err := server.GetBundlePath(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetTPMSocketPath_Success(t *testing.T) {
	mock := &mockVTPMService{
		getTPMSocketPathFunc: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id + "/swtpm.sock"
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetTPMSocketPathRequest{
		Id: "bundle-123",
	}

	resp, err := server.GetTPMSocketPath(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "/var/lib/vtpm/bundles/bundle-123/swtpm.sock"
	if resp.Path != expected {
		t.Errorf("expected path %s, got %s", expected, resp.Path)
	}
}

func TestVTPMServiceServer_GetTPMSocketPath_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetTPMSocketPathRequest{
		Id: "",
	}

	_, err := server.GetTPMSocketPath(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetNVRAMPath_Success(t *testing.T) {
	mock := &mockVTPMService{
		getNVRAMPathFunc: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id + "/OVMF_VARS.fd"
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetNVRAMPathRequest{
		Id: "bundle-123",
	}

	resp, err := server.GetNVRAMPath(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "/var/lib/vtpm/bundles/bundle-123/OVMF_VARS.fd"
	if resp.Path != expected {
		t.Errorf("expected path %s, got %s", expected, resp.Path)
	}
}

func TestVTPMServiceServer_GetNVRAMPath_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetNVRAMPathRequest{
		Id: "",
	}

	_, err := server.GetNVRAMPath(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_mapError(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: codes.OK,
		},
		{
			name:         "not found error",
			err:          errors.New("bundle not found"),
			expectedCode: codes.NotFound,
		},
		{
			name:         "does not exist error",
			err:          errors.New("resource does not exist"),
			expectedCode: codes.NotFound,
		},
		{
			name:         "already exists error",
			err:          errors.New("bundle already exists"),
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "invalid argument error",
			err:          errors.New("invalid bundle ID"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "required field error",
			err:          errors.New("hostname is required"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "permission denied error",
			err:          errors.New("permission denied"),
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "internal error",
			err:          errors.New("something went wrong"),
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.mapError(tt.err)

			if tt.err == nil {
				if result != nil {
					t.Errorf("expected nil error, got %v", result)
				}
				return
			}

			st, ok := status.FromError(result)
			if !ok {
				t.Fatal("expected grpc status error")
			}

			if st.Code() != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, st.Code())
			}
		})
	}
}

func TestVTPMServiceServer_BundleModeConversion(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		protoMode    platformv1.BundleMode
		expectedMode vtpm.BundleMode
	}{
		{platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, vtpm.BundleModeTemplate},
		{platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, vtpm.BundleModePreAssigned},
		{platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		t.Run(tt.protoMode.String(), func(t *testing.T) {
			result := server.protoToBundleMode(tt.protoMode)
			if result != tt.expectedMode {
				t.Errorf("expected %v, got %v", tt.expectedMode, result)
			}
		})
	}
}

func TestVTPMServiceServer_BundleModeToProto(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		mode         vtpm.BundleMode
		expectedMode platformv1.BundleMode
	}{
		{vtpm.BundleModeTemplate, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE},
		{vtpm.BundleModePreAssigned, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED},
		{"", platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			result := server.bundleModeToProto(tt.mode)
			if result != tt.expectedMode {
				t.Errorf("expected %v, got %v", tt.expectedMode, result)
			}
		})
	}
}

func TestVTPMServiceServer_EKAlgorithmConversion(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		protoAlg    platformv1.EKAlgorithm
		expectedAlg vtpm.EKAlgorithm
	}{
		{platformv1.EKAlgorithm_EK_ALGORITHM_RSA, vtpm.EKAlgorithmRSA},
		{platformv1.EKAlgorithm_EK_ALGORITHM_ECC, vtpm.EKAlgorithmECC},
		{platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, vtpm.EKAlgorithmRSA},
	}

	for _, tt := range tests {
		t.Run(tt.protoAlg.String(), func(t *testing.T) {
			result := server.protoToEKAlgorithm(tt.protoAlg)
			if result != tt.expectedAlg {
				t.Errorf("expected %v, got %v", tt.expectedAlg, result)
			}
		})
	}
}

func TestVTPMServiceServer_EKAlgorithmToProto(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		alg         vtpm.EKAlgorithm
		expectedAlg platformv1.EKAlgorithm
	}{
		{vtpm.EKAlgorithmRSA, platformv1.EKAlgorithm_EK_ALGORITHM_RSA},
		{vtpm.EKAlgorithmECC, platformv1.EKAlgorithm_EK_ALGORITHM_ECC},
		{"", platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			result := server.ekAlgorithmToProto(tt.alg)
			if result != tt.expectedAlg {
				t.Errorf("expected %v, got %v", tt.expectedAlg, result)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		s          string
		substrings []string
		expected   bool
	}{
		{"bundle not found", []string{"not found"}, true},
		{"error occurred", []string{"not found"}, false},
		{"already exists", []string{"not found", "already exists"}, true},
		{"", []string{"test"}, false},
		{"test", []string{""}, true},
		{"invalid input required", []string{"invalid", "required"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := containsAny(tt.s, tt.substrings...)
			if result != tt.expected {
				t.Errorf("containsAny(%q, %v) = %v, expected %v", tt.s, tt.substrings, result, tt.expected)
			}
		})
	}
}

func TestVTPMServiceServer_bundleToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.bundleToProto(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestVTPMServiceServer_templateToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.templateToProto(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestVTPMServiceServer_bundleToProto_Complete(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	now := time.Now()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	bundle := &vtpm.Bundle{
		ID:         "bundle-123",
		Mode:       vtpm.BundleModePreAssigned,
		ClonedFrom: "template-456",
		CreatedAt:  now,
		Manifest: &vtpm.Manifest{
			Version:           "1.0",
			ID:                "bundle-123",
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          "test-host",
			CreatedAt:         now,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			EKHandle:          0x01C00002,
			SecureBootEnabled: true,
			ClonedFrom:        "template-456",
			Checksums: map[string]string{
				"tpm2-00.permall": "abc123",
			},
			Labels: map[string]string{
				"env": "test",
			},
			EKCertificate: &vtpm.EKCertInfo{
				Subject:      "CN=TPM EK",
				Issuer:       "CN=TPM CA",
				SerialNumber: "123456",
				NotBefore:    notBefore,
				NotAfter:     notAfter,
				Fingerprint:  "sha256:abc123",
			},
			SecureBootKeys: &vtpm.SecureBootKeyInfo{
				PKFingerprint:  "pk-fp",
				KEKFingerprint: "kek-fp",
				DBFingerprint:  "db-fp",
				OwnerGUID:      "guid-123",
			},
		},
		TPMState: &vtpm.TPMState{
			StateDir:     "/var/lib/vtpm/bundles/bundle-123/tpm",
			PermallFile:  "/var/lib/vtpm/bundles/bundle-123/tpm/tpm2-00.permall",
			VolatileFile: "/var/lib/vtpm/bundles/bundle-123/tpm/tpm2-00.volatilestate",
		},
		OVMFState: &vtpm.OVMFState{
			NVRAMFile: "/var/lib/vtpm/bundles/bundle-123/OVMF_VARS.fd",
		},
		SecureBootKeys: &vtpm.SecureBootKeyPaths{
			Dir:     "/var/lib/vtpm/bundles/bundle-123/secureboot",
			PKKey:   "/var/lib/vtpm/bundles/bundle-123/secureboot/PK.key",
			PKCert:  "/var/lib/vtpm/bundles/bundle-123/secureboot/PK.crt",
			KEKKey:  "/var/lib/vtpm/bundles/bundle-123/secureboot/KEK.key",
			KEKCert: "/var/lib/vtpm/bundles/bundle-123/secureboot/KEK.crt",
			DBKey:   "/var/lib/vtpm/bundles/bundle-123/secureboot/DB.key",
			DBCert:  "/var/lib/vtpm/bundles/bundle-123/secureboot/DB.crt",
		},
	}

	result := server.bundleToProto(bundle)

	if result.Id != "bundle-123" {
		t.Errorf("expected ID bundle-123, got %s", result.Id)
	}

	if result.Mode != platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED {
		t.Errorf("expected pre-assigned mode, got %v", result.Mode)
	}

	if result.ClonedFrom != "template-456" {
		t.Errorf("expected cloned from template-456, got %s", result.ClonedFrom)
	}

	if result.Manifest == nil {
		t.Fatal("expected manifest to be set")
	}

	if result.Manifest.Hostname != "test-host" {
		t.Errorf("expected hostname test-host, got %s", result.Manifest.Hostname)
	}

	if result.Manifest.EkCertificate == nil {
		t.Fatal("expected EK certificate to be set")
	}

	if result.Manifest.EkCertificate.Subject != "CN=TPM EK" {
		t.Errorf("expected subject CN=TPM EK, got %s", result.Manifest.EkCertificate.Subject)
	}

	if result.TpmState == nil {
		t.Fatal("expected TPM state to be set")
	}

	if result.OvmfState == nil {
		t.Fatal("expected OVMF state to be set")
	}

	if result.SecureBootKeys == nil {
		t.Fatal("expected Secure Boot keys to be set")
	}
}

// Mock for export/import stream tests
type mockExportStream struct {
	platformv1.VTPMService_ExportBundleServer
	chunks [][]byte
	ctx    context.Context
}

func (m *mockExportStream) Context() context.Context {
	return m.ctx
}

func (m *mockExportStream) Send(resp *platformv1.ExportBundleResponse) error {
	m.chunks = append(m.chunks, resp.Data)
	return nil
}

type mockImportStream struct {
	platformv1.VTPMService_ImportBundleServer
	chunks   [][]byte
	index    int
	ctx      context.Context
	response *platformv1.ImportBundleResponse
}

func (m *mockImportStream) Context() context.Context {
	return m.ctx
}

func (m *mockImportStream) Recv() (*platformv1.ImportBundleRequest, error) {
	if m.index >= len(m.chunks) {
		return nil, io.EOF
	}
	req := &platformv1.ImportBundleRequest{
		Data: m.chunks[m.index],
	}
	m.index++
	return req, nil
}

func (m *mockImportStream) SendAndClose(resp *platformv1.ImportBundleResponse) error {
	m.response = resp
	return nil
}

func TestVTPMServiceServer_ExportBundle_Success(t *testing.T) {
	testData := []byte("test bundle data for export")

	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			_, err := w.Write(testData)
			return err
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockExportStream{
		ctx: context.Background(),
	}

	req := &platformv1.ExportBundleRequest{
		Id: "bundle-123",
	}

	err := server.ExportBundle(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reconstruct the data from chunks
	var received bytes.Buffer
	for _, chunk := range stream.chunks {
		received.Write(chunk)
	}

	if !bytes.Equal(received.Bytes(), testData) {
		t.Errorf("expected data %v, got %v", testData, received.Bytes())
	}
}

func TestVTPMServiceServer_ExportBundle_MissingID(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockExportStream{
		ctx: context.Background(),
	}

	req := &platformv1.ExportBundleRequest{
		Id: "",
	}

	err := server.ExportBundle(req, stream)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ImportBundle_Success(t *testing.T) {
	now := time.Now()
	expectedBundle := &vtpm.Bundle{
		ID:        "imported-bundle",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: now,
	}

	mock := &mockVTPMService{
		importBundleFunc: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			// Read all data to verify it was received
			data, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			if len(data) == 0 {
				return nil, errors.New("no data received")
			}
			return expectedBundle, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockImportStream{
		ctx: context.Background(),
		chunks: [][]byte{
			[]byte("chunk1"),
			[]byte("chunk2"),
		},
	}

	err := server.ImportBundle(stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stream.response == nil {
		t.Fatal("expected response to be set")
	}

	if !stream.response.Status.Success {
		t.Error("expected success status")
	}

	if stream.response.Bundle.Id != "imported-bundle" {
		t.Errorf("expected bundle ID imported-bundle, got %s", stream.response.Bundle.Id)
	}
}
