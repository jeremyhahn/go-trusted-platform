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

package grpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockVTPMService implements vtpm.VTPMService for testing.
type mockVTPMService struct {
	createBundleResp   *vtpm.Bundle
	createBundleErr    error
	getBundleResp      *vtpm.Bundle
	getBundleErr       error
	deleteBundleErr    error
	listBundlesResp    []*vtpm.Bundle
	listBundlesErr     error
	createTemplateResp *vtpm.Template
	createTemplateErr  error
	getTemplateResp    *vtpm.Template
	getTemplateErr     error
	deleteTemplateErr  error
	listTemplatesResp  []*vtpm.Template
	listTemplatesErr   error
	cloneTemplateResp  *vtpm.Bundle
	cloneTemplateErr   error
	exportBundleData   []byte
	exportBundleErr    error
	importBundleResp   *vtpm.Bundle
	importBundleErr    error
	validateBundleErr  error
	bundlePath         string
	tpmSocketPath      string
	nvramPath          string
}

func newMockVTPMService() *mockVTPMService {
	now := time.Now()
	return &mockVTPMService{
		createBundleResp: &vtpm.Bundle{
			ID:   "test-bundle-123",
			Mode: vtpm.BundleModePreAssigned,
			Manifest: &vtpm.Manifest{
				Version:           "1.0",
				ID:                "test-bundle-123",
				Mode:              vtpm.BundleModePreAssigned,
				Hostname:          "test-vm",
				CreatedAt:         now,
				EKAlgorithm:       vtpm.EKAlgorithmRSA,
				EKHandle:          0x01C00002,
				SecureBootEnabled: true,
				Checksums:         map[string]string{"tpm/tpm2-00.permall": "sha256:abc123"},
				Labels:            map[string]string{"env": "test"},
				EKCertificate: &vtpm.EKCertInfo{
					Subject:      "CN=test-vm",
					Issuer:       "CN=Test CA",
					SerialNumber: "123456",
					NotBefore:    now,
					NotAfter:     now.Add(365 * 24 * time.Hour),
					Fingerprint:  "sha256:fingerprint123",
				},
				SecureBootKeys: &vtpm.SecureBootKeyInfo{
					PKFingerprint:  "sha256:pk123",
					KEKFingerprint: "sha256:kek123",
					DBFingerprint:  "sha256:db123",
					OwnerGUID:      "test-guid",
				},
			},
			TPMState: &vtpm.TPMState{
				StateDir:    "/var/vtpm/bundles/test-bundle-123/tpm",
				PermallFile: "/var/vtpm/bundles/test-bundle-123/tpm/tpm2-00.permall",
			},
			OVMFState: &vtpm.OVMFState{
				NVRAMFile: "/var/vtpm/bundles/test-bundle-123/ovmf/OVMF_VARS.fd",
			},
			SecureBootKeys: &vtpm.SecureBootKeyPaths{
				Dir:     "/var/vtpm/bundles/test-bundle-123/secure-boot-keys",
				PKKey:   "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/PK.key",
				PKCert:  "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/PK.crt",
				KEKKey:  "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/KEK.key",
				KEKCert: "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/KEK.crt",
				DBKey:   "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/DB.key",
				DBCert:  "/var/vtpm/bundles/test-bundle-123/secure-boot-keys/DB.crt",
			},
			CreatedAt: now,
		},
		getBundleResp: &vtpm.Bundle{
			ID:   "test-bundle-123",
			Mode: vtpm.BundleModePreAssigned,
			Manifest: &vtpm.Manifest{
				Version:     "1.0",
				ID:          "test-bundle-123",
				Mode:        vtpm.BundleModePreAssigned,
				Hostname:    "test-vm",
				CreatedAt:   now,
				EKAlgorithm: vtpm.EKAlgorithmRSA,
			},
			CreatedAt: now,
		},
		listBundlesResp: []*vtpm.Bundle{
			{
				ID:   "bundle-1",
				Mode: vtpm.BundleModePreAssigned,
				Manifest: &vtpm.Manifest{
					ID:          "bundle-1",
					Hostname:    "vm-1",
					EKAlgorithm: vtpm.EKAlgorithmRSA,
				},
				CreatedAt: now,
			},
			{
				ID:   "bundle-2",
				Mode: vtpm.BundleModeTemplate,
				Manifest: &vtpm.Manifest{
					ID:          "bundle-2",
					EKAlgorithm: vtpm.EKAlgorithmECC,
				},
				CreatedAt: now,
			},
		},
		createTemplateResp: &vtpm.Template{
			ID:                "test-template",
			Description:       "Test template",
			TPMStateDir:       "/var/vtpm/templates/test-template/tpm",
			NVRAMPath:         "/var/vtpm/templates/test-template/ovmf/OVMF_VARS.fd",
			SecureBootKeysDir: "/var/vtpm/templates/test-template/secure-boot-keys",
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
			CreatedAt:         now,
		},
		getTemplateResp: &vtpm.Template{
			ID:          "test-template",
			Description: "Test template",
			EKAlgorithm: vtpm.EKAlgorithmRSA,
			CreatedAt:   now,
		},
		listTemplatesResp: []*vtpm.Template{
			{
				ID:          "template-1",
				Description: "Template 1",
				EKAlgorithm: vtpm.EKAlgorithmRSA,
				CreatedAt:   now,
			},
			{
				ID:          "template-2",
				Description: "Template 2",
				EKAlgorithm: vtpm.EKAlgorithmECC,
				CreatedAt:   now,
			},
		},
		cloneTemplateResp: &vtpm.Bundle{
			ID:         "cloned-bundle-123",
			Mode:       vtpm.BundleModePreAssigned,
			ClonedFrom: "test-template",
			CreatedAt:  now,
		},
		importBundleResp: &vtpm.Bundle{
			ID:        "imported-bundle-123",
			Mode:      vtpm.BundleModePreAssigned,
			CreatedAt: now,
		},
		exportBundleData: []byte("mock-tar-gz-data-for-testing"),
		bundlePath:       "/var/vtpm/bundles/test-bundle-123",
		tpmSocketPath:    "/var/vtpm/bundles/test-bundle-123/tpm/swtpm.sock",
		nvramPath:        "/var/vtpm/bundles/test-bundle-123/ovmf/OVMF_VARS.fd",
	}
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	if m.createBundleErr != nil {
		return nil, m.createBundleErr
	}
	return m.createBundleResp, nil
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.getBundleErr != nil {
		return nil, m.getBundleErr
	}
	return m.getBundleResp, nil
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	return m.deleteBundleErr
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	if m.listBundlesErr != nil {
		return nil, m.listBundlesErr
	}
	return m.listBundlesResp, nil
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	if m.createTemplateErr != nil {
		return nil, m.createTemplateErr
	}
	return m.createTemplateResp, nil
}

func (m *mockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	if m.getTemplateErr != nil {
		return nil, m.getTemplateErr
	}
	return m.getTemplateResp, nil
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	return m.deleteTemplateErr
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	if m.listTemplatesErr != nil {
		return nil, m.listTemplatesErr
	}
	return m.listTemplatesResp, nil
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if m.cloneTemplateErr != nil {
		return nil, m.cloneTemplateErr
	}
	return m.cloneTemplateResp, nil
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if m.exportBundleErr != nil {
		return m.exportBundleErr
	}
	_, err := w.Write(m.exportBundleData)
	return err
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	if m.importBundleErr != nil {
		return nil, m.importBundleErr
	}
	return m.importBundleResp, nil
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	return m.validateBundleErr
}

func (m *mockVTPMService) GetBundlePath(id string) string {
	return m.bundlePath
}

func (m *mockVTPMService) GetTPMSocketPath(id string) string {
	return m.tpmSocketPath
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	return m.nvramPath
}

func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	return nil
}

func (m *mockVTPMService) Stop(ctx context.Context, bundleID string) error {
	return nil
}

func (m *mockVTPMService) IsRunning(bundleID string) bool {
	return false
}

func (m *mockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	return nil, nil
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	return nil, nil
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	return nil, nil
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	return nil
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	return nil, nil
}

func (m *mockVTPMService) Close() error {
	return nil
}

// Ensure mockVTPMService implements vtpm.VTPMService at compile time.
var _ vtpm.VTPMService = (*mockVTPMService)(nil)

func newTestVTPMService() (*VTPMGRPCService, *mockVTPMService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockVTPMService()
	service := NewVTPMGRPCService(logger, mock)
	return service, mock
}

// Test CreateBundle

func TestVTPMGRPCService_CreateBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Hostname:          "test-vm",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "test"},
		},
	}

	resp, err := service.CreateBundle(ctx, req)
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetBundle() == nil {
		t.Error("Expected bundle in response")
	}

	if resp.GetBundle().GetId() != "test-bundle-123" {
		t.Errorf("Expected bundle ID 'test-bundle-123', got '%s'", resp.GetBundle().GetId())
	}

	if resp.GetBundle().GetMode() != platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED {
		t.Errorf("Expected pre-assigned mode")
	}
}

func TestVTPMGRPCService_CreateBundle_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewVTPMGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Hostname: "test-vm",
		},
	}

	_, err := service.CreateBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestVTPMGRPCService_CreateBundle_MissingOptions(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CreateBundleRequest{}

	_, err := service.CreateBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing options")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_CreateBundle_ServiceError(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.createBundleErr = errors.New("bundle already exists")
	ctx := context.Background()

	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Hostname: "test-vm",
		},
	}

	_, err := service.CreateBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.AlreadyExists {
		t.Errorf("Expected AlreadyExists error, got %v", st.Code())
	}
}

// Test GetBundle

func TestVTPMGRPCService_GetBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetBundleRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.GetBundle(ctx, req)
	if err != nil {
		t.Fatalf("GetBundle failed: %v", err)
	}

	if resp.GetBundle() == nil || resp.GetBundle().GetId() != "test-bundle-123" {
		t.Error("Expected bundle in response")
	}
}

func TestVTPMGRPCService_GetBundle_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetBundleRequest{}

	_, err := service.GetBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_GetBundle_NotFound(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.getBundleErr = errors.New("bundle not found")
	ctx := context.Background()

	req := &platformv1.GetBundleRequest{
		Id: "nonexistent-bundle",
	}

	_, err := service.GetBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found bundle")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

// Test DeleteBundle

func TestVTPMGRPCService_DeleteBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.DeleteBundleRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.DeleteBundle(ctx, req)
	if err != nil {
		t.Fatalf("DeleteBundle failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestVTPMGRPCService_DeleteBundle_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.DeleteBundleRequest{}

	_, err := service.DeleteBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_DeleteBundle_NotFound(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.deleteBundleErr = errors.New("bundle not found")
	ctx := context.Background()

	req := &platformv1.DeleteBundleRequest{
		Id: "nonexistent-bundle",
	}

	_, err := service.DeleteBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found bundle")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

// Test ListBundles

func TestVTPMGRPCService_ListBundles_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Limit: 10,
		},
	}

	resp, err := service.ListBundles(ctx, req)
	if err != nil {
		t.Fatalf("ListBundles failed: %v", err)
	}

	if len(resp.GetBundles()) != 2 {
		t.Errorf("Expected 2 bundles, got %d", len(resp.GetBundles()))
	}

	if resp.GetTotal() != 2 {
		t.Errorf("Expected total 2, got %d", resp.GetTotal())
	}
}

func TestVTPMGRPCService_ListBundles_WithFilter(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Mode:   platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Labels: map[string]string{"env": "test"},
		},
	}

	resp, err := service.ListBundles(ctx, req)
	if err != nil {
		t.Fatalf("ListBundles failed: %v", err)
	}

	if resp.GetBundles() == nil {
		t.Error("Expected bundles in response")
	}
}

func TestVTPMGRPCService_ListBundles_NilOptions(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ListBundlesRequest{}

	resp, err := service.ListBundles(ctx, req)
	if err != nil {
		t.Fatalf("ListBundles failed: %v", err)
	}

	if resp.GetBundles() == nil {
		t.Error("Expected bundles in response")
	}
}

// Test CreateTemplate

func TestVTPMGRPCService_CreateTemplate_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                "test-template",
			Description:       "Test template",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
			SecureBootEnabled: true,
		},
	}

	resp, err := service.CreateTemplate(ctx, req)
	if err != nil {
		t.Fatalf("CreateTemplate failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetTemplate() == nil {
		t.Error("Expected template in response")
	}

	if resp.GetTemplate().GetId() != "test-template" {
		t.Errorf("Expected template ID 'test-template', got '%s'", resp.GetTemplate().GetId())
	}
}

func TestVTPMGRPCService_CreateTemplate_MissingOptions(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CreateTemplateRequest{}

	_, err := service.CreateTemplate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing options")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetTemplate

func TestVTPMGRPCService_GetTemplate_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetTemplateRequest{
		Id: "test-template",
	}

	resp, err := service.GetTemplate(ctx, req)
	if err != nil {
		t.Fatalf("GetTemplate failed: %v", err)
	}

	if resp.GetTemplate() == nil || resp.GetTemplate().GetId() != "test-template" {
		t.Error("Expected template in response")
	}
}

func TestVTPMGRPCService_GetTemplate_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetTemplateRequest{}

	_, err := service.GetTemplate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_GetTemplate_NotFound(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.getTemplateErr = errors.New("template does not exist")
	ctx := context.Background()

	req := &platformv1.GetTemplateRequest{
		Id: "nonexistent-template",
	}

	_, err := service.GetTemplate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found template")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

// Test DeleteTemplate

func TestVTPMGRPCService_DeleteTemplate_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.DeleteTemplateRequest{
		Id: "test-template",
	}

	resp, err := service.DeleteTemplate(ctx, req)
	if err != nil {
		t.Fatalf("DeleteTemplate failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestVTPMGRPCService_DeleteTemplate_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.DeleteTemplateRequest{}

	_, err := service.DeleteTemplate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ListTemplates

func TestVTPMGRPCService_ListTemplates_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ListTemplatesRequest{}

	resp, err := service.ListTemplates(ctx, req)
	if err != nil {
		t.Fatalf("ListTemplates failed: %v", err)
	}

	if len(resp.GetTemplates()) != 2 {
		t.Errorf("Expected 2 templates, got %d", len(resp.GetTemplates()))
	}
}

func TestVTPMGRPCService_ListTemplates_ServiceError(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.listTemplatesErr = errors.New("internal error")
	ctx := context.Background()

	req := &platformv1.ListTemplatesRequest{}

	_, err := service.ListTemplates(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// Test CloneTemplate

func TestVTPMGRPCService_CloneTemplate_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: "test-template",
			Hostname:   "cloned-vm",
			Labels:     map[string]string{"env": "prod"},
		},
	}

	resp, err := service.CloneTemplate(ctx, req)
	if err != nil {
		t.Fatalf("CloneTemplate failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetBundle() == nil {
		t.Error("Expected bundle in response")
	}

	if resp.GetBundle().GetClonedFrom() != "test-template" {
		t.Errorf("Expected cloned_from 'test-template', got '%s'", resp.GetBundle().GetClonedFrom())
	}
}

func TestVTPMGRPCService_CloneTemplate_MissingOptions(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.CloneTemplateRequest{}

	_, err := service.CloneTemplate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing options")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ValidateBundle

func TestVTPMGRPCService_ValidateBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ValidateBundleRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.ValidateBundle(ctx, req)
	if err != nil {
		t.Fatalf("ValidateBundle failed: %v", err)
	}

	if !resp.GetValid() {
		t.Error("Expected valid bundle")
	}

	if len(resp.GetErrors()) > 0 {
		t.Error("Expected no validation errors")
	}
}

func TestVTPMGRPCService_ValidateBundle_Invalid(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.validateBundleErr = errors.New("checksum mismatch")
	ctx := context.Background()

	req := &platformv1.ValidateBundleRequest{
		Id: "corrupted-bundle",
	}

	resp, err := service.ValidateBundle(ctx, req)
	if err != nil {
		t.Fatalf("ValidateBundle should not return error, got: %v", err)
	}

	if resp.GetValid() {
		t.Error("Expected invalid bundle")
	}

	if len(resp.GetErrors()) == 0 {
		t.Error("Expected validation errors")
	}
}

func TestVTPMGRPCService_ValidateBundle_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.ValidateBundleRequest{}

	_, err := service.ValidateBundle(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetBundlePath

func TestVTPMGRPCService_GetBundlePath_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetBundlePathRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.GetBundlePath(ctx, req)
	if err != nil {
		t.Fatalf("GetBundlePath failed: %v", err)
	}

	if resp.GetPath() != "/var/vtpm/bundles/test-bundle-123" {
		t.Errorf("Expected path '/var/vtpm/bundles/test-bundle-123', got '%s'", resp.GetPath())
	}
}

func TestVTPMGRPCService_GetBundlePath_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetBundlePathRequest{}

	_, err := service.GetBundlePath(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetTPMSocketPath

func TestVTPMGRPCService_GetTPMSocketPath_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetTPMSocketPathRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.GetTPMSocketPath(ctx, req)
	if err != nil {
		t.Fatalf("GetTPMSocketPath failed: %v", err)
	}

	if resp.GetPath() != "/var/vtpm/bundles/test-bundle-123/tpm/swtpm.sock" {
		t.Errorf("Expected socket path '/var/vtpm/bundles/test-bundle-123/tpm/swtpm.sock', got '%s'", resp.GetPath())
	}
}

func TestVTPMGRPCService_GetTPMSocketPath_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetTPMSocketPathRequest{}

	_, err := service.GetTPMSocketPath(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetNVRAMPath

func TestVTPMGRPCService_GetNVRAMPath_Success(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetNVRAMPathRequest{
		Id: "test-bundle-123",
	}

	resp, err := service.GetNVRAMPath(ctx, req)
	if err != nil {
		t.Fatalf("GetNVRAMPath failed: %v", err)
	}

	if resp.GetPath() != "/var/vtpm/bundles/test-bundle-123/ovmf/OVMF_VARS.fd" {
		t.Errorf("Expected NVRAM path '/var/vtpm/bundles/test-bundle-123/ovmf/OVMF_VARS.fd', got '%s'", resp.GetPath())
	}
}

func TestVTPMGRPCService_GetNVRAMPath_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()
	ctx := context.Background()

	req := &platformv1.GetNVRAMPathRequest{}

	_, err := service.GetNVRAMPath(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test error type definitions

func TestErrNilVTPMService_Error(t *testing.T) {
	err := ErrNilVTPMService{}
	expected := "vtpm service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingBundleID_Error(t *testing.T) {
	err := ErrMissingBundleID{}
	expected := "bundle id is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingTemplateID_Error(t *testing.T) {
	err := ErrMissingTemplateID{}
	expected := "template id is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingOptions_Error(t *testing.T) {
	err := ErrMissingOptions{}
	expected := "options are required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingCloneOptions_Error(t *testing.T) {
	err := ErrMissingCloneOptions{}
	expected := "clone options are required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrStreamSendFailed_Error(t *testing.T) {
	cause := errors.New("network error")
	err := ErrStreamSendFailed{Operation: "ExportBundle", Cause: cause}
	expected := "stream send failed during ExportBundle: network error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrStreamRecvFailed_Error(t *testing.T) {
	cause := errors.New("connection closed")
	err := ErrStreamRecvFailed{Operation: "ImportBundle", Cause: cause}
	expected := "stream receive failed during ImportBundle: connection closed"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// Test conversion helpers

func TestVTPMGRPCService_protoToBundleMode(t *testing.T) {
	service, _ := newTestVTPMService()

	tests := []struct {
		input    platformv1.BundleMode
		expected vtpm.BundleMode
	}{
		{platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, vtpm.BundleModeTemplate},
		{platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, vtpm.BundleModePreAssigned},
		{platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		result := service.protoToBundleMode(tt.input)
		if result != tt.expected {
			t.Errorf("protoToBundleMode(%v) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestVTPMGRPCService_protoToEKAlgorithm(t *testing.T) {
	service, _ := newTestVTPMService()

	tests := []struct {
		input    platformv1.EKAlgorithm
		expected vtpm.EKAlgorithm
	}{
		{platformv1.EKAlgorithm_EK_ALGORITHM_RSA, vtpm.EKAlgorithmRSA},
		{platformv1.EKAlgorithm_EK_ALGORITHM_ECC, vtpm.EKAlgorithmECC},
		{platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, vtpm.EKAlgorithmRSA}, // Default
	}

	for _, tt := range tests {
		result := service.protoToEKAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("protoToEKAlgorithm(%v) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestVTPMGRPCService_bundleModeToProto(t *testing.T) {
	service, _ := newTestVTPMService()

	tests := []struct {
		input    vtpm.BundleMode
		expected platformv1.BundleMode
	}{
		{vtpm.BundleModeTemplate, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE},
		{vtpm.BundleModePreAssigned, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED},
		{"", platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED},
	}

	for _, tt := range tests {
		result := service.bundleModeToProto(tt.input)
		if result != tt.expected {
			t.Errorf("bundleModeToProto(%v) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestVTPMGRPCService_ekAlgorithmToProto(t *testing.T) {
	service, _ := newTestVTPMService()

	tests := []struct {
		input    vtpm.EKAlgorithm
		expected platformv1.EKAlgorithm
	}{
		{vtpm.EKAlgorithmRSA, platformv1.EKAlgorithm_EK_ALGORITHM_RSA},
		{vtpm.EKAlgorithmECC, platformv1.EKAlgorithm_EK_ALGORITHM_ECC},
		{"", platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED},
	}

	for _, tt := range tests {
		result := service.ekAlgorithmToProto(tt.input)
		if result != tt.expected {
			t.Errorf("ekAlgorithmToProto(%v) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

// Test nil handling in conversions

func TestVTPMGRPCService_bundleToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.bundleToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_templateToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.templateToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_manifestToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.manifestToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_ekCertInfoToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.ekCertInfoToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_secureBootKeyInfoToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.secureBootKeyInfoToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_secureBootKeyPathsToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.secureBootKeyPathsToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_tpmStateToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.tpmStateToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestVTPMGRPCService_ovmfStateToProto_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.ovmfStateToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

// Test mapError

func TestVTPMGRPCService_mapError_NilError(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.mapError("test", nil)
	if result != nil {
		t.Error("Expected nil result for nil error")
	}
}

func TestVTPMGRPCService_mapError_NotFoundError(t *testing.T) {
	service, _ := newTestVTPMService()
	err := errors.New("bundle not found")
	result := service.mapError("GetBundle", err)
	st, _ := status.FromError(result)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestVTPMGRPCService_mapError_AlreadyExistsError(t *testing.T) {
	service, _ := newTestVTPMService()
	err := errors.New("bundle already exists")
	result := service.mapError("CreateBundle", err)
	st, _ := status.FromError(result)
	if st.Code() != codes.AlreadyExists {
		t.Errorf("Expected AlreadyExists, got %v", st.Code())
	}
}

func TestVTPMGRPCService_mapError_InvalidArgumentError(t *testing.T) {
	service, _ := newTestVTPMService()
	err := errors.New("invalid hostname")
	result := service.mapError("CreateBundle", err)
	st, _ := status.FromError(result)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_mapError_PermissionDeniedError(t *testing.T) {
	service, _ := newTestVTPMService()
	err := errors.New("permission denied")
	result := service.mapError("DeleteBundle", err)
	st, _ := status.FromError(result)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Expected PermissionDenied, got %v", st.Code())
	}
}

func TestVTPMGRPCService_mapError_InternalError(t *testing.T) {
	service, _ := newTestVTPMService()
	err := errors.New("unknown error occurred")
	result := service.mapError("CreateBundle", err)
	st, _ := status.FromError(result)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// Test containsAnyVTPM

func TestContainsAnyVTPM(t *testing.T) {
	tests := []struct {
		s          string
		substrings []string
		expected   bool
	}{
		{"bundle not found", []string{"not found", "does not exist"}, true},
		{"template already exists", []string{"already exists", "duplicate"}, true},
		{"no errors here", []string{"not found", "already exists"}, false},
		{"Permission Denied", []string{"permission", "denied"}, true}, // Case insensitive
		{"", []string{"not found"}, false},
	}

	for _, tt := range tests {
		result := containsAnyVTPM(tt.s, tt.substrings...)
		if result != tt.expected {
			t.Errorf("containsAnyVTPM(%q, %v) = %v, expected %v", tt.s, tt.substrings, result, tt.expected)
		}
	}
}

// Test successStatusVTPM

func TestSuccessStatusVTPM(t *testing.T) {
	msg := "operation completed"
	result := successStatusVTPM(msg)

	if !result.GetSuccess() {
		t.Error("Expected success to be true")
	}

	if result.GetMessage() != msg {
		t.Errorf("Expected message '%s', got '%s'", msg, result.GetMessage())
	}
}

// Test protoToListOptions with nil

func TestVTPMGRPCService_protoToListOptions_NilInput(t *testing.T) {
	service, _ := newTestVTPMService()
	result := service.protoToListOptions(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

// Test protoToCreateBundleOptions

func TestVTPMGRPCService_protoToCreateBundleOptions(t *testing.T) {
	service, _ := newTestVTPMService()

	opts := &platformv1.CreateBundleOptions{
		Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
		Hostname:          "test-vm",
		EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
		SecureBootEnabled: true,
		Labels:            map[string]string{"env": "test"},
		TemplateId:        "base-template",
	}

	result := service.protoToCreateBundleOptions(opts)

	if result.Mode != vtpm.BundleModePreAssigned {
		t.Errorf("Expected mode pre-assigned, got %v", result.Mode)
	}
	if result.Hostname != "test-vm" {
		t.Errorf("Expected hostname 'test-vm', got '%s'", result.Hostname)
	}
	if result.EKAlgorithm != vtpm.EKAlgorithmECC {
		t.Errorf("Expected ECC algorithm, got %v", result.EKAlgorithm)
	}
	if !result.SecureBootEnabled {
		t.Error("Expected SecureBootEnabled to be true")
	}
	if result.Labels["env"] != "test" {
		t.Errorf("Expected label env=test, got %v", result.Labels)
	}
	if result.TemplateID != "base-template" {
		t.Errorf("Expected template ID 'base-template', got '%s'", result.TemplateID)
	}
}

// Test protoToCreateTemplateOptions

func TestVTPMGRPCService_protoToCreateTemplateOptions(t *testing.T) {
	service, _ := newTestVTPMService()

	opts := &platformv1.CreateTemplateOptions{
		Id:                "my-template",
		Description:       "My template description",
		EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
		SecureBootEnabled: false,
	}

	result := service.protoToCreateTemplateOptions(opts)

	if result.ID != "my-template" {
		t.Errorf("Expected ID 'my-template', got '%s'", result.ID)
	}
	if result.Description != "My template description" {
		t.Errorf("Expected description, got '%s'", result.Description)
	}
	if result.EKAlgorithm != vtpm.EKAlgorithmRSA {
		t.Errorf("Expected RSA algorithm, got %v", result.EKAlgorithm)
	}
	if result.SecureBootEnabled {
		t.Error("Expected SecureBootEnabled to be false")
	}
}

// Test protoToCloneOptions

func TestVTPMGRPCService_protoToCloneOptions(t *testing.T) {
	service, _ := newTestVTPMService()

	opts := &platformv1.CloneOptions{
		TemplateId: "source-template",
		Hostname:   "cloned-vm",
		Labels:     map[string]string{"cloned": "true"},
	}

	result := service.protoToCloneOptions(opts)

	if result.TemplateID != "source-template" {
		t.Errorf("Expected template ID 'source-template', got '%s'", result.TemplateID)
	}
	if result.Hostname != "cloned-vm" {
		t.Errorf("Expected hostname 'cloned-vm', got '%s'", result.Hostname)
	}
	if result.Labels["cloned"] != "true" {
		t.Errorf("Expected label cloned=true, got %v", result.Labels)
	}
}

// Test full bundle conversion with all fields populated

func TestVTPMGRPCService_bundleToProto_FullConversion(t *testing.T) {
	service, mock := newTestVTPMService()

	result := service.bundleToProto(mock.createBundleResp)

	if result.GetId() != "test-bundle-123" {
		t.Errorf("Expected ID 'test-bundle-123', got '%s'", result.GetId())
	}
	if result.GetMode() != platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED {
		t.Errorf("Expected pre-assigned mode")
	}
	if result.GetManifest() == nil {
		t.Fatal("Expected manifest in result")
	}
	if result.GetManifest().GetHostname() != "test-vm" {
		t.Errorf("Expected hostname 'test-vm', got '%s'", result.GetManifest().GetHostname())
	}
	if result.GetTpmState() == nil {
		t.Error("Expected TPM state in result")
	}
	if result.GetOvmfState() == nil {
		t.Error("Expected OVMF state in result")
	}
	if result.GetSecureBootKeys() == nil {
		t.Error("Expected Secure Boot keys in result")
	}
}

// Test nil service checks for all methods

func TestVTPMGRPCService_NilServiceChecks(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewVTPMGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "GetBundle",
			fn: func() error {
				_, err := service.GetBundle(ctx, &platformv1.GetBundleRequest{Id: "test"})
				return err
			},
		},
		{
			name: "DeleteBundle",
			fn: func() error {
				_, err := service.DeleteBundle(ctx, &platformv1.DeleteBundleRequest{Id: "test"})
				return err
			},
		},
		{
			name: "ListBundles",
			fn: func() error {
				_, err := service.ListBundles(ctx, &platformv1.ListBundlesRequest{})
				return err
			},
		},
		{
			name: "CreateTemplate",
			fn: func() error {
				_, err := service.CreateTemplate(ctx, &platformv1.CreateTemplateRequest{
					Options: &platformv1.CreateTemplateOptions{Id: "test"},
				})
				return err
			},
		},
		{
			name: "GetTemplate",
			fn: func() error {
				_, err := service.GetTemplate(ctx, &platformv1.GetTemplateRequest{Id: "test"})
				return err
			},
		},
		{
			name: "DeleteTemplate",
			fn: func() error {
				_, err := service.DeleteTemplate(ctx, &platformv1.DeleteTemplateRequest{Id: "test"})
				return err
			},
		},
		{
			name: "ListTemplates",
			fn: func() error {
				_, err := service.ListTemplates(ctx, &platformv1.ListTemplatesRequest{})
				return err
			},
		},
		{
			name: "CloneTemplate",
			fn: func() error {
				_, err := service.CloneTemplate(ctx, &platformv1.CloneTemplateRequest{
					Options: &platformv1.CloneOptions{TemplateId: "test"},
				})
				return err
			},
		},
		{
			name: "ValidateBundle",
			fn: func() error {
				_, err := service.ValidateBundle(ctx, &platformv1.ValidateBundleRequest{Id: "test"})
				return err
			},
		},
		{
			name: "GetBundlePath",
			fn: func() error {
				_, err := service.GetBundlePath(ctx, &platformv1.GetBundlePathRequest{Id: "test"})
				return err
			},
		},
		{
			name: "GetTPMSocketPath",
			fn: func() error {
				_, err := service.GetTPMSocketPath(ctx, &platformv1.GetTPMSocketPathRequest{Id: "test"})
				return err
			},
		},
		{
			name: "GetNVRAMPath",
			fn: func() error {
				_, err := service.GetNVRAMPath(ctx, &platformv1.GetNVRAMPathRequest{Id: "test"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatalf("%s: expected error for nil service", tt.name)
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("%s: expected gRPC status error", tt.name)
			}
			if st.Code() != codes.FailedPrecondition {
				t.Errorf("%s: expected FailedPrecondition, got %v", tt.name, st.Code())
			}
		})
	}
}

// Test streaming methods with mock streams

type mockExportStream struct {
	sent []*platformv1.ExportBundleResponse
	ctx  context.Context
}

func (m *mockExportStream) Send(resp *platformv1.ExportBundleResponse) error {
	m.sent = append(m.sent, resp)
	return nil
}

func (m *mockExportStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockExportStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockExportStream) SetTrailer(metadata.MD) {
}

func (m *mockExportStream) Context() context.Context {
	return m.ctx
}

func (m *mockExportStream) SendMsg(msg any) error {
	return nil
}

func (m *mockExportStream) RecvMsg(msg any) error {
	return nil
}

type mockImportStream struct {
	chunks []*platformv1.ImportBundleRequest
	index  int
	resp   *platformv1.ImportBundleResponse
	ctx    context.Context
}

func (m *mockImportStream) Recv() (*platformv1.ImportBundleRequest, error) {
	if m.index >= len(m.chunks) {
		return nil, io.EOF
	}
	chunk := m.chunks[m.index]
	m.index++
	return chunk, nil
}

func (m *mockImportStream) SendAndClose(resp *platformv1.ImportBundleResponse) error {
	m.resp = resp
	return nil
}

func (m *mockImportStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockImportStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockImportStream) SetTrailer(metadata.MD) {
}

func (m *mockImportStream) Context() context.Context {
	return m.ctx
}

func (m *mockImportStream) SendMsg(msg any) error {
	return nil
}

func (m *mockImportStream) RecvMsg(msg any) error {
	return nil
}

func TestVTPMGRPCService_ExportBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()

	req := &platformv1.ExportBundleRequest{
		Id: "test-bundle-123",
	}

	stream := &mockExportStream{
		ctx: context.Background(),
	}

	err := service.ExportBundle(req, stream)
	if err != nil {
		t.Fatalf("ExportBundle failed: %v", err)
	}

	if len(stream.sent) == 0 {
		t.Error("Expected at least one chunk to be sent")
	}

	// Verify all data was sent
	var received bytes.Buffer
	for _, chunk := range stream.sent {
		received.Write(chunk.GetData())
	}

	if received.String() != "mock-tar-gz-data-for-testing" {
		t.Errorf("Expected exported data to match mock data")
	}
}

func TestVTPMGRPCService_ExportBundle_MissingID(t *testing.T) {
	service, _ := newTestVTPMService()

	req := &platformv1.ExportBundleRequest{}
	stream := &mockExportStream{ctx: context.Background()}

	err := service.ExportBundle(req, stream)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestVTPMGRPCService_ExportBundle_ServiceError(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.exportBundleErr = errors.New("bundle not found")

	req := &platformv1.ExportBundleRequest{Id: "nonexistent"}
	stream := &mockExportStream{ctx: context.Background()}

	err := service.ExportBundle(req, stream)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestVTPMGRPCService_ImportBundle_Success(t *testing.T) {
	service, _ := newTestVTPMService()

	stream := &mockImportStream{
		chunks: []*platformv1.ImportBundleRequest{
			{Data: []byte("chunk1")},
			{Data: []byte("chunk2")},
		},
		ctx: context.Background(),
	}

	err := service.ImportBundle(stream)
	if err != nil {
		t.Fatalf("ImportBundle failed: %v", err)
	}

	if stream.resp == nil {
		t.Fatal("Expected response to be sent")
	}

	if !stream.resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if stream.resp.GetBundle() == nil {
		t.Error("Expected bundle in response")
	}
}

func TestVTPMGRPCService_ImportBundle_ServiceError(t *testing.T) {
	service, mock := newTestVTPMService()
	mock.importBundleErr = errors.New("invalid archive format")

	stream := &mockImportStream{
		chunks: []*platformv1.ImportBundleRequest{
			{Data: []byte("invalid-data")},
		},
		ctx: context.Background(),
	}

	err := service.ImportBundle(stream)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ExportBundle with nil service
func TestVTPMGRPCService_ExportBundle_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewVTPMGRPCService(logger, nil)

	req := &platformv1.ExportBundleRequest{Id: "test"}
	stream := &mockExportStream{ctx: context.Background()}

	err := service.ExportBundle(req, stream)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// Test ImportBundle with nil service
func TestVTPMGRPCService_ImportBundle_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewVTPMGRPCService(logger, nil)

	stream := &mockImportStream{
		chunks: []*platformv1.ImportBundleRequest{{Data: []byte("data")}},
		ctx:    context.Background(),
	}

	err := service.ImportBundle(stream)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}
