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
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Additional VTPM Service Tests for Coverage
// =============================================================================

func TestVTPMServiceServer_CreateBundle_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		createBundleFunc: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			return nil, errors.New("failed to create bundle")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:     platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Hostname: "test-host",
		},
	}

	_, err := server.CreateBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_DeleteBundle_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		deleteBundleFunc: func(ctx context.Context, id string) error {
			return errors.New("failed to delete bundle")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteBundleRequest{
		Id: "bundle-123",
	}

	_, err := server.DeleteBundle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ListBundles_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		listBundlesFunc: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return nil, errors.New("failed to list bundles")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ListBundlesRequest{}

	_, err := server.ListBundles(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ListBundles_NilOptions(t *testing.T) {
	now := time.Now()
	bundles := []*vtpm.Bundle{
		{ID: "bundle-1", Mode: vtpm.BundleModeTemplate, CreatedAt: now},
	}

	mock := &mockVTPMService{
		listBundlesFunc: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return bundles, nil
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ListBundlesRequest{
		Options: nil,
	}

	resp, err := server.ListBundles(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Bundles) != 1 {
		t.Errorf("expected 1 bundle, got %d", len(resp.Bundles))
	}
}

func TestVTPMServiceServer_CreateTemplate_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			return nil, errors.New("failed to create template")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:          "template-123",
			Description: "Test template",
		},
	}

	_, err := server.CreateTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_GetTemplate_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		getTemplateFunc: func(ctx context.Context, id string) (*vtpm.Template, error) {
			return nil, errors.New("template not found")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.GetTemplateRequest{
		Id: "template-123",
	}

	_, err := server.GetTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_DeleteTemplate_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		deleteTemplateFunc: func(ctx context.Context, id string) error {
			return errors.New("failed to delete template")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.DeleteTemplateRequest{
		Id: "template-123",
	}

	_, err := server.DeleteTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ListTemplates_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		listTemplatesFunc: func(ctx context.Context) ([]*vtpm.Template, error) {
			return nil, errors.New("failed to list templates")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.ListTemplatesRequest{}

	_, err := server.ListTemplates(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_CloneTemplate_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		cloneTemplateFunc: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			return nil, errors.New("failed to clone template")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	req := &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: "template-123",
			Hostname:   "cloned-host",
		},
	}

	_, err := server.CloneTemplate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ExportBundle_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			return errors.New("failed to export bundle")
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
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

// mockExportStreamWithError simulates stream send errors
type mockExportStreamWithError struct {
	platformv1.VTPMService_ExportBundleServer
	ctx context.Context
}

func (m *mockExportStreamWithError) Context() context.Context {
	return m.ctx
}

func (m *mockExportStreamWithError) Send(resp *platformv1.ExportBundleResponse) error {
	return errors.New("stream send failed")
}

func TestVTPMServiceServer_ExportBundle_StreamSendError(t *testing.T) {
	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			_, err := w.Write([]byte("test data"))
			return err
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockExportStreamWithError{
		ctx: context.Background(),
	}

	req := &platformv1.ExportBundleRequest{
		Id: "bundle-123",
	}

	err := server.ExportBundle(req, stream)
	if err == nil {
		t.Fatal("expected error from stream send")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

// mockImportStreamWithRecvError simulates stream recv errors
type mockImportStreamWithRecvError struct {
	platformv1.VTPMService_ImportBundleServer
	ctx context.Context
}

func (m *mockImportStreamWithRecvError) Context() context.Context {
	return m.ctx
}

func (m *mockImportStreamWithRecvError) Recv() (*platformv1.ImportBundleRequest, error) {
	return nil, errors.New("stream recv failed")
}

func (m *mockImportStreamWithRecvError) SendAndClose(resp *platformv1.ImportBundleResponse) error {
	return nil
}

func TestVTPMServiceServer_ImportBundle_StreamRecvError(t *testing.T) {
	mock := &mockVTPMService{}
	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockImportStreamWithRecvError{
		ctx: context.Background(),
	}

	err := server.ImportBundle(stream)
	if err == nil {
		t.Fatal("expected error from stream recv")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_ImportBundle_ServiceError(t *testing.T) {
	mock := &mockVTPMService{
		importBundleFunc: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			// Read the data to simulate processing
			io.ReadAll(r)
			return nil, errors.New("failed to import bundle")
		},
	}

	server := NewVTPMServiceServer(mock, vtpmTestLogger())

	stream := &mockImportStream{
		ctx: context.Background(),
		chunks: [][]byte{
			[]byte("chunk1"),
		},
	}

	err := server.ImportBundle(stream)
	if err == nil {
		t.Fatal("expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected grpc status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestVTPMServiceServer_protoToListOptions_NilInput(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.protoToListOptions(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_protoToListOptions_WithValues(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	protoOpts := &platformv1.ListBundleOptions{
		Mode:   platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
		Limit:  50,
		Offset: 10,
	}

	result := server.protoToListOptions(protoOpts)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.Mode != vtpm.BundleModeTemplate {
		t.Errorf("expected mode template, got %v", result.Mode)
	}

	if result.Limit != 50 {
		t.Errorf("expected limit 50, got %d", result.Limit)
	}

	if result.Offset != 10 {
		t.Errorf("expected offset 10, got %d", result.Offset)
	}
}

func TestVTPMServiceServer_ekCertInfoToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.ekCertInfoToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_secureBootKeyInfoToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.secureBootKeyInfoToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_secureBootKeyPathsToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.secureBootKeyPathsToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_manifestToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.manifestToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_tpmStateToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.tpmStateToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestVTPMServiceServer_ovmfStateToProto_Nil(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	result := server.ovmfStateToProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

// Test template with all fields populated
func TestVTPMServiceServer_templateToProto_Complete(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	now := time.Now()
	template := &vtpm.Template{
		ID:                "template-123",
		Description:       "Test template",
		EKAlgorithm:       vtpm.EKAlgorithmECC,
		SecureBootEnabled: true,
		CreatedAt:         now,
	}

	result := server.templateToProto(template)

	if result.Id != "template-123" {
		t.Errorf("expected ID template-123, got %s", result.Id)
	}

	if result.Description != "Test template" {
		t.Errorf("expected description 'Test template', got %s", result.Description)
	}

	if result.EkAlgorithm != platformv1.EKAlgorithm_EK_ALGORITHM_ECC {
		t.Errorf("expected ECC algorithm, got %v", result.EkAlgorithm)
	}

	if !result.SecureBootEnabled {
		t.Error("expected secure boot to be enabled")
	}
}

// Test mapError with additional error patterns that match actual implementation
func TestVTPMServiceServer_mapError_AdditionalPatterns(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "does not exist error",
			err:          errors.New("bundle does not exist"),
			expectedCode: codes.NotFound,
		},
		{
			name:         "no such error",
			err:          errors.New("no such file or directory"),
			expectedCode: codes.NotFound,
		},
		{
			name:         "already exists error",
			err:          errors.New("bundle already exists"),
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "duplicate error",
			err:          errors.New("duplicate bundle"),
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "invalid error",
			err:          errors.New("invalid bundle configuration"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "required error",
			err:          errors.New("field is required"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "must be error",
			err:          errors.New("value must be provided"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "cannot be error",
			err:          errors.New("value cannot be empty"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "unauthorized error",
			err:          errors.New("unauthorized access"),
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "access denied error",
			err:          errors.New("access denied"),
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "forbidden error",
			err:          errors.New("operation forbidden"),
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "permission error",
			err:          errors.New("permission denied"),
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "generic error",
			err:          errors.New("unexpected server error"),
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.mapError(tt.err)

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

// Test with large data for ExportBundle (multi-chunk scenario)
func TestVTPMServiceServer_ExportBundle_LargeData(t *testing.T) {
	// Create data larger than the chunk size (32KB)
	largeData := make([]byte, 100*1024) // 100KB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			_, err := w.Write(largeData)
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

	// Should have multiple chunks
	if len(stream.chunks) <= 1 {
		t.Errorf("expected multiple chunks for large data, got %d", len(stream.chunks))
	}

	// Verify total data
	var totalReceived int
	for _, chunk := range stream.chunks {
		totalReceived += len(chunk)
	}

	if totalReceived != len(largeData) {
		t.Errorf("expected %d bytes, received %d", len(largeData), totalReceived)
	}
}

// Test bundle with nil nested structs
func TestVTPMServiceServer_bundleToProto_NilNestedStructs(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	now := time.Now()
	bundle := &vtpm.Bundle{
		ID:        "bundle-123",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: now,
		// All nested structs are nil
		Manifest:       nil,
		TPMState:       nil,
		OVMFState:      nil,
		SecureBootKeys: nil,
	}

	result := server.bundleToProto(bundle)

	if result.Id != "bundle-123" {
		t.Errorf("expected ID bundle-123, got %s", result.Id)
	}

	if result.Manifest != nil {
		t.Error("expected nil manifest")
	}

	if result.TpmState != nil {
		t.Error("expected nil tpm state")
	}

	if result.OvmfState != nil {
		t.Error("expected nil ovmf state")
	}

	if result.SecureBootKeys != nil {
		t.Error("expected nil secure boot keys")
	}
}

// Test manifest with nil nested structs
func TestVTPMServiceServer_manifestToProto_NilNestedStructs(t *testing.T) {
	server := NewVTPMServiceServer(&mockVTPMService{}, vtpmTestLogger())

	now := time.Now()
	manifest := &vtpm.Manifest{
		Version:   "1.0",
		ID:        "bundle-123",
		CreatedAt: now,
		// Nil nested structs
		EKCertificate:  nil,
		SecureBootKeys: nil,
	}

	result := server.manifestToProto(manifest)

	if result.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", result.Version)
	}

	if result.EkCertificate != nil {
		t.Error("expected nil EK certificate")
	}

	if result.SecureBootKeys != nil {
		t.Error("expected nil secure boot keys")
	}
}
