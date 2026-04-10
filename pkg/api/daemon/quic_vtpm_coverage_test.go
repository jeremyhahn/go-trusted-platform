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
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// handleVTPMIsRunning Tests
// =============================================================================

func TestVTPMIsRunning_Success_Running(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	checkReq := VTPMIsRunningRequest{BundleID: "test-001"}
	payload, err := quic.EncodePayload(&checkReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMIsRunning,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var isRunningResp VTPMIsRunningResponse
	if err := quic.DecodePayload(resp.Payload, &isRunningResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !isRunningResp.Running {
		t.Error("expected vTPM to be running")
	}
	if isRunningResp.BundleID != "test-001" {
		t.Errorf("expected bundle ID test-001, got %s", isRunningResp.BundleID)
	}
}

func TestVTPMIsRunning_Success_NotRunning(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	checkReq := VTPMIsRunningRequest{BundleID: "test-001"}
	payload, err := quic.EncodePayload(&checkReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMIsRunning,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var isRunningResp VTPMIsRunningResponse
	if err := quic.DecodePayload(resp.Payload, &isRunningResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if isRunningResp.Running {
		t.Error("expected vTPM to not be running")
	}
}

func TestVTPMIsRunning_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	checkReq := VTPMIsRunningRequest{BundleID: ""}
	payload, err := quic.EncodePayload(&checkReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMIsRunning,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMIsRunning_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMIsRunning,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMIsRunning_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	checkReq := VTPMIsRunningRequest{BundleID: "test-001"}
	payload, err := quic.EncodePayload(&checkReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMIsRunning,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusUnavailable {
		t.Errorf("expected status Unavailable, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMDeleteTemplate Tests
// =============================================================================

func TestVTPMDeleteTemplate_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.templates["test-template"] = &vtpm.Template{ID: "test-template"}

	deleteReq := VTPMDeleteTemplateRequest{ID: "test-template"}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDeleteTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var deleteResp VTPMDeleteTemplateResponse
	if err := quic.DecodePayload(resp.Payload, &deleteResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !deleteResp.Deleted {
		t.Error("expected template to be deleted")
	}
	if deleteResp.ID != "test-template" {
		t.Errorf("expected template ID test-template, got %s", deleteResp.ID)
	}
}

func TestVTPMDeleteTemplate_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	deleteReq := VTPMDeleteTemplateRequest{ID: "nonexistent"}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDeleteTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMDeleteTemplate_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	deleteReq := VTPMDeleteTemplateRequest{ID: ""}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDeleteTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMDeleteTemplate_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMDeleteTemplate,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMExportBundle Tests
// =============================================================================

func TestVTPMExportBundle_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	exportReq := VTPMExportBundleRequest{ID: "test-001"}
	payload, err := quic.EncodePayload(&exportReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMExportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var exportResp VTPMExportBundleResponse
	if err := quic.DecodePayload(resp.Payload, &exportResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if exportResp.ID != "test-001" {
		t.Errorf("expected bundle ID test-001, got %s", exportResp.ID)
	}
	if len(exportResp.Data) == 0 {
		t.Error("expected exported data to be non-empty")
	}
	if exportResp.Size == 0 {
		t.Error("expected size to be non-zero")
	}
}

func TestVTPMExportBundle_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	exportReq := VTPMExportBundleRequest{ID: "nonexistent"}
	payload, err := quic.EncodePayload(&exportReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMExportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMExportBundle_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	exportReq := VTPMExportBundleRequest{ID: ""}
	payload, err := quic.EncodePayload(&exportReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMExportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMExportBundle_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMExportBundle,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMImportBundle Tests
// =============================================================================

func TestVTPMImportBundle_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	importReq := VTPMImportBundleRequest{Data: []byte("mock-bundle-data")}
	payload, err := quic.EncodePayload(&importReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMImportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var importResp VTPMImportBundleResponse
	if err := quic.DecodePayload(resp.Payload, &importResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if importResp.BundleID == "" {
		t.Error("expected bundle ID to be non-empty")
	}
}

func TestVTPMImportBundle_MissingData(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	importReq := VTPMImportBundleRequest{Data: nil}
	payload, err := quic.EncodePayload(&importReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMImportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMImportBundle_EmptyData(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	importReq := VTPMImportBundleRequest{Data: []byte{}}
	payload, err := quic.EncodePayload(&importReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMImportBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMImportBundle_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMImportBundle,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMCreate Tests
// =============================================================================

func TestVTPMCreate_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateRequest{
		Hostname:          "test-vm",
		EKAlgorithm:       "RSA",
		SecureBootEnabled: true,
		Labels:            map[string]string{"env": "test"},
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var createResp VTPMCreateResponse
	if err := quic.DecodePayload(resp.Payload, &createResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if createResp.BundleID == "" {
		t.Error("expected bundle ID to be non-empty")
	}
	if createResp.Hostname != "test-vm" {
		t.Errorf("expected hostname test-vm, got %s", createResp.Hostname)
	}
}

func TestVTPMCreate_WithECCAlgorithm(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateRequest{
		Hostname:    "test-vm-ecc",
		EKAlgorithm: "ECC",
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCreate_WithECDSAAlgorithm(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateRequest{
		Hostname:    "test-vm-ecdsa",
		EKAlgorithm: "ECDSA",
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCreate_MissingHostname(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateRequest{
		Hostname: "",
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCreate_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreate,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMDelete Tests
// =============================================================================

func TestVTPMDelete_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}

	deleteReq := VTPMDeleteRequest{BundleID: "test-001"}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDelete,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var deleteResp VTPMDeleteResponse
	if err := quic.DecodePayload(resp.Payload, &deleteResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !deleteResp.Deleted {
		t.Error("expected bundle to be deleted")
	}
	if deleteResp.BundleID != "test-001" {
		t.Errorf("expected bundle ID test-001, got %s", deleteResp.BundleID)
	}
}

func TestVTPMDelete_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	deleteReq := VTPMDeleteRequest{BundleID: "nonexistent"}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDelete,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected status NotFound, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMDelete_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	deleteReq := VTPMDeleteRequest{BundleID: ""}
	payload, err := quic.EncodePayload(&deleteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMDelete,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMDelete_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMDelete,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMList Tests
// =============================================================================

func TestVTPMList_Success(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["bundle-1"] = &vtpm.Bundle{
		ID:        "bundle-1",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:          "vm-1",
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
		},
	}
	mockSvc.bundles["bundle-2"] = &vtpm.Bundle{
		ID:        "bundle-2",
		Mode:      vtpm.BundleModeTemplate,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:          "vm-2",
			EKAlgorithm:       vtpm.EKAlgorithmECC,
			SecureBootEnabled: false,
		},
	}
	mockSvc.running["bundle-1"] = true

	req := &quic.Request{
		Opcode:  quic.OpVTPMList,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var listResp VTPMListResponse
	if err := quic.DecodePayload(resp.Payload, &listResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if listResp.Total != 2 {
		t.Errorf("expected 2 bundles, got %d", listResp.Total)
	}
}

func TestVTPMList_WithModeFilter(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["bundle-1"] = &vtpm.Bundle{
		ID:   "bundle-1",
		Mode: vtpm.BundleModePreAssigned,
	}
	mockSvc.bundles["bundle-2"] = &vtpm.Bundle{
		ID:   "bundle-2",
		Mode: vtpm.BundleModeTemplate,
	}

	listReq := VTPMListRequest{Mode: string(vtpm.BundleModePreAssigned)}
	payload, err := quic.EncodePayload(&listReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMList,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var listResp VTPMListResponse
	if err := quic.DecodePayload(resp.Payload, &listResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if listResp.Total != 1 {
		t.Errorf("expected 1 bundle after filtering, got %d", listResp.Total)
	}
}

func TestVTPMList_EmptyResult(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMList,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var listResp VTPMListResponse
	if err := quic.DecodePayload(resp.Payload, &listResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if listResp.Total != 0 {
		t.Errorf("expected 0 bundles, got %d", listResp.Total)
	}
}

func TestVTPMList_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMList,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMGetTPMSocketPath Tests
// =============================================================================

func TestVTPMGetTPMSocketPath_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: "test-001"}
	payload, err := quic.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetSocketPath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var pathResp VTPMGetPathResponse
	if err := quic.DecodePayload(resp.Payload, &pathResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if pathResp.Path == "" {
		t.Error("expected non-empty socket path")
	}
	if pathResp.ID != "test-001" {
		t.Errorf("expected ID test-001, got %s", pathResp.ID)
	}
}

func TestVTPMGetTPMSocketPath_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: ""}
	payload, err := quic.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetSocketPath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMGetTPMSocketPath_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetSocketPath,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMGetNVRAMPath Tests
// =============================================================================

func TestVTPMGetNVRAMPath_Success(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: "test-001"}
	payload, err := quic.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetNVRAMPath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var pathResp VTPMGetPathResponse
	if err := quic.DecodePayload(resp.Payload, &pathResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if pathResp.Path == "" {
		t.Error("expected non-empty NVRAM path")
	}
	if pathResp.ID != "test-001" {
		t.Errorf("expected ID test-001, got %s", pathResp.ID)
	}
}

func TestVTPMGetNVRAMPath_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: ""}
	payload, err := quic.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetNVRAMPath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMGetNVRAMPath_InvalidPayload(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetNVRAMPath,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidRequest {
		t.Errorf("expected status InvalidRequest, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// handleVTPMOperation Routing Tests
// =============================================================================

func TestVTPMOperation_UnknownOpcode(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  0xFE, // Container Stop opcode - returns Unavailable without container service
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)
	// Without container service configured, container opcodes return Unavailable
	if resp.Status != quic.StatusUnavailable && resp.Status != quic.StatusNotImplemented {
		t.Errorf("expected status Unavailable or NotImplemented, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMOperation_AllOpcodes_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	opcodes := []byte{
		quic.OpVTPMCreateTemplate,
		quic.OpVTPMGetTemplate,
		quic.OpVTPMDeleteTemplate,
		quic.OpVTPMListTemplates,
		quic.OpVTPMCloneTemplate,
		quic.OpVTPMExportBundle,
		quic.OpVTPMImportBundle,
		quic.OpVTPMValidateBundle,
		quic.OpVTPMGetBundlePath,
		quic.OpVTPMGetSocketPath,
		quic.OpVTPMGetNVRAMPath,
		quic.OpVTPMGetBundle,
		quic.OpVTPMIsRunning,
		quic.OpVTPMCreate,
		quic.OpVTPMDelete,
		quic.OpVTPMStart,
		quic.OpVTPMStop,
		quic.OpVTPMGetState,
		quic.OpVTPMList,
		quic.OpVTPMQuote,
		quic.OpVTPMSeal,
		quic.OpVTPMUnseal,
		quic.OpVTPMExtendPCR,
		quic.OpVTPMReadPCR,
	}

	for _, opcode := range opcodes {
		req := &quic.Request{
			Opcode:  opcode,
			Payload: nil,
		}

		resp := handler.HandleRequest(ctx, req)
		if resp.Status != quic.StatusUnavailable {
			t.Errorf("opcode 0x%02X: expected status Unavailable when service is nil, got %s",
				opcode, quic.StatusToString(resp.Status))
		}
	}
}

// =============================================================================
// mapVTPMError Tests
// =============================================================================

func TestMapVTPMError_NilError(t *testing.T) {
	handler, _ := createQUICTestHandler()

	resp := handler.mapVTPMError(nil)
	if resp != nil {
		t.Error("expected nil response for nil error")
	}
}

func TestMapVTPMError_NotFound(t *testing.T) {
	handler, _ := createQUICTestHandler()

	testCases := []struct {
		name string
		err  error
	}{
		{"bundle not found", vtpm.ErrBundleNotFound{ID: "test"}},
		{"template not found", vtpm.ErrTemplateNotFound{ID: "test"}},
		{"does not exist", errors.New("resource does not exist")},
		{"no such file", errors.New("no such file or directory")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.mapVTPMError(tc.err)
			if resp.Status != quic.StatusNotFound {
				t.Errorf("expected status NotFound, got %s", quic.StatusToString(resp.Status))
			}
		})
	}
}

func TestMapVTPMError_AlreadyExists(t *testing.T) {
	handler, _ := createQUICTestHandler()

	testCases := []struct {
		name string
		err  error
	}{
		{"already exists", errors.New("bundle already exists")},
		{"already running", vtpm.ErrVTPMAlreadyRunning{BundleID: "test"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.mapVTPMError(tc.err)
			if resp.Status != quic.StatusAlreadyExists {
				t.Errorf("expected status AlreadyExists, got %s", quic.StatusToString(resp.Status))
			}
		})
	}
}

func TestMapVTPMError_InvalidArgument(t *testing.T) {
	handler, _ := createQUICTestHandler()

	testCases := []struct {
		name string
		err  error
	}{
		{"invalid", errors.New("invalid bundle ID")},
		{"required", errors.New("hostname is required")},
		{"must be", errors.New("value must be non-negative")},
		{"cannot be", errors.New("ID cannot be empty")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.mapVTPMError(tc.err)
			if resp.Status != quic.StatusInvalidArgument {
				t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
			}
		})
	}
}

func TestMapVTPMError_Unavailable(t *testing.T) {
	handler, _ := createQUICTestHandler()

	testCases := []struct {
		name string
		err  error
	}{
		{"not running", vtpm.ErrVTPMNotRunning{BundleID: "test"}},
		{"not started", errors.New("vTPM not started")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.mapVTPMError(tc.err)
			if resp.Status != quic.StatusUnavailable {
				t.Errorf("expected status Unavailable, got %s", quic.StatusToString(resp.Status))
			}
		})
	}
}

func TestMapVTPMError_InternalError(t *testing.T) {
	handler, _ := createQUICTestHandler()

	resp := handler.mapVTPMError(errors.New("some unexpected error"))
	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected status InternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// containsVTPMErrorPattern Tests
// =============================================================================

func TestContainsVTPMErrorPattern_Match(t *testing.T) {
	testCases := []struct {
		input    string
		patterns []string
		expected bool
	}{
		{"bundle not found", []string{"not found"}, true},
		{"resource does not exist", []string{"does not exist"}, true},
		{"no such file", []string{"no such"}, true},
		{"already exists", []string{"already exists", "already running"}, true},
		{"vTPM already running", []string{"already exists", "already running"}, true},
		{"invalid input", []string{"invalid"}, true},
		{"some random error", []string{"not found"}, false},
		{"", []string{"not found"}, false},
		{"short", []string{"longer pattern"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := containsVTPMErrorPattern(tc.input, tc.patterns...)
			if result != tc.expected {
				t.Errorf("containsVTPMErrorPattern(%q, %v) = %v, want %v",
					tc.input, tc.patterns, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// bundleToQUICResponse Tests
// =============================================================================

func TestBundleToQUICResponse_MinimalBundle(t *testing.T) {
	handler, _ := createQUICTestHandler()

	bundle := &vtpm.Bundle{
		ID:        "test-bundle",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Unix(1704067200, 0),
	}

	resp := handler.bundleToQUICResponse(bundle)

	if resp.ID != "test-bundle" {
		t.Errorf("expected ID test-bundle, got %s", resp.ID)
	}
	if resp.Mode != string(vtpm.BundleModePreAssigned) {
		t.Errorf("expected mode preassigned, got %s", resp.Mode)
	}
	if resp.TPMState != nil {
		t.Error("expected TPMState to be nil")
	}
	if resp.OVMFState != nil {
		t.Error("expected OVMFState to be nil")
	}
	if resp.SecureBootKeys != nil {
		t.Error("expected SecureBootKeys to be nil")
	}
}

func TestBundleToQUICResponse_FullBundle(t *testing.T) {
	handler, _ := createQUICTestHandler()

	bundle := &vtpm.Bundle{
		ID:         "test-bundle",
		Mode:       vtpm.BundleModePreAssigned,
		CreatedAt:  time.Unix(1704067200, 0),
		ClonedFrom: "base-template",
		Manifest: &vtpm.Manifest{
			Hostname:          "test-host",
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "test"},
			Checksums:         map[string]string{"file1": "abc123"},
			EKCertificate: &vtpm.EKCertInfo{
				Subject:      "CN=test",
				Issuer:       "CN=CA",
				SerialNumber: "123456",
				NotBefore:    time.Unix(1704067200, 0),
				NotAfter:     time.Unix(1735603200, 0),
				Fingerprint:  "AA:BB:CC:DD",
			},
		},
		TPMState: &vtpm.TPMState{
			StateDir:     "/var/lib/vtpm/test/tpm",
			PermallFile:  "/var/lib/vtpm/test/tpm/permall",
			VolatileFile: "/var/lib/vtpm/test/tpm/volatile",
		},
		OVMFState: &vtpm.OVMFState{
			NVRAMFile: "/var/lib/vtpm/test/OVMF_VARS.fd",
		},
		SecureBootKeys: &vtpm.SecureBootKeyPaths{
			Dir:     "/var/lib/vtpm/test/keys",
			PKKey:   "/var/lib/vtpm/test/keys/PK.key",
			PKCert:  "/var/lib/vtpm/test/keys/PK.crt",
			KEKKey:  "/var/lib/vtpm/test/keys/KEK.key",
			KEKCert: "/var/lib/vtpm/test/keys/KEK.crt",
			DBKey:   "/var/lib/vtpm/test/keys/db.key",
			DBCert:  "/var/lib/vtpm/test/keys/db.crt",
		},
	}

	resp := handler.bundleToQUICResponse(bundle)

	if resp.ID != "test-bundle" {
		t.Errorf("expected ID test-bundle, got %s", resp.ID)
	}
	if resp.Hostname != "test-host" {
		t.Errorf("expected hostname test-host, got %s", resp.Hostname)
	}
	if resp.EKAlgorithm != string(vtpm.EKAlgorithmRSA) {
		t.Errorf("expected EK algorithm RSA, got %s", resp.EKAlgorithm)
	}
	if !resp.SecureBootEnabled {
		t.Error("expected SecureBootEnabled to be true")
	}
	if resp.ClonedFrom != "base-template" {
		t.Errorf("expected cloned from base-template, got %s", resp.ClonedFrom)
	}

	if resp.TPMState == nil {
		t.Fatal("expected TPMState to be non-nil")
	}
	if resp.TPMState.StateDir != "/var/lib/vtpm/test/tpm" {
		t.Errorf("expected TPMState.StateDir to match, got %s", resp.TPMState.StateDir)
	}

	if resp.OVMFState == nil {
		t.Fatal("expected OVMFState to be non-nil")
	}
	if resp.OVMFState.NVRAMFile != "/var/lib/vtpm/test/OVMF_VARS.fd" {
		t.Errorf("expected OVMFState.NVRAMFile to match, got %s", resp.OVMFState.NVRAMFile)
	}

	if resp.SecureBootKeys == nil {
		t.Fatal("expected SecureBootKeys to be non-nil")
	}
	if resp.SecureBootKeys.Dir != "/var/lib/vtpm/test/keys" {
		t.Errorf("expected SecureBootKeys.Dir to match, got %s", resp.SecureBootKeys.Dir)
	}

	if resp.EKCertificate == nil {
		t.Fatal("expected EKCertificate to be non-nil")
	}
	if resp.EKCertificate.Subject != "CN=test" {
		t.Errorf("expected EKCertificate.Subject to be CN=test, got %s", resp.EKCertificate.Subject)
	}
	if resp.EKCertificate.Fingerprint != "AA:BB:CC:DD" {
		t.Errorf("expected EKCertificate.Fingerprint to match, got %s", resp.EKCertificate.Fingerprint)
	}
}

func TestBundleToQUICResponse_NilManifest(t *testing.T) {
	handler, _ := createQUICTestHandler()

	bundle := &vtpm.Bundle{
		ID:        "test-bundle",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Unix(1704067200, 0),
		Manifest:  nil,
	}

	resp := handler.bundleToQUICResponse(bundle)

	if resp.Hostname != "" {
		t.Errorf("expected empty hostname, got %s", resp.Hostname)
	}
	if resp.EKAlgorithm != "" {
		t.Errorf("expected empty EK algorithm, got %s", resp.EKAlgorithm)
	}
}

// =============================================================================
// Request/Response Encoding Tests
// =============================================================================

func TestVTPMRequestResponse_RoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		request interface{}
	}{
		{"GetBundleRequest", &VTPMGetBundleRequest{ID: "test-001"}},
		{"StartRequest", &VTPMStartRequest{BundleID: "test-001"}},
		{"StopRequest", &VTPMStopRequest{BundleID: "test-001"}},
		{"IsRunningRequest", &VTPMIsRunningRequest{BundleID: "test-001"}},
		{"CreateRequest", &VTPMCreateRequest{Hostname: "test", EKAlgorithm: "RSA"}},
		{"DeleteRequest", &VTPMDeleteRequest{BundleID: "test-001"}},
		{"ListRequest", &VTPMListRequest{Mode: "preassigned"}},
		{"ExportBundleRequest", &VTPMExportBundleRequest{ID: "test-001"}},
		{"ImportBundleRequest", &VTPMImportBundleRequest{Data: []byte("data")}},
		{"ValidateBundleRequest", &VTPMValidateBundleRequest{ID: "test-001"}},
		{"GetPathRequest", &VTPMGetPathRequest{ID: "test-001"}},
		{"CreateTemplateRequest", &VTPMCreateTemplateRequest{ID: "tmpl", Description: "desc"}},
		{"GetTemplateRequest", &VTPMGetTemplateRequest{ID: "tmpl"}},
		{"DeleteTemplateRequest", &VTPMDeleteTemplateRequest{ID: "tmpl"}},
		{"CloneTemplateRequest", &VTPMCloneTemplateRequest{TemplateID: "tmpl", Hostname: "host"}},
		{"QuoteRequest", &VTPMQuoteRequest{BundleID: "test", Nonce: []byte("nonce"), PCRs: []int{0, 1}}},
		{"SealRequest", &VTPMSealRequest{BundleID: "test", Data: []byte("data"), PCRs: []int{7}}},
		{"UnsealRequest", &VTPMUnsealRequest{BundleID: "test", SealedData: []byte("sealed")}},
		{"ExtendPCRRequest", &VTPMExtendPCRRequest{BundleID: "test", PCRIndex: 7, Data: []byte("data")}},
		{"ReadPCRRequest", &VTPMReadPCRRequest{BundleID: "test", PCRIndex: 0}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := quic.EncodePayload(tc.request)
			if err != nil {
				t.Fatalf("failed to encode %s: %v", tc.name, err)
			}

			if len(encoded) == 0 {
				t.Errorf("encoded payload should not be empty for %s", tc.name)
			}
		})
	}
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestVTPMCloneTemplate_MissingTemplateID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	cloneReq := VTPMCloneTemplateRequest{
		TemplateID: "",
		Hostname:   "new-vm",
	}
	payload, err := quic.EncodePayload(&cloneReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCloneTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCloneTemplate_MissingHostname(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.templates["base-template"] = &vtpm.Template{ID: "base-template"}

	cloneReq := VTPMCloneTemplateRequest{
		TemplateID: "base-template",
		Hostname:   "",
	}
	payload, err := quic.EncodePayload(&cloneReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCloneTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMQuote_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	quoteReq := VTPMQuoteRequest{
		BundleID: "",
		Nonce:    []byte("nonce"),
		PCRs:     []int{0},
	}
	payload, err := quic.EncodePayload(&quoteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMQuote,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMQuote_MissingNonce(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	quoteReq := VTPMQuoteRequest{
		BundleID: "test-001",
		Nonce:    nil,
		PCRs:     []int{0},
	}
	payload, err := quic.EncodePayload(&quoteReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMQuote,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMSeal_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	sealReq := VTPMSealRequest{
		BundleID: "",
		Data:     []byte("data"),
	}
	payload, err := quic.EncodePayload(&sealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMSeal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMUnseal_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	unsealReq := VTPMUnsealRequest{
		BundleID:   "",
		SealedData: []byte("sealed"),
	}
	payload, err := quic.EncodePayload(&unsealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMUnseal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMUnseal_MissingSealedData(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	unsealReq := VTPMUnsealRequest{
		BundleID:   "test-001",
		SealedData: nil,
	}
	payload, err := quic.EncodePayload(&unsealReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMUnseal,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMExtendPCR_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	extendReq := VTPMExtendPCRRequest{
		BundleID: "",
		PCRIndex: 7,
		Data:     []byte("data"),
	}
	payload, err := quic.EncodePayload(&extendReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMExtendPCR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMExtendPCR_MissingData(t *testing.T) {
	handler, mockSvc := createQUICTestHandler()
	ctx := context.Background()

	mockSvc.bundles["test-001"] = &vtpm.Bundle{ID: "test-001"}
	mockSvc.running["test-001"] = true

	extendReq := VTPMExtendPCRRequest{
		BundleID: "test-001",
		PCRIndex: 7,
		Data:     nil,
	}
	payload, err := quic.EncodePayload(&extendReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMExtendPCR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMReadPCR_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	readReq := VTPMReadPCRRequest{
		BundleID: "",
		PCRIndex: 0,
	}
	payload, err := quic.EncodePayload(&readReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMReadPCR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMStart_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	startReq := VTPMStartRequest{BundleID: ""}
	payload, err := quic.EncodePayload(&startReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMStart,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMStop_MissingBundleID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	stopReq := VTPMStopRequest{BundleID: ""}
	payload, err := quic.EncodePayload(&stopReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMStop,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMValidateBundle_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	validateReq := VTPMValidateBundleRequest{ID: ""}
	payload, err := quic.EncodePayload(&validateReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMValidateBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMValidateBundle_Invalid(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	validateReq := VTPMValidateBundleRequest{ID: "nonexistent"}
	payload, err := quic.EncodePayload(&validateReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMValidateBundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var validateResp VTPMValidateBundleResponse
	if err := quic.DecodePayload(resp.Payload, &validateResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if validateResp.Valid {
		t.Error("expected bundle to be invalid")
	}
	if len(validateResp.Errors) == 0 {
		t.Error("expected validation errors")
	}
}

func TestVTPMGetBundlePath_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	pathReq := VTPMGetPathRequest{ID: ""}
	payload, err := quic.EncodePayload(&pathReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetBundlePath,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMGetTemplate_MissingID(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	getReq := VTPMGetTemplateRequest{ID: ""}
	payload, err := quic.EncodePayload(&getReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMGetTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected status InvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCreateTemplate_WithECCAlgorithm(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateTemplateRequest{
		ID:          "test-template-ecc",
		Description: "Test ECC template",
		EKAlgorithm: "ECC",
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreateTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}

func TestVTPMCreateTemplate_WithECDSAAlgorithm(t *testing.T) {
	handler, _ := createQUICTestHandler()
	ctx := context.Background()

	createReq := VTPMCreateTemplateRequest{
		ID:          "test-template-ecdsa",
		Description: "Test ECDSA template",
		EKAlgorithm: "ECDSA",
	}
	payload, err := quic.EncodePayload(&createReq)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}

	req := &quic.Request{
		Opcode:  quic.OpVTPMCreateTemplate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}
