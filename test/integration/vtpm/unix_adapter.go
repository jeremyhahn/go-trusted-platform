//go:build integration

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

package vtpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Constants
// =============================================================================

const (
	// DefaultUnixTimeoutVTPM is the default timeout for Unix socket operations.
	DefaultUnixTimeoutVTPM = 60 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixVTPMConnectionFailed indicates a Unix socket connection failure.
type ErrUnixVTPMConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixVTPMConnectionFailed) Error() string {
	return fmt.Sprintf("Unix vTPM connection to %s failed: %v", e.Path, e.Err)
}

func (e ErrUnixVTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixVTPMBackendUnavailable indicates the backend is unavailable.
type ErrUnixVTPMBackendUnavailable struct {
	Err error
}

func (e ErrUnixVTPMBackendUnavailable) Error() string {
	return fmt.Sprintf("Unix vTPM backend unavailable: %v", e.Err)
}

func (e ErrUnixVTPMBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrUnixVTPMRPCFailed indicates an RPC call failure.
type ErrUnixVTPMRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixVTPMRPCFailed) Error() string {
	return fmt.Sprintf("Unix vTPM RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixVTPMRPCFailed) Unwrap() error {
	return e.Err
}

// ErrUnixVTPMValidationFailed represents a Unix socket validation failure
// returned as a successful response with Valid=false.
type ErrUnixVTPMValidationFailed struct {
	Errors []string
}

func (e ErrUnixVTPMValidationFailed) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("bundle validation failed: %s", e.Errors[0])
	}
	return "bundle validation failed"
}

// =============================================================================
// Unix Adapter
// =============================================================================

// UnixAdapter implements VTPMCommands using gRPC over Unix sockets.
// This adapter uses the local Unix domain socket for IPC with platformd.
type UnixAdapter struct {
	conn       *grpc.ClientConn
	socketPath string
	timeout    time.Duration
	client     platformv1.VTPMServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter for vTPM integration testing.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
		timeout:    DefaultUnixTimeoutVTPM,
	}
}

// Name returns the protocol adapter identifier.
func (s *UnixAdapter) Name() string {
	return "Unix"
}

// Setup establishes the gRPC connection over Unix socket.
func (s *UnixAdapter) Setup(ctx context.Context) error {
	// Check if socket exists
	if _, err := os.Stat(s.socketPath); os.IsNotExist(err) {
		return ErrUnixVTPMConnectionFailed{Path: s.socketPath, Err: err}
	}

	conn, err := grpc.NewClient(
		"unix://"+s.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrUnixVTPMConnectionFailed{Path: s.socketPath, Err: err}
	}

	s.conn = conn
	s.client = platformv1.NewVTPMServiceClient(conn)

	return nil
}

// Teardown closes the Unix socket connection.
func (s *UnixAdapter) Teardown(ctx context.Context) error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// =============================================================================
// Bundle CRUD Commands
// =============================================================================

// CreateBundle creates a new vTPM bundle via Unix socket.
func (s *UnixAdapter) CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error) {
	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:              unixBundleModeToProto(opts.Mode),
			Hostname:          opts.Hostname,
			EkAlgorithm:       unixEKAlgorithmToProto(opts.EKAlgorithm),
			SecureBootEnabled: opts.SecureBootEnabled,
			Labels:            opts.Labels,
			TemplateId:        opts.TemplateID,
		},
	}

	resp, err := s.client.CreateBundle(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "CreateBundle", Err: err}
	}

	return &CreateBundleResult{
		Bundle: unixProtoToBundle(resp.GetBundle()),
	}, nil
}

// GetBundle retrieves a bundle by ID via Unix socket.
func (s *UnixAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	req := &platformv1.GetBundleRequest{
		Id: opts.ID,
	}

	resp, err := s.client.GetBundle(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "GetBundle", Err: err}
	}

	return &GetBundleResult{
		Bundle: unixProtoToBundle(resp.GetBundle()),
	}, nil
}

// DeleteBundle deletes a bundle via Unix socket.
func (s *UnixAdapter) DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error) {
	req := &platformv1.DeleteBundleRequest{
		Id: opts.ID,
	}

	resp, err := s.client.DeleteBundle(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "DeleteBundle", Err: err}
	}

	return &DeleteBundleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListBundles lists bundles via Unix socket.
func (s *UnixAdapter) ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error) {
	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Mode:   unixBundleModeToProto(opts.Mode),
			Labels: opts.Labels,
			Limit:  int32(opts.Limit),
			Offset: int32(opts.Offset),
		},
	}

	resp, err := s.client.ListBundles(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ListBundles", Err: err}
	}

	bundles := make([]*vtpm.Bundle, 0, len(resp.GetBundles()))
	for _, pb := range resp.GetBundles() {
		bundles = append(bundles, unixProtoToBundle(pb))
	}

	return &ListBundlesResult{
		Bundles: bundles,
		Total:   int(resp.GetTotal()),
	}, nil
}

// =============================================================================
// Template CRUD Commands
// =============================================================================

// CreateTemplate creates a new vTPM template via Unix socket.
func (s *UnixAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	req := &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                opts.ID,
			Description:       opts.Description,
			EkAlgorithm:       unixEKAlgorithmToProto(opts.EKAlgorithm),
			SecureBootEnabled: opts.SecureBootEnabled,
		},
	}

	resp, err := s.client.CreateTemplate(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "CreateTemplate", Err: err}
	}

	return &CreateTemplateResult{
		Template: unixProtoToTemplate(resp.GetTemplate()),
	}, nil
}

// GetTemplate retrieves a template by ID via Unix socket.
func (s *UnixAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	req := &platformv1.GetTemplateRequest{
		Id: opts.ID,
	}

	resp, err := s.client.GetTemplate(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "GetTemplate", Err: err}
	}

	return &GetTemplateResult{
		Template: unixProtoToTemplate(resp.GetTemplate()),
	}, nil
}

// DeleteTemplate deletes a template via Unix socket.
func (s *UnixAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	req := &platformv1.DeleteTemplateRequest{
		Id: opts.ID,
	}

	resp, err := s.client.DeleteTemplate(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "DeleteTemplate", Err: err}
	}

	return &DeleteTemplateResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListTemplates lists templates via Unix socket.
func (s *UnixAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	req := &platformv1.ListTemplatesRequest{}

	resp, err := s.client.ListTemplates(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ListTemplates", Err: err}
	}

	templates := make([]*vtpm.Template, 0, len(resp.GetTemplates()))
	for _, pt := range resp.GetTemplates() {
		templates = append(templates, unixProtoToTemplate(pt))
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     len(templates),
	}, nil
}

// CloneTemplate clones a template to create a new bundle via Unix socket.
func (s *UnixAdapter) CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error) {
	req := &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: opts.TemplateID,
			Hostname:   opts.Hostname,
			Labels:     opts.Labels,
		},
	}

	resp, err := s.client.CloneTemplate(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "CloneTemplate", Err: err}
	}

	return &CloneTemplateResult{
		Bundle: unixProtoToBundle(resp.GetBundle()),
	}, nil
}

// =============================================================================
// Export/Import Commands
// =============================================================================

// ExportBundle exports a bundle to a tar.gz archive via Unix socket.
func (s *UnixAdapter) ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error) {
	req := &platformv1.ExportBundleRequest{
		Id: opts.ID,
	}

	stream, err := s.client.ExportBundle(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ExportBundle", Err: err}
	}

	var buf bytes.Buffer
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrUnixVTPMRPCFailed{Method: "ExportBundle.Recv", Err: err}
		}
		buf.Write(resp.GetData())
	}

	data := buf.Bytes()
	checksum := sha256.Sum256(data)

	// Write to specified path or generate a temp file
	archivePath := opts.OutputPath
	if archivePath == "" {
		tmpFile, tmpErr := os.CreateTemp("", "vtpm-export-*.tar.gz")
		if tmpErr != nil {
			return nil, ErrUnixVTPMRPCFailed{Method: "ExportBundle.CreateTemp", Err: tmpErr}
		}
		archivePath = tmpFile.Name()
		tmpFile.Close()
	}
	if err := os.WriteFile(archivePath, data, 0600); err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ExportBundle.WriteFile", Err: err}
	}

	return &ExportBundleResult{
		ArchivePath: archivePath,
		Size:        int64(len(data)),
		Checksum:    hex.EncodeToString(checksum[:]),
	}, nil
}

// ImportBundle imports a bundle from a tar.gz archive via Unix socket.
func (s *UnixAdapter) ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error) {
	var data []byte

	if opts.ArchivePath != "" {
		var err error
		data, err = os.ReadFile(opts.ArchivePath)
		if err != nil {
			return nil, ErrUnixVTPMRPCFailed{Method: "ImportBundle.ReadFile", Err: err}
		}
	} else if len(opts.ArchiveData) > 0 {
		data = opts.ArchiveData
	} else {
		return nil, ErrUnixVTPMRPCFailed{Method: "ImportBundle", Err: fmt.Errorf("archive path or data required")}
	}

	stream, err := s.client.ImportBundle(ctx)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ImportBundle", Err: err}
	}

	const chunkSize = 32 * 1024
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		if err := stream.Send(&platformv1.ImportBundleRequest{
			Data: data[i:end],
		}); err != nil {
			return nil, ErrUnixVTPMRPCFailed{Method: "ImportBundle.Send", Err: err}
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ImportBundle.CloseAndRecv", Err: err}
	}

	return &ImportBundleResult{
		Bundle: unixProtoToBundle(resp.GetBundle()),
	}, nil
}

// =============================================================================
// Validation Commands
// =============================================================================

// ValidateBundle validates bundle integrity via Unix socket.
func (s *UnixAdapter) ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error) {
	req := &platformv1.ValidateBundleRequest{
		Id: opts.ID,
	}

	resp, err := s.client.ValidateBundle(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ValidateBundle", Err: err}
	}

	// The gRPC server returns a successful response with Valid=false
	// when validation fails (including nonexistent bundles). Translate
	// this into an error so callers can distinguish success from failure.
	if !resp.GetValid() {
		return nil, ErrUnixVTPMValidationFailed{Errors: resp.GetErrors()}
	}

	return &ValidateBundleResult{
		Valid:            resp.GetValid(),
		Errors:           resp.GetErrors(),
		ChecksumVerified: resp.GetValid(),
	}, nil
}

// =============================================================================
// Path Commands
// =============================================================================

// GetBundlePath returns the filesystem path to a bundle via Unix socket.
func (s *UnixAdapter) GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error) {
	req := &platformv1.GetBundlePathRequest{
		Id: opts.ID,
	}

	resp, err := s.client.GetBundlePath(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "GetBundlePath", Err: err}
	}

	return &GetBundlePathResult{
		Path: resp.GetPath(),
	}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle via Unix socket.
func (s *UnixAdapter) GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error) {
	req := &platformv1.GetTPMSocketPathRequest{
		Id: opts.ID,
	}

	resp, err := s.client.GetTPMSocketPath(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "GetTPMSocketPath", Err: err}
	}

	return &GetTPMSocketPathResult{
		Path: resp.GetPath(),
	}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle via Unix socket.
func (s *UnixAdapter) GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error) {
	req := &platformv1.GetNVRAMPathRequest{
		Id: opts.ID,
	}

	resp, err := s.client.GetNVRAMPath(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "GetNVRAMPath", Err: err}
	}

	return &GetNVRAMPathResult{
		Path: resp.GetPath(),
	}, nil
}

// =============================================================================
// Runtime TPM Commands
// =============================================================================

// Start starts the swtpm daemon for a bundle via Unix socket.
func (s *UnixAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	req := &platformv1.StartVTPMRequest{
		BundleId: opts.BundleID,
	}

	resp, err := s.client.StartVTPM(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "StartVTPM", Err: err}
	}

	return &StartResult{
		BundleID:   resp.GetBundleId(),
		Running:    resp.GetRunning(),
		SocketPath: resp.GetSocketPath(),
	}, nil
}

// Stop stops the swtpm daemon for a bundle via Unix socket.
func (s *UnixAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	req := &platformv1.StopVTPMRequest{
		BundleId: opts.BundleID,
	}

	resp, err := s.client.StopVTPM(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "StopVTPM", Err: err}
	}

	return &StopResult{
		BundleID: resp.GetBundleId(),
		Stopped:  resp.GetStopped(),
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running via Unix socket.
func (s *UnixAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	req := &platformv1.IsVTPMRunningRequest{
		BundleId: opts.BundleID,
	}

	resp, err := s.client.IsVTPMRunning(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "IsVTPMRunning", Err: err}
	}

	return &IsRunningResult{
		BundleID: resp.GetBundleId(),
		Running:  resp.GetRunning(),
	}, nil
}

// Quote generates a TPM quote over specified PCRs via Unix socket.
func (s *UnixAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
	// Convert []int to []int32 for proto
	pcrs := make([]int32, 0, len(opts.PCRs))
	for _, p := range opts.PCRs {
		pcrs = append(pcrs, int32(p))
	}

	req := &platformv1.QuoteVTPMRequest{
		BundleId: opts.BundleID,
		Nonce:    opts.Nonce,
		Pcrs:     pcrs,
	}

	resp, err := s.client.QuoteVTPM(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "QuoteVTPM", Err: err}
	}

	// Convert map[int32][]byte to map[int][]byte
	pcrValues := make(map[int][]byte, len(resp.GetPcrValues()))
	for k, v := range resp.GetPcrValues() {
		pcrValues[int(k)] = v
	}

	return &QuoteResult{
		BundleID:      resp.GetBundleId(),
		Quote:         resp.GetQuote(),
		Signature:     resp.GetSignature(),
		PCRValues:     pcrValues,
		HashAlgorithm: resp.GetHashAlgorithm(),
	}, nil
}

// Seal encrypts data to the TPM, optionally binding to PCR values via Unix socket.
func (s *UnixAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	// Convert []int to []int32 for proto
	pcrs := make([]int32, 0, len(opts.PCRs))
	for _, p := range opts.PCRs {
		pcrs = append(pcrs, int32(p))
	}

	req := &platformv1.SealVTPMRequest{
		BundleId:  opts.BundleID,
		Data:      opts.Data,
		Pcrs:      pcrs,
		AuthValue: opts.AuthValue,
	}

	resp, err := s.client.SealVTPM(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "SealVTPM", Err: err}
	}

	return &SealResult{
		BundleID:   resp.GetBundleId(),
		SealedData: resp.GetSealedData(),
	}, nil
}

// Unseal decrypts data that was previously sealed to the TPM via Unix socket.
func (s *UnixAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &platformv1.UnsealVTPMRequest{
		BundleId:   opts.BundleID,
		SealedData: opts.SealedData,
		AuthValue:  opts.AuthValue,
	}

	resp, err := s.client.UnsealVTPM(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "UnsealVTPM", Err: err}
	}

	return &UnsealResult{
		BundleID: resp.GetBundleId(),
		Data:     resp.GetData(),
	}, nil
}

// ExtendPCR extends a PCR with the provided data via Unix socket.
func (s *UnixAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	req := &platformv1.ExtendVTPMPCRRequest{
		BundleId: opts.BundleID,
		PcrIndex: int32(opts.PCRIndex),
		Data:     opts.Data,
	}

	resp, err := s.client.ExtendVTPMPCR(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ExtendVTPMPCR", Err: err}
	}

	return &ExtendPCRResult{
		BundleID: resp.GetBundleId(),
		PCRIndex: int(resp.GetPcrIndex()),
		Extended: resp.GetExtended(),
	}, nil
}

// ReadPCR reads the current value of a PCR via Unix socket.
func (s *UnixAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	req := &platformv1.ReadVTPMPCRRequest{
		BundleId: opts.BundleID,
		PcrIndex: int32(opts.PCRIndex),
	}

	resp, err := s.client.ReadVTPMPCR(ctx, req)
	if err != nil {
		return nil, ErrUnixVTPMRPCFailed{Method: "ReadVTPMPCR", Err: err}
	}

	return &ReadPCRResult{
		BundleID: resp.GetBundleId(),
		PCRIndex: int(resp.GetPcrIndex()),
		Value:    resp.GetValue(),
	}, nil
}

// =============================================================================
// Proto Conversion Helpers
// =============================================================================

// unixBundleModeToProto converts vtpm.BundleMode to proto BundleMode.
func unixBundleModeToProto(mode vtpm.BundleMode) platformv1.BundleMode {
	switch mode {
	case vtpm.BundleModeTemplate:
		return platformv1.BundleMode_BUNDLE_MODE_TEMPLATE
	case vtpm.BundleModePreAssigned:
		return platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED
	default:
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	}
}

// unixEKAlgorithmToProto converts vtpm.EKAlgorithm to proto EKAlgorithm.
func unixEKAlgorithmToProto(alg vtpm.EKAlgorithm) platformv1.EKAlgorithm {
	switch alg {
	case vtpm.EKAlgorithmRSA:
		return platformv1.EKAlgorithm_EK_ALGORITHM_RSA
	case vtpm.EKAlgorithmECC:
		return platformv1.EKAlgorithm_EK_ALGORITHM_ECC
	default:
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED
	}
}

// unixProtoToBundleMode converts proto BundleMode to vtpm.BundleMode.
func unixProtoToBundleMode(mode platformv1.BundleMode) vtpm.BundleMode {
	switch mode {
	case platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:
		return vtpm.BundleModeTemplate
	case platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED:
		return vtpm.BundleModePreAssigned
	default:
		return ""
	}
}

// unixProtoToEKAlgorithm converts proto EKAlgorithm to vtpm.EKAlgorithm.
func unixProtoToEKAlgorithm(alg platformv1.EKAlgorithm) vtpm.EKAlgorithm {
	switch alg {
	case platformv1.EKAlgorithm_EK_ALGORITHM_RSA:
		return vtpm.EKAlgorithmRSA
	case platformv1.EKAlgorithm_EK_ALGORITHM_ECC:
		return vtpm.EKAlgorithmECC
	default:
		return vtpm.EKAlgorithmRSA
	}
}

// unixProtoToBundle converts proto Bundle to vtpm.Bundle.
func unixProtoToBundle(pb *platformv1.Bundle) *vtpm.Bundle {
	if pb == nil {
		return nil
	}

	bundle := &vtpm.Bundle{
		ID:         pb.GetId(),
		Mode:       unixProtoToBundleMode(pb.GetMode()),
		Manifest:   unixProtoToManifest(pb.GetManifest()),
		TPMState:   unixProtoToTPMState(pb.GetTpmState()),
		OVMFState:  unixProtoToOVMFState(pb.GetOvmfState()),
		ClonedFrom: pb.GetClonedFrom(),
	}

	if pb.GetCreatedAt() != nil {
		bundle.CreatedAt = pb.GetCreatedAt().AsTime()
	}

	if pb.GetSecureBootKeys() != nil {
		bundle.SecureBootKeys = unixProtoToSecureBootKeyPaths(pb.GetSecureBootKeys())
	}

	return bundle
}

// unixProtoToTemplate converts proto Template to vtpm.Template.
func unixProtoToTemplate(pt *platformv1.Template) *vtpm.Template {
	if pt == nil {
		return nil
	}

	template := &vtpm.Template{
		ID:                pt.GetId(),
		Description:       pt.GetDescription(),
		TPMStateDir:       pt.GetTpmStateDir(),
		NVRAMPath:         pt.GetNvramPath(),
		SecureBootKeysDir: pt.GetSecureBootKeysDir(),
		EKAlgorithm:       unixProtoToEKAlgorithm(pt.GetEkAlgorithm()),
		SecureBootEnabled: pt.GetSecureBootEnabled(),
	}

	if pt.GetCreatedAt() != nil {
		template.CreatedAt = pt.GetCreatedAt().AsTime()
	}

	return template
}

// unixProtoToManifest converts proto Manifest to vtpm.Manifest.
func unixProtoToManifest(pm *platformv1.Manifest) *vtpm.Manifest {
	if pm == nil {
		return nil
	}

	manifest := &vtpm.Manifest{
		Version:           pm.GetVersion(),
		ID:                pm.GetId(),
		Mode:              unixProtoToBundleMode(pm.GetMode()),
		Hostname:          pm.GetHostname(),
		EKAlgorithm:       unixProtoToEKAlgorithm(pm.GetEkAlgorithm()),
		EKHandle:          pm.GetEkHandle(),
		SecureBootEnabled: pm.GetSecureBootEnabled(),
		Checksums:         pm.GetChecksums(),
		Labels:            pm.GetLabels(),
		ClonedFrom:        pm.GetClonedFrom(),
	}

	if pm.GetCreatedAt() != nil {
		manifest.CreatedAt = pm.GetCreatedAt().AsTime()
	}

	if pm.GetEkCertificate() != nil {
		manifest.EKCertificate = unixProtoToEKCertInfo(pm.GetEkCertificate())
	}

	if pm.GetSecureBootKeys() != nil {
		manifest.SecureBootKeys = unixProtoToSecureBootKeyInfo(pm.GetSecureBootKeys())
	}

	return manifest
}

// unixProtoToEKCertInfo converts proto EKCertInfo to vtpm.EKCertInfo.
func unixProtoToEKCertInfo(pc *platformv1.EKCertInfo) *vtpm.EKCertInfo {
	if pc == nil {
		return nil
	}

	info := &vtpm.EKCertInfo{
		Subject:      pc.GetSubject(),
		Issuer:       pc.GetIssuer(),
		SerialNumber: pc.GetSerialNumber(),
		Fingerprint:  pc.GetFingerprint(),
	}

	if pc.GetNotBefore() != nil {
		info.NotBefore = pc.GetNotBefore().AsTime()
	}

	if pc.GetNotAfter() != nil {
		info.NotAfter = pc.GetNotAfter().AsTime()
	}

	return info
}

// unixProtoToSecureBootKeyInfo converts proto SecureBootKeyInfo to vtpm.SecureBootKeyInfo.
func unixProtoToSecureBootKeyInfo(ps *platformv1.SecureBootKeyInfo) *vtpm.SecureBootKeyInfo {
	if ps == nil {
		return nil
	}

	return &vtpm.SecureBootKeyInfo{
		PKFingerprint:  ps.GetPkFingerprint(),
		KEKFingerprint: ps.GetKekFingerprint(),
		DBFingerprint:  ps.GetDbFingerprint(),
		OwnerGUID:      ps.GetOwnerGuid(),
	}
}

// unixProtoToSecureBootKeyPaths converts proto SecureBootKeyPaths to vtpm.SecureBootKeyPaths.
func unixProtoToSecureBootKeyPaths(ps *platformv1.SecureBootKeyPaths) *vtpm.SecureBootKeyPaths {
	if ps == nil {
		return nil
	}

	return &vtpm.SecureBootKeyPaths{
		Dir:     ps.GetDir(),
		PKKey:   ps.GetPkKey(),
		PKCert:  ps.GetPkCrt(),
		KEKKey:  ps.GetKekKey(),
		KEKCert: ps.GetKekCrt(),
		DBKey:   ps.GetDbKey(),
		DBCert:  ps.GetDbCrt(),
	}
}

// unixProtoToTPMState converts proto TPMState to vtpm.TPMState.
func unixProtoToTPMState(pt *platformv1.TPMState) *vtpm.TPMState {
	if pt == nil {
		return nil
	}

	return &vtpm.TPMState{
		StateDir:     pt.GetStateDir(),
		PermallFile:  pt.GetPermallFile(),
		VolatileFile: pt.GetVolatileFile(),
	}
}

// unixProtoToOVMFState converts proto OVMFState to vtpm.OVMFState.
func unixProtoToOVMFState(po *platformv1.OVMFState) *vtpm.OVMFState {
	if po == nil {
		return nil
	}

	return &vtpm.OVMFState{
		NVRAMFile: po.GetNvramFile(),
	}
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure UnixAdapter implements VTPMCommands interface.
var _ VTPMCommands = (*UnixAdapter)(nil)
